"""Synthetic v24 supervisor tests. No real external authority is provisioned."""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from atomic_replay_authority_v19 import AtomicReplayAuthority
from checkpoint_publication_recovery_v23 import CheckpointPublicationRecovery
from checkpoint_recovery_supervisor_v24 import (
    CheckpointRecoverySupervisor, SupervisorError,
)
from durable_checkpoint_anchor_v22 import DurableCheckpointAnchor
from distributed_replay_v18 import candidate
from monotonic_authority_checkpoints_v21 import GENESIS


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.authority = AtomicReplayAuthority(
            root / "authority.sqlite", authorize_candidate=lambda _: True,
            sign_receipt=lambda _: "synthetic-receipt")
        self.anchor = DurableCheckpointAnchor(root / "anchor.sqlite")
        self.queue = CheckpointPublicationRecovery(
            root / "outbox.sqlite", authority=self.authority, anchor=self.anchor)
        self.path = root / "supervisor.sqlite"
        self.supervisor = self.reopen()
        self.authority.decide(candidate(
            "sender", "recipient", "message-1",
            hashlib.sha256(b"message").hexdigest(), "device"))
        self.queue.stage_next()

    def reopen(self, **kwargs):
        return CheckpointRecoverySupervisor(self.path, queue=self.queue, **kwargs)

    def attempt(self, **kwargs):
        options = {
            "verify_receipt": lambda *_: True,
            "authorize_publish": lambda *_: True,
            "independently_verify_anchor": lambda seq, head:
                self.anchor.current() == (seq, head),
        }
        options.update(kwargs)
        return self.supervisor.run_once(**options)

    @staticmethod
    def outage(*_):
        raise ConnectionError("synthetic offline")

    def test_initial_ready(self):
        report = self.supervisor.inspect()
        self.assertEqual(report["state"], "READY")
        self.assertEqual(report["authorization"], "DENY")

    def test_single_success(self):
        report = self.attempt()
        self.assertEqual(report["state"], "SUCCEEDED")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)
        self.assertEqual(self.anchor.current()[0], 1)

    def test_no_automatic_second_attempt(self):
        self.attempt()
        with self.assertRaisesRegex(SupervisorError, "NO_PENDING_INTENT"):
            self.attempt()

    def test_transient_external_outage_is_retryable(self):
        self.assertEqual(self.attempt(
            independently_verify_anchor=self.outage)["state"], "RETRYABLE")
        self.assertEqual(self.supervisor.inspect()["attempts"], 1)
        self.assertTrue(self.queue.inspect_local()["pending"])

    def test_retries_are_explicit_only(self):
        self.attempt(independently_verify_anchor=self.outage)
        self.assertEqual(self.supervisor.inspect()["attempts"], 1)
        self.assertEqual(self.supervisor.inspect()["attempts"], 1)

    def test_resume_after_restart(self):
        self.attempt(independently_verify_anchor=self.outage)
        self.supervisor = self.reopen()
        self.assertEqual(self.attempt()["state"], "SUCCEEDED")
        self.assertEqual(self.anchor.current()[0], 1)

    def test_retry_budget_exhaustion(self):
        states = [self.attempt(
            independently_verify_anchor=self.outage)["state"] for _ in range(3)]
        self.assertEqual(states, ["RETRYABLE", "RETRYABLE", "EXHAUSTED"])
        with self.assertRaisesRegex(SupervisorError, "TERMINAL_ATTEMPT"):
            self.attempt()
        self.assertEqual(self.supervisor.inspect()["state"], "EXHAUSTED")

    def test_invalid_signature_is_blocked(self):
        report = self.attempt(verify_receipt=lambda *_: False)
        self.assertEqual(report["state"], "BLOCKED")
        self.assertEqual(report["error_code"], "ANCHOR_PUBLISH_FAILED")
        with self.assertRaisesRegex(SupervisorError, "TERMINAL_ATTEMPT"):
            self.attempt()

    def test_invalid_publisher_is_blocked(self):
        report = self.attempt(authorize_publish=lambda *_: False)
        self.assertEqual(report["state"], "BLOCKED")

    def test_false_external_attestation_is_blocked(self):
        report = self.attempt(independently_verify_anchor=lambda *_: False)
        self.assertEqual(report["error_code"], "EXTERNAL_ANCHOR_UNVERIFIED")
        self.assertEqual(report["state"], "BLOCKED")

    def test_truthy_nonboolean_attestation_is_blocked(self):
        report = self.attempt(independently_verify_anchor=lambda *_: 1)
        self.assertEqual(report["state"], "BLOCKED")

    def test_missing_verifier_is_not_attempted(self):
        with self.assertRaisesRegex(SupervisorError, "EXTERNAL_TRUST_REQUIRED"):
            self.attempt(verify_receipt=None)
        self.assertEqual(self.supervisor.inspect()["attempts"], 0)

    def test_missing_anchor_is_not_attempted(self):
        with self.assertRaisesRegex(SupervisorError, "EXTERNAL_TRUST_REQUIRED"):
            self.attempt(independently_verify_anchor=None)
        self.assertEqual(self.supervisor.inspect()["attempts"], 0)

    def test_restart_preserves_block(self):
        self.attempt(authorize_publish=lambda *_: False)
        self.supervisor = self.reopen()
        self.assertEqual(self.supervisor.inspect()["state"], "BLOCKED")
        with self.assertRaisesRegex(SupervisorError, "TERMINAL_ATTEMPT"):
            self.attempt()

    def test_invalid_max_attempts_rejected(self):
        with self.assertRaisesRegex(SupervisorError, "INVALID_RETRY_LIMIT"):
            self.reopen(max_attempts=0)

    def test_boolean_max_attempts_rejected(self):
        with self.assertRaisesRegex(SupervisorError, "INVALID_RETRY_LIMIT"):
            self.reopen(max_attempts=True)

    def test_single_retry_budget(self):
        self.supervisor = self.reopen(max_attempts=1)
        self.assertEqual(self.attempt(
            independently_verify_anchor=self.outage)["state"], "EXHAUSTED")

    def test_database_append_only_guards(self):
        self.attempt(independently_verify_anchor=self.outage)
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE supervisor_attempts SET result='SUCCEEDED'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM supervisor_attempts")

    def test_corrupt_attempt_sequence_denied(self):
        self.attempt(independently_verify_anchor=self.outage)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER supervisor_no_update")
            db.execute("UPDATE supervisor_attempts SET attempt=9")
        with self.assertRaisesRegex(SupervisorError, "CORRUPT_ATTEMPT_HISTORY"):
            self.supervisor.inspect()

    def test_no_raw_exception_leakage(self):
        report = self.attempt(independently_verify_anchor=self.outage)
        self.assertNotIn("synthetic offline", str(report))
        self.assertEqual(report["error_code"], "EXTERNAL_ANCHOR_UNAVAILABLE")

    def test_second_sequence_has_fresh_budget(self):
        self.attempt()
        self.authority.decide(candidate("sender", "recipient", "message-2",
                                        "b"*64, "device"))
        self.queue.stage_next()
        self.assertEqual(self.supervisor.inspect()["attempts"], 0)
        self.assertEqual(self.attempt()["target_sequence"], 2)

    def test_no_pending_is_not_approval(self):
        self.attempt()
        report = self.supervisor.inspect()
        self.assertEqual(report["state"], "NO_PENDING")
        self.assertEqual(report["authorization"], "DENY")


if __name__ == "__main__":
    unittest.main()
