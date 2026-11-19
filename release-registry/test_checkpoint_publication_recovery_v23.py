"""PALACO v23 checkpoint publication recovery regression tests.

All proof, publisher and attestation callbacks are synthetic test fixtures.
"""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from atomic_replay_authority_v19 import AtomicReplayAuthority
from durable_checkpoint_anchor_v22 import DurableCheckpointAnchor
from checkpoint_publication_recovery_v23 import (
    CheckpointPublicationRecovery, PublicationError,
)
from distributed_replay_v18 import candidate
from monotonic_authority_checkpoints_v21 import GENESIS


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.authority = AtomicReplayAuthority(
            folder / "authority.sqlite",
            authorize_candidate=lambda _: True,
            sign_receipt=lambda _: "synthetic-proof")
        self.anchor = DurableCheckpointAnchor(folder / "anchor.sqlite")
        self.path = folder / "publication.sqlite"
        self.queue = self.reopen()
        self.claim = candidate("sender", "recipient", "msg-1",
                               hashlib.sha256(b"one").hexdigest(), "phone")
        self.authority.decide(self.claim)
        self.signatures = lambda *_: True
        self.publisher = lambda *_: True
        self.attest = lambda n, h: self.anchor.current() == (n, h)

    def reopen(self):
        return CheckpointPublicationRecovery(
            self.path, authority=self.authority, anchor=self.anchor)

    def stage(self):
        return self.queue.stage_next()

    def reconcile(self, **overrides):
        options = dict(verify_receipt=self.signatures,
                       authorize_publish=self.publisher,
                       independently_verify_anchor=self.attest)
        options.update(overrides)
        return self.queue.reconcile(**options)

    def test_stage_persists_after_restart(self):
        staged = self.stage()
        self.assertEqual(staged["state"], "PENDING")
        self.assertIs(self.reopen().inspect_local()["pending"], True)

    def test_reconcile_publishes_once(self):
        self.stage()
        report = self.reconcile()
        self.assertEqual(report["state"], "LOCALLY_RECONCILED")
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)
        self.assertEqual(self.anchor.current(), (1, report["head"]))

    def test_restart_reconcile(self):
        self.stage()
        self.queue = self.reopen()
        self.assertEqual(self.reconcile()["sequence"], 1)

    def test_no_duplicate_publication(self):
        self.stage()
        self.reconcile()
        with self.assertRaisesRegex(PublicationError, "NO_PENDING_INTENT"):
            self.reconcile()
        self.assertEqual(self.anchor.current()[0], 1)

    def test_lost_acknowledgement_recovered(self):
        staged = self.stage()
        claims, receipts = self.authority.read_decisions()
        self.anchor.advance(claims, receipts, expected_sequence=0,
                            expected_head=GENESIS,
                            verify_receipt=self.signatures,
                            authorize_publish=self.publisher)
        self.queue = self.reopen()
        report = self.reconcile()
        self.assertEqual(report["head"], staged["head"])
        self.assertEqual(self.anchor.current()[0], 1)

    def test_external_anchor_denied_keeps_pending(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "EXTERNAL_ANCHOR_UNVERIFIED"):
            self.reconcile(independently_verify_anchor=lambda *_: False)
        self.assertIs(self.queue.inspect_local()["pending"], True)

    def test_anchor_unavailable_keeps_pending(self):
        self.stage()
        def fail(*_):
            raise ConnectionError("external anchor offline")
        with self.assertRaisesRegex(PublicationError, "EXTERNAL_ANCHOR_UNAVAILABLE"):
            self.reconcile(independently_verify_anchor=fail)

    def test_external_anchor_nonboolean_denied(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "EXTERNAL_ANCHOR_UNVERIFIED"):
            self.reconcile(independently_verify_anchor=lambda *_: 1)

    def test_no_signature_provider_denied(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "EXTERNAL_TRUST_REQUIRED"):
            self.reconcile(verify_receipt=None)
        self.assertEqual(self.anchor.current(), (0, GENESIS))

    def test_no_publisher_provider_denied(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "EXTERNAL_TRUST_REQUIRED"):
            self.reconcile(authorize_publish=None)

    def test_bad_signature_keeps_pending(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "ANCHOR_PUBLISH_FAILED"):
            self.reconcile(verify_receipt=lambda *_: False)
        self.assertEqual(self.anchor.current(), (0, GENESIS))
        self.assertIs(self.queue.inspect_local()["pending"], True)

    def test_bad_publisher_keeps_pending(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "ANCHOR_PUBLISH_FAILED"):
            self.reconcile(authorize_publish=lambda *_: False)
        self.assertEqual(self.anchor.current(), (0, GENESIS))

    def test_double_stage_denied(self):
        self.stage()
        with self.assertRaisesRegex(PublicationError, "PENDING_INTENT_EXISTS"):
            self.stage()

    def test_no_authority_decision_denied(self):
        self.authority = AtomicReplayAuthority(
            self.path.parent / "empty-authority.sqlite",
            authorize_candidate=lambda _: True,
            sign_receipt=lambda _: "fixture")
        with self.assertRaisesRegex(PublicationError, "NO_UNPUBLISHED_DECISION"):
            self.stage()

    def test_next_contiguous_checkpoint(self):
        self.stage()
        self.reconcile()
        self.authority.decide(candidate(
            "sender", "recipient", "msg-2", "b"*64, "tablet"))
        staged = self.stage()
        self.assertEqual(staged["sequence"], 2)
        self.assertEqual(self.reconcile()["sequence"], 2)

    def test_restart_after_publication_no_duplicate(self):
        self.stage()
        self.reconcile()
        self.queue = self.reopen()
        self.assertFalse(self.queue.inspect_local()["pending"])
        self.assertEqual(self.queue.inspect_local()["completion_count"], 1)

    def test_deleted_anchor_history_denied(self):
        self.stage()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER intents_no_update")
            db.execute("UPDATE publication_intents SET previous_head=?",
                       ("0"*64,))
        with self.assertRaisesRegex(PublicationError, "CORRUPT_INTENT_CHAIN"):
            self.queue.inspect_local()

    def test_modified_intent_head_denied(self):
        self.stage()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER intents_no_update")
            db.execute("UPDATE publication_intents SET head=?", ("0"*64,))
        with self.assertRaises(PublicationError):
            self.reconcile()

    def test_update_trigger(self):
        self.stage()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE publication_intents SET head=?", ("0"*64,))

    def test_delete_trigger(self):
        self.stage()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM publication_intents")

    def test_no_trust_is_derived_from_local_queue(self):
        self.stage()
        local = self.queue.inspect_local()
        self.assertEqual(local["authorization"], "DENY")
        self.assertEqual(local["release"], "HOLD")
        self.assertNotIn("approved", local)

    def test_source_history_must_still_match(self):
        self.stage()
        with sqlite3.connect(self.path.parent / "authority.sqlite") as db:
            db.execute("DROP TRIGGER authority_decisions_no_update")
            db.execute("UPDATE authority_decisions SET proof='altered' WHERE sequence=1")
        with self.assertRaises(Exception):
            self.reconcile()


if __name__ == "__main__":
    unittest.main()
