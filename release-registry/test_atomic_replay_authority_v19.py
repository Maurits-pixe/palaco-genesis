"""Synthetic tests for v19 atomic coordinator, NOT real trusted signing."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from atomic_replay_authority_v19 import AtomicReplayAuthority, AuthorityError
from distributed_replay_v18 import candidate, inspect_decisions


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "authority.sqlite"
        self.sign = lambda statement: hashlib.sha256(statement).hexdigest()
        self.make = lambda policy=None, sign=None: AtomicReplayAuthority(
            self.file, authorize_candidate=(
                (lambda _: True) if policy is None else policy),
            sign_receipt=self.sign if sign is None else sign)
        self.authority = self.make()
        self.c = candidate("alice", "bob", "msg-1", hashlib.sha256(b"one").hexdigest(), "phone")

    def test_first_then_duplicate(self):
        first = self.authority.decide(self.c)
        second = self.authority.decide(self.c)
        self.assertEqual(first["decision"], "first-claim")
        self.assertEqual(second["decision"], "duplicate")
        self.assertEqual((first["authority_sequence"], second["authority_sequence"]), (1, 2))

    def test_conflict_changes_package(self):
        self.authority.decide(self.c)
        other = dict(self.c, package_sha256=hashlib.sha256(b"two").hexdigest())
        self.assertEqual(self.authority.decide(other)["decision"], "conflict")

    def test_restart_does_not_reset(self):
        self.authority.decide(self.c)
        self.assertEqual(self.make().decide(self.c)["decision"], "duplicate")

    def test_independent_messages_first(self):
        other = dict(self.c, message_id="msg-2")
        self.assertEqual(self.authority.decide(self.c)["decision"], "first-claim")
        self.assertEqual(self.authority.decide(other)["decision"], "first-claim")

    def test_other_device_same_tuple_duplicate(self):
        self.authority.decide(self.c)
        other = dict(self.c, device_id="tablet")
        self.assertEqual(self.authority.decide(other)["decision"], "duplicate")

    def test_concurrent_only_one_first(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            decisions = list(executor.map(
                lambda _: self.authority.decide(self.c)["decision"], range(12)))
        self.assertEqual(decisions.count("first-claim"), 1)
        self.assertEqual(decisions.count("duplicate"), 11)

    def test_independent_connections_serial(self):
        second = self.make()
        with ThreadPoolExecutor(max_workers=2) as executor:
            decisions = list(executor.map(
                lambda a: a.decide(self.c)["decision"], (self.authority, second)))
        self.assertEqual(set(decisions), {"first-claim", "duplicate"})

    def test_policy_denial_before_write(self):
        denied = self.make(policy=lambda _: False)
        with self.assertRaisesRegex(AuthorityError, "INTAKE_NOT_AUTHORIZED"):
            denied.decide(self.c)
        self.assertEqual(self.authority.read_decisions(), ((), ()))

    def test_truthy_policy_denied(self):
        with self.assertRaisesRegex(AuthorityError, "INTAKE_NOT_AUTHORIZED"):
            self.make(policy=lambda _: 1).decide(self.c)

    def test_policy_exception_denied(self):
        def fail(_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(AuthorityError, "INTAKE_POLICY_UNAVAILABLE"):
            self.make(policy=fail).decide(self.c)

    def test_signer_exception_rolls_back(self):
        def fail(_):
            raise ConnectionError("signer unavailable")
        with self.assertRaisesRegex(AuthorityError, "SIGNING_UNAVAILABLE"):
            self.make(sign=fail).decide(self.c)
        self.assertEqual(self.authority.read_decisions(), ((), ()))

    def test_bad_signer_proof_rolls_back(self):
        with self.assertRaisesRegex(AuthorityError, "INVALID_RECEIPT_PROOF"):
            self.make(sign=lambda _: "").decide(self.c)
        self.assertEqual(self.authority.decide(self.c)["authority_sequence"], 1)

    def test_signer_receives_domain_statement(self):
        statements = []
        def sign(s):
            statements.append(s)
            return "synthetic"
        self.make(sign=sign).decide(self.c)
        self.assertTrue(statements[0].startswith(
            b"PALACO-DISTRIBUTED-REPLAY-v18:RECEIPT"))

    def test_readback_receipts(self):
        a = self.authority.decide(self.c)
        b = self.authority.decide(self.c)
        claims, receipts = self.authority.read_decisions()
        self.assertEqual(claims, (self.c, self.c))
        self.assertEqual(receipts, (a, b))

    def test_v18_contract_still_denies(self):
        self.authority.decide(self.c)
        claims, receipts = self.authority.read_decisions()
        output = inspect_decisions(
            claims, receipts, verify_authority=lambda statement, proof:
                self.sign(statement) == proof,
            get_trusted_watermark=lambda: 1)
        self.assertEqual(output["authorization"], "DENY")
        self.assertEqual(output["release"], "HOLD")

    def test_no_authority_callbacks(self):
        with self.assertRaisesRegex(AuthorityError, "EXTERNAL_AUTHORITY_REQUIRED"):
            AtomicReplayAuthority(self.file, authorize_candidate=None,
                                  sign_receipt=self.sign)

    def test_update_triggers(self):
        self.authority.decide(self.c)
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE authority_decisions SET proof='forged'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE authority_first_claims SET device_id='forged'")

    def test_delete_triggers(self):
        self.authority.decide(self.c)
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM authority_decisions")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM authority_first_claims")

    def test_detect_decision_history_gap(self):
        self.authority.decide(self.c)
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER authority_decisions_no_delete")
            db.execute("DELETE FROM authority_decisions")
        with self.assertRaisesRegex(AuthorityError, "FIRST_CLAIM_INDEX_MISMATCH"):
            self.authority.read_decisions()

    def test_detect_index_corruption(self):
        self.authority.decide(self.c)
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER authority_first_no_delete")
            db.execute("DELETE FROM authority_first_claims")
        with self.assertRaisesRegex(AuthorityError, "FIRST_CLAIM_INDEX_MISMATCH"):
            self.authority.read_decisions()

    def test_invalid_candidate(self):
        with self.assertRaises(ValueError):
            self.authority.decide(dict(self.c, message_id="../bad"))

    def test_invalid_parent(self):
        with self.assertRaisesRegex(AuthorityError, "INVALID_DATABASE_PATH"):
            AtomicReplayAuthority(self.file.parent / "missing" / "a.db",
                authorize_candidate=lambda _: True, sign_receipt=self.sign)


if __name__ == "__main__":
    unittest.main()
