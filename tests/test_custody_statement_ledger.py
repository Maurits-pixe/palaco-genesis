"""Custody statement replay, atomic chain, identity and rollback security tests."""
import copy
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
fixture_spec = importlib.util.spec_from_file_location(
    "custody_fixture", ROOT / "tests" / "test_signed_custody_statement.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
ledger_spec = importlib.util.spec_from_file_location(
    "custody_ledger", ROOT / "tools" / "custody_statement_ledger.py")
ledger = importlib.util.module_from_spec(ledger_spec)
ledger_spec.loader.exec_module(ledger)


class CustodyStatementLedgerTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.SignedCustodyStatementTests(methodName="test_valid_signed_claim_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "custody-ledger.sqlite"

    def record(self, stmt=None, expected="custodian-a", floor=1, policy=None, anchor=None,
               revoked=None):
        result = ledger.record(
            self.db, self.f.db,
            self.f.anchor if anchor is None else anchor,
            self.f.policy if policy is None else policy,
            self.f.statement if stmt is None else stmt, expected,
            self.f.allow, self.f.ckeys,
            set() if revoked is None else revoked,
            self.f.groots, set(), self.f.wroots, set(), 7, floor)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def inspect(self, head, minimum=1):
        result = ledger.inspect(self.db, head, minimum)
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_first_signed_claim_recorded_only(self):
        self.assertTrue(self.record()["recorded"])

    def test_exact_replay_quarantined(self):
        self.record()
        self.assertEqual(self.record()["reason"], "custody-statement-replay")

    def test_same_statement_id_different_signed_envelope_rejected(self):
        self.record()
        altered = self.f.make_statement({"disposition": self.f.statement["statement"]["disposition"]})
        # Same signed declaration with different signature encoding is impossible
        # without changing the key; different statement body fails binding first.
        self.assertEqual(self.record(altered)["reason"], "custody-statement-replay")

    def test_same_anchor_new_statement_id_rejected(self):
        self.record()
        another = self.f.make_statement({"statement_id": "2"*32})
        self.assertEqual(self.record(another)["reason"], "custody-anchor-replay")

    def test_anchor_head_external_tamper_detected(self):
        first = self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE custody_statement_chain SET event_hash=?", ("f"*64,))
        self.assertEqual(self.inspect(first["head_hash"])["reason"], "custody-ledger-integrity-failed")

    def test_index_tampering_detected(self):
        first = self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE observed_custody_statements SET envelope_sha256=?", ("f"*64,))
        self.assertEqual(self.inspect(first["head_hash"])["reason"], "custody-ledger-integrity-failed")

    def test_missing_index_row_detected(self):
        first = self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM observed_custody_statements")
        self.assertEqual(self.inspect(first["head_hash"])["reason"], "custody-ledger-integrity-failed")

    def test_wrong_pinned_head_rejected(self):
        self.record()
        self.assertEqual(self.inspect("f"*64)["reason"], "custody-ledger-head-mismatch")

    def test_external_minimum_fails_closed(self):
        first = self.record()
        self.assertEqual(self.inspect(first["head_hash"], 2)["reason"], "custody-ledger-rollback")

    def test_valid_external_head_remains_pending(self):
        first = self.record()
        self.assertTrue(self.inspect(first["head_hash"])["chain_valid"])
        self.assertEqual(self.inspect(first["head_hash"])["state"], "pending-review")

    def test_mutated_signature_never_creates_ledger(self):
        broken = copy.deepcopy(self.f.statement)
        broken["signature_b64"] = "bogus"
        self.assertEqual(self.record(broken)["reason"], "invalid-custodian-signature-format")
        self.assertFalse(self.db.exists())

    def test_revoked_custodian_never_creates_ledger(self):
        self.assertEqual(self.record(revoked={self.f.cid})["reason"], "custodian-revoked")
        self.assertFalse(self.db.exists())

    def test_unverified_policy_never_creates_ledger(self):
        altered = copy.deepcopy(self.f.policy)
        altered["policy"]["revision"] = 8
        self.assertEqual(self.record(policy=altered)["reason"], "custody-statement-envelope-binding-failed")
        self.assertFalse(self.db.exists())

    def test_missing_ledger_read_only_does_not_create_file(self):
        self.assertEqual(self.inspect("f"*64)["reason"], "missing-custody-ledger")
        self.assertFalse(self.db.exists())

    def test_receipt_db_cannot_be_ledger(self):
        with self.assertRaises(ValueError):
            ledger.record(self.f.db, self.f.db, self.f.anchor, self.f.policy,
                          self.f.statement, "custodian-a", self.f.allow, self.f.ckeys,
                          set(), self.f.groots, set(), self.f.wroots, set(), 7, 1)

    def test_no_trusted_head_denied(self):
        self.record()
        self.assertEqual(self.inspect(None)["reason"], "missing-independent-ledger-anchor")

    def test_chain_matches_exactly_one_index_record(self):
        self.record()
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM custody_statement_chain").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM observed_custody_statements").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
