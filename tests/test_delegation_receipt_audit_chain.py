"""Transactional delegation receipt audit and independently pinned rollback checks."""
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
fixture_spec = importlib.util.spec_from_file_location(
    "delegation_receipt_audit_fixture",
    ROOT / "tests" / "test_delegation_evidence_handoff.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location(
    "delegation_receipt_audit", ROOT / "tools" / "delegation_receipt_audit_chain.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class DelegationReceiptAuditTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.DelegationEvidenceHandoffTests(
            methodName="test_valid_claim_stays_pending")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def check(self, head, minimum=1):
        result = audit.inspect(self.f.db, head, minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_first_receipt_is_chained(self):
        result = self.f.record()
        self.assertTrue(result["recorded"])
        self.assertEqual(result["entries"], 1)
        self.assertTrue(self.check(result["head_hash"])["chain_valid"])

    def test_replay_does_not_change_head(self):
        first = self.f.record()
        self.assertEqual(self.f.record()["reason"], "receipt-replay")
        self.assertEqual(self.check(first["head_hash"])["entries"], 1)

    def test_second_receipt_same_package_is_denied_atomically(self):
        first = self.f.record()
        self.assertEqual(self.f.record(self.f.receipt(id="b"*32))["reason"],
                         "duplicate-package-receipt")
        self.assertTrue(self.check(first["head_hash"])["chain_valid"])

    def test_tampered_chain_hash_denied(self):
        first = self.f.record()
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("UPDATE delegation_receipt_audit SET event_hash=?", ("f"*64,))
        self.assertEqual(self.check(first["head_hash"])["reason"],
                         "receipt-audit-integrity-failed")

    def test_tampered_receipt_index_denied(self):
        first = self.f.record()
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("UPDATE delegation_handoff_receipts SET receipt_sha256=?", ("f"*64,))
        self.assertEqual(self.check(first["head_hash"])["reason"],
                         "receipt-audit-integrity-failed")

    def test_deleted_index_denied(self):
        first = self.f.record()
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("DELETE FROM delegation_handoff_receipts")
        self.assertEqual(self.check(first["head_hash"])["reason"],
                         "receipt-audit-integrity-failed")

    def test_deleted_audit_row_denied(self):
        first = self.f.record()
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("DELETE FROM delegation_receipt_audit")
        self.assertEqual(self.check(first["head_hash"])["reason"],
                         "receipt-audit-integrity-failed")

    def test_wrong_external_head_denied(self):
        self.f.record()
        self.assertEqual(self.check("f"*64)["reason"], "receipt-audit-head-mismatch")

    def test_stronger_external_floor_denied(self):
        first = self.f.record()
        self.assertEqual(self.check(first["head_hash"], 2)["reason"],
                         "receipt-audit-rollback")

    def test_missing_external_head_denied(self):
        self.f.record()
        self.assertEqual(self.check(None)["reason"], "missing-independent-audit-pin")

    def test_boolean_floor_denied(self):
        self.f.record()
        self.assertEqual(self.check("f"*64, True)["reason"],
                         "missing-independent-audit-pin")

    def test_missing_file_not_created_by_inspection(self):
        self.assertEqual(self.check("f"*64)["reason"], "missing-receipt-register")
        self.assertFalse(self.f.db.exists())

    def test_corrupt_chain_rejects_next_registration_without_extra_row(self):
        first = self.f.record()
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("UPDATE delegation_receipt_audit SET previous_hash=?", ("f"*64,))
        with self.assertRaises(ValueError):
            self.f.record(self.f.receipt(id="b"*32))
        with sqlite3.connect(self.f.db) as conn:
            count = conn.execute("SELECT COUNT(*) FROM delegation_handoff_receipts").fetchone()[0]
        self.assertEqual(count, 1)

    def test_append_requires_transaction(self):
        with sqlite3.connect(":memory:") as conn:
            with self.assertRaisesRegex(ValueError, "active transaction"):
                audit.append(conn, "a"*32, "b"*64, "archive-alpha", "c"*64, "d"*64)

    def test_append_invalid_recipient_rejected(self):
        with sqlite3.connect(":memory:") as conn:
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(ValueError, "invalid-delegation-receipt-event"):
                audit.append(conn, "a"*32, "b"*64, "../bad", "c"*64, "d"*64)
            conn.rollback()

    def test_duplicate_event_sequence_denied(self):
        first = self.f.record()
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("UPDATE delegation_receipt_audit SET sequence=2")
        self.assertEqual(self.check(first["head_hash"])["reason"],
                         "receipt-audit-integrity-failed")

    def test_local_genesis_never_sufficient(self):
        self.f.record()
        self.assertEqual(self.check(audit.GENESIS)["reason"],
                         "receipt-audit-head-mismatch")


if __name__ == "__main__":
    unittest.main()
