"""Transactional audit chaining and pinned-head checks for custody receipts."""
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_fixture_spec = importlib.util.spec_from_file_location(
    "custody_ack_fixture", ROOT/"tests"/"test_custody_anchor_handoff.py")
fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(fixture)
_spec = importlib.util.spec_from_file_location(
    "custody_ack_chain", ROOT/"tools"/"custody_ack_audit_chain.py")
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


class CustodyAckAuditTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.CustodyAnchorHandoffTests(methodName="test_verified_signed_receipt_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def inspect(self, head, minimum=1):
        result = audit.inspect(self.f.receipts, head, minimum)
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_record_contains_first_chain_event(self):
        result = self.f.record()
        self.assertTrue(result["recorded"])
        self.assertEqual(result["entries"],1)
        self.assertTrue(self.inspect(result["head_hash"])["chain_valid"])

    def test_replay_does_not_append(self):
        result = self.f.record()
        self.assertEqual(self.f.record()["reason"],"acknowledgement-replay")
        self.assertEqual(self.inspect(result["head_hash"])["entries"],1)

    def test_duplicate_package_does_not_append(self):
        result = self.f.record()
        self.assertEqual(self.f.record(self.f.ack("b"*32))["reason"],"duplicate-package-acknowledgement")
        self.assertTrue(self.inspect(result["head_hash"])["chain_valid"])

    def test_tampered_event_rejected(self):
        result = self.f.record()
        with sqlite3.connect(self.f.receipts) as conn:
            conn.execute("UPDATE custody_ack_audit_chain SET event_hash=?",("f"*64,))
        self.assertEqual(self.inspect(result["head_hash"])["reason"],"ack-chain-integrity-failed")

    def test_tampered_index_rejected(self):
        result = self.f.record()
        with sqlite3.connect(self.f.receipts) as conn:
            conn.execute("UPDATE custody_anchor_acknowledgements SET receipt_sha256=?",("f"*64,))
        self.assertEqual(self.inspect(result["head_hash"])["reason"],"ack-chain-integrity-failed")

    def test_deleted_index_row_rejected(self):
        result = self.f.record()
        with sqlite3.connect(self.f.receipts) as conn:
            conn.execute("DELETE FROM custody_anchor_acknowledgements")
        self.assertEqual(self.inspect(result["head_hash"])["reason"],"ack-chain-integrity-failed")

    def test_wrong_external_head_rejected(self):
        self.f.record()
        self.assertEqual(self.inspect("f"*64)["reason"],"ack-chain-head-mismatch")

    def test_external_floor_rejects_rollback(self):
        result = self.f.record()
        self.assertEqual(self.inspect(result["head_hash"],2)["reason"],"ack-chain-rollback")

    def test_missing_external_head_denied(self):
        self.f.record()
        self.assertEqual(self.inspect(None)["reason"],"missing-independent-ack-head")

    def test_no_missing_file_creation_on_inspection(self):
        self.assertEqual(self.inspect("f"*64)["reason"],"missing-ack-register")
        self.assertFalse(self.f.receipts.exists())

    def test_register_write_is_atomic_if_chain_invalid(self):
        result = self.f.record()
        with sqlite3.connect(self.f.receipts) as conn:
            conn.execute("UPDATE custody_ack_audit_chain SET event_hash=?",("f"*64,))
        # A separate, signed receipt for the same packet should fail-closed;
        # an attempted new insert must not expand the receipt index.
        with self.assertRaises(ValueError):
            self.f.record(self.f.ack("b"*32))
        with sqlite3.connect(self.f.receipts) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM custody_anchor_acknowledgements").fetchone()[0],1)

    def test_append_requires_transaction(self):
        with sqlite3.connect(":memory:") as conn:
            with self.assertRaisesRegex(ValueError, "active transaction"):
                audit.append(conn,"a"*32,"b"*64,"custodian-a","c"*64,"d"*64)

    def test_append_input_validation(self):
        with sqlite3.connect(":memory:") as conn:
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(ValueError, "invalid acknowledgement"):
                audit.append(conn,"invalid","b"*64,"custodian-a","c"*64,"d"*64)
            conn.rollback()

    def test_reversed_head_is_not_accepted(self):
        result = self.f.record()
        self.assertNotEqual(result["head_hash"],audit.GENESIS)
        self.assertEqual(self.inspect(audit.GENESIS)["reason"],"ack-chain-head-mismatch")


if __name__ == "__main__":
    unittest.main()
