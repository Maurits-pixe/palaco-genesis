"""Atomic receipt chain, independent head requirement and tamper regressions."""
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("receipt_chain", ROOT / "tools" / "receipt_audit_chain.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ReceiptAuditChainTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db = Path(t.name) / "receipts.sqlite"
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE observed_handoff_receipts(
                receipt_id TEXT PRIMARY KEY, bundle_sha256 TEXT, recipient_id TEXT,
                custodian_key_id TEXT, receipt_digest TEXT)""")

    def put(self, rid):
        with sqlite3.connect(self.db) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO observed_handoff_receipts VALUES(?,?,?,?,?)",
                      (rid, "b"*64, "custodian-a", "c"*64, "d"*64))
            answer = mod.append(c, rid, "b"*64, "custodian-a", "c"*64, "d"*64)
            c.commit()
            return answer

    def check(self, head, minimum=1):
        report = mod.verify(self.db, head, minimum)
        self.assertEqual(report["release_gate"], "HOLD")
        self.assertFalse(report["authorization_granted"])
        self.assertFalse(report["automatic_restore"])
        self.assertFalse(report["recovery_approved"])
        return report

    def test_first_receipt(self):
        head = self.put("1"*32)
        self.assertTrue(self.check(head["head_hash"])["chain_valid"])

    def test_second_receipt(self):
        self.put("1"*32)
        head = self.put("2"*32)
        self.assertEqual(self.check(head["head_hash"], 2)["entries"], 2)

    def test_tampered_history(self):
        head = self.put("1"*32)
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE receipt_audit_chain SET receipt_digest=?", ("f"*64,))
        self.assertEqual(self.check(head["head_hash"])["reason"], "receipt-chain-corrupt")

    def test_tampered_receipt_index(self):
        head = self.put("1"*32)
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE observed_handoff_receipts SET receipt_digest=?", ("f"*64,))
        self.assertEqual(self.check(head["head_hash"])["reason"], "receipt-index-chain-mismatch")

    def test_deleted_receipt_index(self):
        head = self.put("1"*32)
        with sqlite3.connect(self.db) as c:
            c.execute("DELETE FROM observed_handoff_receipts")
        self.assertEqual(self.check(head["head_hash"])["reason"], "receipt-index-chain-mismatch")

    def test_missing_head(self):
        self.put("1"*32)
        self.assertEqual(self.check(None)["reason"], "missing-external-chain-anchor")

    def test_wrong_external_head(self):
        self.put("1"*32)
        self.assertEqual(self.check("f"*64)["reason"], "receipt-chain-head-mismatch")

    def test_floor_blocks_rollback(self):
        head = self.put("1"*32)
        self.assertEqual(self.check(head["head_hash"], 2)["reason"], "receipt-history-rollback")

    def test_no_database_creation(self):
        self.db.unlink()
        self.assertEqual(self.check("f"*64)["reason"], "missing-receipt-db")
        self.assertFalse(self.db.exists())

    def test_transaction_rollback_is_atomic(self):
        with sqlite3.connect(self.db) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO observed_handoff_receipts VALUES(?,?,?,?,?)",
                      ("1"*32, "b"*64, "custodian-a", "c"*64, "d"*64))
            mod.append(c, "1"*32, "b"*64, "custodian-a", "c"*64, "d"*64)
            c.rollback()
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM observed_handoff_receipts").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM receipt_audit_chain").fetchone()[0], 0)

    def test_no_transaction_rejected(self):
        with sqlite3.connect(self.db) as c:
            with self.assertRaisesRegex(ValueError, "caller transaction"):
                mod.append(c, "1"*32, "b"*64, "custodian-a", "c"*64, "d"*64)

    def test_chain_append_duplicate_rejected(self):
        self.put("1"*32)
        with sqlite3.connect(self.db) as c:
            c.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.IntegrityError):
                mod.append(c, "1"*32, "b"*64, "custodian-a", "c"*64, "d"*64)
            c.rollback()


if __name__ == "__main__":
    unittest.main()
