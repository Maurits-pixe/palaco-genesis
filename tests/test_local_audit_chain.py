"""SHA-256 chained local audit tests and atomic integration tests."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit", ROOT / "tools" / "local_audit_chain.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class LocalAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "audit.sqlite"

    def add(self, entries):
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("BEGIN IMMEDIATE")
            for kind, subject, detail in entries:
                audit.append(conn, kind, subject, detail)
            conn.commit()
        finally:
            conn.close()

    def test_single_append_verifies(self):
        self.add([("registry-revision", "issuer-a", "revision-1")])
        self.assertTrue(audit.verify(self.db)["chain_valid"])

    def test_two_events_and_external_head(self):
        self.add([("registry-revision", "issuer-a", "revision-1"),
                  ("candidate-indexed", "candidate-a", "lineage-a")])
        head = audit.verify(self.db)["head_hash"]
        self.assertTrue(audit.verify(self.db, expected_head=head)["chain_valid"])

    def test_external_head_mismatch(self):
        self.add([("registry-revision", "issuer-a", "revision-1")])
        self.assertEqual(audit.verify(self.db, expected_head="f" * 64)["reason"], "external-head-mismatch")

    def test_mutation_detected(self):
        self.add([("registry-revision", "issuer-a", "revision-1")])
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE local_audit_chain SET detail='forged' WHERE sequence=1")
        self.assertEqual(audit.verify(self.db)["reason"], "audit-hash-mismatch")

    def test_truncated_chain_detected_with_external_head(self):
        self.add([("registry-revision", "issuer-a", "revision-1"),
                  ("candidate-indexed", "candidate-a", "lineage-a")])
        head = audit.verify(self.db)["head_hash"]
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM local_audit_chain WHERE sequence=2")
        self.assertEqual(audit.verify(self.db, expected_head=head)["reason"], "external-head-mismatch")

    def test_sequence_gap_detected(self):
        self.add([("registry-revision", "issuer-a", "revision-1"),
                  ("candidate-indexed", "candidate-a", "lineage-a")])
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM local_audit_chain WHERE sequence=1")
        self.assertEqual(audit.verify(self.db)["reason"], "audit-sequence-break")

    def test_missing_database_no_creation(self):
        self.assertEqual(audit.verify(self.db)["reason"], "missing-database")
        self.assertFalse(self.db.exists())

    def test_empty_table_rejected(self):
        with sqlite3.connect(self.db) as conn:
            audit._schema(conn)
        self.assertEqual(audit.verify(self.db)["reason"], "empty-audit-chain")

    def test_append_requires_transaction(self):
        with sqlite3.connect(self.db) as conn:
            with self.assertRaises(ValueError):
                audit.append(conn, "candidate-indexed", "x", "y")

    def test_rejected_event_does_not_mutate_audit(self):
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ValueError):
                audit.append(conn, "grant-authority", "x", "y")
            conn.rollback()
        finally:
            conn.close()
        self.assertEqual(audit.verify(self.db)["reason"], "missing-audit-table")

    def test_rollback_removes_uncommitted_audit(self):
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("BEGIN IMMEDIATE")
            audit.append(conn, "registry-revision", "issuer-a", "revision-1")
            conn.rollback()
        finally:
            conn.close()
        self.assertEqual(audit.verify(self.db)["reason"], "missing-audit-table")


if __name__ == "__main__":
    unittest.main()
