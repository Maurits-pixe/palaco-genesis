"""WNRA-04G isolated SQLite fixture regressions. No production database."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from windows_test_lease_model import LeaseDenied, TestLease
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger


class SqliteLeaseLedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wnra04g-")
        self.db = Path(self.directory.name) / "fixture.sqlite3"
        self.ledger = TestSqliteLeaseLedger(self.db)
        self.ledger.issue(TestLease("lease-A", "statement-A", "reader-A", 10, 20))

    def tearDown(self):
        self.ledger.close()
        self.directory.cleanup()

    def test_one_shot_and_audit_commit(self):
        first = self.ledger.transition(
            "lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING"
        )
        self.assertEqual(first, ("REDEEMING", 1))
        last = self.ledger.transition(
            "lease-A", "t2", 1, 12, "reader-A", "REDEEMING", "CONSUMED"
        )
        self.assertEqual(last, ("CONSUMED", 2))
        self.assertEqual(len(self.ledger.audit("lease-A")), 2)
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "t3", 2, 13, "reader-A", "ISSUED", "REDEEMING")

    def test_two_connections_stale_cas_denied(self):
        another = TestSqliteLeaseLedger(self.db)
        try:
            self.assertEqual(another.inspect("lease-A")[1], 0)
            self.ledger.transition("lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING")
            with self.assertRaises(LeaseDenied):
                another.transition("lease-A", "t2", 0, 11, "reader-A", "ISSUED", "REDEEMING")
            self.assertEqual(len(another.audit("lease-A")), 1)
        finally:
            another.close()

    def test_restart_recovery_denies_pending_replay(self):
        self.ledger.transition("lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING")
        self.ledger.close()
        self.ledger = TestSqliteLeaseLedger(self.db)
        self.assertEqual(self.ledger.recover("restart-1"), 1)
        self.assertEqual(self.ledger.inspect("lease-A")[0], "DENIED")
        self.assertEqual(self.ledger.recover("restart-2"), 0)
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "t2", 2, 12, "reader-A", "REDEEMING", "CONSUMED")
        self.assertEqual(len(self.ledger.audit("lease-A")), 2)

    def test_duplicate_transition_id_rolls_back_state(self):
        self.ledger.transition("lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING")
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "t1", 1, 12, "reader-A", "REDEEMING", "CONSUMED")
        self.assertEqual(self.ledger.inspect("lease-A")[0:2], ("REDEEMING", 1))
        self.assertEqual(len(self.ledger.audit("lease-A")), 1)

    def test_failed_audit_insert_rolls_back_cas(self):
        self.ledger.connection.execute(
            "CREATE TRIGGER fixture_fail_audit BEFORE INSERT ON fixture_audit "
            "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END"
        )
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING")
        self.assertEqual(self.ledger.inspect("lease-A")[0:2], ("ISSUED", 0))

    def test_expiry_consumer_and_backwards_time_fail_closed(self):
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "early", 0, 9, "reader-A", "ISSUED", "REDEEMING")
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "late", 0, 20, "reader-A", "ISSUED", "REDEEMING")
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "wrong-reader", 0, 11, "reader-B", "ISSUED", "REDEEMING")
        self.ledger.transition("lease-A", "t1", 0, 15, "reader-A", "ISSUED", "REDEEMING")
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "rollback", 1, 14, "reader-A", "REDEEMING", "CONSUMED")

    def test_revocation_preempts_handoff(self):
        self.ledger.transition("lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING")
        self.ledger.transition("lease-A", "revoke", 1, 12, "reader-A", "REDEEMING", "REVOKED")
        with self.assertRaises(LeaseDenied):
            self.ledger.transition("lease-A", "handoff", 2, 13, "reader-A", "REDEEMING", "CONSUMED")
        self.assertEqual(self.ledger.inspect("lease-A")[0], "REVOKED")

    def test_locked_writer_denies_without_capability(self):
        another = TestSqliteLeaseLedger(self.db)
        try:
            self.ledger.connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(LeaseDenied):
                another.transition("lease-A", "blocked", 0, 11, "reader-A", "ISSUED", "REDEEMING")
            self.assertEqual(self.ledger.inspect("lease-A")[0], "ISSUED")
        finally:
            self.ledger.connection.execute("ROLLBACK")
            another.close()


if __name__ == "__main__":
    unittest.main()
