"""WNRA-04J deterministic storage-fault negatives for a disposable SQLite ledger.

No production database or issuer. Each case owns a temporary database.
A denied storage operation must not leave partial lease or audit state.
"""

import tempfile
import unittest
from pathlib import Path

from windows_test_lease_model import LeaseDenied, TestLease
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger


class StorageFaultFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wnra04j-")
        self.path = Path(self.directory.name) / "storage-fault.sqlite3"
        self.ledger = TestSqliteLeaseLedger(self.path)
        self.ledger.issue(TestLease("lease-A", "statement-A", "reader-A", 10, 20))

    def tearDown(self):
        self.ledger.close()
        self.directory.cleanup()

    def _assert_issued_clean(self):
        self.assertEqual(self.ledger.inspect("lease-A")[0:2], ("ISSUED", 0))
        self.assertEqual(self.ledger.audit("lease-A"), [])

    def test_update_write_failure_denies_without_partial_audit(self):
        self.ledger.connection.execute(
            "CREATE TRIGGER fail_update BEFORE UPDATE ON fixture_lease "
            "BEGIN SELECT RAISE(ABORT, 'injected state write failure'); END"
        )
        with self.assertRaises(LeaseDenied):
            self.ledger.transition(
                "lease-A", "fault-update", 0, 11, "reader-A", "ISSUED", "REDEEMING"
            )
        self._assert_issued_clean()

    def test_query_only_storage_denies_then_unblocks_without_replay(self):
        self.ledger.connection.execute("PRAGMA query_only=ON")
        try:
            with self.assertRaises(LeaseDenied):
                self.ledger.transition(
                    "lease-A", "fault-readonly", 0, 11, "reader-A", "ISSUED", "REDEEMING"
                )
            self._assert_issued_clean()
        finally:
            self.ledger.connection.execute("PRAGMA query_only=OFF")
        self.assertEqual(
            self.ledger.transition(
                "lease-A", "after-readonly", 0, 11, "reader-A", "ISSUED", "REDEEMING"
            ),
            ("REDEEMING", 1),
        )
        self.assertEqual(len(self.ledger.audit("lease-A")), 1)

    def test_issue_insert_failure_does_not_create_lease(self):
        self.ledger.connection.execute(
            "CREATE TRIGGER fail_issue BEFORE INSERT ON fixture_lease "
            "BEGIN SELECT RAISE(ABORT, 'injected issue write failure'); END"
        )
        with self.assertRaises(LeaseDenied):
            self.ledger.issue(TestLease("lease-B", "statement-B", "reader-B", 10, 20))
        self.assertIsNone(self.ledger.inspect("lease-B"))
        self._assert_issued_clean()

    def test_recovery_audit_failure_rolls_back_state(self):
        self.ledger.transition(
            "lease-A", "redeem", 0, 11, "reader-A", "ISSUED", "REDEEMING"
        )
        self.ledger.connection.execute(
            "CREATE TRIGGER fail_recovery_audit BEFORE INSERT ON fixture_audit "
            "WHEN NEW.new_state='DENIED' "
            "BEGIN SELECT RAISE(ABORT, 'injected recovery audit failure'); END"
        )
        with self.assertRaises(LeaseDenied):
            self.ledger.recover("fault-recovery")
        self.assertEqual(self.ledger.inspect("lease-A")[0:2], ("REDEEMING", 1))
        self.assertEqual(len(self.ledger.audit("lease-A")), 1)
        self.ledger.connection.execute("DROP TRIGGER fail_recovery_audit")
        self.assertEqual(self.ledger.recover("retry-recovery"), 1)
        self.assertEqual(self.ledger.inspect("lease-A")[0:2], ("DENIED", 2))
        self.assertEqual(len(self.ledger.audit("lease-A")), 2)
        with self.assertRaises(LeaseDenied):
            self.ledger.transition(
                "lease-A", "forbidden-replay", 2, 12,
                "reader-A", "REDEEMING", "CONSUMED"
            )


if __name__ == "__main__":
    unittest.main()
