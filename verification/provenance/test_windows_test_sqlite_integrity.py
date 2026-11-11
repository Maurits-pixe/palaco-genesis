"""WNRA-04K negative integrity fixtures. Disposable databases only."""

import tempfile
import unittest
from pathlib import Path

from windows_test_lease_model import LeaseDenied, TestLease
from windows_test_sqlite_integrity import verify_fixture_integrity
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger


class IntegrityFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wnra04k-")
        self.path = Path(self.directory.name) / "fixture.sqlite3"
        self.ledger = TestSqliteLeaseLedger(self.path)
        self.ledger.issue(TestLease("lease-A", "statement-A", "reader-A", 10, 20))

    def tearDown(self):
        self.ledger.close()
        self.directory.cleanup()

    def test_clean_issue_redeem_and_recovery_are_structurally_consistent(self):
        self.assertTrue(verify_fixture_integrity(self.ledger))
        self.ledger.transition(
            "lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING"
        )
        self.assertTrue(verify_fixture_integrity(self.ledger))
        self.assertEqual(self.ledger.recover("restart"), 1)
        self.assertTrue(verify_fixture_integrity(self.ledger))

    def test_tampered_state_without_audit_is_rejected(self):
        self.ledger.connection.execute(
            "UPDATE fixture_lease SET state='CONSUMED', revision=1 "
            "WHERE lease_id='lease-A'"
        )
        with self.assertRaises(LeaseDenied):
            verify_fixture_integrity(self.ledger)

    def test_audit_revision_gap_is_rejected(self):
        self.ledger.transition(
            "lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING"
        )
        self.ledger.connection.execute(
            "UPDATE fixture_audit SET revision=9 WHERE transition_id='t1'"
        )
        with self.assertRaises(LeaseDenied):
            verify_fixture_integrity(self.ledger)

    def test_orphan_audit_is_rejected(self):
        self.ledger.connection.execute(
            "INSERT INTO fixture_audit VALUES "
            "('orphan', 'missing-lease', 'ISSUED', 'REDEEMING', 1)"
        )
        with self.assertRaises(LeaseDenied):
            verify_fixture_integrity(self.ledger)

    def test_non_database_header_is_rejected(self):
        self.ledger.close()
        self.path.write_bytes(b"NOT A SQLITE DATABASE" + bytes(4096))
        with self.assertRaises((LeaseDenied, Exception)) as caught:
            # The unmodified test-only constructor may raise sqlite3.DatabaseError.
            broken = TestSqliteLeaseLedger(self.path)
            try:
                verify_fixture_integrity(broken)
            finally:
                broken.close()
        self.assertIsNotNone(caught.exception)

    def test_coordinated_rewrite_is_not_cryptographically_detected(self):
        # A consistent rewrite by a direct DB writer remains outside this
        # structural verifier's security claim.
        self.ledger.connection.execute(
            "UPDATE fixture_lease SET state='REVOKED', revision=1, last_time=11 "
            "WHERE lease_id='lease-A'"
        )
        self.ledger.connection.execute(
            "INSERT INTO fixture_audit VALUES "
            "('forged', 'lease-A', 'ISSUED', 'REVOKED', 1)"
        )
        self.assertTrue(verify_fixture_integrity(self.ledger))


if __name__ == "__main__":
    unittest.main()
