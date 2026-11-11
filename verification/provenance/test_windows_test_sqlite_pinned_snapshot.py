"""WNRA-04L isolated externally pinned digest regressions; no production data."""

import tempfile
import unittest
from pathlib import Path

from windows_test_lease_model import LeaseDenied, TestLease
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger
from windows_test_sqlite_pinned_snapshot import (
    fixture_snapshot_digest, verify_pinned_fixture_snapshot,
)


class PinnedSnapshotFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wnra04l-")
        self.path = Path(self.directory.name) / "fixture.sqlite3"
        self.ledger = TestSqliteLeaseLedger(self.path)
        self.ledger.issue(TestLease("lease-A", "statement-A", "reader-A", 10, 20))
        # Test-only independent holder: not stored in fixture DB.
        self.pinned = fixture_snapshot_digest(self.ledger)

    def tearDown(self):
        self.ledger.close()
        self.directory.cleanup()

    def test_unchanged_snapshot_matches_external_pin(self):
        self.assertTrue(verify_pinned_fixture_snapshot(self.ledger, self.pinned))

    def test_coordinated_lease_and_audit_rewrite_mismatches_old_pin(self):
        self.ledger.connection.execute(
            "UPDATE fixture_lease SET state='REVOKED', revision=1, last_time=11 "
            "WHERE lease_id='lease-A'"
        )
        self.ledger.connection.execute(
            "INSERT INTO fixture_audit VALUES "
            "('forged', 'lease-A', 'ISSUED', 'REVOKED', 1)"
        )
        # Structural checks allow this forged but consistent history.
        with self.assertRaises(LeaseDenied):
            verify_pinned_fixture_snapshot(self.ledger, self.pinned)

    def test_legitimate_transition_needs_new_independent_pin(self):
        self.ledger.transition(
            "lease-A", "t1", 0, 11, "reader-A", "ISSUED", "REDEEMING"
        )
        with self.assertRaises(LeaseDenied):
            verify_pinned_fixture_snapshot(self.ledger, self.pinned)
        updated = fixture_snapshot_digest(self.ledger)
        self.assertNotEqual(updated, self.pinned)
        self.assertTrue(verify_pinned_fixture_snapshot(self.ledger, updated))

    def test_missing_or_malformed_external_pin_is_denied(self):
        for invalid in (None, "", "0" * 63, "g" * 64, "A" * 64):
            with self.subTest(invalid=invalid):
                with self.assertRaises(LeaseDenied):
                    verify_pinned_fixture_snapshot(self.ledger, invalid)

    def test_uncommitted_caller_transaction_is_denied_without_rollback(self):
        self.ledger.connection.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(LeaseDenied):
                fixture_snapshot_digest(self.ledger)
            # The verifier cannot roll back or commit a transaction it did not own.
            self.assertTrue(self.ledger.connection.in_transaction)
        finally:
            self.ledger.connection.execute("ROLLBACK")
        self.assertTrue(verify_pinned_fixture_snapshot(self.ledger, self.pinned))

    def test_failed_structural_read_releases_owned_transaction(self):
        self.ledger.connection.execute(
            "UPDATE fixture_lease SET revision=8 WHERE lease_id='lease-A'"
        )
        with self.assertRaises(LeaseDenied):
            fixture_snapshot_digest(self.ledger)
        self.assertFalse(self.ledger.connection.in_transaction)
        self.ledger.connection.execute(
            "UPDATE fixture_lease SET revision=0 WHERE lease_id='lease-A'"
        )
        self.assertTrue(verify_pinned_fixture_snapshot(self.ledger, self.pinned))

    def test_reopen_preserves_snapshot_digest(self):
        self.ledger.close()
        self.ledger = TestSqliteLeaseLedger(self.path)
        self.assertEqual(fixture_snapshot_digest(self.ledger), self.pinned)


if __name__ == "__main__":
    unittest.main()
