"""WNRA-04P: temporary-file persistence and fail-closed recovery regressions."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from windows_test_pin_custody_model import CustodyDenied, PinRecord, authorization_from_test_result
from windows_test_sqlite_pin_custody import DisposableSqliteCustody

A = "a" * 64
B = "b" * 64


def record(sequence=1, digest=A, predecessor=None, fixture_id="fixture-one"):
    return PinRecord(fixture_id, digest, "c" * 40, sequence, predecessor, "review-fixture")


class SqlitePinCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "custody.sqlite3")
        self.custody = DisposableSqliteCustody(self.path, "fixture-one")
        self.custody.initialize()

    def append(self, item):
        self.custody.append(item, simulated_reviewer_acceptance=True)

    def test_initializer_releases_file_handle_for_windows_cleanup(self):
        self.custody.initialize()
        Path(self.path).unlink()
        self.assertFalse(Path(self.path).exists())
        self.custody.initialize()

    def test_reopen_preserves_accepted_pin(self):
        self.append(record())
        reopened = DisposableSqliteCustody(self.path, "fixture-one")
        self.assertTrue(reopened.compare("fixture-one", A, simulated_custodian_available=True))
        self.assertEqual("DENY", authorization_from_test_result(True))

    def test_failed_successor_remains_unchanged_across_restart(self):
        self.append(record())
        with self.assertRaises(CustodyDenied):
            self.append(record(2, B, B))
        reopened = DisposableSqliteCustody(self.path, "fixture-one")
        self.assertTrue(reopened.compare("fixture-one", A, simulated_custodian_available=True))
        self.assertFalse(reopened.compare("fixture-one", B, simulated_custodian_available=True))

    def test_wrong_fixture_replay_denied_without_mutation(self):
        self.append(record())
        other = DisposableSqliteCustody(self.path, "fixture-two")
        with self.assertRaises(CustodyDenied):
            other.append(record(2, B, A, "fixture-two"), simulated_reviewer_acceptance=True)
        self.assertTrue(self.custody.compare("fixture-one", A, simulated_custodian_available=True))

    def test_direct_update_or_delete_is_rejected(self):
        self.append(record())
        with closing(sqlite3.connect(self.path)) as conn, conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE test_pin_history SET snapshot_digest = ?", (B,))
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM test_pin_history")
        self.assertTrue(self.custody.compare("fixture-one", A, simulated_custodian_available=True))

    def test_unreviewed_append_denied_then_reopen(self):
        with self.assertRaises(CustodyDenied):
            self.custody.append(record(), simulated_reviewer_acceptance=False)
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-one", A, simulated_custodian_available=True)
        self.append(record())
        self.assertTrue(self.custody.compare("fixture-one", A, simulated_custodian_available=True))

    def test_recovery_rejects_corrupt_history(self):
        self.append(record())
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("DROP TRIGGER test_pin_no_update")
            conn.execute("UPDATE test_pin_history SET source_commit = ?", ("invalid",))
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-one", A, simulated_custodian_available=True)
        with self.assertRaises(CustodyDenied):
            self.append(record(2, B, A))

    def test_valid_successor_and_rollback_attempt(self):
        self.append(record())
        self.append(record(2, B, A))
        with self.assertRaises(CustodyDenied):
            self.append(record())
        self.assertTrue(self.custody.compare("fixture-one", B, simulated_custodian_available=True))

    def test_custodian_unavailable_is_not_pass(self):
        self.append(record())
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-one", A, simulated_custodian_available=False)


if __name__ == "__main__":
    unittest.main()
