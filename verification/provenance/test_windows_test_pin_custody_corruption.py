"""WNRA-04T: fail-closed negative fixtures for damaged disposable pin custody.

No production database, real custodian, independent anchor or authority is used.
"""
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from windows_test_pin_custody_model import CustodyDenied, PinRecord, authorization_from_test_result
from windows_test_sqlite_pin_custody import DisposableSqliteCustody

A = "a" * 64
B = "b" * 64
SOURCE = "c" * 40


class DamagedCustodyFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "custody.sqlite3"
        self.custody = DisposableSqliteCustody(str(self.path), "fixture-one")

    def assert_denied(self):
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-one", A, simulated_custodian_available=True)
        self.assertEqual("DENY", authorization_from_test_result(True))

    def test_missing_database_is_not_a_valid_pin(self):
        self.assertFalse(self.path.exists())
        self.assert_denied()
        # SQLite may create an empty file on open; that is not accepted custody.
        self.assert_denied()

    def test_invalid_database_header_fails_closed(self):
        self.path.write_bytes(b"NOT-A-SQLITE-DATABASE\x00")
        self.assert_denied()
        self.assertEqual(b"NOT-A-SQLITE-DATABASE\x00", self.path.read_bytes())

    def test_tampered_predecessor_chain_is_rejected_after_reopen(self):
        self.custody.initialize()
        self.custody.append(
            PinRecord("fixture-one", A, SOURCE, 1, None, "genesis"),
            simulated_reviewer_acceptance=True,
        )
        self.custody.append(
            PinRecord("fixture-one", B, SOURCE, 2, A, "successor"),
            simulated_reviewer_acceptance=True,
        )
        with closing(sqlite3.connect(str(self.path))) as conn:
            conn.execute("DROP TRIGGER test_pin_no_update")
            conn.execute(
                "UPDATE test_pin_history SET predecessor_digest = ? WHERE sequence = 2",
                ("f" * 64,),
            )
            conn.commit()
        self.assert_denied()
        with self.assertRaises(CustodyDenied):
            self.custody.append(
                PinRecord("fixture-one", "d" * 64, SOURCE, 3, B, "blocked"),
                simulated_reviewer_acceptance=True,
            )
        with closing(sqlite3.connect(str(self.path))) as conn:
            count = conn.execute("SELECT COUNT(*) FROM test_pin_history").fetchone()[0]
        self.assertEqual(2, count)


if __name__ == "__main__":
    unittest.main()
