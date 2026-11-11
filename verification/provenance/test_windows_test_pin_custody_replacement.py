"""WNRA-04V: replacement between separate disposable custody reads.

These are sequential closed-handle replacements, NOT a proof against a race
inside one read or an independently authenticated custodian.
"""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from windows_test_pin_custody_model import CustodyDenied, PinRecord, authorization_from_test_result
from windows_test_sqlite_pin_custody import DisposableSqliteCustody

A = "a" * 64
B = "b" * 64
SOURCE = "c" * 40


class CustodyReplacementFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.active = root / "active.sqlite3"
        self.replacement = root / "replacement.sqlite3"
        self.custody = DisposableSqliteCustody(str(self.active), "fixture-one")
        self.custody.initialize()
        self.custody.append(
            PinRecord("fixture-one", A, SOURCE, 1, None, "original"),
            simulated_reviewer_acceptance=True,
        )

    def test_invalid_replacement_is_denied_on_next_read(self):
        self.assertTrue(self.custody.compare("fixture-one", A, simulated_custodian_available=True))
        self.replacement.write_bytes(b"invalid replacement")
        os.replace(self.replacement, self.active)
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-one", A, simulated_custodian_available=True)
        self.assertEqual("DENY", authorization_from_test_result(True))

    def test_valid_substitute_is_not_independently_authenticated(self):
        self.assertTrue(self.custody.compare("fixture-one", A, simulated_custodian_available=True))
        alternate = DisposableSqliteCustody(str(self.replacement), "fixture-one")
        alternate.initialize()
        alternate.append(
            PinRecord("fixture-one", B, SOURCE, 1, None, "substituted"),
            simulated_reviewer_acceptance=True,
        )
        os.replace(self.replacement, self.active)
        self.assertFalse(self.custody.compare("fixture-one", A, simulated_custodian_available=True))
        # A structurally valid substitute can compare true: no external trust anchor.
        self.assertTrue(self.custody.compare("fixture-one", B, simulated_custodian_available=True))
        self.assertEqual("DENY", authorization_from_test_result(True))


if __name__ == "__main__":
    unittest.main()
