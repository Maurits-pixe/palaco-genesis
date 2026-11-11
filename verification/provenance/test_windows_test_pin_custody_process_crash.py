"""WNRA-04S: native subprocess crash boundaries for disposable pin custody.

Every subprocess uses an isolated TemporaryDirectory fixture; never production.
A successful test is NOT independent custody or authorization evidence.
"""
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from windows_test_pin_custody_model import CustodyDenied, PinRecord, authorization_from_test_result
from windows_test_sqlite_pin_custody import DisposableSqliteCustody

A = "a" * 64
B = "b" * 64
SOURCE = "c" * 40

_CHILD = """
import os
import sqlite3
import sys
from windows_test_pin_custody_model import PinRecord
from windows_test_sqlite_pin_custody import DisposableSqliteCustody
path, phase = sys.argv[1:3]
if phase == "before_commit":
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO test_pin_history (fixture_id, snapshot_digest, source_commit, sequence, predecessor_digest, evidence_ref, custody_status, schema, algorithm, snapshot_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("fixture-one", "b" * 64, "c" * 40, 2, "a" * 64, "crash-fixture", "REVIEWED", "WNRA-04N-PIN-v0.1", "sha256", "PALACO-WNRA-04L-TEST-SNAPSHOT-v1"))
    os._exit(17)
if phase == "after_commit":
    model = DisposableSqliteCustody(path, "fixture-one")
    model.append(PinRecord("fixture-one", "b" * 64, "c" * 40, 2, "a" * 64, "crash-fixture"), simulated_reviewer_acceptance=True)
    os._exit(19)
if phase == "lock_then_crash":
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    os._exit(23)
raise SystemExit(2)
"""


class CustodyProcessCrashTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "pin-custody.sqlite3")
        self.model = DisposableSqliteCustody(self.path, "fixture-one")
        self.model.initialize()
        self.model.append(PinRecord("fixture-one", A, SOURCE, 1, None, "genesis-fixture"),
                          simulated_reviewer_acceptance=True)

    def child(self, phase, exit_code):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent)
        run = subprocess.run([sys.executable, "-c", _CHILD, self.path, phase],
                             env=env, capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(exit_code, run.returncode, run.stderr)

    def test_crash_before_commit_rolls_back_unpublished_pin(self):
        self.child("before_commit", 17)
        recovered = DisposableSqliteCustody(self.path, "fixture-one")
        self.assertTrue(recovered.compare("fixture-one", A, simulated_custodian_available=True))
        self.assertFalse(recovered.compare("fixture-one", B, simulated_custodian_available=True))
        recovered.append(PinRecord("fixture-one", B, SOURCE, 2, A, "recovered-fixture"),
                         simulated_reviewer_acceptance=True)
        self.assertTrue(recovered.compare("fixture-one", B, simulated_custodian_available=True))

    def test_crash_after_commit_retains_successor(self):
        self.child("after_commit", 19)
        recovered = DisposableSqliteCustody(self.path, "fixture-one")
        self.assertTrue(recovered.compare("fixture-one", B, simulated_custodian_available=True))
        with self.assertRaises(CustodyDenied):
            recovered.append(PinRecord("fixture-one", B, SOURCE, 2, A, "duplicate"),
                             simulated_reviewer_acceptance=True)
        self.assertEqual("DENY", authorization_from_test_result(True))

    def test_crash_releases_writer_lock_without_replay(self):
        self.child("lock_then_crash", 23)
        recovered = DisposableSqliteCustody(self.path, "fixture-one")
        self.assertTrue(recovered.compare("fixture-one", A, simulated_custodian_available=True))
        recovered.append(PinRecord("fixture-one", B, SOURCE, 2, A, "after-lock-crash"),
                         simulated_reviewer_acceptance=True)
        self.assertTrue(recovered.compare("fixture-one", B, simulated_custodian_available=True))


if __name__ == "__main__":
    unittest.main()
