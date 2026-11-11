"""WNRA-04H native process crash/concurrency negatives for disposable test DBs.

No production database, handles, source statements or issuer credentials.
Every subprocess only touches a TemporaryDirectory fixture.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from windows_test_lease_model import LeaseDenied, TestLease
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger


_WORKER = """
import sqlite3
import sys
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger
from windows_test_lease_model import LeaseDenied
ledger = None
try:
    ledger = TestSqliteLeaseLedger(sys.argv[1])
    ledger.transition("lease-A", sys.argv[2], 0, 11, "reader-A", "ISSUED", "REDEEMING")
except (LeaseDenied, sqlite3.OperationalError):
    # Even an initialization lock is a controlled denial, never a redemption.
    sys.exit(3)
else:
    sys.exit(0)
finally:
    if ledger is not None:
        ledger.close()
"""

_CRASH_AFTER_COMMIT = """
import os, sys
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger
ledger = TestSqliteLeaseLedger(sys.argv[1])
ledger.transition("lease-A", "crash-commit", 0, 11, "reader-A", "ISSUED", "REDEEMING")
os._exit(37)
"""

_CRASH_BEFORE_COMMIT = """
import os, sys
from windows_test_sqlite_lease_ledger import TestSqliteLeaseLedger
ledger = TestSqliteLeaseLedger(sys.argv[1])
ledger.connection.execute("BEGIN IMMEDIATE")
ledger.connection.execute("UPDATE fixture_lease SET state='REDEEMING', revision=1 WHERE lease_id='lease-A'")
os._exit(38)
"""


class ProcessCrashFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="wnra04h-")
        self.db_path = Path(self.tempdir.name) / "test-only.sqlite3"
        self.module_dir = Path(__file__).resolve().parent
        ledger = TestSqliteLeaseLedger(self.db_path)
        try:
            ledger.issue(TestLease("lease-A", "statement-A", "reader-A", 10, 20))
        finally:
            ledger.close()

    def tearDown(self):
        self.tempdir.cleanup()

    def _run(self, script, *args):
        return subprocess.run(
            [sys.executable, "-c", script, str(self.db_path), *args],
            cwd=str(self.module_dir), capture_output=True, text=True, timeout=15,
            check=False,
        )

    def test_two_real_processes_only_one_redeems(self):
        commands = [
            [sys.executable, "-c", _WORKER, str(self.db_path), transition]
            for transition in ("worker-1", "worker-2")
        ]
        processes = [
            subprocess.Popen(cmd, cwd=str(self.module_dir), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
            for cmd in commands
        ]
        results = []
        for process in processes:
            try:
                _, stderr = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("fixture child exceeded timeout")
            results.append((process.returncode, stderr))
        self.assertEqual(sorted(code for code, _ in results), [0, 3], results)
        ledger = TestSqliteLeaseLedger(self.db_path)
        try:
            self.assertEqual(ledger.inspect("lease-A")[0:2], ("REDEEMING", 1))
            self.assertEqual(len(ledger.audit("lease-A")), 1)
        finally:
            ledger.close()

    def test_database_lock_is_a_controlled_process_denial(self):
        ledger = TestSqliteLeaseLedger(self.db_path)
        try:
            ledger.connection.execute("BEGIN IMMEDIATE")
            result = self._run(_WORKER, "blocked-worker")
            self.assertEqual(result.returncode, 3, result.stderr)
        finally:
            ledger.connection.execute("ROLLBACK")
            ledger.close()

    def test_process_crash_after_commit_requires_recovery(self):
        result = self._run(_CRASH_AFTER_COMMIT)
        self.assertEqual(result.returncode, 37, result.stderr)
        ledger = TestSqliteLeaseLedger(self.db_path)
        try:
            self.assertEqual(ledger.inspect("lease-A")[0], "REDEEMING")
            self.assertEqual(ledger.recover("restart-after-crash"), 1)
            self.assertEqual(ledger.inspect("lease-A")[0], "DENIED")
            with self.assertRaises(LeaseDenied):
                ledger.transition(
                    "lease-A", "replay", 2, 12, "reader-A", "REDEEMING", "CONSUMED"
                )
            self.assertEqual(len(ledger.audit("lease-A")), 2)
        finally:
            ledger.close()

    def test_process_crash_before_commit_rolls_back(self):
        result = self._run(_CRASH_BEFORE_COMMIT)
        self.assertEqual(result.returncode, 38, result.stderr)
        ledger = TestSqliteLeaseLedger(self.db_path)
        try:
            self.assertEqual(ledger.inspect("lease-A")[0:2], ("ISSUED", 0))
            self.assertEqual(ledger.audit("lease-A"), [])
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
