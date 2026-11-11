"""WNRA-04W: native cross-process replacement while a read snapshot is open.

Only tests an isolated filesystem fixture. An OS refusal or a stable pinned
SQLite read is not independent custody or authorization.
"""
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from windows_test_pin_custody_model import PinRecord, authorization_from_test_result
from windows_test_sqlite_pin_custody import DisposableSqliteCustody

A = "a" * 64
B = "b" * 64
SOURCE = "c" * 40

_READER = """
import sqlite3
import sys
conn = sqlite3.connect(sys.argv[1], isolation_level=None, timeout=2)
try:
    conn.execute("BEGIN")
    first = conn.execute("SELECT snapshot_digest FROM test_pin_history WHERE sequence=1").fetchone()[0]
    print("READY", flush=True)
    sys.stdin.readline()
    second = conn.execute("SELECT snapshot_digest FROM test_pin_history WHERE sequence=1").fetchone()[0]
    print("STABLE" if first == second == "a" * 64 else "CHANGED", flush=True)
    conn.execute("COMMIT")
finally:
    conn.close()
"""


class InReadReplacementFixture(unittest.TestCase):
    def test_replacement_during_open_reader_has_no_mixed_snapshot(self):
        with TemporaryDirectory() as root:
            active = Path(root) / "active.sqlite3"
            substitute = Path(root) / "substitute.sqlite3"
            original = DisposableSqliteCustody(str(active), "fixture-one")
            alternate = DisposableSqliteCustody(str(substitute), "fixture-one")
            for store, digest in ((original, A), (alternate, B)):
                store.initialize()
                store.append(
                    PinRecord("fixture-one", digest, SOURCE, 1, None, "isolated"),
                    simulated_reviewer_acceptance=True,
                )
            proc = subprocess.Popen(
                [sys.executable, "-c", _READER, str(active)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual("READY", proc.stdout.readline().strip())
                replaced = False
                try:
                    os.replace(substitute, active)
                    replaced = True
                except PermissionError:
                    # Windows may prohibit renaming an open SQLite file.
                    pass
                output, errors = proc.communicate(input="CONTINUE\n", timeout=10)
                self.assertEqual(0, proc.returncode, errors)
                self.assertIn("STABLE", output)
                self.assertEqual(replaced, original.compare(
                    "fixture-one", B, simulated_custodian_available=True))
                self.assertEqual(not replaced, original.compare(
                    "fixture-one", A, simulated_custodian_available=True))
                self.assertEqual("DENY", authorization_from_test_result(True))
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
