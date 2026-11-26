"""Real separate-process SQLite fencing tests; still no hardware trust.

Subprocesses use independent interpreters and SQLite connections. These tests
prove file-backed transaction semantics against cooperating writers only.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from protocol import TransferError
from sqlite_fencing_reference import SQLiteFencingReference

NS = b"p" * 32
ROOT1 = "a" * 64
ROOT2 = "b" * 64
PROBE = Path(__file__).with_name("fencing_process_probe.py")


class MultiProcessFencingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "fence.sqlite"
        self.service = SQLiteFencingReference(self.path, NS, create=True)

    def cmd(self, action, *args):
        return [sys.executable, str(PROBE), action, str(self.path),
                NS.hex(), *map(str, args)]

    def run_child(self, action, *args, success=True):
        result = subprocess.run(self.cmd(action, *args), text=True,
                                capture_output=True, timeout=12, check=False)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return json.loads(result.stdout) if result.returncode == 0 and result.stdout else None

    def wait_ready(self, marker):
        deadline = time.monotonic() + 6
        while not marker.exists():
            if time.monotonic() > deadline:
                self.fail("subprocess never acquired transaction lock")
            time.sleep(0.01)

    def test_child_reads_initial_checkpoint(self):
        result = self.run_child("read")
        self.assertEqual((result["count"], result["root"]), (0, EMPTY_ROOT))

    def test_child_commit_visible_to_parent(self):
        self.run_child("advance", 0, EMPTY_ROOT, 1, ROOT1)
        self.assertEqual(self.service.read().checkpoint, NativeCheckpoint(NS, 1, ROOT1))

    def test_parent_commit_visible_to_child(self):
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
        )
        self.assertEqual(self.run_child("read")["root"], ROOT1)

    def test_two_subprocesses_only_one_wins_stale_cas(self):
        commands = (self.cmd("advance", 0, EMPTY_ROOT, 1, ROOT1),
                    self.cmd("advance", 0, EMPTY_ROOT, 1, ROOT2))
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda command: subprocess.run(
                    command, capture_output=True, text=True, timeout=12,
                ).returncode, commands,
            ))
        self.assertEqual(sorted(outcomes), [0, 1])
        self.assertIn(self.service.read().checkpoint.root, (ROOT1, ROOT2))

    def test_child_latches_incident_visible_after_restart(self):
        result = self.run_child("latch")
        self.assertTrue(result["held"])
        self.assertEqual(self.run_child("read")["epoch"], 2)

    def test_child_latch_blocks_parent_cas(self):
        old = self.service.read()
        self.run_child("latch")
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                old, NativeCheckpoint(NS, 1, ROOT1),
            )

    def test_parent_latch_blocks_child_cas(self):
        self.service.latch_incident()
        self.run_child("advance", 0, EMPTY_ROOT, 1, ROOT1, success=False)

    def test_crash_before_commit_rolls_back(self):
        marker = self.dir / "started"
        self.run_child("crash_uncommitted", marker)
        self.assertTrue(marker.exists())
        self.assertEqual(self.service.read().checkpoint.count, 0)
        self.run_child("advance", 0, EMPTY_ROOT, 1, ROOT1)

    def test_crash_after_commit_persists(self):
        marker = self.dir / "committed"
        self.run_child("crash_committed", marker)
        self.assertTrue(marker.exists())
        self.assertEqual(self.service.read().checkpoint.root, "e" * 64)

    def test_other_process_waits_for_write_lock(self):
        ready, release = self.dir / "ready", self.dir / "release"
        child = subprocess.Popen(self.cmd("hold_lock", ready, release),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.wait_ready(ready)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    self.service.compare_and_advance,
                    self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
                )
                time.sleep(0.03)
                self.assertFalse(future.done())
                release.touch()
                result = future.result(timeout=8)
            self.assertEqual(result.checkpoint.root, ROOT1)
        finally:
            release.touch()
            child.communicate(timeout=8)
        self.assertEqual(child.returncode, 0)

    def test_reopen_with_wrong_namespace_in_child_fails(self):
        command = [sys.executable, str(PROBE), "read", str(self.path),
                   (b"x" * 32).hex()]
        result = subprocess.run(command, capture_output=True, text=True, timeout=12)
        self.assertNotEqual(result.returncode, 0)

    def test_corrupt_db_state_denied_in_child(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET root='invalid' WHERE singleton=1")
        self.run_child("read", success=False)

    def test_missing_db_rejected_by_child(self):
        self.path.unlink()
        self.run_child("read", success=False)

    def test_unprotected_direct_sql_can_erase_incident(self):
        self.run_child("latch")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET epoch=1,held=0 WHERE singleton=1")
        self.assertFalse(self.run_child("read")["held"])


if __name__ == "__main__":
    unittest.main()
