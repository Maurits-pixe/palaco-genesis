"""Separate-process crash tests for witness-first, non-atomic two-store commit.

The file witness is mutable and untrusted; tests prove mismatch/HOLD behavior,
NOT durable security or protection against rollback of both stores.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from anchored_challenges import EMPTY_ROOT
from file_witness_fixture import FileWitnessFixture
from native_checkpoint_scope import NativeCheckpoint
from protocol import TransferError
from sqlite_fencing_reference import SQLiteFencingReference
from witnessed_sqlite_fencing import WitnessedFencingService

NS = b"r" * 32
ROOT = "a" * 64
PROBE = Path(__file__).with_name("witness_crash_probe.py")


class WitnessSplitCrashTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.db = base / "fence.sqlite"
        self.wfile = base / "witness.json"
        self.sqlite = SQLiteFencingReference(self.db, NS, create=True)
        self.witness = FileWitnessFixture(self.wfile, NS, create=True)

    def reopen(self):
        return WitnessedFencingService(
            SQLiteFencingReference(self.db, NS),
            FileWitnessFixture(self.wfile, NS), NS,
        )

    def crash(self, action):
        child = subprocess.run(
            [sys.executable, str(PROBE), action, str(self.db), str(self.wfile)],
            capture_output=True, text=True, timeout=12,
        )
        self.assertEqual(child.returncode, 73, child.stderr)

    def test_initial_reference_is_consistent(self):
        self.assertEqual(self.reopen().read().checkpoint.count, 0)

    def test_crash_after_witness_cas_before_sqlite_denies_restart(self):
        self.crash("cas")
        self.assertEqual(self.sqlite.read().checkpoint.count, 0)
        self.assertEqual(self.witness.read().count, 1)
        with self.assertRaises(TransferError):
            self.reopen()

    def test_crash_after_witness_incident_before_sqlite_denies_restart(self):
        self.crash("incident")
        self.assertFalse(self.sqlite.read().incident_held)
        self.assertTrue(self.witness.read().held)
        with self.assertRaises(TransferError):
            self.reopen()

    def test_repeated_restart_does_not_silently_fix_partial_commit(self):
        self.crash("cas")
        for _ in range(3):
            with self.assertRaises(TransferError):
                self.reopen()
        self.assertEqual(self.sqlite.read().checkpoint.root, EMPTY_ROOT)

    def test_unmodified_witness_allows_normal_committed_cas(self):
        service = self.reopen()
        service.compare_and_advance(
            service.read(), NativeCheckpoint(NS, 1, ROOT),
        )
        self.assertEqual(self.reopen().read().checkpoint.root, ROOT)
        self.assertEqual(self.witness.read().revision, 1)

    def test_unmodified_witness_allows_committed_incident(self):
        service = self.reopen()
        service.latch_incident()
        self.assertTrue(self.reopen().read().incident_held)

    def test_witness_removed_after_crash_denies_restart(self):
        self.crash("cas")
        self.wfile.unlink()
        with self.assertRaises(TransferError):
            FileWitnessFixture(self.wfile, NS)

    def test_witness_rollback_alone_denies_restart(self):
        service = self.reopen()
        service.compare_and_advance(
            service.read(), NativeCheckpoint(NS, 1, ROOT),
        )
        # The untrusted fixture can be tampered with; mismatch is detectable.
        self.wfile.write_text(
            '{"namespace":"' + NS.hex() +
            '","revision":0,"epoch":1,"held":false,"count":0,"root":"' +
            EMPTY_ROOT + '"}', encoding="ascii",
        )
        with self.assertRaises(TransferError):
            self.reopen()

    def test_dual_unprotected_rollback_is_not_detected(self):
        service = self.reopen()
        service.compare_and_advance(
            service.read(), NativeCheckpoint(NS, 1, ROOT),
        )
        import sqlite3
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE fence SET count=0,root=? WHERE singleton=1",
                       (EMPTY_ROOT,))
        self.wfile.write_text(
            '{"namespace":"' + NS.hex() +
            '","revision":0,"epoch":1,"held":false,"count":0,"root":"' +
            EMPTY_ROOT + '"}', encoding="ascii",
        )
        self.assertEqual(self.reopen().read().checkpoint.count, 0)


if __name__ == "__main__":
    unittest.main()
