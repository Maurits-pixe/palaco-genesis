"""SQLite fencing witness integration; fake witness is NOT protected storage."""
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedChallengeAnchor
from protocol import TransferError
from sqlite_fencing_reference import SQLiteFencingReference
from witnessed_sqlite_fencing import FencingWitnessState, WitnessedFencingService

NS = b"v" * 32
OTHER = b"x" * 32
ROOT1 = "a" * 64
ROOT2 = "b" * 64


class FakeWitness:
    """Shareable mutable fake; real native protected monotonicity is absent."""
    def __init__(self):
        self.state = FencingWitnessState(NS, 0, 1, False, 0, EMPTY_ROOT)
        self.offline = False
        self.reject = False
        self.uncertain = False

    def read(self):
        if self.offline:
            raise OSError("witness unavailable")
        return self.state

    def advance(self, before, after):
        if self.reject or self.state != before:
            raise OSError("witness CAS rejected")
        self.state = after
        if self.uncertain:
            raise OSError("witness write acknowledgement lost")


class WitnessedSQLiteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "fence.sqlite"
        self.sqlite = SQLiteFencingReference(self.path, NS, create=True)
        self.witness = FakeWitness()
        self.service = WitnessedFencingService(self.sqlite, self.witness, NS)

    def fresh(self):
        return WitnessedFencingService(
            SQLiteFencingReference(self.path, NS), self.witness, NS,
        )

    def test_initial_matching(self):
        self.assertEqual(self.service.read().checkpoint.count, 0)

    def test_witnessed_cas_issue(self):
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
        )
        self.assertEqual(self.fresh().read().checkpoint.root, ROOT1)
        self.assertEqual(self.witness.state.revision, 1)

    def test_same_count_update_increments_revision(self):
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
        )
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT2),
        )
        self.assertEqual(self.witness.state.revision, 2)

    def test_sqlite_checkpoint_rollback_detected_on_restart(self):
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
        )
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE fence SET count=0,root=? WHERE singleton=1", (EMPTY_ROOT,),
            )
        with self.assertRaises(TransferError):
            self.fresh()

    def test_same_count_root_swap_detected(self):
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
        )
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET root=? WHERE singleton=1", (ROOT2,))
        with self.assertRaises(TransferError):
            self.fresh()

    def test_incident_latched_in_both(self):
        state = self.service.latch_incident()
        self.assertTrue(state.incident_held)
        self.assertTrue(self.fresh().read().incident_held)
        self.assertTrue(self.witness.state.held)
        self.assertEqual(self.witness.state.epoch, 2)

    def test_incident_cleared_by_direct_sql_detected(self):
        self.service.latch_incident()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET held=0,epoch=1 WHERE singleton=1")
        with self.assertRaises(TransferError):
            self.fresh()

    def test_incident_epoch_manipulation_detected(self):
        self.service.latch_incident()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET epoch=3 WHERE singleton=1")
        with self.assertRaises(TransferError):
            self.fresh()

    def test_witness_offline_denies(self):
        self.witness.offline = True
        with self.assertRaises(TransferError):
            self.service.read()

    def test_witness_wrong_scope_denies(self):
        self.witness.state = replace(self.witness.state, namespace=OTHER)
        with self.assertRaises(TransferError):
            self.service.read()

    def test_sqlite_failure_after_witness_advance_denies(self):
        original = self.sqlite.compare_and_advance
        def fail(*args):
            raise TransferError("disk failure")
        self.sqlite.compare_and_advance = fail
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
            )
        self.assertEqual(self.witness.state.revision, 1)
        with self.assertRaises(TransferError):
            self.fresh()
        self.sqlite.compare_and_advance = original

    def test_uncertain_witness_write_denies(self):
        self.witness.uncertain = True
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
            )
        self.assertTrue(self.service.is_held)

    def test_rejected_witness_write_does_not_mutate_sqlite(self):
        self.witness.reject = True
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
            )
        self.assertEqual(self.sqlite.read().checkpoint.count, 0)

    def test_local_hold_remains_after_fake_reconciliation(self):
        self.witness.reject = True
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
            )
        self.witness.reject = False
        with self.assertRaises(TransferError):
            self.service.read()

    def test_fenced_anchor_integration(self):
        gate = FencedChallengeAnchor(self.service, NS)
        gate.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.assertEqual(self.fresh().read().checkpoint.count, 1)

    def test_missing_witness_denied(self):
        with self.assertRaises(TransferError):
            WitnessedFencingService(self.sqlite, object(), NS)

    def test_invalid_witness_epoch_denied(self):
        with self.assertRaises(TransferError):
            FencingWitnessState(NS, 0, True, False, 0, EMPTY_ROOT)

    def test_both_fake_stores_reset_not_detected(self):
        self.service.compare_and_advance(
            self.service.read(), NativeCheckpoint(NS, 1, ROOT1),
        )
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE fence SET count=0,root=? WHERE singleton=1", (EMPTY_ROOT,),
            )
        self.witness.state = FencingWitnessState(NS, 0, 1, False, 0, EMPTY_ROOT)
        self.assertEqual(self.fresh().read().checkpoint.count, 0)


if __name__ == "__main__":
    unittest.main()
