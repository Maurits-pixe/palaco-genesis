"""SQLite fencing cross-connection tests: not hardware-security evidence."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedChallengeAnchor
from protocol import TransferError
from sqlite_fencing_reference import SQLiteFencingReference

SCOPE = b"q" * 32
OTHER = b"x" * 32
ROOT_A = "a" * 64
ROOT_B = "b" * 64


class SQLiteFencingReferenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "fence.sqlite"
        self.service = SQLiteFencingReference(self.path, SCOPE, create=True)

    def other(self):
        return SQLiteFencingReference(self.path, SCOPE)

    def test_initial_fence(self):
        state = self.service.read()
        self.assertEqual(state.epoch, 1)
        self.assertFalse(state.incident_held)
        self.assertEqual(state.checkpoint.count, 0)
        self.assertEqual(state.checkpoint.root, EMPTY_ROOT)

    def test_atomic_checkpoint_write(self):
        old = self.service.read()
        new = NativeCheckpoint(SCOPE, 1, ROOT_A)
        self.assertEqual(self.service.compare_and_advance(old, new).checkpoint, new)

    def test_new_connection_sees_committed_state(self):
        old = self.service.read()
        self.service.compare_and_advance(old, NativeCheckpoint(SCOPE, 1, ROOT_A))
        self.assertEqual(self.other().read().checkpoint.count, 1)

    def test_rejects_stale_writer(self):
        old = self.service.read()
        self.service.compare_and_advance(old, NativeCheckpoint(SCOPE, 1, ROOT_A))
        with self.assertRaises(TransferError):
            self.other().compare_and_advance(old, NativeCheckpoint(SCOPE, 1, ROOT_B))

    def test_two_connections_compete_only_one_commits(self):
        first, second = self.service, self.other()
        prior = first.read()
        def submit(service, root):
            try:
                service.compare_and_advance(prior, NativeCheckpoint(SCOPE, 1, root))
                return True
            except TransferError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda args: submit(*args),
                ((first, ROOT_A), (second, ROOT_B)),
            ))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 1)

    def test_same_count_content_change(self):
        old = self.service.read()
        self.service.compare_and_advance(old, NativeCheckpoint(SCOPE, 1, ROOT_A))
        next_state = self.service.read()
        self.service.compare_and_advance(next_state, NativeCheckpoint(SCOPE, 1, ROOT_B))
        self.assertEqual(self.service.read().checkpoint.root, ROOT_B)

    def test_count_jump_denied(self):
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(SCOPE, 2, ROOT_A),
            )

    def test_identical_checkpoint_denied(self):
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(SCOPE, 0, EMPTY_ROOT),
            )

    def test_incident_latches_after_restart(self):
        state = self.service.latch_incident()
        self.assertTrue(state.incident_held)
        self.assertEqual(state.epoch, 2)
        self.assertTrue(self.other().read().incident_held)

    def test_incident_idempotent(self):
        first = self.service.latch_incident()
        self.assertEqual(self.service.latch_incident(), first)

    def test_incident_forbids_previous_cas(self):
        prior = self.service.read()
        self.service.latch_incident()
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(prior, NativeCheckpoint(SCOPE, 1, ROOT_A))

    def test_incident_forbids_new_cas(self):
        self.service.latch_incident()
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(
                self.service.read(), NativeCheckpoint(SCOPE, 1, ROOT_A),
            )

    def test_existing_gate_rejects_incident(self):
        gate = FencedChallengeAnchor(self.service, SCOPE)
        self.service.latch_incident()
        with self.assertRaises(TransferError):
            gate.read()

    def test_reopening_existing_registry_does_not_reset_it(self):
        self.service.latch_incident()
        with self.assertRaises(TransferError):
            SQLiteFencingReference(self.path, SCOPE, create=True)
        self.assertTrue(self.other().read().incident_held)

    def test_missing_registry_not_silently_created(self):
        self.path.unlink()
        with self.assertRaises(TransferError):
            self.other()

    def test_wrong_namespace_denied(self):
        with self.assertRaises(TransferError):
            SQLiteFencingReference(self.path, OTHER)

    def test_symlink_registry_denied(self):
        alias = self.path.parent / "alias.sqlite"
        alias.symlink_to(self.path)
        with self.assertRaises(TransferError):
            SQLiteFencingReference(alias, SCOPE)

    def test_tampered_root_detected_as_stale_not_antirollback(self):
        old = self.service.read()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET root=? WHERE singleton=1", (ROOT_B,))
        with self.assertRaises(TransferError):
            self.service.compare_and_advance(old, NativeCheckpoint(SCOPE, 1, ROOT_A))

    def test_corrupt_state_denied(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET root='invalid' WHERE singleton=1")
        with self.assertRaises(TransferError):
            self.service.read()

    def test_missing_row_denied(self):
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM fence")
        with self.assertRaises(TransferError):
            self.service.read()

    def test_fake_rollback_can_clear_incident(self):
        self.service.latch_incident()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE fence SET epoch=1,held=0 WHERE singleton=1")
        self.assertFalse(self.other().read().incident_held)

    def test_gate_write_integration(self):
        gate = FencedChallengeAnchor(self.service, SCOPE)
        gate.advance((0, EMPTY_ROOT), (1, ROOT_A))
        self.assertEqual(self.other().read().checkpoint, NativeCheckpoint(SCOPE, 1, ROOT_A))


if __name__ == "__main__":
    unittest.main()
