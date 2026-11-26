"""SQLite replay persistence regression tests, no Bluetooth hardware."""
import sqlite3
from pathlib import Path
import tempfile
import unittest

from durable_replay import DurableReceiver
from protocol import Receiver, TransferError, chunks, make_offer
from session import TransferSession

ID_A = "a" * 32
ID_B = "b" * 32


class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "replay.sqlite"
        self.payload = b"offline-citadel" * 100
        self.offer = make_offer("citadel", ID_A, self.payload)

    def open(self):
        return DurableReceiver(self.path)

    def receive(self, guard, offer=None, payload=None):
        if offer is None:
            offer = self.offer
        if payload is None:
            payload = self.payload
        return guard.accept(
            offer, chunks(payload),
            user_approved=True, identity_verified=True,
        )

    def test_persist_after_reopen(self):
        first = self.open()
        self.assertEqual(self.receive(first), self.payload)
        second = self.open()
        self.assertTrue(second.has_seen(ID_A))
        with self.assertRaises(TransferError):
            self.receive(second)

    def test_new_id_after_reopen_allowed(self):
        self.receive(self.open())
        second = self.open()
        other = make_offer("mundo", ID_B, self.payload)
        self.assertEqual(self.receive(second, other), self.payload)

    def test_no_record_before_completion(self):
        guard = self.open()
        session = TransferSession(
            self.offer, guard, user_approved=True, identity_verified=True,
        )
        session.push(0, self.payload)
        session.abort()
        self.assertFalse(self.open().has_seen(ID_A))

    def test_record_only_after_hash_check(self):
        guard = self.open()
        with self.assertRaises(TransferError):
            self.receive(guard, payload=b"X" * len(self.payload))
        self.assertFalse(self.open().has_seen(ID_A))

    def test_missing_consent_not_recorded(self):
        guard = self.open()
        with self.assertRaises(TransferError):
            guard.accept(
                self.offer, chunks(self.payload),
                user_approved=False, identity_verified=True,
            )
        self.assertFalse(self.open().has_seen(ID_A))

    def test_missing_identity_not_recorded(self):
        guard = self.open()
        with self.assertRaises(TransferError):
            guard.accept(
                self.offer, chunks(self.payload),
                user_approved=True, identity_verified=False,
            )
        self.assertFalse(self.open().has_seen(ID_A))

    def test_separate_instances_unique_constraint(self):
        left, right = self.open(), self.open()
        self.assertEqual(self.receive(left), self.payload)
        with self.assertRaises(TransferError):
            self.receive(right)

    def test_duplicate_id_altered_payload_denied(self):
        self.receive(self.open())
        offer = make_offer("citadel", ID_A, b"different")
        with self.assertRaises(TransferError):
            self.receive(self.open(), offer, b"different")

    def test_multiple_ids_survive_reopen(self):
        guard = self.open()
        self.receive(guard)
        second = make_offer("mundo", ID_B, self.payload)
        self.receive(guard, second)
        reopened = self.open()
        self.assertTrue(reopened.has_seen(ID_A))
        self.assertTrue(reopened.has_seen(ID_B))

    def test_absolute_path_required(self):
        with self.assertRaises(TransferError):
            DurableReceiver(Path("relative.sqlite"))

    def test_missing_directory_denied(self):
        with self.assertRaises(TransferError):
            DurableReceiver(self.path.parent / "missing" / "replay.sqlite")

    def test_symlink_path_denied(self):
        target = self.path.parent / "target.sqlite"
        self.open()
        target.write_bytes(self.path.read_bytes())
        link = self.path.parent / "alias.sqlite"
        link.symlink_to(target)
        with self.assertRaises(TransferError):
            DurableReceiver(link)

    def test_missing_database_after_init_fails_closed(self):
        guard = self.open()
        self.path.unlink()
        # A deleted database is not sufficient alone for secure rollback
        # detection, but this test checks that a destroyed schema fails closed.
        self.path.write_bytes(b"broken sqlite file")
        with self.assertRaises(TransferError):
            guard.has_seen(ID_A)

    def test_corrupted_database_refuses_receipt(self):
        self.open()
        self.path.write_bytes(b"corrupt sqlite data")
        with self.assertRaises(TransferError):
            self.receive(self.open())

    def test_malformed_id_denied(self):
        with self.assertRaises(TransferError):
            self.open().has_seen("not-an-id")

    def test_never_authorizes_import(self):
        self.assertIsInstance(self.open(), Receiver)
        self.assertFalse(self.open().has_seen(ID_A))

    def test_failed_record_commit_does_not_return_data(self):
        guard = self.open()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE completed_transfers")
        with self.assertRaises(TransferError):
            self.receive(guard)

    def test_database_has_primary_key(self):
        self.open()
        with sqlite3.connect(self.path) as db:
            fields = db.execute(
                "PRAGMA table_info(completed_transfers)"
            ).fetchall()
        self.assertEqual([f[1] for f in fields if f[5] == 1], ["transfer_id"])


if __name__ == "__main__":
    unittest.main()
