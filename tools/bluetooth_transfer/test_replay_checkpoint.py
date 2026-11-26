"""Synthetic external monotonic counter tests, NOT hardware-backed assurance."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from protocol import TransferError, chunks, make_offer
from replay_checkpoint import AnchoredDurableReceiver


class FakeAnchor:
    """In-memory test double. Production MUST NOT use this as trust anchor."""

    def __init__(self, value=0):
        self.value = value
        self.fail_read = False
        self.fail_advance = False

    def read(self):
        if self.fail_read:
            raise OSError("secure counter offline")
        return self.value

    def advance(self, expected, new_value):
        if self.fail_advance:
            raise OSError("secure counter write failure")
        if expected != self.value or new_value != expected + 1:
            raise ValueError("monotonic compare-and-advance rejected")
        self.value = new_value


class ReplayCheckpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "receipts.sqlite"
        self.anchor = FakeAnchor()
        self.first = make_offer("citadel", "a" * 32, b"first")
        self.second = make_offer("mundo", "b" * 32, b"second")

    def guard(self):
        return AnchoredDurableReceiver(self.path, self.anchor)

    def accept(self, guard, offer, data):
        return guard.accept(
            offer, chunks(data), user_approved=True, identity_verified=True
        )

    def test_zero_initialized(self):
        self.assertFalse(self.guard().has_seen(self.first.transfer_id))

    def test_commit_advances_counter(self):
        guard = self.guard()
        self.assertEqual(self.accept(guard, self.first, b"first"), b"first")
        self.assertEqual(self.anchor.value, 1)
        self.assertTrue(self.guard().has_seen(self.first.transfer_id))

    def test_two_receipts_across_restart(self):
        self.accept(self.guard(), self.first, b"first")
        self.accept(self.guard(), self.second, b"second")
        self.assertEqual(self.anchor.value, 2)
        self.assertTrue(self.guard().has_seen(self.second.transfer_id))

    def test_rolled_back_database_denied(self):
        self.guard()
        snapshot = self.path.read_bytes()
        self.accept(self.guard(), self.first, b"first")
        self.path.write_bytes(snapshot)
        with self.assertRaises(TransferError):
            self.guard()

    def test_external_counter_lower_than_database_denied(self):
        self.accept(self.guard(), self.first, b"first")
        self.anchor.value = 0
        with self.assertRaises(TransferError):
            self.guard()

    def test_external_counter_greater_than_database_denied(self):
        self.anchor.value = 1
        with self.assertRaises(TransferError):
            self.guard()

    def test_anchor_read_unavailable_denied(self):
        self.guard()
        self.anchor.fail_read = True
        with self.assertRaises(TransferError):
            self.guard()

    def test_anchor_advance_failure_denies_payload(self):
        guard = self.guard()
        self.anchor.fail_advance = True
        with self.assertRaises(TransferError):
            self.accept(guard, self.first, b"first")
        self.assertEqual(self.anchor.value, 0)
        with self.assertRaises(TransferError):
            guard.has_seen(self.first.transfer_id)

    def test_duplicate_denied(self):
        guard = self.guard()
        self.accept(guard, self.first, b"first")
        with self.assertRaises(TransferError):
            self.accept(guard, self.first, b"first")
        self.assertEqual(self.anchor.value, 1)

    def test_failed_digest_does_not_advance(self):
        guard = self.guard()
        with self.assertRaises(TransferError):
            self.accept(guard, self.first, b"wrong")
        self.assertEqual(self.anchor.value, 0)

    def test_missing_identity_does_not_advance(self):
        guard = self.guard()
        with self.assertRaises(TransferError):
            guard.accept(self.first, chunks(b"first"),
                         user_approved=True, identity_verified=False)
        self.assertEqual(self.anchor.value, 0)

    def test_non_integer_counter_rejected(self):
        self.anchor.value = True
        with self.assertRaises(TransferError):
            self.guard()

    def test_negative_counter_rejected(self):
        self.anchor.value = -1
        with self.assertRaises(TransferError):
            self.guard()

    def test_missing_anchor_denied(self):
        with self.assertRaises(TransferError):
            AnchoredDurableReceiver(self.path, object())

    def test_corrupted_sqlite_denied(self):
        self.guard()
        self.path.write_bytes(b"corrupted")
        with self.assertRaises(TransferError):
            self.guard()

    def test_registry_deletion_during_session_denied(self):
        guard = self.guard()
        self.path.unlink()
        with self.assertRaises(TransferError):
            guard.has_seen(self.first.transfer_id)

    def test_same_count_substitution_not_crypto_detectable(self):
        # This limitation is documented: the counter only tracks count,
        # not which individual receipt IDs were committed.
        self.accept(self.guard(), self.first, b"first")
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE completed_transfers SET transfer_id=? WHERE transfer_id=?",
                ("c" * 32, self.first.transfer_id),
            )
        self.assertFalse(self.guard().has_seen(self.first.transfer_id))


if __name__ == "__main__":
    unittest.main()
