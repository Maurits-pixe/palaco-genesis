"""SQLite serialized receipt writer regression tests; fake anchor only."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
import tempfile
import unittest

from protocol import TransferError, chunks, make_offer
from receipt_integrity import EMPTY_ROOT
from recovery_inspection import RecoveryStatus, inspect_checkpoint
from serialized_receipts import SerializedContentReceiver


class FakeAnchor:
    """Thread-safe in-memory fake; NOT a hardware security anchor."""

    def __init__(self):
        self.value = (0, EMPTY_ROOT)
        self.lock = Lock()
        self.fail = False
        self.advance_then_fail = False

    def read(self):
        with self.lock:
            return self.value

    def advance(self, previous, current):
        with self.lock:
            if self.fail:
                raise OSError("anchor offline")
            if self.value != previous or current[0] != previous[0] + 1:
                raise ValueError("anchor CAS mismatch")
            self.value = current
            if self.advance_then_fail:
                raise OSError("uncertain anchor acknowledgment")


class SerializedReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "receipts.sqlite"
        self.anchor = FakeAnchor()
        self.first = make_offer("citadel", "a" * 32, b"alpha")
        self.second = make_offer("mundo", "b" * 32, b"beta")

    def receiver(self):
        return SerializedContentReceiver(self.path, self.anchor)

    def accept(self, receiver, offer, data, consent=True, identity=True):
        return receiver.accept(
            offer, chunks(data), user_approved=consent,
            identity_verified=identity,
        )

    def test_first_receipt_verified(self):
        self.assertEqual(self.accept(self.receiver(), self.first, b"alpha"), b"alpha")
        self.assertEqual(self.anchor.value[0], 1)
        self.assertEqual(inspect_checkpoint(self.path, self.anchor).status,
                         RecoveryStatus.MATCH)

    def test_two_receipts_survive_restart(self):
        self.accept(self.receiver(), self.first, b"alpha")
        self.accept(self.receiver(), self.second, b"beta")
        self.assertEqual(self.anchor.value[0], 2)
        self.assertTrue(self.receiver().has_seen(self.second.transfer_id))

    def test_duplicate_denied(self):
        self.accept(self.receiver(), self.first, b"alpha")
        with self.assertRaises(TransferError):
            self.accept(self.receiver(), self.first, b"alpha")
        self.assertEqual(self.anchor.value[0], 1)

    def test_corrupted_payload_denied(self):
        with self.assertRaises(TransferError):
            self.accept(self.receiver(), self.first, b"other")
        self.assertEqual(self.anchor.value[0], 0)
        self.assertEqual(inspect_checkpoint(self.path, self.anchor).status,
                         RecoveryStatus.MATCH)

    def test_missing_consent_denied(self):
        with self.assertRaises(TransferError):
            self.accept(self.receiver(), self.first, b"alpha", consent=False)
        self.assertEqual(self.anchor.value[0], 0)

    def test_missing_identity_denied(self):
        with self.assertRaises(TransferError):
            self.accept(self.receiver(), self.first, b"alpha", identity=False)
        self.assertEqual(self.anchor.value[0], 0)

    def test_anchor_offline_rolls_back_sqlite(self):
        receiver = self.receiver()
        self.anchor.fail = True
        with self.assertRaises(TransferError):
            self.accept(receiver, self.first, b"alpha")
        self.assertEqual(inspect_checkpoint(self.path, self.anchor).status,
                         RecoveryStatus.MATCH)

    def test_advance_then_ack_failure_holds(self):
        receiver = self.receiver()
        self.anchor.advance_then_fail = True
        with self.assertRaises(TransferError):
            self.accept(receiver, self.first, b"alpha")
        self.assertEqual(inspect_checkpoint(self.path, self.anchor).status,
                         RecoveryStatus.ANCHOR_AHEAD)
        with self.assertRaises(TransferError):
            self.receiver()

    def test_insert_failure_does_not_advance(self):
        receiver = self.receiver()
        with sqlite3.connect(self.path) as db:
            db.execute(
                "CREATE TRIGGER deny_insert BEFORE INSERT "
                "ON completed_transfers BEGIN SELECT RAISE(ABORT, 'blocked'); END;"
            )
        with self.assertRaises(TransferError):
            self.accept(receiver, self.first, b"alpha")
        self.assertEqual(self.anchor.value[0], 0)

    def test_same_id_concurrently_one_success(self):
        left, right = self.receiver(), self.receiver()
        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(self.accept, left, self.first, b"alpha")
            f2 = executor.submit(self.accept, right, self.first, b"alpha")
            outcomes = []
            for f in (f1, f2):
                try:
                    outcomes.append(f.result())
                except TransferError:
                    outcomes.append(None)
        self.assertEqual(outcomes.count(b"alpha"), 1)
        self.assertEqual(outcomes.count(None), 1)
        self.assertEqual(self.anchor.value[0], 1)

    def test_distinct_ids_concurrently_serialized(self):
        left, right = self.receiver(), self.receiver()
        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(self.accept, left, self.first, b"alpha")
            f2 = executor.submit(self.accept, right, self.second, b"beta")
            self.assertEqual({f1.result(), f2.result()}, {b"alpha", b"beta"})
        self.assertEqual(self.anchor.value[0], 2)
        self.assertEqual(inspect_checkpoint(self.path, self.anchor).status,
                         RecoveryStatus.MATCH)

    def test_modified_receipt_blocks_future_writes(self):
        self.accept(self.receiver(), self.first, b"alpha")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE completed_transfers SET payload_sha256=?",
                       ("f" * 64,))
        with self.assertRaises(TransferError):
            self.accept(self.receiver(), self.second, b"beta")

    def test_missing_registry_fails_closed(self):
        receiver = self.receiver()
        self.path.unlink()
        with self.assertRaises(TransferError):
            self.accept(receiver, self.first, b"alpha")

    def test_invalid_boolean_flag_denied(self):
        with self.assertRaises(TransferError):
            self.accept(self.receiver(), self.first, b"alpha", consent=1)

    def test_failed_write_rejects_reuse_same_instance(self):
        receiver = self.receiver()
        self.anchor.fail = True
        with self.assertRaises(TransferError):
            self.accept(receiver, self.first, b"alpha")
        self.anchor.fail = False
        with self.assertRaises(TransferError):
            self.accept(receiver, self.first, b"alpha")


if __name__ == "__main__":
    unittest.main()
