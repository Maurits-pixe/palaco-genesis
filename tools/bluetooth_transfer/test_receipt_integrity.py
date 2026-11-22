"""Receipt-content checkpoint tests; fake anchor is NEVER production security."""
import sqlite3
from pathlib import Path
import tempfile
import unittest

from protocol import TransferError, chunks, make_offer
from receipt_integrity import (
    ContentAnchoredReceiver, EMPTY_ROOT, receipt_commitment,
)

ID1, ID2 = "a" * 32, "b" * 32


class FakeAnchor:
    """Volatile test double, NOT a trusted independent secure element."""

    def __init__(self):
        self.state = (0, EMPTY_ROOT)
        self.offline = False
        self.fail_advance = False

    def read(self):
        if self.offline:
            raise OSError("anchor offline")
        return self.state

    def advance(self, previous, current):
        if self.fail_advance:
            raise OSError("anchor write failed")
        if self.state != previous or current[0] != previous[0] + 1:
            raise ValueError("compare and advance mismatch")
        self.state = current


class ContentAnchorTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.path = Path(t.name) / "registry.sqlite"
        self.anchor = FakeAnchor()
        self.offer1 = make_offer("citadel", ID1, b"alpha")
        self.offer2 = make_offer("mundo", ID2, b"beta")

    def receiver(self):
        return ContentAnchoredReceiver(self.path, self.anchor)

    def receipt(self, receiver, offer, payload):
        return receiver.accept(
            offer, chunks(payload), user_approved=True,
            identity_verified=True,
        )

    def test_empty_root_is_domain_separated(self):
        self.assertEqual(receipt_commitment([]), EMPTY_ROOT)

    def test_first_receipt(self):
        self.assertEqual(self.receipt(self.receiver(), self.offer1, b"alpha"), b"alpha")
        self.assertEqual(self.anchor.state[0], 1)
        self.assertNotEqual(self.anchor.state[1], EMPTY_ROOT)

    def test_second_receipt_survives_restart(self):
        self.receipt(self.receiver(), self.offer1, b"alpha")
        self.receipt(self.receiver(), self.offer2, b"beta")
        self.assertEqual(self.anchor.state[0], 2)
        self.assertTrue(self.receiver().has_seen(ID2))

    def test_duplicate_fails(self):
        self.receipt(self.receiver(), self.offer1, b"alpha")
        with self.assertRaises(TransferError):
            self.receipt(self.receiver(), self.offer1, b"alpha")
        self.assertEqual(self.anchor.state[0], 1)

    def test_same_count_id_substitution_detected(self):
        self.receipt(self.receiver(), self.offer1, b"alpha")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE completed_transfers SET transfer_id=?", ("c" * 32,))
        with self.assertRaises(TransferError):
            self.receiver()

    def test_same_count_digest_substitution_detected(self):
        self.receipt(self.receiver(), self.offer1, b"alpha")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE completed_transfers SET payload_sha256=?", ("c" * 64,))
        with self.assertRaises(TransferError):
            self.receiver()

    def test_rollback_detected(self):
        self.receiver()
        old = self.path.read_bytes()
        self.receipt(self.receiver(), self.offer1, b"alpha")
        self.path.write_bytes(old)
        with self.assertRaises(TransferError):
            self.receiver()

    def test_deleted_row_detected(self):
        self.receipt(self.receiver(), self.offer1, b"alpha")
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM completed_transfers")
        with self.assertRaises(TransferError):
            self.receiver()

    def test_injected_row_detected(self):
        self.receiver()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO completed_transfers VALUES (?, ?)", (ID1, "a" * 64))
        with self.assertRaises(TransferError):
            self.receiver()

    def test_external_checkpoint_mismatch_denied(self):
        self.receiver()
        self.anchor.state = (0, "0" * 64)
        with self.assertRaises(TransferError):
            self.receiver()

    def test_anchor_offline_denied(self):
        self.receiver()
        self.anchor.offline = True
        with self.assertRaises(TransferError):
            self.receiver()

    def test_anchor_advance_failure_holds(self):
        receiver = self.receiver()
        self.anchor.fail_advance = True
        with self.assertRaises(TransferError):
            self.receipt(receiver, self.offer1, b"alpha")
        with self.assertRaises(TransferError):
            receiver.has_seen(ID1)

    def test_invalid_digest_not_recorded(self):
        receiver = self.receiver()
        with self.assertRaises(TransferError):
            self.receipt(receiver, self.offer1, b"wrong")
        self.assertEqual(self.anchor.state, (0, EMPTY_ROOT))

    def test_invalid_fingerprint_rejected(self):
        with self.assertRaises(TransferError):
            receipt_commitment([(ID1, "x" * 64)])

    def test_unsorted_rows_rejected(self):
        with self.assertRaises(TransferError):
            receipt_commitment([(ID2, "a" * 64), (ID1, "b" * 64)])

    def test_duplicate_rows_rejected(self):
        with self.assertRaises(TransferError):
            receipt_commitment([(ID1, "a" * 64), (ID1, "b" * 64)])

    def test_invalid_anchor_state_denied(self):
        self.anchor.state = (True, EMPTY_ROOT)
        with self.assertRaises(TransferError):
            self.receiver()

    def test_no_anchor_denied(self):
        with self.assertRaises(TransferError):
            ContentAnchoredReceiver(self.path, object())

    def test_database_corruption_denied(self):
        self.receiver()
        self.path.write_bytes(b"corrupt database")
        with self.assertRaises(TransferError):
            self.receiver()


if __name__ == "__main__":
    unittest.main()
