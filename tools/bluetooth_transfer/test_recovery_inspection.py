"""Read-only recovery diagnostics, synthetic trusted-anchor test double."""
import sqlite3
from pathlib import Path
import tempfile
import unittest

from protocol import chunks, make_offer
from receipt_integrity import ContentAnchoredReceiver, EMPTY_ROOT
from recovery_inspection import RecoveryStatus, inspect_checkpoint


class FakeAnchor:
    def __init__(self):
        self.state = (0, EMPTY_ROOT)

    def read(self):
        return self.state

    def advance(self, before, after):
        if self.state != before:
            raise RuntimeError("anchor mismatch")
        self.state = after


class InspectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "receipts.sqlite"
        self.anchor = FakeAnchor()
        self.offer = make_offer("citadel", "a" * 32, b"hello")

    def initialize(self):
        return ContentAnchoredReceiver(self.path, self.anchor)

    def accept(self):
        return self.initialize().accept(
            self.offer, chunks(b"hello"),
            user_approved=True, identity_verified=True,
        )

    def inspect(self):
        return inspect_checkpoint(self.path, self.anchor)

    def test_absent_database_remains_absent(self):
        self.assertEqual(self.inspect().status, RecoveryStatus.UNAVAILABLE)
        self.assertFalse(self.path.exists())

    def test_empty_registry_match(self):
        self.initialize()
        report = self.inspect()
        self.assertEqual(report.status, RecoveryStatus.MATCH)
        self.assertFalse(report.requires_hold)
        self.assertEqual(report.database_count, 0)

    def test_committed_receipt_match(self):
        self.accept()
        report = self.inspect()
        self.assertEqual(report.status, RecoveryStatus.MATCH)
        self.assertEqual(report.database_count, 1)
        self.assertEqual(report.anchor_count, 1)

    def test_database_ahead_classified(self):
        self.initialize()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO completed_transfers VALUES (?, ?)",
                       (self.offer.transfer_id, self.offer.payload_sha256))
        report = self.inspect()
        self.assertEqual(report.status, RecoveryStatus.DATABASE_AHEAD)
        self.assertTrue(report.requires_hold)

    def test_anchor_ahead_classified(self):
        self.initialize()
        self.anchor.state = (1, "f" * 64)
        self.assertEqual(self.inspect().status, RecoveryStatus.ANCHOR_AHEAD)

    def test_same_count_id_tampering_classified(self):
        self.accept()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE completed_transfers SET transfer_id=?",
                       ("c" * 32,))
        self.assertEqual(self.inspect().status, RecoveryStatus.CONTENT_MISMATCH)

    def test_same_count_hash_tampering_classified(self):
        self.accept()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE completed_transfers SET payload_sha256=?",
                       ("b" * 64,))
        self.assertEqual(self.inspect().status, RecoveryStatus.CONTENT_MISMATCH)

    def test_deleted_receipt_classified(self):
        self.accept()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM completed_transfers")
        self.assertEqual(self.inspect().status, RecoveryStatus.ANCHOR_AHEAD)

    def test_unchanged_database_after_inspection(self):
        self.accept()
        before = self.path.read_bytes()
        self.inspect()
        after = self.path.read_bytes()
        self.assertEqual(before, after)

    def test_no_recovery_on_match(self):
        self.accept()
        before_anchor = self.anchor.state
        self.assertEqual(self.inspect().status, RecoveryStatus.MATCH)
        self.assertEqual(self.anchor.state, before_anchor)

    def test_missing_anchor_unavailable(self):
        self.initialize()
        report = inspect_checkpoint(self.path, None)
        self.assertEqual(report.status, RecoveryStatus.UNAVAILABLE)
        self.assertTrue(report.requires_hold)

    def test_failing_anchor_unavailable(self):
        self.initialize()

        class Broken:
            def read(self):
                raise OSError("offline")

        self.assertEqual(
            inspect_checkpoint(self.path, Broken()).status,
            RecoveryStatus.UNAVAILABLE,
        )

    def test_malformed_anchor_state_unavailable(self):
        self.initialize()
        self.anchor.state = (True, EMPTY_ROOT)
        self.assertEqual(self.inspect().status, RecoveryStatus.UNAVAILABLE)

    def test_corrupt_sqlite_unavailable(self):
        self.initialize()
        self.path.write_bytes(b"corrupt")
        self.assertEqual(self.inspect().status, RecoveryStatus.UNAVAILABLE)

    def test_missing_schema_unavailable(self):
        with sqlite3.connect(self.path):
            pass
        self.assertEqual(self.inspect().status, RecoveryStatus.UNAVAILABLE)

    def test_relative_path_unavailable(self):
        self.assertEqual(
            inspect_checkpoint("relative.sqlite", self.anchor).status,
            RecoveryStatus.UNAVAILABLE,
        )

    def test_symlink_unavailable(self):
        self.initialize()
        link = self.path.parent / "link.sqlite"
        link.symlink_to(self.path)
        self.assertEqual(
            inspect_checkpoint(link, self.anchor).status,
            RecoveryStatus.UNAVAILABLE,
        )

    def test_no_payload_bytes_exposed_in_report(self):
        self.accept()
        report = self.inspect()
        self.assertEqual(report.database_count, 1)
        self.assertNotIn("hello", repr(report))

    def test_unknown_database_invalid_row_unavailable(self):
        self.initialize()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO completed_transfers VALUES (?, ?)",
                       ("not-an-id", "x" * 64))
        self.assertEqual(self.inspect().status, RecoveryStatus.UNAVAILABLE)

    def test_report_frozen(self):
        self.initialize()
        report = self.inspect()
        with self.assertRaises(AttributeError):
            report.status = RecoveryStatus.UNAVAILABLE


if __name__ == "__main__":
    unittest.main()
