"""Regression and negative tests for the candidate local journal."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from offline_journal import JournalError, OfflineJournal
from offline_stage import GENESIS, make_candidate


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "events.sqlite"
        self.journal = OfflineJournal(self.path)
        self.one = make_candidate("rio", "a", 1, GENESIS, b"fixture")

    def insert_first(self):
        return self.journal.append(self.one, expected_head=GENESIS)

    def test_empty_read(self):
        self.assertEqual(self.journal.read(expected_head=GENESIS), ((), GENESIS))

    def test_restart_and_replay(self):
        original, head, retry = self.insert_first()
        self.assertFalse(retry)
        self.assertEqual(OfflineJournal(self.path).read(expected_head=head), (original, head))

    def test_exact_retry(self):
        events, head, _ = self.insert_first()
        self.assertEqual(self.journal.append(self.one, expected_head=head), (events, head, True))

    def test_reject_stale_writer(self):
        self.insert_first()
        candidate = make_candidate("mundo", "b", 2, GENESIS, b"fixture")
        with self.assertRaisesRegex(JournalError, "STALE_CHECKPOINT"):
            OfflineJournal(self.path).append(candidate, expected_head=GENESIS)

    def test_conflicting_retry(self):
        _, head, _ = self.insert_first()
        altered = dict(self.one, payload_sha256="0" * 64)
        with self.assertRaisesRegex(JournalError, "IDEMPOTENCY_CONFLICT"):
            self.journal.append(altered, expected_head=head)

    def test_reject_broken_previous(self):
        _, head, _ = self.insert_first()
        changed = make_candidate("rio", "b", 2, GENESIS, b"x")
        with self.assertRaisesRegex(JournalError, "BROKEN_CHAIN"):
            self.journal.append(changed, expected_head=head)

    def test_reject_tampered_row(self):
        self.insert_first()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER events_no_update")
            db.execute("UPDATE events SET event_json=? WHERE sequence=1", (b'{"x":1}',))
        with self.assertRaises(JournalError):
            self.journal.read(expected_head=GENESIS)

    def test_trigger_rejects_edit(self):
        self.insert_first()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM events")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE events SET event_id='new'")

    def test_rejection_rollback(self):
        original, head, _ = self.insert_first()
        with self.assertRaises(JournalError):
            self.journal.append(dict(self.one, sequence=3), expected_head=head)
        self.assertEqual(self.journal.read(expected_head=head), (original, head))

    def test_two_independent_connections(self):
        first, head, _ = self.insert_first()
        second = make_candidate("mundo", "b", 2, head, b"other")
        history, second_head, retry = OfflineJournal(self.path).append(second, expected_head=head)
        self.assertFalse(retry)
        self.assertEqual(len(history), 2)
        self.assertEqual(self.journal.read(expected_head=second_head)[0], history)

    def test_corrupt_sequence(self):
        self.insert_first()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER events_no_update")
            db.execute("UPDATE events SET sequence=42")
        with self.assertRaises(JournalError):
            self.journal.read(expected_head=GENESIS)

    def test_boolean_event_sequence(self):
        with self.assertRaises(JournalError):
            self.journal.append(dict(self.one, sequence=True), expected_head=GENESIS)


if __name__ == "__main__":
    unittest.main()
