from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from registry import Release, Rejected
from sqlite_journal import Journal
from test_registry import NOW, SOURCE, POLICY, request


class DurableJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'candidate.sqlite'
        self.journal = Journal(self.path)
        self.genesis = Release('synthetic-only', SOURCE, POLICY)
        self.journal.register(self.genesis)

    def append(self, req, head=None, **options):
        kwargs = dict(trusted_head=head, now=NOW, online=True, verify=lambda _: True)
        kwargs.update(options)
        return self.journal.append(self.genesis, req, **kwargs)

    def test_restart_and_exact_retry(self):
        req = request(self.genesis)
        state, event, retry = self.append(req)
        self.assertFalse(retry)
        self.journal = Journal(self.path)
        self.assertEqual(self.journal.read(self.genesis, trusted_head=state.head,
                                          verify=lambda _: True), (state, [event]))
        self.assertEqual(self.append(req, state.head), (state, event, True))

    def test_two_connections_one_winner(self):
        barrier = threading.Barrier(2)
        def writer(index):
            journal = Journal(self.path)
            barrier.wait(timeout=5)
            try:
                journal.append(self.genesis, request(self.genesis, request_id=str(index)),
                               trusted_head=None, now=NOW, online=True, verify=lambda _: True)
                return 'accepted'
            except Rejected:
                return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(writer, [1, 2]))
        self.assertCountEqual(results, ['accepted', 'conflict'])

    def test_id_reuse_changed_payload_rejected(self):
        req = request(self.genesis)
        state, _, _ = self.append(req)
        with self.assertRaisesRegex(Rejected, 'IDEMPOTENCY_CONFLICT'):
            self.append(dict(req, target='REVOKED'), state.head)

    def test_failed_write_rolls_back(self):
        with closing(self.journal.connect()) as db:
            db.execute("CREATE TRIGGER injected_failure AFTER INSERT ON events "
                       "BEGIN SELECT RAISE(ABORT, 'INJECTED'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.append(request(self.genesis))
        self.assertEqual(self.journal.read(self.genesis, trusted_head=None), (self.genesis, []))

    def test_locked_database_and_retry(self):
        db = self.journal.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            self.journal.timeout = 0.01
            with self.assertRaises(sqlite3.OperationalError):
                self.append(request(self.genesis))
        finally:
            db.rollback()
            db.close()
        self.assertEqual(self.append(request(self.genesis))[0].sequence, 1)

    def test_revocation_survives_restart_and_retry(self):
        original = request(self.genesis)
        first, event, _ = self.append(original)
        revoked, _, _ = self.append(request(first, 'REVOKED'), first.head)
        self.journal = Journal(self.path)
        current, receipt, retry = self.append(original, revoked.head)
        self.assertEqual(current.state, 'REVOKED')
        self.assertEqual(receipt, event)
        self.assertTrue(retry)
        with self.assertRaises(Rejected):
            self.append(request(revoked, 'ENABLED'), revoked.head)

    def test_untrusted_checkpoint_and_genesis(self):
        state, _, _ = self.append(request(self.genesis))
        with self.assertRaisesRegex(Rejected, 'UNTRUSTED_CHECKPOINT'):
            self.journal.read(self.genesis, trusted_head=None, verify=lambda _: True)
        with self.assertRaisesRegex(Rejected, 'UNTRUSTED_GENESIS'):
            self.journal.read(Release('synthetic-only', 'c'*64, POLICY),
                              trusted_head=state.head, verify=lambda _: True)

    def test_sql_updates_and_deletes_denied(self):
        self.append(request(self.genesis))
        db = self.journal.connect()
        try:
            for query in ['DELETE FROM events', "UPDATE events SET request_id='changed'",
                          'DELETE FROM releases', "UPDATE releases SET genesis='changed'"]:
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'APPEND_ONLY'):
                    db.execute(query)
        finally:
            db.close()

    def test_retry_requires_current_verification_and_window(self):
        req = request(self.genesis)
        state, _, _ = self.append(req)
        for options in [dict(online=False), dict(verify=lambda _: False),
                        dict(now='2026-09-26T14:05:00Z')]:
            with self.assertRaises(Rejected):
                self.append(req, state.head, **options)


if __name__ == '__main__':
    unittest.main()
