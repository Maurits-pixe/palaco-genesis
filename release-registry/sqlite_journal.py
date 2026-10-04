"""Local draft transaction harness. No network endpoint or production authority.

The caller supplies trusted genesis, checkpoint, clock and verifier. SQLite file
permissions, independent checkpoints and signed receipts remain external gates.
"""
from contextlib import closing
from dataclasses import asdict
import json
import sqlite3

from registry import Release, Rejected, canonical, transition


class Journal:
    def __init__(self, path, *, timeout=5):
        self.path, self.timeout = str(path), timeout
        with closing(self.connect()) as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS releases (
                    release_id TEXT PRIMARY KEY, genesis BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    release_id TEXT NOT NULL REFERENCES releases(release_id),
                    sequence INTEGER NOT NULL, request_id TEXT NOT NULL,
                    body BLOB NOT NULL,
                    PRIMARY KEY(release_id, sequence),
                    UNIQUE(release_id, request_id));
                CREATE TRIGGER IF NOT EXISTS immutable_events_update
                    BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_events_delete
                    BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_releases_update
                    BEFORE UPDATE ON releases BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_releases_delete
                    BEFORE DELETE ON releases BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
            ''')

    def connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def register(self, genesis):
        if not isinstance(genesis, Release) or genesis.sequence != 0:
            raise Rejected('INVALID_GENESIS')
        with closing(self.connect()) as db:
            db.execute('INSERT INTO releases VALUES (?, ?)',
                       (genesis.release_id, canonical(asdict(genesis))))

    def _replay(self, db, genesis, verify):
        row = db.execute('SELECT genesis FROM releases WHERE release_id=?',
                         (genesis.release_id,)).fetchone()
        if row is None or row[0] != canonical(asdict(genesis)):
            raise Rejected('UNTRUSTED_GENESIS')
        state, events, prior = genesis, [], []
        rows = db.execute('SELECT sequence, request_id, body FROM events '
                          'WHERE release_id=? ORDER BY sequence', (genesis.release_id,))
        for sequence, request_id, body in rows:
            event = json.loads(body)
            prior.append(state)
            state, reproduced = transition(state, event['request'],
                                            now=event['recorded_at'], online=True, verify=verify)
            if (reproduced != event or sequence != state.sequence
                    or request_id != event['request']['request_id']):
                raise Rejected('TAMPERED_HISTORY')
            events.append(event)
        return state, events, prior

    def read(self, genesis, *, trusted_head, verify=None):
        with closing(self.connect()) as db:
            db.execute('BEGIN')
            try:
                state, events, _ = self._replay(db, genesis, verify)
                if state.head != trusted_head:
                    raise Rejected('UNTRUSTED_CHECKPOINT')
                return state, events
            finally:
                db.rollback()

    def append(self, genesis, request, *, trusted_head, now, online=False, verify=None):
        """One local DB transaction serializes independent writer connections.

        An exact retry returns its historical receipt alongside CURRENT state;
        it cannot resurrect an earlier state. It is reverified at current time,
        so expired/offline/revoked-credential retries fail closed.
        """
        # Freeze caller-owned payload before acquiring a potentially delayed lock.
        request = json.loads(canonical(request))
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                state, events, prior = self._replay(db, genesis, verify)
                if state.head != trusted_head:
                    raise Rejected('UNTRUSTED_CHECKPOINT')
                for old, before in zip(events, prior):
                    if old['request']['request_id'] == request.get('request_id'):
                        if canonical(old['request']) != canonical(request):
                            raise Rejected('IDEMPOTENCY_CONFLICT')
                        transition(before, request, now=now, online=online, verify=verify)
                        db.commit()
                        return state, old, True
                candidate, event = transition(state, request, now=now,
                                              online=online, verify=verify)
                db.execute('INSERT INTO events VALUES (?, ?, ?, ?)',
                           (genesis.release_id, candidate.sequence,
                            request['request_id'], canonical(event)))
                db.commit()
                return candidate, event, False
            except BaseException:
                db.rollback()
                raise
