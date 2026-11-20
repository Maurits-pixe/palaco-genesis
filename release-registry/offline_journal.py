"""SQLite transaction harness for untrusted, metadata-only PALACO offline events.

NO production authority, distributed sync, durable external trust anchor, or
trusted identity. Caller-supplied trusted_head is an optimistic concurrency
checkpoint only. This module never accepts or stores payload contents.
"""
from contextlib import closing
import json
import sqlite3
from pathlib import Path

from offline_stage import GENESIS, StageError, _canonical, replay, stage


class JournalError(StageError):
    pass


class OfflineJournal:
    def __init__(self, path, *, timeout=5.0):
        self.path = str(Path(path))
        self.timeout = timeout
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                    event_id TEXT NOT NULL UNIQUE,
                    event_json BLOB NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events BEGIN
                    SELECT RAISE(ABORT, 'APPEND_ONLY');
                END;
                CREATE TRIGGER IF NOT EXISTS events_no_delete
                BEFORE DELETE ON events BEGIN
                    SELECT RAISE(ABORT, 'APPEND_ONLY');
                END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA foreign_keys = ON")
        return db

    @staticmethod
    def _history(db):
        rows = db.execute("SELECT sequence,event_id,event_json FROM events ORDER BY sequence")
        events = []
        for sequence, event_id, payload in rows:
            try:
                event = json.loads(payload)
            except (ValueError, TypeError, UnicodeDecodeError) as exc:
                raise JournalError("CORRUPT_EVENT_JSON") from exc
            if (type(event) is not dict or event.get("sequence") != sequence or
                    event.get("event_id") != event_id or _canonical(event) != payload):
                raise JournalError("CORRUPT_EVENT_ROW")
            events.append(event)
        try:
            head = replay(events)
        except StageError as exc:
            raise JournalError("CORRUPT_CHAIN") from exc
        return tuple(events), head

    def read(self, *, expected_head):
        """Read current events only when caller's checkpoint matches.

        A returned head is NOT independently authoritative or anti-rollback.
        """
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                events, head = self._history(db)
                if type(expected_head) is not str or head != expected_head:
                    raise JournalError("STALE_CHECKPOINT")
                return events, head
            finally:
                db.rollback()

    def append(self, event, *, expected_head):
        """One serialized append; returns (events, head, exact_retry)."""
        # Freeze caller input prior to DB lock acquisition.
        try:
            frozen = json.loads(_canonical(event))
        except (ValueError, TypeError, OverflowError) as exc:
            raise JournalError("INVALID_EVENT") from exc
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                events, head = self._history(db)
                try:
                    next_events, new_head, retry = stage(
                        events, frozen, expected_head=expected_head)
                except StageError as exc:
                    raise JournalError(str(exc)) from exc
                if not retry:
                    db.execute(
                        "INSERT INTO events (sequence,event_id,event_json) VALUES (?,?,?)",
                        (frozen["sequence"], frozen["event_id"], _canonical(frozen)))
                db.commit()
                return next_events, new_head, retry
            except BaseException:
                db.rollback()
                raise
