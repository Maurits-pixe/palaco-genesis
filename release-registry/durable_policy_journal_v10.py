"""PALACO v10 SQLite policy-ledger candidate. Not a trusted authority.

Each read replays exact canonical event bytes. Writes serialize locally and
require the expected head. A trusted, independently controlled policy anchor
and current revocation decision remain external obligations.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3

from offline_stage import _canonical
from policy_ledger_v9 import (
    GENESIS, LedgerError, propose_event, replay_ledger,
    verify_anchored_ledger,
)


class PolicyJournalError(LedgerError):
    pass


class DurablePolicyJournal:
    def __init__(self, path, *, timeout=5.0):
        self.path = str(Path(path))
        self.timeout = timeout
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS policy_events (
                    sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                    body BLOB NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS policy_events_no_update
                    BEFORE UPDATE ON policy_events
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS policy_events_no_delete
                    BEFORE DELETE ON policy_events
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA busy_timeout = 5000")
        return db

    @staticmethod
    def _load(db):
        events = []
        for sequence, body in db.execute(
                "SELECT sequence, body FROM policy_events ORDER BY sequence"):
            if type(body) is not bytes:
                raise PolicyJournalError("INVALID_STORED_BYTES")
            try:
                event = json.loads(body.decode("ascii"))
                if _canonical(event) != body or (
                        type(event) is not dict or
                        type(event.get("sequence")) is not int or
                        event["sequence"] != sequence):
                    raise PolicyJournalError("CORRUPT_STORED_EVENT")
            except (UnicodeError, ValueError, TypeError, OverflowError) as exc:
                raise PolicyJournalError("CORRUPT_STORED_EVENT") from exc
            events.append(event)
        try:
            head, current = replay_ledger(events)
        except (LedgerError, ValueError, TypeError, OverflowError) as exc:
            raise PolicyJournalError("CORRUPT_POLICY_HISTORY") from exc
        return tuple(events), head, current

    def read(self, *, expected_head):
        """Read without changing state; expected head is NOT a trusted anchor."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                events, head, snapshot = self._load(db)
                if type(expected_head) is not str or head != expected_head:
                    raise PolicyJournalError("STALE_CHECKPOINT")
                return events, head, snapshot
            finally:
                db.rollback()

    def append(self, before, after, *, expected_head):
        """Append one v9 event in a serialized SQLite transaction."""
        # Freeze inputs before waiting on the database lock.
        try:
            frozen_before = json.loads(_canonical(before))
            frozen_after = json.loads(_canonical(after))
        except (ValueError, TypeError, OverflowError) as exc:
            raise PolicyJournalError("INVALID_INPUT") from exc
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                events, head, _ = self._load(db)
                if type(expected_head) is not str or expected_head != head:
                    raise PolicyJournalError("STALE_CHECKPOINT")
                event, new_head = propose_event(
                    events, frozen_before, frozen_after, expected_head=head)
                db.execute(
                    "INSERT INTO policy_events(sequence, body) VALUES (?, ?)",
                    (event["sequence"], _canonical(event)),
                )
                db.commit()
                return event, new_head
            except BaseException:
                db.rollback()
                raise

    def inspect_trusted(self, *, get_trusted_anchor, verify_policy):
        """Read/replay within one snapshot and invoke external trust checks.

        Callbacks must themselves be independently secured and fresh.
        The returned diagnostic explicitly refuses release authority.
        """
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                events, _, _ = self._load(db)
                return verify_anchored_ledger(
                    events, get_trusted_anchor=get_trusted_anchor,
                    verify_policy=verify_policy)
            finally:
                db.rollback()
