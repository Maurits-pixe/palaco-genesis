"""WNRA-04P: disposable SQLite-backed custody fixture, not a trusted anchor.

Caller supplies a dedicated temporary database path. It must NOT point to the
lease ledger. Filesystem ownership, custodian identity and signing are NOT proven.
"""
from dataclasses import fields
import sqlite3

from windows_test_pin_custody_model import (
    CustodyDenied, DisposableCustody, PinRecord,
)

_COLUMNS = tuple(item.name for item in fields(PinRecord))
_SELECT = ", ".join(_COLUMNS)


class DisposableSqliteCustody:
    def __init__(self, path: str, fixture_id: str):
        if not path or path == ":memory:" or not fixture_id:
            raise CustodyDenied("requires a named disposable fixture path and identity")
        self.path = path
        self.fixture_id = fixture_id

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=0.25, isolation_level=None)
        conn.execute("PRAGMA busy_timeout = 250")
        return conn

    def initialize(self):
        conn = self._connect()
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS test_pin_history (
                fixture_id TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL,
                source_commit TEXT NOT NULL,
                sequence INTEGER NOT NULL PRIMARY KEY,
                predecessor_digest TEXT,
                evidence_ref TEXT NOT NULL,
                custody_status TEXT NOT NULL,
                schema TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                snapshot_domain TEXT NOT NULL
            )""")
            conn.execute("""CREATE TRIGGER IF NOT EXISTS test_pin_no_update
                BEFORE UPDATE ON test_pin_history BEGIN SELECT RAISE(ABORT, 'immutable'); END""")
            conn.execute("""CREATE TRIGGER IF NOT EXISTS test_pin_no_delete
                BEFORE DELETE ON test_pin_history BEGIN SELECT RAISE(ABORT, 'immutable'); END""")
        finally:
            conn.close()

    def _load(self, conn):
        model = DisposableCustody(self.fixture_id)
        rows = conn.execute("SELECT " + _SELECT + " FROM test_pin_history ORDER BY sequence").fetchall()
        for row in rows:
            model.accept(PinRecord(*row), simulated_reviewer_acceptance=True)
        return model

    def append(self, record: PinRecord, *, simulated_reviewer_acceptance: bool):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            model = self._load(conn)
            model.accept(record, simulated_reviewer_acceptance=simulated_reviewer_acceptance)
            names = ", ".join(_COLUMNS)
            params = ", ".join("?" for _ in _COLUMNS)
            conn.execute("INSERT INTO test_pin_history (" + names + ") VALUES (" + params + ")",
                         tuple(getattr(record, key) for key in _COLUMNS))
            conn.execute("COMMIT")
        except (sqlite3.Error, CustodyDenied) as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise CustodyDenied("disposable custody append denied") from exc
        finally:
            conn.close()

    def compare(self, fixture_id: str, digest: str, *, simulated_custodian_available: bool):
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            result = self._load(conn).compare(
                fixture_id, digest,
                simulated_custodian_available=simulated_custodian_available)
            conn.execute("COMMIT")
            return result
        except (sqlite3.Error, CustodyDenied) as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise CustodyDenied("disposable custody comparison denied") from exc
        finally:
            conn.close()
