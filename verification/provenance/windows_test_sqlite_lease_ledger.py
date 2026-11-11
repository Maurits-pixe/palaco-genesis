"""WNRA-04G disposable SQLite ledger; TEST ONLY, never a production issuer.

Single-host local database fixture. Caller supplies an isolated temporary path.
No credentials, trusted time source, producer authentication, Windows file opens,
cross-host fencing, cryptographic audit proof or actual authority are provided.
"""

import sqlite3

from windows_test_lease_model import LeaseDenied, TestLease

_FINAL = frozenset(("CONSUMED", "DENIED", "EXPIRED", "REVOKED"))


class TestSqliteLeaseLedger:
    """Transactional CAS plus audit; no capability objects can be returned."""

    def __init__(self, fixture_db_path):
        self.connection = sqlite3.connect(str(fixture_db_path), timeout=0.0, isolation_level=None)
        try:
            self.connection.execute("PRAGMA journal_mode=DELETE")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA busy_timeout=0")
            self.connection.executescript("""
                CREATE TABLE IF NOT EXISTS fixture_lease (
                    lease_id TEXT PRIMARY KEY,
                    statement_id TEXT NOT NULL,
                    consumer_id TEXT NOT NULL,
                    not_before INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    last_time INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fixture_audit (
                    transition_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    previous_state TEXT NOT NULL,
                    new_state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    FOREIGN KEY(lease_id) REFERENCES fixture_lease(lease_id)
                );
            """)
        except Exception:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def _tx(self, action):
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            result = action()
            self.connection.execute("COMMIT")
            return result
        except (sqlite3.Error, LeaseDenied) as exc:
            try:
                self.connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise LeaseDenied("fixture transaction denied or unavailable") from exc

    def issue(self, lease):
        if (
            not isinstance(lease, TestLease)
            or not lease.lease_id or not lease.statement_id or not lease.consumer_id
            or type(lease.not_before) is not int or type(lease.expires_at) is not int
            or lease.not_before >= lease.expires_at or lease.state != "ISSUED"
            or lease.revision != 0 or lease.last_time != 0
        ):
            raise LeaseDenied("invalid fixture lease")

        def act():
            self.connection.execute(
                "INSERT INTO fixture_lease VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (lease.lease_id, lease.statement_id, lease.consumer_id, lease.not_before,
                 lease.expires_at, "ISSUED", 0, 0),
            )
        self._tx(act)

    def inspect(self, lease_id):
        row = self.connection.execute(
            "SELECT state, revision, last_time FROM fixture_lease WHERE lease_id=?",
            (lease_id,),
        ).fetchone()
        return row

    def audit(self, lease_id):
        return self.connection.execute(
            "SELECT transition_id, previous_state, new_state, revision "
            "FROM fixture_audit WHERE lease_id=? ORDER BY revision",
            (lease_id,),
        ).fetchall()

    def transition(self, lease_id, transition_id, expected_revision, now,
                   consumer_id, expected_state, next_state):
        if (
            not lease_id or not transition_id or type(expected_revision) is not int
            or type(now) is not int
            or (expected_state, next_state) not in (
                ("ISSUED", "REDEEMING"), ("REDEEMING", "CONSUMED"),
                ("ISSUED", "REVOKED"), ("REDEEMING", "REVOKED"),
                ("REDEEMING", "DENIED"),
            )
        ):
            raise LeaseDenied("invalid fixture transition")

        def act():
            row = self.connection.execute(
                "SELECT consumer_id, not_before, expires_at, state, revision, last_time "
                "FROM fixture_lease WHERE lease_id=?", (lease_id,),
            ).fetchone()
            if row is None:
                raise LeaseDenied("unknown lease")
            bound_consumer, start, expiry, state, revision, last_time = row
            if (
                state in _FINAL or state != expected_state
                or revision != expected_revision or now < last_time
                or now < start or now >= expiry
                or consumer_id != bound_consumer
            ):
                raise LeaseDenied("fixture binding, replay, time or state denied")
            updated = self.connection.execute(
                "UPDATE fixture_lease SET state=?, revision=?, last_time=? "
                "WHERE lease_id=? AND state=? AND revision=?",
                (next_state, revision + 1, now, lease_id, state, revision),
            )
            if updated.rowcount != 1:
                raise LeaseDenied("fixture CAS conflict")
            self.connection.execute(
                "INSERT INTO fixture_audit VALUES (?, ?, ?, ?, ?)",
                (transition_id, lease_id, state, next_state, revision + 1),
            )
            return (next_state, revision + 1)
        return self._tx(act)

    def recover(self, recovery_id_prefix):
        """On restart, atomically retire stranded REDEEMING rows; never reuse."""
        if not recovery_id_prefix:
            raise LeaseDenied("recovery marker required")

        def act():
            rows = self.connection.execute(
                "SELECT lease_id, revision FROM fixture_lease WHERE state='REDEEMING'"
            ).fetchall()
            for lease_id, revision in rows:
                updated = self.connection.execute(
                    "UPDATE fixture_lease SET state='DENIED', revision=? "
                    "WHERE lease_id=? AND state='REDEEMING' AND revision=?",
                    (revision + 1, lease_id, revision),
                )
                if updated.rowcount != 1:
                    raise LeaseDenied("fixture recovery CAS failed")
                self.connection.execute(
                    "INSERT INTO fixture_audit VALUES (?, ?, 'REDEEMING', 'DENIED', ?)",
                    (recovery_id_prefix + ":" + lease_id, lease_id, revision + 1),
                )
            return len(rows)
        return self._tx(act)
