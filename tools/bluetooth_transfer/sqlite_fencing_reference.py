"""SQLite process-shared fencing reference, NOT a trusted native secure store.

BEGIN IMMEDIATE serializes cooperating SQLite writers across processes. This
reference implements the fencing contract and incident latch in one database
transaction. A local attacker can alter, delete, copy, or roll back that
database; SQLite is NOT TPM/KeyMint, privileged custody, or anti-rollback.
Use only in isolated tests or explicit development environments.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from protocol import TransferError


class SQLiteFencingReference:
    """One-row, one-namespace transactional CAS/incident reference."""

    def __init__(self, database_path: str | Path, namespace: bytes, *,
                 create: bool = False):
        if type(namespace) is not bytes or len(namespace) != 32:
            raise TransferError("explicit 32-byte fencing namespace required")
        if type(create) is not bool:
            raise TransferError("explicit reference registry mode required")
        try:
            path = Path(database_path)
        except (TypeError, ValueError) as exc:
            raise TransferError("invalid fencing registry path") from exc
        if (not path.is_absolute() or not path.parent.is_dir() or
                path.is_symlink() or (path.exists() == create)):
            raise TransferError("explicit existing/new fencing registry required")
        self._path = path
        self._namespace = namespace
        if create:
            try:
                # Atomic exclusive creation; do not silently replace old ledgers.
                fd = __import__("os").open(
                    path, __import__("os").O_CREAT | __import__("os").O_EXCL |
                    __import__("os").O_RDWR, 0o600,
                )
                __import__("os").close(fd)
                with self._db() as db:
                    with db:
                        db.execute("CREATE TABLE fence ("
                                   "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                                   "namespace BLOB NOT NULL,"
                                   "epoch INTEGER NOT NULL CHECK(epoch>=1),"
                                   "held INTEGER NOT NULL CHECK(held IN (0,1)),"
                                   "count INTEGER NOT NULL CHECK(count>=0),"
                                   "root TEXT NOT NULL)")
                        db.execute(
                            "INSERT INTO fence VALUES (1,?,1,0,0,?)",
                            (namespace, EMPTY_ROOT),
                        )
            except (OSError, sqlite3.Error) as exc:
                raise TransferError("unable to create fencing reference") from exc
        self.read()

    def _db(self):
        if self._path.is_symlink() or not self._path.is_file():
            raise TransferError("fencing reference registry missing or replaced")
        try:
            return closing(sqlite3.connect(str(self._path), timeout=5))
        except sqlite3.Error as exc:
            raise TransferError("fencing reference database unavailable") from exc

    def _snapshot(self, db):
        row = db.execute(
            "SELECT namespace,epoch,held,count,root FROM fence WHERE singleton=1"
        ).fetchone()
        if row is None or db.execute("SELECT COUNT(*) FROM fence").fetchone()[0] != 1:
            raise TransferError("fencing reference registry malformed")
        namespace, epoch, held, count, root = row
        if type(namespace) is not bytes or namespace != self._namespace or (
                type(held) is not int or held not in (0, 1)):
            raise TransferError("fencing reference scope or state invalid")
        return FencedSnapshot(
            namespace, epoch, bool(held),
            NativeCheckpoint(namespace, count, root),
        )

    def read(self) -> FencedSnapshot:
        try:
            with self._db() as db:
                return self._snapshot(db)
        except sqlite3.Error as exc:
            raise TransferError("fencing reference read failed") from exc

    def compare_and_advance(self, expected: FencedSnapshot,
                            replacement: NativeCheckpoint) -> FencedSnapshot:
        if (type(expected) is not FencedSnapshot or
                type(replacement) is not NativeCheckpoint or
                expected.namespace != self._namespace or
                replacement.namespace != self._namespace):
            raise TransferError("invalid reference CAS scope")
        try:
            with self._db() as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    before = self._snapshot(db)
                    if before != expected or before.incident_held:
                        raise TransferError("fencing CAS stale or HOLD active")
                    if (replacement == before.checkpoint or
                            replacement.count not in (
                                before.checkpoint.count,
                                before.checkpoint.count + 1,
                            )):
                        raise TransferError("invalid fencing CAS transition")
                    if db.execute(
                        "UPDATE fence SET count=?,root=? "
                        "WHERE singleton=1 AND epoch=? AND held=0 AND count=? AND root=?",
                        (replacement.count, replacement.root, before.epoch,
                         before.checkpoint.count, before.checkpoint.root),
                    ).rowcount != 1:
                        raise TransferError("fencing CAS lost")
                    return self._snapshot(db)
        except sqlite3.Error as exc:
            raise TransferError("fencing reference CAS unavailable") from exc

    def latch_incident(self) -> FencedSnapshot:
        """Atomically and irreversibly (via this API) revoke all old fences."""
        try:
            with self._db() as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    prior = self._snapshot(db)
                    if not prior.incident_held:
                        if prior.epoch == 2**63 - 1:
                            raise TransferError("fence epoch exhausted: HOLD")
                        db.execute(
                            "UPDATE fence SET held=1,epoch=? WHERE singleton=1",
                            (prior.epoch + 1,),
                        )
                    return self._snapshot(db)
        except sqlite3.Error as exc:
            raise TransferError("fencing incident latch unavailable") from exc
