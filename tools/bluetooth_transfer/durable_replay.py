"""SQLite-backed replay guard for verified offline transfer receipts.

Persists *completed* transfer identifiers across process restarts, with a
unique key enforced atomically by SQLite. This module is not encryption,
device authentication or import authorization.

The file must reside in an OS-protected, non-shared, local directory controlled
by the application. Losing/restoring an old DB snapshot weakens replay defense.
"""
from __future__ import annotations

import os
from contextlib import closing
from pathlib import Path
import sqlite3

from protocol import Offer, Receiver, TransferError, _validate_id, _validate_offer

MAX_RECEIPTS = 100_000


class DurableReceiver(Receiver):
    """Completed-receipt replay guard with persistent unique ID claims.

    The *entire* transfer is validated by Receiver.accept() before its ID is
    written. SQLITE unique constraints arbitrate concurrent processes.
    """

    def __init__(self, database_path: str | os.PathLike[str]) -> None:
        super().__init__()
        try:
            path = Path(database_path)
        except (TypeError, ValueError) as exc:
            raise TransferError("invalid replay database path") from exc
        if not path.is_absolute() or str(path) == ":memory:":
            raise TransferError("absolute persistent database path required")
        if path.is_symlink() or not path.parent.is_dir():
            raise TransferError("replay database must use existing local directory")
        self._path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(str(self._path), timeout=5)
            connection.execute("PRAGMA busy_timeout=5000")
            return connection
        except sqlite3.Error as exc:
            raise TransferError("replay database unavailable") from exc

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as db:
                with db:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS completed_transfers ("
                        "transfer_id TEXT PRIMARY KEY NOT NULL, "
                        "payload_sha256 TEXT NOT NULL)"
                    )
        except sqlite3.Error as exc:
            raise TransferError("replay database could not initialize") from exc

    def has_seen(self, transfer_id: str) -> bool:
        """Durable lookup. On database failure DENY instead of bypassing."""
        _validate_id(transfer_id)
        try:
            if not self._path.is_file() or self._path.is_symlink():
                raise TransferError("replay database missing or replaced")
            with closing(self._connect()) as db:
                row = db.execute(
                    "SELECT 1 FROM completed_transfers WHERE transfer_id=?",
                    (transfer_id,),
                ).fetchone()
                return row is not None
        except sqlite3.Error as exc:
            raise TransferError("replay database lookup unavailable") from exc

    def accept(
        self, offer: Offer, parts: tuple[bytes, ...], *,
        user_approved: bool, identity_verified: bool,
    ) -> bytes:
        """Validate bytes, then atomically record receipt before returning."""
        _validate_offer(offer)
        if self.has_seen(offer.transfer_id):
            raise TransferError("completed transfer already received")
        payload = super().accept(
            offer, parts, user_approved=user_approved,
            identity_verified=identity_verified,
        )
        try:
            if not self._path.is_file() or self._path.is_symlink():
                raise TransferError("replay database missing or replaced")
            with closing(self._connect()) as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    count = db.execute(
                        "SELECT COUNT(*) FROM completed_transfers"
                    ).fetchone()[0]
                    if count >= MAX_RECEIPTS:
                        raise TransferError("replay registry at maximum capacity")
                    db.execute(
                        "INSERT INTO completed_transfers "
                        "(transfer_id, payload_sha256) VALUES (?, ?)",
                        (offer.transfer_id, offer.payload_sha256),
                    )
        except sqlite3.IntegrityError as exc:
            raise TransferError("completed transfer already received") from exc
        except sqlite3.Error as exc:
            raise TransferError("replay database commit unavailable") from exc
        return payload
