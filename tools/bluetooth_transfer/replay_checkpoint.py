"""Optional external anti-rollback checkpoint contract for PALACO receipts.

The counter backend MUST be independent of, and more strongly protected than,
the SQLite database. This module does not implement a trusted counter, TPM,
Secure Enclave, Android Keystore or secure persistence. It detects a rolled-
back receipt count only when its external counter is genuinely trustworthy.

Fail closed on mismatch. Cross-store commits are NOT atomic: a crash between
SQLite commit and external advance requires explicit authorized recovery.
"""
from __future__ import annotations

from contextlib import closing
import sqlite3
from typing import Protocol

from durable_replay import DurableReceiver
from protocol import Offer, TransferError


class MonotonicAnchor(Protocol):
    """Native trusted component with irreversible compare-and-advance."""

    def read(self) -> int:
        """Return the durable monotonic receipt count."""

    def advance(self, expected: int, new_value: int) -> None:
        """Durably advance exactly one, or raise without claiming success."""


class AnchoredDurableReceiver(DurableReceiver):
    """Replay registry that refuses rollback relative to an external anchor."""

    def __init__(self, database_path, anchor: MonotonicAnchor) -> None:
        if not callable(getattr(anchor, "read", None)) or not callable(
            getattr(anchor, "advance", None)
        ):
            raise TransferError("trusted external anchor required")
        self._anchor = anchor
        super().__init__(database_path)
        self._check_checkpoint()

    def _count(self) -> int:
        try:
            if not self._path.is_file() or self._path.is_symlink():
                raise TransferError("registry missing or replaced")
            with closing(self._connect()) as db:
                row = db.execute(
                    "SELECT COUNT(*) FROM completed_transfers"
                ).fetchone()
            if row is None or type(row[0]) is not int:
                raise TransferError("invalid replay registry count")
            return row[0]
        except sqlite3.Error as exc:
            raise TransferError("replay registry unavailable") from exc

    def _read_anchor(self) -> int:
        try:
            value = self._anchor.read()
        except Exception as exc:
            raise TransferError("trusted counter unavailable") from exc
        if type(value) is not int or not 0 <= value <= 100_000:
            raise TransferError("trusted counter value invalid")
        return value

    def _check_checkpoint(self) -> int:
        counter = self._read_anchor()
        if self._count() != counter:
            raise TransferError("replay registry / trusted counter mismatch")
        return counter

    def has_seen(self, transfer_id: str) -> bool:
        """Never accept replay checks if the external anchor disagrees."""
        self._check_checkpoint()
        return super().has_seen(transfer_id)

    def accept(
        self, offer: Offer, parts: tuple[bytes, ...], *,
        user_approved: bool, identity_verified: bool,
    ) -> bytes:
        """Persist receipt then advance anchor; any mismatch denies output."""
        count = self._check_checkpoint()
        payload = super().accept(
            offer, parts,
            user_approved=user_approved,
            identity_verified=identity_verified,
        )
        try:
            self._anchor.advance(count, count + 1)
        except Exception as exc:
            raise TransferError("trusted counter advance unavailable") from exc
        self._check_checkpoint()
        return payload
