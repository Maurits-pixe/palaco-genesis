"""Receipt-content checkpoint for PALACO offline Bluetooth exports.

A domain-separated SHA-256 commitment covers every (transfer ID, payload hash)
in canonical key order. The external anchor MUST be trusted, independent and
rollback resistant. This module does not create a real secure anchor.

WARNING: this is a single-writer reference. SQLite commits and external
anchor updates cannot be atomic; interruption requires manual HOLD recovery.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import sqlite3
from typing import Protocol

from durable_replay import DurableReceiver, MAX_RECEIPTS
from protocol import Offer, TransferError, _validate_id

DOMAIN = b"PALACO:BLUETOOTH:RECEIPT-COMMITMENT:V1\0"
EMPTY_ROOT = hashlib.sha256(DOMAIN).hexdigest()


class ReceiptAnchor(Protocol):
    """External trusted count + 256-bit digest checkpoint."""

    def read(self) -> tuple[int, str]:
        """Read durable trusted sequence and content digest."""

    def advance(
        self, previous: tuple[int, str], current: tuple[int, str],
    ) -> None:
        """Atomically compare-and-advance trusted checkpoint or raise."""


def receipt_commitment(rows: list[tuple[str, str]]) -> str:
    """Canonical commitment for validated, strictly increasing receipt rows."""
    if len(rows) > MAX_RECEIPTS:
        raise TransferError("receipt registry exceeds maximum")
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    previous = ""
    for transfer_id, payload_hash in rows:
        _validate_id(transfer_id)
        if (type(payload_hash) is not str or len(payload_hash) != 64 or
                any(c not in "0123456789abcdef" for c in payload_hash)):
            raise TransferError("invalid receipt digest")
        if transfer_id <= previous:
            raise TransferError("receipt rows are not strictly ordered")
        previous = transfer_id
        digest.update(bytes.fromhex(transfer_id))
        digest.update(bytes.fromhex(payload_hash))
    return digest.hexdigest()


def _check_anchor_state(value: object) -> tuple[int, str]:
    if (type(value) is not tuple or len(value) != 2 or
            type(value[0]) is not int or not 0 <= value[0] <= MAX_RECEIPTS or
            type(value[1]) is not str or len(value[1]) != 64 or
            any(c not in "0123456789abcdef" for c in value[1])):
        raise TransferError("invalid external receipt checkpoint")
    return value


class ContentAnchoredReceiver(DurableReceiver):
    """Deny if saved receipts differ from external trusted content checkpoint."""

    def __init__(self, database_path, anchor: ReceiptAnchor) -> None:
        if not callable(getattr(anchor, "read", None)) or not callable(
            getattr(anchor, "advance", None)
        ):
            raise TransferError("trusted receipt anchor required")
        self._anchor = anchor
        super().__init__(database_path)
        self._verify()

    def _state(self) -> tuple[int, str]:
        try:
            if self._path.is_symlink() or not self._path.is_file():
                raise TransferError("receipt registry missing")
            with closing(self._connect()) as db:
                rows = db.execute(
                    "SELECT transfer_id, payload_sha256 "
                    "FROM completed_transfers ORDER BY transfer_id"
                ).fetchall()
        except sqlite3.Error as exc:
            raise TransferError("receipt registry unavailable") from exc
        return len(rows), receipt_commitment(rows)

    def _trusted(self) -> tuple[int, str]:
        try:
            value = self._anchor.read()
        except Exception as exc:
            raise TransferError("external receipt anchor unavailable") from exc
        return _check_anchor_state(value)

    def _verify(self) -> tuple[int, str]:
        trusted = self._trusted()
        actual = self._state()
        if trusted[0] != actual[0] or not hmac.compare_digest(trusted[1], actual[1]):
            raise TransferError("receipt content checkpoint mismatch")
        return trusted

    def has_seen(self, transfer_id: str) -> bool:
        self._verify()
        return super().has_seen(transfer_id)

    def accept(
        self, offer: Offer, parts: tuple[bytes, ...], *,
        user_approved: bool, identity_verified: bool,
    ) -> bytes:
        """Persist validated receipt; checkpoint before releasing bytes."""
        before = self._verify()
        payload = super().accept(
            offer, parts,
            user_approved=user_approved, identity_verified=identity_verified,
        )
        after = self._state()
        if after[0] != before[0] + 1:
            raise TransferError("unexpected concurrent receipt modification")
        try:
            self._anchor.advance(before, after)
        except Exception as exc:
            raise TransferError("receipt checkpoint advancement failed") from exc
        self._verify()
        return payload
