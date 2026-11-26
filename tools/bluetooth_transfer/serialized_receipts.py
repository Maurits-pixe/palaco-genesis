"""Serialized receipt writer for PALACO Bluetooth offline transfer.

SQLite BEGIN IMMEDIATE serializes cooperating writers sharing one database.
The external checkpoint is advanced before SQLite COMMIT so readers never
receive bytes before both stages. This is NOT a cross-store atomic commit:
a crash after checkpoint advancement but before DB COMMIT leads to HOLD.

External anchor must be independent, tamper resistant and compare-and-advance
atomically. The test double is NOT security evidence. No native radio or
import authority is provided.
"""
from __future__ import annotations

from contextlib import closing
import hmac
import sqlite3

from durable_replay import MAX_RECEIPTS
from protocol import Offer, Receiver, TransferError, _validate_offer
from receipt_integrity import (
    ContentAnchoredReceiver, receipt_commitment,
)


class SerializedContentReceiver(ContentAnchoredReceiver):
    """Bound cooperating SQLite writers around content checkpoint advancement."""

    def accept(
        self, offer: Offer, parts: tuple[bytes, ...], *,
        user_approved: bool, identity_verified: bool,
    ) -> bytes:
        _validate_offer(offer)
        if type(user_approved) is not bool or type(identity_verified) is not bool:
            raise TransferError("verification flags must be booleans")
        if not user_approved or not identity_verified:
            raise TransferError("local consent and verified identity required")
        if self._path.is_symlink() or not self._path.is_file():
            raise TransferError("receipt registry missing or replaced")

        try:
            with closing(self._connect()) as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    rows = db.execute(
                        "SELECT transfer_id, payload_sha256 "
                        "FROM completed_transfers ORDER BY transfer_id"
                    ).fetchall()
                    before = (len(rows), receipt_commitment(rows))
                    trusted = self._trusted()
                    if (trusted[0] != before[0] or
                            not hmac.compare_digest(trusted[1], before[1])):
                        raise TransferError("external receipt checkpoint mismatch")
                    if len(rows) >= MAX_RECEIPTS:
                        raise TransferError("receipt registry at maximum capacity")
                    if db.execute(
                        "SELECT 1 FROM completed_transfers WHERE transfer_id=?",
                        (offer.transfer_id,),
                    ).fetchone() is not None:
                        raise TransferError("duplicate transfer")

                    # Receiver.accept checks chunk boundaries, digest and consent.
                    # It cannot be called through DurableReceiver: that would
                    # start a second independent SQLite transaction.
                    payload = Receiver.accept(
                        self, offer, parts,
                        user_approved=user_approved,
                        identity_verified=identity_verified,
                    )
                    db.execute(
                        "INSERT INTO completed_transfers "
                        "(transfer_id, payload_sha256) VALUES (?, ?)",
                        (offer.transfer_id, offer.payload_sha256),
                    )
                    after_rows = db.execute(
                        "SELECT transfer_id, payload_sha256 "
                        "FROM completed_transfers ORDER BY transfer_id"
                    ).fetchall()
                    after = (len(after_rows), receipt_commitment(after_rows))
                    if after[0] != before[0] + 1:
                        raise TransferError("unexpected receipt count change")
                    try:
                        self._anchor.advance(before, after)
                    except Exception as exc:
                        raise TransferError("external checkpoint advance failed") from exc
                # SQLite commit completes here, before any payload is returned.
        except sqlite3.IntegrityError as exc:
            raise TransferError("duplicate or invalid transfer") from exc
        except sqlite3.Error as exc:
            raise TransferError("receipt transaction failed; inspect HOLD") from exc
        # Any crash after checkpoint advancement but before SQLite commit
        # leaves an anchor-ahead state and requires supervised recovery.
        self._verify()
        return payload
