"""External content checkpoint for a PALACO one-time challenge ledger.

A protected, independent anchor must implement atomic compare-and-advance of
(count, SHA256 root). This module does not provide trusted hardware or secure
persistence. SQLite and that anchor cannot commit atomically; interruption
means HOLD. Cooperating writers must use this anchored class exclusively.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import sqlite3
from typing import Protocol

from protocol import TransferError
from recovery_evidence import verify_evidence
from review_challenges import PersistentReviewChallenges, MAX_CHALLENGES
from signed_review_gate import (
    SignedReviewSubmission, TrustedReviewVerifier, ReviewDisposition,
    assess_review_submission,
)

DOMAIN = b"PALACO:BT:CHALLENGE-LEDGER:V1\0"
EMPTY_ROOT = hashlib.sha256(DOMAIN).hexdigest()


class ChallengeLedgerAnchor(Protocol):
    """Out-of-process trusted counter + content-root anchor."""

    def read(self) -> tuple[int, str]: ...
    def advance(
        self, previous: tuple[int, str], current: tuple[int, str],
    ) -> None: ...


def _validate_state(value):
    if (type(value) is not tuple or len(value) != 2 or
            type(value[0]) is not int or not 0 <= value[0] <= MAX_CHALLENGES or
            type(value[1]) is not str or len(value[1]) != 64 or
            any(x not in "0123456789abcdef" for x in value[1])):
        raise TransferError("invalid protected challenge checkpoint")
    return value


def challenge_commitment(rows) -> tuple[int, str]:
    """Commit all six fields in ascending binary challenge order."""
    if len(rows) > MAX_CHALLENGES:
        raise TransferError("challenge registry over capacity")
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    previous = None
    for token, evidence, key_id, issued, expires, consumed in rows:
        if (type(token) is not bytes or len(token) != 32 or
                (previous is not None and token <= previous) or
                type(evidence) is not str or len(evidence) != 64 or
                any(c not in "0123456789abcdef" for c in evidence) or
                type(key_id) is not str or
                not 1 <= len(key_id) <= 128 or
                any(not (c.isascii() and (c.isalnum() or c in "-_.")) for c in key_id) or
                type(issued) is not int or type(expires) is not int or
                not 0 <= issued < expires < 2**63 or
                type(consumed) is not int or consumed not in (0, 1)):
            raise TransferError("malformed challenge registry record")
        previous = token
        key_raw = key_id.encode("ascii")
        digest.update(token)
        digest.update(bytes.fromhex(evidence))
        digest.update(len(key_raw).to_bytes(2, "big") + key_raw)
        digest.update(issued.to_bytes(8, "big"))
        digest.update(expires.to_bytes(8, "big"))
        digest.update(bytes((consumed,)))
    return len(rows), digest.hexdigest()


class AnchoredChallengeLedger(PersistentReviewChallenges):
    """Single database writer with an externally anchored one-time ledger."""

    def __init__(self, database_path, clock, anchor: ChallengeLedgerAnchor):
        if not callable(getattr(anchor, "read", None)) or not callable(
            getattr(anchor, "advance", None)
        ):
            raise TransferError("trusted challenge ledger anchor required")
        self._anchor = anchor
        super().__init__(database_path, clock)
        self._check()

    @classmethod
    def reopen(cls, database_path, clock, anchor: ChallengeLedgerAnchor):
        if not callable(getattr(anchor, "read", None)) or not callable(
            getattr(anchor, "advance", None)
        ):
            raise TransferError("trusted challenge ledger anchor required")
        obj = super().reopen(database_path, clock)
        obj._anchor = anchor
        obj._check()
        return obj

    def _trusted(self):
        try:
            value = self._anchor.read()
        except Exception as exc:
            raise TransferError("protected challenge ledger unavailable") from exc
        return _validate_state(value)

    @staticmethod
    def _state(db):
        return challenge_commitment(db.execute(
            "SELECT token,evidence_hash,key_id,issued_at,expires_at,consumed "
            "FROM challenges ORDER BY token"
        ).fetchall())

    def _match(self, db):
        local = self._state(db)
        trusted = self._trusted()
        if local[0] != trusted[0] or not hmac.compare_digest(local[1], trusted[1]):
            raise TransferError("challenge ledger checkpoint mismatch: HOLD")
        return trusted

    def _check(self):
        try:
            with self._db() as db:
                self._match(db)
        except sqlite3.Error as exc:
            raise TransferError("challenge ledger unavailable: HOLD") from exc

    def _advance(self, previous, current):
        try:
            self._anchor.advance(previous, current)
        except Exception as exc:
            raise TransferError("protected challenge checkpoint write failed: HOLD") from exc

    def issue(self, evidence, reviewer_key_id, *, ttl_seconds=300):
        if not verify_evidence(evidence):
            raise TransferError("invalid recovery evidence")
        if (type(reviewer_key_id) is not str or
                not 1 <= len(reviewer_key_id) <= 128 or
                any(not (c.isascii() and (c.isalnum() or c in "-_."))
                    for c in reviewer_key_id) or
                type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600):
            raise TransferError("invalid reviewer key or TTL")
        import secrets
        token = secrets.token_bytes(32)
        now = self._now()
        try:
            with self._db() as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    before = self._match(db)
                    if before[0] >= MAX_CHALLENGES:
                        raise TransferError("challenge registry full")
                    db.execute(
                        "INSERT INTO challenges VALUES (?,?,?,?,?,0)",
                        (token, evidence.sha256, reviewer_key_id,
                         now, now + ttl_seconds),
                    )
                    after = self._state(db)
                    self._advance(before, after)
        except sqlite3.Error as exc:
            raise TransferError("challenge issue transaction failed: HOLD") from exc
        self._check()
        return token

    def submit(
        self, submission: SignedReviewSubmission,
        verifier: TrustedReviewVerifier,
    ) -> ReviewDisposition:
        if type(submission) is not SignedReviewSubmission:
            raise TransferError("signed review submission required")
        now = self._now()
        try:
            with self._db() as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    before = self._match(db)
                    row = db.execute(
                        "SELECT evidence_hash,key_id,issued_at,expires_at,consumed "
                        "FROM challenges WHERE token=?", (submission.challenge,),
                    ).fetchone()
                    if (row is None or row[4] != 0 or
                            not row[2] <= now < row[3] or
                            row[0] != submission.evidence.sha256 or
                            row[1] != submission.reviewer_key_id):
                        raise TransferError("challenge unavailable or expired")
                    result = assess_review_submission(submission, verifier)
                    updated = db.execute(
                        "UPDATE challenges SET consumed=1 WHERE token=? AND consumed=0",
                        (submission.challenge,),
                    ).rowcount
                    if updated != 1:
                        raise TransferError("challenge already consumed")
                    after = self._state(db)
                    if after[0] != before[0]:
                        raise TransferError("unexpected challenge count mutation")
                    self._advance(before, after)
        except sqlite3.Error as exc:
            raise TransferError("challenge submission transaction failed: HOLD") from exc
        self._check()
        return result
