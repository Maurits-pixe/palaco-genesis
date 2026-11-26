"""Persisted one-time challenge admission for offline PALACO review intake.

A native privileged service must own this SQLite database and supply trusted UTC
seconds. SQLite is not tamper-proof or anti-rollback; database replacement can
re-enable old challenges. Verifier remains external and must validate real
signatures, keys, roles and revocation. No recovery authority is granted.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import secrets
import sqlite3
from collections.abc import Callable

from protocol import TransferError
from recovery_evidence import RecoveryEvidence, verify_evidence
from signed_review_gate import (
    ReviewDisposition, SignedReviewSubmission, TrustedReviewVerifier,
    assess_review_submission,
)

MAX_CHALLENGES = 100_000
DEFAULT_TTL_SECONDS = 300


class PersistentReviewChallenges:
    """One-shot, reviewer- and evidence-bound challenges with atomic consumption."""

    def __init__(self, database_path: str | Path, clock: Callable[[], int]) -> None:
        try:
            path = Path(database_path)
        except (TypeError, ValueError) as exc:
            raise TransferError("invalid challenge database path") from exc
        if (not path.is_absolute() or not path.parent.is_dir()
                or path.is_symlink() or path.exists()):
            raise TransferError("new challenge database in private existing directory required")
        if not callable(clock):
            raise TransferError("trusted UTC clock required")
        self._path = path
        self._clock = clock
        try:
            with closing(sqlite3.connect(str(path), timeout=5)) as db:
                with db:
                    db.execute(
                        "CREATE TABLE challenges ("
                        "token BLOB PRIMARY KEY NOT NULL,"
                        "evidence_hash TEXT NOT NULL,"
                        "key_id TEXT NOT NULL,"
                        "issued_at INTEGER NOT NULL,"
                        "expires_at INTEGER NOT NULL,"
                        "consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)))"
                    )
        except sqlite3.Error as exc:
            raise TransferError("challenge registry unavailable") from exc

    @classmethod
    def reopen(cls, database_path: str | Path, clock: Callable[[], int]):
        """Reopen an existing trusted registry; never initialize it silently."""
        obj = cls.__new__(cls)
        obj._path = Path(database_path)
        obj._clock = clock
        if not obj._path.is_absolute() or not callable(clock):
            raise TransferError("invalid registry")
        obj._check_file()
        try:
            with obj._db() as db:
                db.execute("SELECT token, consumed FROM challenges LIMIT 0")
        except sqlite3.Error as exc:
            raise TransferError("challenge registry schema unavailable") from exc
        return obj

    def _check_file(self) -> None:
        if not self._path.is_file() or self._path.is_symlink():
            raise TransferError("challenge registry missing or replaced")

    def _db(self):
        self._check_file()
        try:
            return closing(sqlite3.connect(str(self._path), timeout=5))
        except sqlite3.Error as exc:
            raise TransferError("challenge registry unavailable") from exc

    def _now(self) -> int:
        try:
            now = self._clock()
        except Exception as exc:
            raise TransferError("trusted UTC clock unavailable") from exc
        if type(now) is not int or not 0 <= now < 2**63 - 3600:
            raise TransferError("invalid trusted UTC time")
        return now

    def issue(
        self, evidence: RecoveryEvidence, reviewer_key_id: str, *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> bytes:
        """Generate 256-bit challenge; bind to exact evidence and reviewer key."""
        if not verify_evidence(evidence):
            raise TransferError("invalid evidence")
        if (type(reviewer_key_id) is not str or not 1 <= len(reviewer_key_id) <= 128
                or not all(c.isascii() and (c.isalnum() or c in "-_.")
                           for c in reviewer_key_id)):
            raise TransferError("invalid reviewer key identifier")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise TransferError("invalid challenge TTL")
        now = self._now()
        token = secrets.token_bytes(32)
        try:
            with self._db() as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    n = db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
                    if n >= MAX_CHALLENGES:
                        raise TransferError("challenge registry full")
                    db.execute(
                        "INSERT INTO challenges VALUES (?,?,?,?,?,0)",
                        (token, evidence.sha256, reviewer_key_id, now, now + ttl_seconds),
                    )
        except sqlite3.IntegrityError as exc:
            raise TransferError("challenge collision") from exc
        except sqlite3.Error as exc:
            raise TransferError("challenge issuance unavailable") from exc
        return token

    def submit(
        self, submission: SignedReviewSubmission, verifier: TrustedReviewVerifier,
    ) -> ReviewDisposition:
        """Atomically verify and consume once; never authorize actual recovery."""
        if type(submission) is not SignedReviewSubmission:
            raise TransferError("signed review submission required")
        now = self._now()
        try:
            with self._db() as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT evidence_hash,key_id,issued_at,expires_at,consumed "
                        "FROM challenges WHERE token=?", (submission.challenge,),
                    ).fetchone()
                    if (row is None or row[4] != 0 or
                            not row[2] <= now < row[3] or
                            row[0] != submission.evidence.sha256 or
                            row[1] != submission.reviewer_key_id):
                        raise TransferError("challenge missing, expired or already used")
                    result = assess_review_submission(submission, verifier)
                    updated = db.execute(
                        "UPDATE challenges SET consumed=1 WHERE token=? AND consumed=0",
                        (submission.challenge,),
                    ).rowcount
                    if updated != 1:
                        raise TransferError("challenge could not be consumed")
            return result
        except sqlite3.Error as exc:
            raise TransferError("challenge admission unavailable") from exc
