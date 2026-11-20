"""PALACO v27 owner-session decision gateway: draft, not an identity provider.

One-use challenge binds a verified owner, daily JA/NEE, evidence reference and
current v26 snapshot. It stores only SHA-256 of a random challenge. Production
requires independent, fresh session/role/revocation and trusted UTC time.
A confirmed review is ALWAYS non-authorizing (DENY/HOLD).
"""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import secrets
import sqlite3

from owner_decision_cockpit_v26 import OwnerDecisionCockpit, _day
from recovery_operations_cockpit_v25 import ID

HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_TTL_SECONDS = 300


class GatewayError(ValueError):
    pass


def _trusted_seconds(provider):
    if not callable(provider):
        raise GatewayError("TRUSTED_CLOCK_REQUIRED")
    try:
        now = provider()
    except Exception as exc:
        raise GatewayError("TRUSTED_CLOCK_UNAVAILABLE") from exc
    # Require integer epoch seconds from an authenticated external UTC clock.
    if type(now) is not int or not 1_700_000_000 <= now <= 4_102_444_800:
        raise GatewayError("INVALID_TRUSTED_TIME")
    return now


def _owner(provider, assertion, action, day):
    if not callable(provider):
        raise GatewayError("SESSION_PROVIDER_REQUIRED")
    if type(assertion) is not str or not 1 <= len(assertion) <= 8192:
        raise GatewayError("INVALID_SESSION_ASSERTION")
    try:
        principal = provider(assertion, action, day)
    except Exception as exc:
        raise GatewayError("SESSION_UNAVAILABLE") from exc
    if type(principal) is not str or not ID.fullmatch(principal):
        raise GatewayError("SESSION_NOT_AUTHORIZED")
    return principal


class OwnerSessionDecisionGateway:
    """A session-bound, one-use acknowledgment workflow without release APIs.

    verify_session(assertion, action, day) must verify the session's authentic
    issuer, owner role, MFA/freshness, scope, expiry and current revocation.
    trusted_now() must be an independent trusted UTC epoch-seconds service.
    Neither service is implemented in this development candidate.
    """

    def __init__(self, path, *, cockpit):
        if not isinstance(cockpit, OwnerDecisionCockpit):
            raise GatewayError("INVALID_COCKPIT")
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise GatewayError("INVALID_DATABASE_PATH")
        self.path = str(target)
        self.cockpit = cockpit
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS owner_challenges(
                    token_sha256 TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    day TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK(verdict IN ('JA','NEE')),
                    evidence_ref TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );
                CREATE TRIGGER IF NOT EXISTS challenges_no_delete
                  BEFORE DELETE ON owner_challenges
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS challenges_no_mutation
                  BEFORE UPDATE ON owner_challenges
                  WHEN NOT (OLD.consumed_at IS NULL AND
                    NEW.consumed_at IS NOT NULL AND
                    NEW.token_sha256=OLD.token_sha256 AND
                    NEW.owner_id=OLD.owner_id AND NEW.day=OLD.day AND
                    NEW.verdict=OLD.verdict AND
                    NEW.evidence_ref=OLD.evidence_ref AND
                    NEW.snapshot_sha256=OLD.snapshot_sha256 AND
                    NEW.issued_at=OLD.issued_at AND
                    NEW.expires_at=OLD.expires_at)
                  BEGIN SELECT RAISE(ABORT,'CHALLENGE_IMMUTABLE'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def begin(self, *, session_assertion, day, verdict, evidence_ref,
              expected_snapshot_sha256, verify_session, trusted_now):
        """Create a pending challenge; never record a review at this step."""
        parsed = _day(day)
        if parsed.weekday() == 6:
            raise GatewayError("SUNDAY_FREE")
        if type(verdict) is not str or verdict not in ("JA", "NEE"):
            raise GatewayError("INVALID_VERDICT")
        if type(evidence_ref) is not str or not ID.fullmatch(evidence_ref):
            raise GatewayError("INVALID_EVIDENCE_REF")
        if type(expected_snapshot_sha256) is not str or not HEX.fullmatch(
                expected_snapshot_sha256):
            raise GatewayError("INVALID_EXPECTED_SNAPSHOT")
        now = _trusted_seconds(trusted_now)
        if datetime.fromtimestamp(now, tz=timezone.utc).date().isoformat() != day:
            raise GatewayError("TRUSTED_DATE_MISMATCH")
        owner_id = _owner(verify_session, session_assertion, "OWNER_REVIEW", day)
        view = self.cockpit.overview(day=day)
        if not view["review_available"]:
            raise GatewayError(view["review_reason"])
        if view["snapshot"]["snapshot_sha256"] != expected_snapshot_sha256:
            raise GatewayError("STALE_SNAPSHOT")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO owner_challenges(token_sha256,owner_id,day,verdict,"
                    "evidence_ref,snapshot_sha256,issued_at,expires_at,consumed_at) "
                    "VALUES(?,?,?,?,?,?,?,?,NULL)",
                    (digest, owner_id, day, verdict, evidence_ref,
                     expected_snapshot_sha256, now, now + MAX_TTL_SECONDS))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"schema": "palaco-owner-challenge/v27",
                "challenge": token, "expires_at": now + MAX_TTL_SECONDS,
                "action_executed": False, "authorization": "DENY",
                "release": "HOLD", "production_release_enabled": False}

    def confirm(self, *, challenge, session_assertion, verify_session, trusted_now,
                verify_owner, verify_trusted_date):
        """One explicit review acknowledgment; consumes challenge after v25 commit.

        A crash between v25 insert and challenge consumption fails closed on
        replay because v25 permits only one review/day. No execution capability.
        """
        if type(challenge) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", challenge):
            raise GatewayError("INVALID_CHALLENGE")
        digest = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        now = _trusted_seconds(trusted_now)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT owner_id,day,verdict,evidence_ref,snapshot_sha256,"
                    "issued_at,expires_at,consumed_at FROM owner_challenges "
                    "WHERE token_sha256=?", (digest,)).fetchone()
                if row is None:
                    raise GatewayError("UNKNOWN_CHALLENGE")
                owner_id, day, verdict, evidence_ref, snap, issued, expires, consumed = row
                if consumed is not None:
                    raise GatewayError("CHALLENGE_ALREADY_USED")
                if now < issued or now >= expires:
                    raise GatewayError("CHALLENGE_EXPIRED")
                if datetime.fromtimestamp(now, tz=timezone.utc).date().isoformat() != day:
                    raise GatewayError("TRUSTED_DATE_MISMATCH")
                fresh_owner = _owner(
                    verify_session, session_assertion, "OWNER_REVIEW", day)
                if fresh_owner != owner_id:
                    raise GatewayError("SESSION_IDENTITY_CHANGED")
                if not callable(verify_owner) or not callable(verify_trusted_date):
                    raise GatewayError("EXTERNAL_TRUST_REQUIRED")
                result = self.cockpit.record(
                    day=day, verdict=verdict, owner_id=owner_id,
                    evidence_ref=evidence_ref, expected_snapshot_sha256=snap,
                    verify_owner=verify_owner,
                    verify_trusted_date=verify_trusted_date)
                if (type(result) is not dict or result.get("action_executed") is not False
                        or result.get("authorization") != "DENY" or
                        result.get("release") != "HOLD" or
                        result.get("production_release_enabled") is not False):
                    raise GatewayError("UNSAFE_REVIEW_RESULT")
                db.execute(
                    "UPDATE owner_challenges SET consumed_at=? "
                    "WHERE token_sha256=? AND consumed_at IS NULL",
                    (now, digest))
                db.commit()
                return {"schema": "palaco-owner-decision-confirmation/v27",
                        "day": day, "verdict": verdict,
                        "review_sha256": result["review_sha256"],
                        "action_executed": False, "authorization": "DENY",
                        "release": "HOLD", "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise
