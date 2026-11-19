"""PALACO v25 Recovery Operations Cockpit: read-only view + review ledger.

Owner JA/NEE is a NON-AUTHORIZING acknowledgment, never an instruction to
run v24.run_once, issue a key, restore data or release a system. Dashboard data
is local self-reported metadata, NOT an independently verified trust result.
"""
from contextlib import closing
from datetime import date
import hashlib
from html import escape
import json
from pathlib import Path
import re
import sqlite3

from offline_stage import _canonical

SCHEMA = "palaco-recovery-operations-cockpit/v25"
REVIEW_SCHEMA = "palaco-recovery-operations-review/v25"
HASH_DOMAIN = b"PALACO-RECOVERY-OPERATIONS-v25:SNAPSHOT\x00"
REVIEW_DOMAIN = b"PALACO-RECOVERY-OPERATIONS-v25:REVIEW\x00"
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
STATES = frozenset((
    "NO_PENDING", "READY", "RETRYABLE", "BLOCKED", "EXHAUSTED"
))
REVIEW_VALUES = frozenset(("JA", "NEE"))


class CockpitError(ValueError):
    pass


def _validate(report):
    """Strict, untrusted, redacted v24 inspection format."""
    if type(report) is not dict or set(report) != {
        "schema", "target_sequence", "pending", "attempts", "max_attempts",
        "state", "last_error", "authorization", "release",
        "production_release_enabled"
    } or report["schema"] != "palaco-recovery-supervisor-inspection/v24":
        raise CockpitError("INVALID_SOURCE_REPORT")
    if (type(report["pending"]) is not bool or
            type(report["attempts"]) is not int or report["attempts"] < 0 or
            type(report["max_attempts"]) is not int or not 1 <= report["max_attempts"] <= 10 or
            report["attempts"] > report["max_attempts"] or
            type(report["state"]) is not str or report["state"] not in STATES or
            report["authorization"] != "DENY" or
            report["release"] != "HOLD" or
            report["production_release_enabled"] is not False):
        raise CockpitError("UNSAFE_SOURCE_REPORT")
    if ((report["pending"] and (type(report["target_sequence"]) is not int or
                                 report["target_sequence"] < 1 or
                                 report["state"] == "NO_PENDING")) or
            (not report["pending"] and (report["target_sequence"] is not None or
                                        report["state"] != "NO_PENDING"))):
        raise CockpitError("INCONSISTENT_SOURCE")
    code = report["last_error"]
    if code is not None and (
            type(code) is not str or not re.fullmatch(r"[A-Z0-9_]{1,80}", code)):
        raise CockpitError("INVALID_ERROR_CODE")


def snapshot(supervisor):
    """Pure diagnostic derived from live read-only v24 inspect() only."""
    if not callable(getattr(supervisor, "inspect", None)):
        raise CockpitError("INVALID_SUPERVISOR")
    try:
        report = supervisor.inspect()
    except Exception as exc:
        raise CockpitError("SOURCE_UNAVAILABLE") from exc
    _validate(report)
    state = report["state"]
    result = {
        "schema": SCHEMA, "status": state,
        "target_sequence": report["target_sequence"],
        "pending": report["pending"],
        "attempts": report["attempts"],
        "max_attempts": report["max_attempts"],
        "last_error": report["last_error"],
        "requires_independent_trust": True,
        "owner_review_recorded": False,
        "operations_enabled": False,
        "authorization": "DENY", "release": "HOLD",
        "production_release_enabled": False,
    }
    result["snapshot_sha256"] = hashlib.sha256(
        HASH_DOMAIN + _canonical(result)).hexdigest()
    return result


def _snapshot_check(value):
    if type(value) is not dict or set(value) != {
        "schema", "status", "target_sequence", "pending", "attempts",
        "max_attempts", "last_error", "requires_independent_trust",
        "owner_review_recorded", "operations_enabled", "authorization",
        "release", "production_release_enabled", "snapshot_sha256"
    } or value["schema"] != SCHEMA:
        raise CockpitError("INVALID_SNAPSHOT")
    digest = value["snapshot_sha256"]
    if type(digest) is not str or not HEX.fullmatch(digest):
        raise CockpitError("INVALID_SNAPSHOT_HASH")
    without_digest = {key: v for key, v in value.items() if key != "snapshot_sha256"}
    expected = hashlib.sha256(HASH_DOMAIN + _canonical(without_digest)).hexdigest()
    if digest != expected or value["authorization"] != "DENY" or (
            value["release"] != "HOLD" or value["production_release_enabled"] is not False or
            value["operations_enabled"] is not False or
            value["requires_independent_trust"] is not True or
            value["owner_review_recorded"] is not False):
        raise CockpitError("UNSAFE_SNAPSHOT")


def render_html(value):
    """Standalone static, offline-friendly, HTML-escaped *read-only* dashboard."""
    _snapshot_check(value)
    fields = (
        ("Herstelstatus", value["status"]),
        ("Openstaand", "JA" if value["pending"] else "NEE"),
        ("Checkpoint", value["target_sequence"] if value["pending"] else "Geen"),
        ("Pogingen", str(value["attempts"]) + " / " + str(value["max_attempts"])),
        ("Laatste foutcode", value["last_error"] or "Geen"),
        ("Productieautorisatie", "DENY / HOLD"),
    )
    cells = "".join(
        "<tr><th scope='row'>" + escape(str(k)) +
        "</th><td>" + escape(str(v)) + "</td></tr>" for k, v in fields)
    return (
        "<!doctype html><html lang='nl'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>PALACO — Recovery Operations v25</title>"
        "<style>body{font:16px system-ui;background:#071e18;color:#e9e3cb;"
        "margin:0;padding:2rem;max-width:820px}h1{color:#d5b76f}"
        "table{width:100%;border-collapse:collapse}th,td{padding:1rem;"
        "border-bottom:1px solid #647464;text-align:left}footer{margin-top:2rem;"
        "color:#f1c881}</style></head><body>"
        "<h1>PALACO · Recovery Operations</h1>"
        "<p>Alleen inzage — lokale diagnose, geen vertrouwensbewijs.</p>"
        "<table><caption>Checkpointoverzicht</caption>" + cells + "</table>"
        "<footer>GO-13 HOLD · JA/NEE is alleen een beoordelingsregistratie; "
        "geen herstel, publicatie of autorisatie.</footer></body></html>"
    )


class OwnerReviewLedger:
    """One owner acknowledgment per calendar date (Mon-Sat). No action hooks.

    verify_owner(owner_id, day, verdict, snapshot_sha256, evidence_ref)
    MUST authenticate an active owner and permission *independently*, with
    current revocation and trusted date, before returning literal True.
    These requirements are not implemented in this local prototype.
    """

    def __init__(self, path):
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise CockpitError("INVALID_LEDGER_PATH")
        self.path = str(target)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cockpit_owner_reviews (
                    day TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK(verdict IN ('JA','NEE')),
                    snapshot_sha256 TEXT NOT NULL,
                    evidence_ref TEXT NOT NULL,
                    review_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS owner_reviews_no_update
                    BEFORE UPDATE ON cockpit_owner_reviews
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS owner_reviews_no_delete
                    BEFORE DELETE ON cockpit_owner_reviews
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def record(self, value, *, day, verdict, owner_id, evidence_ref,
               verify_owner, verify_trusted_date):
        """Log one JA/NEE, never invoke reconciliation or any production action."""
        _snapshot_check(value)
        if type(day) is not str:
            raise CockpitError("INVALID_DATE")
        try:
            parsed = date.fromisoformat(day)
        except ValueError as exc:
            raise CockpitError("INVALID_DATE") from exc
        if parsed.isoformat() != day or parsed.weekday() == 6:
            raise CockpitError("NON_WORKDAY_OR_INVALID_DATE")
        if type(verdict) is not str or verdict not in REVIEW_VALUES:
            raise CockpitError("INVALID_VERDICT")
        if (type(owner_id) is not str or not ID.fullmatch(owner_id) or
                type(evidence_ref) is not str or not ID.fullmatch(evidence_ref)):
            raise CockpitError("INVALID_REVIEW_IDENTITY")
        if not callable(verify_owner) or not callable(verify_trusted_date):
            raise CockpitError("EXTERNAL_TRUST_REQUIRED")
        try:
            if verify_trusted_date(day) is not True:
                raise CockpitError("UNTRUSTED_DATE")
            if verify_owner(owner_id, day, verdict,
                            value["snapshot_sha256"], evidence_ref) is not True:
                raise CockpitError("OWNER_NOT_VERIFIED")
        except CockpitError:
            raise
        except Exception as exc:
            raise CockpitError("TRUST_PROVIDER_UNAVAILABLE") from exc
        statement = {
            "schema": REVIEW_SCHEMA, "day": day, "verdict": verdict,
            "owner_id": owner_id, "evidence_ref": evidence_ref,
            "snapshot_sha256": value["snapshot_sha256"],
        }
        digest = hashlib.sha256(REVIEW_DOMAIN + _canonical(statement)).hexdigest()
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO cockpit_owner_reviews(day,owner_id,verdict,"
                        "snapshot_sha256,evidence_ref,review_sha256) VALUES(?,?,?,?,?,?)",
                        (day, owner_id, verdict, value["snapshot_sha256"],
                         evidence_ref, digest))
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
        except sqlite3.IntegrityError as exc:
            raise CockpitError("ALREADY_REVIEWED_FOR_DAY") from exc
        return {"schema": "palaco-owner-review-result/v25",
                "day": day, "verdict": verdict, "review_sha256": digest,
                "action_executed": False, "authorization": "DENY",
                "release": "HOLD", "production_release_enabled": False}

    def read(self, *, day):
        if type(day) is not str:
            raise CockpitError("INVALID_DATE")
        try:
            if date.fromisoformat(day).isoformat() != day:
                raise ValueError("format")
        except ValueError as exc:
            raise CockpitError("INVALID_DATE") from exc
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT owner_id,verdict,snapshot_sha256,evidence_ref,review_sha256 "
                "FROM cockpit_owner_reviews WHERE day=?", (day,)).fetchone()
        if row is None:
            return None
        owner, verdict, snap, evidence, digest = row
        expected = hashlib.sha256(REVIEW_DOMAIN + _canonical({
            "schema": REVIEW_SCHEMA, "day": day, "owner_id": owner,
            "verdict": verdict, "snapshot_sha256": snap,
            "evidence_ref": evidence,
        })).hexdigest()
        if digest != expected:
            raise CockpitError("CORRUPT_OWNER_REVIEW")
        return {"day": day, "verdict": verdict, "snapshot_sha256": snap,
                "review_sha256": digest, "authorization": "DENY",
                "release": "HOLD", "action_executed": False}
