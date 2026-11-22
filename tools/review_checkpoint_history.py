#!/usr/bin/env python3
"""Locally chained history of signed review-register checkpoints; HOLD only.

The local history file is mutable/replayable. External head/minimum are required
for independent rollback detection; no remote witness is implemented.
"""
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "palaco_review_history_checkpoint", Path(__file__).with_name("signed_review_register_checkpoint.py"))
checkpoint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checkpoint)

GENESIS = "0" * 64
MAX_HISTORY = 100000


def _hash(issuer, ordinal, count, rows_sha, previous):
    body = {"issuer": issuer, "ordinal": ordinal, "count": count,
            "rows_sha256": rows_sha, "previous": previous}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"PALACO-REVIEW-CHECKPOINT-HISTORY-V1\x00" + canonical).hexdigest()


def _schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS review_checkpoint_history(
            issuer_key_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL CHECK(ordinal > 0),
            record_count INTEGER NOT NULL CHECK(record_count > 0),
            rows_sha256 TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            PRIMARY KEY(issuer_key_id, ordinal),
            UNIQUE(issuer_key_id, record_count)
        )
    """)


def _read_rows(conn, issuer):
    return conn.execute("""
        SELECT ordinal,record_count,rows_sha256,previous_hash,event_hash
        FROM review_checkpoint_history WHERE issuer_key_id=?
        ORDER BY ordinal
    """, (issuer,)).fetchall()


def _validate_rows(issuer, rows):
    prior = GENESIS
    if len(rows) > MAX_HISTORY:
        return None
    old_count = 0
    for ordinal, (seq, count, sha, prev, event_hash) in enumerate(rows, 1):
        if (type(seq) is not int or seq != ordinal or type(count) is not int
            or count <= old_count or not isinstance(sha, str)
            or not checkpoint.HEX.fullmatch(sha) or prev != prior
            or event_hash != _hash(issuer, seq, count, sha, prev)):
            return None
        old_count, prior = count, event_hash
    return {"entries": len(rows), "count": old_count, "head_hash": prior}


def observe(history_db, review_db, signed_checkpoint, roots, revoked, minimum_count):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "state": "quarantined", "history_updated": False}
    def deny(reason):
        return {**base, "reason": reason}
    if (not isinstance(history_db, (str, Path)) or str(history_db) == ":memory:"
        or Path(history_db).resolve() == Path(review_db).resolve()):
        raise ValueError("separate persistent history database required")
    verified = checkpoint.verify(review_db, signed_checkpoint, roots, revoked, minimum_count)
    if not verified["checkpoint_valid"]:
        return deny(verified["reason"])
    issuer = signed_checkpoint["issuer_key_id"]
    count, sha = verified["count"], verified["rows_sha256"]
    conn = sqlite3.connect(str(history_db), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        rows = _read_rows(conn, issuer)
        current = _validate_rows(issuer, rows)
        if current is None:
            conn.rollback()
            return deny("history-integrity-failed")
        if rows:
            old_count = current["count"]
            if count < old_count:
                conn.rollback()
                return deny("history-rollback")
            if count == old_count:
                conn.rollback()
                if rows[-1][2] != sha:
                    return deny("history-equivocation")
                return {**base, "state": "pending-review", "reason": "already-observed",
                        "head_hash": current["head_hash"]}
        if len(rows) >= MAX_HISTORY:
            conn.rollback()
            return deny("history-limit-reached")
        ordinal, previous = len(rows) + 1, current["head_hash"]
        event_hash = _hash(issuer, ordinal, count, sha, previous)
        conn.execute("""
            INSERT INTO review_checkpoint_history
              (issuer_key_id,ordinal,record_count,rows_sha256,previous_hash,event_hash)
            VALUES(?,?,?,?,?,?)
        """, (issuer, ordinal, count, sha, previous, event_hash))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {**base, "state": "pending-review", "reason": "local-history-only-unanchored",
            "history_updated": True, "head_hash": event_hash}


def inspect(history_db, issuer, expected_head, minimum_entries):
    """Read-only local chain verification with caller-authenticated head/floor."""
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "history_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if (not isinstance(issuer, str) or not checkpoint.HEX.fullmatch(issuer)
        or not isinstance(expected_head, str) or not checkpoint.HEX.fullmatch(expected_head)
        or type(minimum_entries) is not int or minimum_entries < 1):
        return deny("missing-trusted-history-anchor")
    if not isinstance(history_db, (str, Path)) or not Path(history_db).is_file():
        return deny("missing-history-db")
    try:
        conn = sqlite3.connect(Path(history_db).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("BEGIN")
            rows = _read_rows(conn, issuer)
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return deny("history-unreadable")
    result = _validate_rows(issuer, rows)
    if result is None or result["entries"] == 0:
        return deny("history-integrity-failed")
    if result["entries"] < minimum_entries:
        return deny("history-rollback")
    if result["head_hash"] != expected_head:
        return deny("external-history-head-mismatch")
    return {**base, "history_valid": True, "state": "pending-review",
            "reason": "history-matches-caller-anchor-authority-unverified",
            **result}
