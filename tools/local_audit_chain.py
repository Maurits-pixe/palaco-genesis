#!/usr/bin/env python3
"""Local SHA-256 chained audit for a single SQLite file; HOLD only.

NOT externally anchored, independently timestamped or tamper-proof: an attacker
who can edit the SQLite file can recompute hashes and delete the chain.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

GENESIS = "0" * 64
MAX_EVENTS = 1000000
EVENT_TYPES = {"registry-revision", "candidate-indexed"}


def _canonical(event):
    return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _hash(seq, prev, kind, subject, detail):
    record = {"sequence": seq, "previous_hash": prev, "event_type": kind,
              "subject": subject, "detail": detail}
    return hashlib.sha256(b"PALACO-LOCAL-AUDIT-V1\x00" + _canonical(record)).hexdigest()


def _schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS local_audit_chain(
            sequence INTEGER PRIMARY KEY,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            event_type TEXT NOT NULL,
            subject TEXT NOT NULL,
            detail TEXT NOT NULL
        )
    """)


def append(conn, kind, subject, detail):
    """Append inside caller's active transaction (does not commit).

    Subject and detail must be bounded public metadata only, not raw evidence.
    """
    if not conn.in_transaction:
        raise ValueError("active transaction required")
    if kind not in EVENT_TYPES or not isinstance(subject, str) or not subject or len(subject) > 128:
        raise ValueError("invalid audit event")
    if not isinstance(detail, str) or not detail or len(detail) > 128:
        raise ValueError("invalid audit detail")
    _schema(conn)
    row = conn.execute(
        "SELECT sequence, event_hash FROM local_audit_chain ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
    if seq > MAX_EVENTS:
        raise ValueError("audit chain event limit exceeded")
    digest = _hash(seq, prev, kind, subject, detail)
    conn.execute(
        "INSERT INTO local_audit_chain(sequence,previous_hash,event_hash,event_type,subject,detail) VALUES (?,?,?,?,?,?)",
        (seq, prev, digest, kind, subject, detail),
    )
    return {"sequence": seq, "head_hash": digest}


def verify(database, expected_head=None):
    """Read-only chain check; optional expected head must be externally trusted.

    An internal self-consistency PASS is not attestation or rollback proof.
    """
    fail = lambda reason: {"chain_valid": False, "release_gate": "HOLD",
                           "authorization_granted": False, "reason": reason}
    if expected_head is not None and (
        not isinstance(expected_head, str) or len(expected_head) != 64 or
        any(c not in "0123456789abcdef" for c in expected_head)
    ):
        return fail("invalid-expected-head")
    if not isinstance(database, (str, Path)) or not Path(database).is_file():
        return fail("missing-database")
    try:
        conn = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            try:
                rows = conn.execute(
                    "SELECT sequence,previous_hash,event_hash,event_type,subject,detail FROM local_audit_chain ORDER BY sequence"
                ).fetchall()
            except sqlite3.OperationalError:
                return fail("missing-audit-table")
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return fail("unreadable-database")
    if not rows:
        return fail("empty-audit-chain")
    if len(rows) > MAX_EVENTS:
        return fail("audit-limit-exceeded")
    previous = GENESIS
    for position, row in enumerate(rows, start=1):
        seq, prev, actual, kind, subject, detail = row
        if seq != position or prev != previous or kind not in EVENT_TYPES:
            return fail("audit-sequence-break")
        try:
            calculated = _hash(seq, prev, kind, subject, detail)
        except (TypeError, ValueError, OverflowError):
            return fail("malformed-audit-event")
        if actual != calculated:
            return fail("audit-hash-mismatch")
        previous = calculated
    if expected_head is not None and previous != expected_head:
        return fail("external-head-mismatch")
    return {"chain_valid": True, "release_gate": "HOLD", "authorization_granted": False,
            "events_checked": len(rows), "head_hash": previous,
            "reason": "local-consistency-only-not-authenticated"}
