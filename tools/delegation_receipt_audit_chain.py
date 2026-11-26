#!/usr/bin/env python3
"""Atomic local audit chain for offline delegation-evidence receipt claims.

The receipt index and audit chain are cross-checked on each append and on
read-only inspection. A separately authenticated head/count is REQUIRED for
rollback detection. Local SQLite is not a remote immutable evidence service.
"""
import hashlib
import json
import re
import sqlite3
from pathlib import Path

DOMAIN = b"PALACO-DELEGATION-RECEIPT-AUDIT-V1\x00"
GENESIS = "0" * 64
HEX = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
IDENT = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
MAX_EVENTS = 100000


def _out(**kw):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "automatic_restore": False, "recovery_approved": False,
            "state": "quarantined", **kw}


def _event_hash(seq, receipt_id, recipient_key_id, recipient_id,
                package_sha256, receipt_sha256, previous):
    raw = json.dumps([seq, receipt_id, recipient_key_id, recipient_id,
                      package_sha256, receipt_sha256, previous],
                     ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(DOMAIN + raw).hexdigest()


def schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS delegation_receipt_audit (
        sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
        receipt_id TEXT NOT NULL UNIQUE,
        recipient_key_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        package_sha256 TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
    )""")


def _rows(conn):
    indexed = conn.execute("""SELECT receipt_id, recipient_key_id,
        recipient_id, package_sha256, receipt_sha256
        FROM delegation_handoff_receipts LIMIT ?""", (MAX_EVENTS + 1,)).fetchall()
    chained = conn.execute("""SELECT sequence, receipt_id, recipient_key_id,
        recipient_id, package_sha256, receipt_sha256,
        previous_hash, event_hash
        FROM delegation_receipt_audit ORDER BY sequence LIMIT ?""",
        (MAX_EVENTS + 1,)).fetchall()
    return indexed, chained


def _validate(indexed, chained):
    if len(indexed) != len(chained) or len(chained) > MAX_EVENTS:
        return None
    previous = GENESIS
    seen = set()
    for sequence, row in enumerate(chained, 1):
        number, ident, key, recipient, package, digest, prior, event = row
        if (type(number) is not int or number != sequence
            or not isinstance(ident, str) or not NONCE.fullmatch(ident)
            or not isinstance(recipient, str) or not IDENT.fullmatch(recipient)
            or any(not isinstance(x, str) or not HEX.fullmatch(x)
                   for x in (key, package, digest))
            or prior != previous
            or event != _event_hash(number, ident, key, recipient,
                                    package, digest, prior)):
            return None
        seen.add((ident, key, recipient, package, digest))
        previous = event
    if len(seen) != len(chained) or set(indexed) != seen:
        return None
    return {"entries": len(chained), "head_hash": previous}


def append(conn, receipt_id, recipient_key_id, recipient_id,
           package_sha256, receipt_sha256):
    """Append BEFORE inserting the matching index row, under BEGIN IMMEDIATE."""
    if not conn.in_transaction:
        raise ValueError("active transaction required")
    if (not isinstance(receipt_id, str) or not NONCE.fullmatch(receipt_id)
        or not isinstance(recipient_id, str) or not IDENT.fullmatch(recipient_id)
        or any(not isinstance(x, str) or not HEX.fullmatch(x)
               for x in (recipient_key_id, package_sha256, receipt_sha256))):
        raise ValueError("invalid-delegation-receipt-event")
    schema(conn)
    state = _validate(*_rows(conn))
    if state is None:
        raise ValueError("delegation-receipt-audit-integrity-failed")
    if state["entries"] >= MAX_EVENTS:
        raise ValueError("delegation-receipt-audit-full")
    sequence = state["entries"] + 1
    previous = state["head_hash"]
    event = _event_hash(sequence, receipt_id, recipient_key_id, recipient_id,
                        package_sha256, receipt_sha256, previous)
    conn.execute("INSERT INTO delegation_receipt_audit VALUES(?,?,?,?,?,?,?,?)",
                 (sequence, receipt_id, recipient_key_id, recipient_id,
                  package_sha256, receipt_sha256, previous, event))
    return {"entries": sequence, "head_hash": event}


def inspect(db, expected_head, minimum_entries):
    """Read-only: trust anchors must come from a different authenticated channel."""
    if (not isinstance(expected_head, str) or not HEX.fullmatch(expected_head)
        or type(minimum_entries) is not int or not 1 <= minimum_entries <= MAX_EVENTS):
        return _out(chain_valid=False, reason="missing-independent-audit-pin")
    if not isinstance(db, (str, Path)) or not Path(db).is_file():
        return _out(chain_valid=False, reason="missing-receipt-register")
    try:
        conn = sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("BEGIN")
            state = _validate(*_rows(conn))
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return _out(chain_valid=False, reason="unreadable-receipt-audit")
    if state is None or state["entries"] == 0:
        return _out(chain_valid=False, reason="receipt-audit-integrity-failed")
    if state["entries"] < minimum_entries:
        return _out(chain_valid=False, reason="receipt-audit-rollback")
    if state["head_hash"] != expected_head:
        return _out(chain_valid=False, reason="receipt-audit-head-mismatch")
    return _out(chain_valid=True, state="pending-review",
                reason="local-receipt-audit-matches-external-pin-no-authority",
                **state)
