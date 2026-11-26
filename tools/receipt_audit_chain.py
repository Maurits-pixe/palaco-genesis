#!/usr/bin/env python3
"""Local atomic receipt hash chain, anchored only when caller pins its head.

Receipts and chain events share one SQLite transaction. A database owner can
replace both tables; this does not constitute an independent tamper-proof log.
"""
import hashlib
import json
import re
import sqlite3
from pathlib import Path

DOMAIN = b"PALACO-RECEIPT-CHAIN-V1\x00"
GENESIS = "0" * 64
HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_EVENTS = 100000


def _hash(number, receipt_id, bundle, recipient, custodian, digest, previous):
    body = [number, receipt_id, bundle, recipient, custodian, digest, previous]
    encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(DOMAIN + encoded).hexdigest()


def _schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS receipt_audit_chain(
            sequence INTEGER PRIMARY KEY NOT NULL CHECK(sequence >= 1),
            receipt_id TEXT NOT NULL UNIQUE,
            bundle_sha256 TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            custodian_key_id TEXT NOT NULL,
            receipt_digest TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )
    """)


def append(conn, receipt_id, bundle, recipient, custodian, digest):
    """Requires caller's active BEGIN IMMEDIATE and matching receipt INSERT."""
    if not conn.in_transaction:
        raise ValueError("append requires caller transaction")
    if not isinstance(recipient, str) or not 1 <= len(recipient) <= 128:
        raise ValueError("invalid recipient")
    if not isinstance(receipt_id, str) or not re.fullmatch(r"[0-9a-f]{32}", receipt_id):
        raise ValueError("invalid receipt")
    if any(not isinstance(x, str) or not HEX.fullmatch(x) for x in (bundle, custodian, digest)):
        raise ValueError("invalid receipt digest")
    _schema(conn)
    previous = conn.execute(
        "SELECT sequence,event_hash FROM receipt_audit_chain ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    sequence = previous[0] + 1 if previous else 1
    if sequence > MAX_EVENTS:
        raise ValueError("receipt chain limit exceeded")
    previous_hash = previous[1] if previous else GENESIS
    event_hash = _hash(sequence, receipt_id, bundle, recipient, custodian, digest, previous_hash)
    conn.execute("""INSERT INTO receipt_audit_chain
        (sequence,receipt_id,bundle_sha256,recipient_id,custodian_key_id,
         receipt_digest,previous_hash,event_hash)
        VALUES(?,?,?,?,?,?,?,?)""",
        (sequence,receipt_id,bundle,recipient,custodian,digest,previous_hash,event_hash))
    return {"sequence": sequence, "head_hash": event_hash}


def verify(database, expected_head, minimum_events):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "automatic_restore": False, "recovery_approved": False,
            "chain_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(expected_head, str) or not HEX.fullmatch(expected_head) or (
        type(minimum_events) is not int or minimum_events < 1 or minimum_events > MAX_EVENTS
    ):
        return deny("missing-external-chain-anchor")
    if not isinstance(database, (str, Path)) or not Path(database).is_file():
        return deny("missing-receipt-db")
    try:
        conn = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("BEGIN")
            rows = conn.execute("""SELECT sequence,receipt_id,bundle_sha256,recipient_id,
                custodian_key_id,receipt_digest,previous_hash,event_hash
                FROM receipt_audit_chain ORDER BY sequence LIMIT ?""", (MAX_EVENTS + 1,)).fetchall()
            original = conn.execute("""SELECT receipt_id,bundle_sha256,recipient_id,
                custodian_key_id,receipt_digest FROM observed_handoff_receipts""").fetchall()
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return deny("unreadable-receipt-db")
    if not rows or len(rows) > MAX_EVENTS:
        return deny("missing-or-oversized-chain")
    previous = GENESIS
    signatures = set()
    for number, row in enumerate(rows, 1):
        seq, receipt_id, bundle, recipient, custodian, digest, prior, head = row
        if (seq != number or prior != previous
            or not isinstance(receipt_id, str) or not re.fullmatch(r"[0-9a-f]{32}", receipt_id)
            or not isinstance(recipient, str) or not 1 <= len(recipient) <= 128
            or any(not isinstance(x, str) or not HEX.fullmatch(x) for x in (bundle, custodian, digest))
            or head != _hash(number, receipt_id, bundle, recipient, custodian, digest, prior)):
            return deny("receipt-chain-corrupt")
        signatures.add((receipt_id, bundle, recipient, custodian, digest))
        previous = head
    if len(original) != len(rows) or signatures != set(original):
        return deny("receipt-index-chain-mismatch")
    if len(rows) < minimum_events:
        return deny("receipt-history-rollback")
    if previous != expected_head:
        return deny("receipt-chain-head-mismatch")
    return {**base, "chain_valid": True, "state": "pending-review",
            "reason": "locally-consistent-chain-with-external-anchor",
            "entries": len(rows), "head_hash": previous}
