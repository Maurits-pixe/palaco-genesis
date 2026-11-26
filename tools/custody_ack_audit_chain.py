#!/usr/bin/env python3
"""Transactional hash chain for custody-anchor acknowledgements (HOLD only).

An externally authenticated head and minimum count are required for rollback
detection. Neither the local register nor this hash chain is immutable storage.
"""
import hashlib
import json
import re
import sqlite3
from pathlib import Path

DOMAIN = b"PALACO-CUSTODY-ACK-AUDIT-V1\x00"
HEX = re.compile(r"^[0-9a-f]{64}$")
RECEIPT = re.compile(r"^[0-9a-f]{32}$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
GENESIS = "0" * 64
MAX_EVENTS = 100000


def _out(**kw):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "state": "quarantined", **kw}


def _hash(sequence, receipt, key, recipient, package, digest, previous):
    raw = json.dumps([sequence, receipt, key, recipient, package, digest, previous],
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(DOMAIN + raw).hexdigest()


def schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS custody_ack_audit_chain (
        sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
        receipt_id TEXT NOT NULL UNIQUE,
        custodian_key_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        package_sha256 TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
    )""")


def _read(conn):
    index = conn.execute("""SELECT receipt_id,custodian_key_id,recipient_id,
        package_sha256,receipt_sha256 FROM custody_anchor_acknowledgements""").fetchall()
    chain = conn.execute("""SELECT sequence,receipt_id,custodian_key_id,
        recipient_id,package_sha256,receipt_sha256,previous_hash,event_hash
        FROM custody_ack_audit_chain ORDER BY sequence LIMIT ?""",
        (MAX_EVENTS+1,)).fetchall()
    return index, chain


def _validate(index, chain):
    if len(chain) > MAX_EVENTS or len(index) != len(chain):
        return None
    previous = GENESIS
    seen = set()
    for position, row in enumerate(chain, 1):
        seq, receipt, key, recipient, package, digest, prior, value = row
        if (type(seq) is not int or seq != position or prior != previous
            or not isinstance(receipt, str) or not RECEIPT.fullmatch(receipt)
            or not isinstance(recipient, str) or not IDENT.fullmatch(recipient)
            or any(not isinstance(x, str) or not HEX.fullmatch(x)
                   for x in (key,package,digest))
            or value != _hash(seq, receipt, key, recipient, package, digest, prior)):
            return None
        seen.add((receipt,key,recipient,package,digest))
        previous = value
    if len(seen) != len(chain) or set(index) != seen:
        return None
    return {"entries": len(chain), "head_hash": previous}


def append(conn, receipt, key, recipient, package, digest):
    """Caller must hold BEGIN IMMEDIATE; append alongside acknowledgement."""
    if not conn.in_transaction:
        raise ValueError("active transaction required")
    if (not isinstance(receipt, str) or not RECEIPT.fullmatch(receipt)
        or not isinstance(recipient, str) or not IDENT.fullmatch(recipient)
        or any(not isinstance(x, str) or not HEX.fullmatch(x)
               for x in (key,package,digest))):
        raise ValueError("invalid acknowledgement event")
    schema(conn)
    state = _validate(*_read(conn))
    if state is None:
        raise ValueError("custody ack chain integrity failed")
    if state["entries"] >= MAX_EVENTS:
        raise ValueError("custody ack chain limit")
    sequence = state["entries"] + 1
    previous = state["head_hash"]
    value = _hash(sequence, receipt, key, recipient, package, digest, previous)
    conn.execute("""INSERT INTO custody_ack_audit_chain VALUES(?,?,?,?,?,?,?,?)""",
                 (sequence,receipt,key,recipient,package,digest,previous,value))
    return {"entries":sequence,"head_hash":value}


def inspect(db, expected_head, minimum_events):
    if (not isinstance(expected_head, str) or not HEX.fullmatch(expected_head)
        or type(minimum_events) is not int or not 1 <= minimum_events <= MAX_EVENTS):
        return _out(chain_valid=False,reason="missing-independent-ack-head")
    if not isinstance(db, (str,Path)) or not Path(db).is_file():
        return _out(chain_valid=False,reason="missing-ack-register")
    try:
        conn = sqlite3.connect(Path(db).resolve().as_uri()+"?mode=ro",uri=True)
        try:
            conn.execute("BEGIN")
            state = _validate(*_read(conn))
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error,OSError,ValueError):
        return _out(chain_valid=False,reason="unreadable-ack-register")
    if state is None or state["entries"] == 0:
        return _out(chain_valid=False,reason="ack-chain-integrity-failed")
    if state["entries"] < minimum_events:
        return _out(chain_valid=False,reason="ack-chain-rollback")
    if state["head_hash"] != expected_head:
        return _out(chain_valid=False,reason="ack-chain-head-mismatch")
    return _out(chain_valid=True,state="pending-review",
                reason="local-ack-chain-matched-external-head-no-authority",**state)
