#!/usr/bin/env python3
"""Atomic, locally chained index of independently signed custody statements.

A signature is an authenticated claim, not evidence of actual off-device
custody. Database rollback resistance requires an independently pinned head.
No issuing, publication, release, restoration or external network access.
"""
import hashlib
import importlib.util
import json
import re
import sqlite3
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "palaco_custody_ledger_signature", Path(__file__).with_name("signed_custody_statement.py"))
statements = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(statements)

DOMAIN = b"PALACO-CUSTODY-STATEMENT-LEDGER-V1\x00"
GENESIS = "0" * 64
HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_ENTRIES = 100000


def _result(**values):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "state": "quarantined", **values}


def _hash(seq, ident, custodian, key, envelope_hash, policy_hash,
          anchor_hash, receipt_entries, chain_head, previous):
    record = [seq, ident, custodian, key, envelope_hash, policy_hash,
              anchor_hash, receipt_entries, chain_head, previous]
    return hashlib.sha256(DOMAIN + json.dumps(record, separators=(",", ":")).encode()).hexdigest()


def _schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS observed_custody_statements (
            statement_id TEXT PRIMARY KEY,
            custodian_id TEXT NOT NULL,
            custodian_key_id TEXT NOT NULL,
            envelope_sha256 TEXT NOT NULL UNIQUE,
            policy_sha256 TEXT NOT NULL,
            anchor_sha256 TEXT NOT NULL,
            receipt_entries INTEGER NOT NULL,
            receipt_head_sha256 TEXT NOT NULL,
            UNIQUE(custodian_id, anchor_sha256)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custody_statement_chain (
            sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
            statement_id TEXT NOT NULL UNIQUE,
            custodian_id TEXT NOT NULL,
            custodian_key_id TEXT NOT NULL,
            envelope_sha256 TEXT NOT NULL,
            policy_sha256 TEXT NOT NULL,
            anchor_sha256 TEXT NOT NULL,
            receipt_entries INTEGER NOT NULL,
            receipt_head_sha256 TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )
    """)


def _validate(index, events):
    if len(index) != len(events) or len(events) > MAX_ENTRIES:
        return None
    if not events:
        return {"entries": 0, "head_hash": GENESIS}
    if len(set(index)) != len(index):
        return None
    observed = set()
    previous = GENESIS
    latest_by_custodian = {}
    for number, row in enumerate(events, 1):
        (seq, ident, custodian, key, envelope, policy, anchor,
         count, head, prev, event_hash) = row
        if (type(seq) is not int or seq != number or prev != previous
            or not isinstance(ident, str) or not statements.STATEMENT_ID.fullmatch(ident)
            or not isinstance(custodian, str) or not statements.ID.fullmatch(custodian)
            or any(not isinstance(x, str) or not HEX.fullmatch(x)
                   for x in (key, envelope, policy, anchor, head))
            or type(count) is not int or count < 1 or count > MAX_ENTRIES):
            return None
        if event_hash != _hash(seq, ident, custodian, key, envelope, policy,
                               anchor, count, head, prev):
            return None
        old = latest_by_custodian.get(custodian)
        if old is not None and count <= old:
            return None
        latest_by_custodian[custodian] = count
        observed.add((ident, custodian, key, envelope, policy, anchor, count, head))
        previous = event_hash
    if observed != set(index) or len(observed) != len(events):
        return None
    return {"entries": len(events), "head_hash": previous}


def _rows(conn):
    index = conn.execute("""SELECT statement_id,custodian_id,custodian_key_id,
        envelope_sha256,policy_sha256,anchor_sha256,receipt_entries,receipt_head_sha256
        FROM observed_custody_statements""").fetchall()
    events = conn.execute("""SELECT sequence,statement_id,custodian_id,custodian_key_id,
        envelope_sha256,policy_sha256,anchor_sha256,receipt_entries,receipt_head_sha256,
        previous_hash,event_hash FROM custody_statement_chain ORDER BY sequence
        LIMIT ?""", (MAX_ENTRIES + 1,)).fetchall()
    return index, events


def record(ledger_db, receipt_db, signed_anchor, signed_policy, signed_statement,
           expected_custodian_id, trusted_custodian_key_ids, custodian_keys,
           revoked_custodians, governance_roots, revoked_governance,
           witness_roots, revoked_witnesses, minimum_policy_revision,
           minimum_external_events):
    """Verify the full signature/policy/receipt chain before BEGIN IMMEDIATE.

    Neither the validated receipt database nor the external trust policy is
    protected from subsequent changes; re-verify them for every use.
    """
    if (not isinstance(ledger_db, (str, Path)) or str(ledger_db) == ":memory:"
        or not isinstance(receipt_db, (str, Path))
        or Path(ledger_db).resolve() == Path(receipt_db).resolve()):
        raise ValueError("distinct persistent custody ledger path required")
    verdict = statements.verify(
        receipt_db, signed_anchor, signed_policy, signed_statement,
        expected_custodian_id, trusted_custodian_key_ids, custodian_keys,
        revoked_custodians, governance_roots, revoked_governance,
        witness_roots, revoked_witnesses, minimum_policy_revision,
        minimum_external_events)
    if not verdict["custody_statement_valid"]:
        return _result(recorded=False, reason=verdict["reason"])
    body = signed_statement["statement"]
    ident, custodian, key = body["statement_id"], body["custodian_id"], signed_statement["custodian_key_id"]
    envelope_hash = statements.digest(b"PALACO-CUSTODY-STATEMENT-ENVELOPE-V1\x00", signed_statement)
    policy_hash, anchor_hash = body["policy_envelope_sha256"], body["anchor_envelope_sha256"]
    count, head = body["receipt_entries"], body["receipt_head_sha256"]
    conn = sqlite3.connect(str(ledger_db), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        index, events = _rows(conn)
        state = _validate(index, events)
        if state is None:
            conn.rollback()
            return _result(recorded=False, reason="custody-ledger-integrity-failed")
        prior = next((x for x in index if x[0] == ident), None)
        if prior is not None:
            conn.rollback()
            reason = "custody-statement-replay" if prior[3] == envelope_hash else "custody-statement-id-conflict"
            return _result(recorded=False, reason=reason)
        earlier = [x for x in index if x[1] == custodian]
        if any(x[5] == anchor_hash for x in earlier):
            conn.rollback()
            return _result(recorded=False, reason="custody-anchor-replay")
        if earlier and count <= max(x[6] for x in earlier):
            conn.rollback()
            return _result(recorded=False, reason="custody-history-stale-or-equivocated")
        if state["entries"] >= MAX_ENTRIES:
            conn.rollback()
            return _result(recorded=False, reason="custody-ledger-limit")
        seq, previous = state["entries"] + 1, state["head_hash"]
        event_hash = _hash(seq, ident, custodian, key, envelope_hash,
                           policy_hash, anchor_hash, count, head, previous)
        conn.execute("""INSERT INTO observed_custody_statements VALUES (?,?,?,?,?,?,?,?)""",
                     (ident, custodian, key, envelope_hash, policy_hash, anchor_hash, count, head))
        conn.execute("""INSERT INTO custody_statement_chain VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                     (seq, ident, custodian, key, envelope_hash, policy_hash,
                      anchor_hash, count, head, previous, event_hash))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _result(recorded=True, state="pending-review",
                   reason="local-custody-claim-indexed-no-authority",
                   entries=seq, head_hash=event_hash)


def inspect(ledger_db, expected_head, minimum_entries):
    """Read-only chain/index consistency and externally pinned head check."""
    if (not isinstance(expected_head, str) or not HEX.fullmatch(expected_head)
        or type(minimum_entries) is not int or not 1 <= minimum_entries <= MAX_ENTRIES):
        return _result(chain_valid=False, reason="missing-independent-ledger-anchor")
    if not isinstance(ledger_db, (str, Path)) or not Path(ledger_db).is_file():
        return _result(chain_valid=False, reason="missing-custody-ledger")
    try:
        conn = sqlite3.connect(Path(ledger_db).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("BEGIN")
            index, events = _rows(conn)
            conn.commit()
        finally:
            conn.close()
    except (OSError, ValueError, sqlite3.Error):
        return _result(chain_valid=False, reason="unreadable-custody-ledger")
    state = _validate(index, events)
    if state is None or state["entries"] == 0:
        return _result(chain_valid=False, reason="custody-ledger-integrity-failed")
    if state["entries"] < minimum_entries:
        return _result(chain_valid=False, reason="custody-ledger-rollback")
    if state["head_hash"] != expected_head:
        return _result(chain_valid=False, reason="custody-ledger-head-mismatch")
    return _result(chain_valid=True, state="pending-review",
                   reason="local-chain-matches-external-head-no-authority", **state)
