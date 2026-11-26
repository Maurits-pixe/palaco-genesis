#!/usr/bin/env python3
"""Local monotonic signed-checkpoint journal, separate from the evidence DB.

This is NOT an independent externally secured checkpoint repository. Callers
must authenticate issuer roots, revocation status and the minimum sequence.
"""
import hashlib
import importlib.util
import sqlite3
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "palaco_checkpoint_reg", Path(__file__).with_name("signed_audit_checkpoint.py"))
checkpoint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checkpoint)


def record(store, evidence_db, envelope, roots, revoked_issuers, minimum_sequence):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "checkpoint_recorded": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(store, (str, Path)) or str(store) == ":memory:":
        raise ValueError("persistent checkpoint store required")
    if not isinstance(roots, dict) or not isinstance(revoked_issuers, (set, frozenset)):
        return deny("missing-authenticated-policy")
    if any(not isinstance(x, str) or not checkpoint.HEX.fullmatch(x) for x in revoked_issuers):
        return deny("invalid-revocation-policy")
    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= checkpoint.audit.MAX_EVENTS:
        return deny("missing-trusted-sequence-floor")
    if not isinstance(envelope, dict) or set(envelope) != checkpoint.ENVELOPE:
        return deny("invalid-envelope")
    issuer = envelope.get("issuer_key_id")
    if not isinstance(issuer, str) or not checkpoint.HEX.fullmatch(issuer):
        return deny("invalid-issuer-id")
    if issuer in revoked_issuers:
        return deny("checkpoint-issuer-revoked")
    verified = checkpoint.verify_checkpoint(evidence_db, envelope, roots, minimum_sequence)
    if not verified["checkpoint_valid"]:
        return deny(verified["reason"])
    sequence = verified["sequence"]
    head = verified["head_hash"]
    # The issuer may have more than one checkpoint, but each checkpoint may
    # only move forward; never overwrite or accept equivocation at the same seq.
    connection = sqlite3.connect(str(store), timeout=5)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS checkpoint_floor(
                issuer_key_id TEXT PRIMARY KEY NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence >= 1),
                head_hash TEXT NOT NULL CHECK(length(head_hash) = 64),
                checkpoint_digest TEXT NOT NULL CHECK(length(checkpoint_digest) = 64)
            )
        """)
        content_digest = hashlib.sha256(
            checkpoint.canonical_checkpoint(envelope["checkpoint"])
        ).hexdigest()
        existing = connection.execute(
            "SELECT sequence, head_hash, checkpoint_digest FROM checkpoint_floor WHERE issuer_key_id=?",
            (issuer,)
        ).fetchone()
        if existing and sequence < existing[0]:
            connection.rollback()
            return deny("checkpoint-rollback")
        if existing and sequence == existing[0]:
            connection.rollback()
            if existing[1] != head or existing[2] != content_digest:
                return deny("checkpoint-equivocation")
            return {**base, "checkpoint_recorded": True, "state": "pending-review",
                    "reason": "already-observed"}
        connection.execute("""
            INSERT INTO checkpoint_floor(issuer_key_id, sequence, head_hash, checkpoint_digest)
            VALUES(?,?,?,?)
            ON CONFLICT(issuer_key_id) DO UPDATE SET
                sequence=excluded.sequence, head_hash=excluded.head_hash,
                checkpoint_digest=excluded.checkpoint_digest
        """, (issuer, sequence, head, content_digest))
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {**base, "checkpoint_recorded": True, "state": "pending-review",
            "reason": "local-checkpoint-only-not-an-external-anchor"}


def read_floor(store, issuer):
    """Read-only local state. Never use as a trusted external minimum."""
    if not isinstance(store, (str, Path)) or not Path(store).is_file():
        return None
    if not isinstance(issuer, str) or not checkpoint.HEX.fullmatch(issuer):
        return None
    try:
        conn = sqlite3.connect(Path(store).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT sequence, head_hash FROM checkpoint_floor WHERE issuer_key_id=?",
                (issuer,)
            ).fetchone()
        finally:
            conn.close()
    except (sqlite3.Error, OSError):
        return None
    return {"sequence": row[0], "head_hash": row[1]} if row else None
