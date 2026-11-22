#!/usr/bin/env python3
"""SQLite revision floor for issuer-signed reviewer snapshots (HOLD).

The caller supplies the issuer trust roots; these must be authenticated by a
separate authority. The local database can be rolled back or replaced.
"""
import hashlib
import importlib.util
import sqlite3
from pathlib import Path

FILE = Path(__file__).with_name("signed_reviewer_registry.py")
_spec = importlib.util.spec_from_file_location("palaco_registry_floor_verifier", FILE)
_reviewers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_reviewers)


def _schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reviewer_revision_floor (
            issuer_key_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL CHECK(revision >= 1),
            snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest) = 64)
        )
    """)


def observe(database, signed_snapshot, issuer_roots):
    """Atomically refuse stale or equivocated signed revisions on one SQLite file.

    Signature verification is completed before ANY database mutation.
    Reobserving identical revision+content is idempotent.
    """
    verdict = {"release_gate": "HOLD", "authorization_granted": False,
               "revision_recorded": False, "state": "quarantined"}
    def reject(reason):
        return {**verdict, "reason": reason}
    if not isinstance(database, (str, Path)) or str(database) == ":memory:":
        raise ValueError("persistent database path required")
    if not isinstance(signed_snapshot, dict):
        return reject("invalid-snapshot")
    snapshot = signed_snapshot.get("snapshot")
    if not isinstance(snapshot, dict):
        return reject("invalid-snapshot")
    revision = snapshot.get("revision")
    # A verified snapshot is required before it may advance the floor.
    reviewers = snapshot.get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        return reject("no-reviewers")
    verification = verify_snapshot(signed_snapshot, issuer_roots)
    if verification is None:
        return reject("invalid-snapshot-signature")
    issuer_id, digest = verification
    conn = sqlite3.connect(str(database), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        row = conn.execute(
            "SELECT revision, snapshot_digest FROM reviewer_revision_floor WHERE issuer_key_id=?",
            (issuer_id,)
        ).fetchone()
        if row is not None:
            old_revision, old_digest = row
            if revision < old_revision:
                conn.rollback()
                return reject("registry-rollback")
            if revision == old_revision:
                conn.rollback()
                if digest == old_digest:
                    return {**verdict, "state": "pending-review",
                            "reason": "already-observed", "revision_recorded": True}
                return reject("registry-equivocation")
        conn.execute("""
            INSERT INTO reviewer_revision_floor(issuer_key_id, revision, snapshot_digest)
            VALUES (?, ?, ?)
            ON CONFLICT(issuer_key_id) DO UPDATE SET
                revision=excluded.revision, snapshot_digest=excluded.snapshot_digest
        """, (issuer_id, revision, digest))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {**verdict, "state": "pending-review",
            "reason": "locally-recorded-untrusted", "revision_recorded": True}


def verify_snapshot(envelope, roots):
    """Verify issuer signature on complete canonical snapshot; return id, hash."""
    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(envelope, dict) or set(envelope) != _reviewers.ENVELOPE_FIELDS:
        return None
    if not isinstance(roots, dict):
        return None
    try:
        canonical = _reviewers.canonical(envelope["snapshot"])
    except (ValueError, TypeError, OverflowError):
        return None
    key_id = envelope.get("issuer_key_id")
    if not isinstance(key_id, str) or not _reviewers.HEX64.fullmatch(key_id):
        return None
    key = roots.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32 or hashlib.sha256(key).hexdigest() != key_id:
        return None
    encoded = envelope.get("issuer_signature_b64")
    if not isinstance(encoded, str) or len(encoded) > 96:
        return None
    try:
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64:
            return None
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature, b"PALACO-REVIEWER-REGISTRY-V1\x00" + canonical
        )
    except (ValueError, InvalidSignature, base64.binascii.Error):
        return None
    return key_id, hashlib.sha256(canonical).hexdigest()
