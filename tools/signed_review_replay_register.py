#!/usr/bin/env python3
"""Locally quarantine replayed or conflicting signed recovery reviews.

Advisory SQLite prototype. No remote replay defense, trust-root governance,
identity proof, or restore authorization. HOLD and DENY are unconditional.
"""
import hashlib
import importlib.util
import sqlite3
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "palaco_review_register_signature", Path(__file__).with_name("signed_recovery_review.py"))
signed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(signed)


def inspect_and_register(database, dossier, envelope, reviewer_public_keys,
                         revoked_reviewer_keys, signed_registry, issuer_roots,
                         at_utc, minimum_revision):
    base = {"schema_version": "0.1.0", "release_gate": "HOLD",
            "authorization_granted": False, "recovery_approved": False,
            "automatic_restore": False, "state": "quarantined",
            "review_recorded": False}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(database, (str, Path)) or str(database) == ":memory:":
        raise ValueError("persistent review database path required")
    # Cryptography and strict dossier binding are checked BEFORE opening SQLite.
    verdict = signed.verify_declaration(
        dossier, envelope, reviewer_public_keys, revoked_reviewer_keys,
        signed_registry, issuer_roots, at_utc, minimum_revision
    )
    if not verdict["review_signature_valid"]:
        return deny(verdict["reason"])
    declaration = envelope["declaration"]
    dossier_digest = declaration["dossier_sha256"]
    reviewer_id = declaration["reviewer_id"]
    key_id = envelope["key_id"]
    # Deliberately record hashes and identifiers only, no original reason or PII.
    declaration_digest = hashlib.sha256(
        signed.DOMAIN + signed.canonical_declaration(declaration)
    ).hexdigest()
    signature_digest = hashlib.sha256(
        signed.dossiers.canonical(envelope)
    ).hexdigest()
    conn = sqlite3.connect(str(database), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observed_recovery_reviews(
                dossier_sha256 TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                declaration_digest TEXT NOT NULL UNIQUE,
                signature_digest TEXT NOT NULL UNIQUE,
                PRIMARY KEY (dossier_sha256, reviewer_id)
            )
        """)
        existing = conn.execute("""
            SELECT declaration_digest, signature_digest
            FROM observed_recovery_reviews
            WHERE dossier_sha256=? AND reviewer_id=?
        """, (dossier_digest, reviewer_id)).fetchone()
        if existing:
            conn.rollback()
            if existing == (declaration_digest, signature_digest):
                return deny("previously-seen-signed-review")
            return deny("conflicting-review-for-dossier")
        # No duplicates across reviewer names or dossier identifiers.
        try:
            conn.execute("""
                INSERT INTO observed_recovery_reviews(
                    dossier_sha256, reviewer_id, key_id,
                    declaration_digest, signature_digest
                ) VALUES (?,?,?,?,?)
            """, (dossier_digest, reviewer_id, key_id, declaration_digest, signature_digest))
        except sqlite3.IntegrityError:
            conn.rollback()
            return deny("signed-review-digest-reuse")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {**base, "state": "pending-review", "review_recorded": True,
            "reason": "locally-indexed-review-no-authority"}


def inspect(database, dossier_digest, reviewer_id):
    """Read-only inspection, not proof of independently persistent state."""
    if not isinstance(database, (str, Path)) or not Path(database).is_file():
        return None
    if not isinstance(dossier_digest, str) or not signed.HEX.fullmatch(dossier_digest):
        return None
    if not isinstance(reviewer_id, str) or not signed.dossiers.ID.fullmatch(reviewer_id):
        return None
    try:
        conn = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            row = conn.execute("""
                SELECT key_id, declaration_digest FROM observed_recovery_reviews
                WHERE dossier_sha256=? AND reviewer_id=?
            """, (dossier_digest, reviewer_id)).fetchone()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return None
    return {"key_id": row[0], "declaration_digest": row[1]} if row else None
