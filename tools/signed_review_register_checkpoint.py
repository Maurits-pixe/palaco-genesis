#!/usr/bin/env python3
"""Read-only signed checkpoint of the local recovery review replay register.

A signed checkpoint binds the *entire* sorted local register state. No remote
witness publishing or authenticated issuer governance exists. HOLD only.
"""
import base64
import hashlib
import importlib.util
import json
import re
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX = re.compile(r"^[0-9a-f]{64}$")
FIELDS = {"schema_version", "count", "rows_sha256"}
ENVELOPE = {"checkpoint", "issuer_key_id", "signature_b64"}
DOMAIN = b"PALACO-SIGNED-REVIEW-REGISTER-CHECKPOINT-V1\x00"
MAX_ROWS = 100000


def canonical(checkpoint):
    if not isinstance(checkpoint, dict) or set(checkpoint) != FIELDS:
        raise ValueError("invalid-checkpoint-schema")
    if checkpoint["schema_version"] != "0.1.0":
        raise ValueError("invalid-checkpoint-version")
    if type(checkpoint["count"]) is not int or not 1 <= checkpoint["count"] <= MAX_ROWS:
        raise ValueError("invalid-checkpoint-count")
    if not isinstance(checkpoint["rows_sha256"], str) or not HEX.fullmatch(checkpoint["rows_sha256"]):
        raise ValueError("invalid-checkpoint-hash")
    return json.dumps(checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def snapshot(database):
    """Read in one SQLite read transaction, without creating/mutating a file."""
    if not isinstance(database, (str, Path)) or not Path(database).is_file():
        return None
    try:
        conn = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        try:
            conn.execute("BEGIN")
            rows = conn.execute("""
                SELECT dossier_sha256, reviewer_id, key_id, declaration_digest,
                       signature_digest
                FROM observed_recovery_reviews
                ORDER BY dossier_sha256, reviewer_id
                LIMIT ?
            """, (MAX_ROWS + 1,)).fetchall()
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return None
    if not rows or len(rows) > MAX_ROWS:
        return None
    for row in rows:
        if len(row) != 5 or any(not isinstance(v, str) or not v for v in row):
            return None
        if any(not HEX.fullmatch(row[k]) for k in (0, 2, 3, 4)):
            return None
        if len(row[1]) > 128:
            return None
    encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode()
    return {"schema_version": "0.1.0", "count": len(rows),
            "rows_sha256": hashlib.sha256(b"PALACO-REVIEW-REGISTER-ROWS-V1\x00" + encoded).hexdigest()}


def verify(database, envelope, roots, revoked_issuers, minimum_count):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "checkpoint_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if type(minimum_count) is not int or not 1 <= minimum_count <= MAX_ROWS:
        return deny("missing-trusted-count-floor")
    if not isinstance(roots, dict) or not isinstance(revoked_issuers, (set, frozenset)):
        return deny("missing-issuer-policy")
    if any(not isinstance(i, str) or not HEX.fullmatch(i) for i in revoked_issuers):
        return deny("invalid-revocation-policy")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE:
        return deny("invalid-envelope")
    try:
        body = canonical(envelope["checkpoint"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    if envelope["checkpoint"]["count"] < minimum_count:
        return deny("stale-review-register-checkpoint")
    issuer = envelope["issuer_key_id"]
    if not isinstance(issuer, str) or not HEX.fullmatch(issuer):
        return deny("invalid-issuer-id")
    if issuer in revoked_issuers:
        return deny("issuer-revoked")
    key = roots.get(issuer)
    if not isinstance(key, bytes) or len(key) != 32 or hashlib.sha256(key).hexdigest() != issuer:
        return deny("untrusted-issuer")
    encoded = envelope["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-signature-format")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-signature-format")
    if len(signature) != 64:
        return deny("invalid-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, DOMAIN + body)
    except (InvalidSignature, ValueError):
        return deny("invalid-checkpoint-signature")
    actual = snapshot(database)
    if actual is None:
        return deny("missing-or-unreadable-review-register")
    if actual["count"] != envelope["checkpoint"]["count"]:
        return deny("review-register-count-mismatch")
    if actual["rows_sha256"] != envelope["checkpoint"]["rows_sha256"]:
        return deny("review-register-hash-mismatch")
    return {**base, "checkpoint_valid": True, "state": "pending-review",
            "reason": "local-register-matches-signed-checkpoint-authority-unverified",
            "count": actual["count"], "rows_sha256": actual["rows_sha256"]}
