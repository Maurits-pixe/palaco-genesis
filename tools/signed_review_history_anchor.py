#!/usr/bin/env python3
"""Verify detached Ed25519 witness for a local review-checkpoint history.

No signing keys, external hosting, trust bootstrap, restore or release flow.
The authenticated issuer roots, revocations and minimum ordinal come from the
caller. Only an independently held witness can help detect local file rollback.
"""
import base64
import hashlib
import importlib.util
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_history_anchor_history", Path(__file__).with_name("review_checkpoint_history.py"))
history = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(history)

HEX = re.compile(r"^[0-9a-f]{64}$")
BODY_FIELDS = {"schema_version", "history_issuer_key_id", "entries", "record_count", "history_head_sha256"}
ENVELOPE_FIELDS = {"anchor", "witness_key_id", "signature_b64"}
DOMAIN = b"PALACO-REVIEW-HISTORY-ANCHOR-V1\x00"


def canonical_anchor(body):
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise ValueError("invalid-anchor-schema")
    if body["schema_version"] != "0.1.0":
        raise ValueError("unsupported-anchor-version")
    if any(not isinstance(body[k], str) or not HEX.fullmatch(body[k])
           for k in ("history_issuer_key_id", "history_head_sha256")):
        raise ValueError("invalid-anchor-hash")
    if type(body["entries"]) is not int or not 1 <= body["entries"] <= history.MAX_HISTORY:
        raise ValueError("invalid-anchor-entries")
    if type(body["record_count"]) is not int or not 1 <= body["record_count"] <= history.checkpoint.MAX_ROWS:
        raise ValueError("invalid-anchor-record-count")
    if body["entries"] > body["record_count"]:
        raise ValueError("invalid-anchor-monotonicity")
    return json.dumps(body, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def verify(history_db, envelope, witness_roots, revoked_witnesses, minimum_entries):
    """Fail closed, read-only. A signature is not independent publication."""
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "anchor_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if type(minimum_entries) is not int or not 1 <= minimum_entries <= history.MAX_HISTORY:
        return deny("missing-trusted-minimum-entries")
    if not isinstance(witness_roots, dict) or not isinstance(revoked_witnesses, (set, frozenset)):
        return deny("missing-witness-policy")
    if any(not isinstance(x, str) or not HEX.fullmatch(x) for x in revoked_witnesses):
        return deny("invalid-revocation-policy")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        return deny("invalid-anchor-envelope")
    try:
        canonical = canonical_anchor(envelope["anchor"])
    except (TypeError, ValueError, OverflowError) as exc:
        return deny(str(exc))
    body = envelope["anchor"]
    if body["entries"] < minimum_entries:
        return deny("stale-anchor")
    witness_id = envelope["witness_key_id"]
    if not isinstance(witness_id, str) or not HEX.fullmatch(witness_id):
        return deny("invalid-witness-key-id")
    if witness_id in revoked_witnesses:
        return deny("witness-key-revoked")
    pub = witness_roots.get(witness_id)
    if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != witness_id:
        return deny("untrusted-witness")
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
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, DOMAIN + canonical)
    except (InvalidSignature, ValueError):
        return deny("invalid-anchor-signature")
    checked = history.inspect(
        history_db, body["history_issuer_key_id"], body["history_head_sha256"],
        minimum_entries
    )
    if not checked["history_valid"]:
        return deny(checked["reason"])
    if checked["entries"] != body["entries"] or checked["count"] != body["record_count"]:
        return deny("history-anchor-state-mismatch")
    return {**base, "anchor_valid": True, "state": "pending-review",
            "reason": "detached-witness-matched-no-authority",
            "entries": checked["entries"], "head_hash": checked["head_hash"]}
