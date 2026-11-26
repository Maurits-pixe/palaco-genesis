#!/usr/bin/env python3
"""Detached Ed25519 witness for a local receipt audit chain (HOLD only).

The head/count must be independently preserved for rollback resistance.
This verifier neither signs nor distributes witnesses; all roots and
revocation policies are externally supplied, never automatically trusted.
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
    "palaco_signed_receipt_chain_audit", Path(__file__).with_name("receipt_audit_chain.py"))
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

DOMAIN = b"PALACO-SIGNED-RECEIPT-CHAIN-ANCHOR-V1\x00"
HEX = re.compile(r"^[0-9a-f]{64}$")
FIELDS = {"schema_version", "entries", "receipt_head_sha256"}
ENVELOPE_FIELDS = {"anchor", "witness_key_id", "signature_b64"}


def canonical_anchor(body):
    if not isinstance(body, dict) or set(body) != FIELDS:
        raise ValueError("invalid-anchor-schema")
    if body["schema_version"] != "0.1.0":
        raise ValueError("invalid-anchor-version")
    if type(body["entries"]) is not int or not 1 <= body["entries"] <= audit.MAX_EVENTS:
        raise ValueError("invalid-anchor-entries")
    if not isinstance(body["receipt_head_sha256"], str) or not HEX.fullmatch(body["receipt_head_sha256"]):
        raise ValueError("invalid-anchor-head")
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def verify(receipt_db, envelope, roots, revoked_witnesses, minimum_events):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "anchor_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if type(minimum_events) is not int or not 1 <= minimum_events <= audit.MAX_EVENTS:
        return deny("missing-external-event-floor")
    if not isinstance(roots, dict) or not isinstance(revoked_witnesses, (set, frozenset)):
        return deny("missing-witness-trust-policy")
    if any(not isinstance(k, str) or not HEX.fullmatch(k) for k in revoked_witnesses):
        return deny("invalid-revocation-policy")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        return deny("invalid-envelope")
    try:
        canonical = canonical_anchor(envelope["anchor"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    body = envelope["anchor"]
    if body["entries"] < minimum_events:
        return deny("stale-receipt-anchor")
    key_id = envelope["witness_key_id"]
    if not isinstance(key_id, str) or not HEX.fullmatch(key_id):
        return deny("invalid-witness-key-id")
    if key_id in revoked_witnesses:
        return deny("witness-revoked")
    pub = roots.get(key_id)
    if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != key_id:
        return deny("untrusted-witness")
    encoded_sig = envelope["signature_b64"]
    if not isinstance(encoded_sig, str) or len(encoded_sig) > 96:
        return deny("invalid-signature-format")
    try:
        signature = base64.b64decode(encoded_sig, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-signature-format")
    if len(signature) != 64:
        return deny("invalid-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, DOMAIN + canonical)
    except (ValueError, InvalidSignature):
        return deny("invalid-anchor-signature")
    verified = audit.verify(receipt_db, body["receipt_head_sha256"], minimum_events)
    if not verified["chain_valid"]:
        return deny(verified["reason"])
    if verified["entries"] != body["entries"]:
        return deny("receipt-chain-count-mismatch")
    return {**base, "anchor_valid": True, "state": "pending-review",
            "reason": "signed-receipt-anchor-matched-no-authority",
            "entries": verified["entries"], "head_hash": verified["head_hash"]}
