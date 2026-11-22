#!/usr/bin/env python3
"""Verify an issuer-signed external audit checkpoint against a local chain.

This is a read-only verification prototype, not an external checkpoint service
or trust anchor. Authentic roots, freshness and checkpoint storage are caller
responsibilities. Authorization permanently DENY / HOLD.
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
    "palaco_checkpoint_audit", Path(__file__).with_name("local_audit_chain.py")
)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

HEX = re.compile(r"^[0-9a-f]{64}$")
FIELDS = {"schema_version", "sequence", "head_hash"}
ENVELOPE = {"checkpoint", "issuer_key_id", "signature_b64"}
DOMAIN = b"PALACO-AUDIT-CHECKPOINT-V1\x00"


def canonical_checkpoint(body):
    if not isinstance(body, dict) or set(body) != FIELDS:
        raise ValueError("invalid-checkpoint-schema")
    if body["schema_version"] != "0.1.0":
        raise ValueError("invalid-checkpoint-version")
    if type(body["sequence"]) is not int or not 1 <= body["sequence"] <= audit.MAX_EVENTS:
        raise ValueError("invalid-checkpoint-sequence")
    if not isinstance(body["head_hash"], str) or not HEX.fullmatch(body["head_hash"]):
        raise ValueError("invalid-checkpoint-head")
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def verify_checkpoint(database, envelope, issuer_roots, minimum_sequence):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "checkpoint_valid": False, "state": "quarantined"}
    def reject(reason):
        return {**base, "reason": reason}
    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= audit.MAX_EVENTS:
        return reject("missing-trusted-sequence-floor")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE:
        return reject("invalid-envelope")
    if not isinstance(issuer_roots, dict):
        return reject("missing-trusted-roots")
    try:
        encoded_body = canonical_checkpoint(envelope["checkpoint"])
    except (TypeError, ValueError, OverflowError) as exc:
        return reject(str(exc))
    body = envelope["checkpoint"]
    if body["sequence"] < minimum_sequence:
        return reject("stale-checkpoint")
    issuer = envelope["issuer_key_id"]
    if not isinstance(issuer, str) or not HEX.fullmatch(issuer):
        return reject("invalid-issuer-id")
    key = issuer_roots.get(issuer)
    if not isinstance(key, bytes) or len(key) != 32 or hashlib.sha256(key).hexdigest() != issuer:
        return reject("untrusted-checkpoint-issuer")
    encoded_signature = envelope["signature_b64"]
    if not isinstance(encoded_signature, str) or len(encoded_signature) > 96:
        return reject("invalid-signature-format")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, base64.binascii.Error):
        return reject("invalid-signature-format")
    if len(signature) != 64:
        return reject("invalid-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, DOMAIN + encoded_body)
    except (InvalidSignature, ValueError):
        return reject("invalid-checkpoint-signature")
    checked = audit.verify(database, expected_head=body["head_hash"])
    if not checked["chain_valid"]:
        return reject("audit-" + checked["reason"])
    if checked["events_checked"] != body["sequence"]:
        return reject("audit-sequence-mismatch")
    return {**base, "checkpoint_valid": True, "state": "pending-review",
            "reason": "signed-checkpoint-matched-but-authority-unverified",
            "sequence": body["sequence"], "head_hash": body["head_hash"]}
