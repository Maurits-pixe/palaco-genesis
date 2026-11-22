#!/usr/bin/env python3
"""Read-only verification of detached witness-signed custody acknowledgement heads.

No signing, key issuance, transfer, external storage or release authorization.
The caller must independently authenticate witness roots, revocations and floor.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_signed_ack_chain_source", Path(__file__).with_name("custody_ack_audit_chain.py"))
chain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chain)

DOMAIN = b"PALACO-SIGNED-CUSTODY-ACK-ANCHOR-V1\x00"
ANCHOR_FIELDS = {"schema_version", "entries", "ack_head_sha256"}
ENVELOPE_FIELDS = {"anchor", "witness_key_id", "signature_b64"}


def canonical_anchor(value):
    if not isinstance(value, dict) or set(value) != ANCHOR_FIELDS:
        raise ValueError("invalid-signed-ack-schema")
    if value["schema_version"] != "0.1.0":
        raise ValueError("unsupported-signed-ack-version")
    if type(value["entries"]) is not int or not 1 <= value["entries"] <= chain.MAX_EVENTS:
        raise ValueError("invalid-signed-ack-count")
    if not isinstance(value["ack_head_sha256"], str) or not chain.HEX.fullmatch(value["ack_head_sha256"]):
        raise ValueError("invalid-signed-ack-head")
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def verify(receipt_db, envelope, witness_roots, revoked_witnesses, minimum_events):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "anchor_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if type(minimum_events) is not int or not 1 <= minimum_events <= chain.MAX_EVENTS:
        return deny("missing-external-ack-floor")
    if not isinstance(witness_roots, dict) or not isinstance(revoked_witnesses, (set, frozenset)):
        return deny("missing-independent-ack-witness-policy")
    if any(not isinstance(x, str) or not chain.HEX.fullmatch(x) for x in revoked_witnesses):
        return deny("invalid-witness-revocations")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        return deny("invalid-signed-ack-envelope")
    try:
        canonical = canonical_anchor(envelope["anchor"])
    except (TypeError, ValueError, OverflowError) as exc:
        return deny(str(exc))
    anchor = envelope["anchor"]
    if anchor["entries"] < minimum_events:
        return deny("stale-signed-ack-anchor")
    key_id = envelope["witness_key_id"]
    if not isinstance(key_id, str) or not chain.HEX.fullmatch(key_id):
        return deny("invalid-ack-witness-key-id")
    if key_id in revoked_witnesses:
        return deny("ack-witness-revoked")
    pub = witness_roots.get(key_id)
    if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != key_id:
        return deny("untrusted-ack-witness")
    encoded = envelope["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-ack-anchor-signature-format")
    try:
        sig = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-ack-anchor-signature-format")
    if len(sig) != 64:
        return deny("invalid-ack-anchor-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, DOMAIN + canonical)
    except (InvalidSignature, ValueError):
        return deny("invalid-signed-ack-signature")
    checked = chain.inspect(receipt_db, anchor["ack_head_sha256"], minimum_events)
    if not checked["chain_valid"]:
        return deny(checked["reason"])
    if checked["entries"] != anchor["entries"]:
        return deny("signed-ack-count-mismatch")
    return {**base, "anchor_valid": True, "state": "pending-review",
            "reason": "signed-ack-head-matched-no-authority",
            "entries": checked["entries"], "head_hash": checked["head_hash"]}
