#!/usr/bin/env python3
"""Verify a detached Ed25519 witness for the local custody-statement ledger.

Requires independently pinned signer roots, revocations, and event-count floor.
This is a verifier of claims, not external storage or release authorization.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_custody_anchor_ledger", Path(__file__).with_name("custody_statement_ledger.py"))
ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger)

DOMAIN = b"PALACO-SIGNED-CUSTODY-LEDGER-ANCHOR-V1\x00"
FIELDS = {"schema_version", "entries", "custody_head_sha256"}
ENVELOPE_FIELDS = {"anchor", "witness_key_id", "signature_b64"}


def canonical_anchor(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("invalid-custody-anchor-schema")
    if value["schema_version"] != "0.1.0":
        raise ValueError("unsupported-custody-anchor-version")
    if type(value["entries"]) is not int or not 1 <= value["entries"] <= ledger.MAX_ENTRIES:
        raise ValueError("invalid-custody-anchor-count")
    if not isinstance(value["custody_head_sha256"], str) or not ledger.HEX.fullmatch(value["custody_head_sha256"]):
        raise ValueError("invalid-custody-anchor-head")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def verify(ledger_db, envelope, witness_roots, revoked_witnesses, minimum_entries):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "anchor_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if type(minimum_entries) is not int or not 1 <= minimum_entries <= ledger.MAX_ENTRIES:
        return deny("missing-external-custody-floor")
    if not isinstance(witness_roots, dict) or not isinstance(revoked_witnesses, (set, frozenset)):
        return deny("missing-independent-witness-policy")
    if any(not isinstance(k, str) or not ledger.HEX.fullmatch(k) for k in revoked_witnesses):
        return deny("invalid-revocation-policy")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        return deny("invalid-custody-anchor-envelope")
    try:
        canonical = canonical_anchor(envelope["anchor"])
    except (TypeError, ValueError, OverflowError) as exc:
        return deny(str(exc))
    body = envelope["anchor"]
    if body["entries"] < minimum_entries:
        return deny("stale-custody-anchor")
    signer = envelope["witness_key_id"]
    if not isinstance(signer, str) or not ledger.HEX.fullmatch(signer):
        return deny("invalid-custody-witness-id")
    if signer in revoked_witnesses:
        return deny("custody-witness-revoked")
    pub = witness_roots.get(signer)
    if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != signer:
        return deny("untrusted-custody-witness")
    encoded = envelope["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-anchor-signature-format")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-anchor-signature-format")
    if len(signature) != 64:
        return deny("invalid-anchor-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, DOMAIN + canonical)
    except (InvalidSignature, ValueError):
        return deny("invalid-custody-anchor-signature")
    result = ledger.inspect(ledger_db, body["custody_head_sha256"], minimum_entries)
    if not result["chain_valid"]:
        return deny(result["reason"])
    if result["entries"] != body["entries"]:
        return deny("custody-anchor-count-mismatch")
    return {**base, "anchor_valid": True, "state": "pending-review",
            "reason": "signed-custody-ledger-anchor-matched-no-release",
            "entries": result["entries"], "head_hash": result["head_hash"]}
