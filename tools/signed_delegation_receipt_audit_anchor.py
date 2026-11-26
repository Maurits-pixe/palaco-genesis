#!/usr/bin/env python3
"""Verify multiple independent Ed25519 witness claims about a receipt audit head.

Offline, verification-only. The expected head and lower count bound MUST be
independently pinned; witness organizations, trust roots and revocations MUST
come from an independently authenticated governance policy. No signing or
operational permissions are provided.
"""
import base64
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_delegation_receipt_audit_source",
    Path(__file__).with_name("delegation_receipt_audit_chain.py"))
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

DOMAIN = b"PALACO-DELEGATION-RECEIPT-WITNESS-V1\x00"
BODY_FIELDS = {"schema_version", "entries", "audit_head_sha256"}
ENVELOPE_FIELDS = {"checkpoint", "witness_key_id", "signature_b64"}
MAX_WITNESSES = 16


def canonical(body):
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise ValueError("invalid-receipt-checkpoint-schema")
    if body["schema_version"] != "0.1.0":
        raise ValueError("invalid-receipt-checkpoint-version")
    if type(body["entries"]) is not int or not 1 <= body["entries"] <= audit.MAX_EVENTS:
        raise ValueError("invalid-receipt-checkpoint-count")
    if (not isinstance(body["audit_head_sha256"], str)
        or not audit.HEX.fullmatch(body["audit_head_sha256"])):
        raise ValueError("invalid-receipt-checkpoint-hash")
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _out(**fields):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "automatic_restore": False, "recovery_approved": False,
            "witnessed_audit_valid": False, "state": "quarantined", **fields}


def verify(db, envelopes, witness_roots, witness_organizations,
           revoked_witnesses, required_organizations,
           independently_pinned_head, minimum_entries):
    def deny(reason):
        return _out(reason=reason)

    if (not isinstance(independently_pinned_head, str)
        or not audit.HEX.fullmatch(independently_pinned_head)
        or type(minimum_entries) is not int
        or not 1 <= minimum_entries <= audit.MAX_EVENTS):
        return deny("missing-independent-receipt-audit-anchor")
    if (not isinstance(witness_roots, dict)
        or not isinstance(witness_organizations, dict)
        or not isinstance(revoked_witnesses, (set, frozenset))
        or type(required_organizations) is not int
        or not 2 <= required_organizations <= MAX_WITNESSES):
        return deny("missing-independent-witness-policy")
    if any(not isinstance(k, str) or not audit.HEX.fullmatch(k)
           for k in revoked_witnesses):
        return deny("invalid-witness-revocations")
    for key, organization in witness_organizations.items():
        if (not isinstance(key, str) or not audit.HEX.fullmatch(key)
            or not isinstance(organization, str)
            or not audit.IDENT.fullmatch(organization)):
            return deny("invalid-witness-organization-policy")
    eligible_organizations = {
        org for key, org in witness_organizations.items() if key not in revoked_witnesses}
    if len(eligible_organizations) < required_organizations:
        return deny("insufficient-eligible-organizations")
    if (not isinstance(envelopes, list)
        or not required_organizations <= len(envelopes) <= MAX_WITNESSES):
        return deny("invalid-witness-count")

    checked = audit.inspect(db, independently_pinned_head, minimum_entries)
    if not checked["chain_valid"]:
        return deny(checked["reason"])
    expected = {"schema_version": "0.1.0", "entries": checked["entries"],
                "audit_head_sha256": checked["head_hash"]}

    # Avoid treating the receipt signer as a separate independent witness.
    # Open only after audit.inspect has verified both local tables.
    try:
        conn = sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            receipt_signers = {row[0] for row in conn.execute(
                "SELECT recipient_key_id FROM delegation_handoff_receipts LIMIT ?",
                (audit.MAX_EVENTS + 1,))}
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return deny("unreadable-receipt-signers")

    seen_keys = set()
    seen_organizations = set()
    for envelope in envelopes:
        if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
            return deny("invalid-receipt-witness-envelope")
        try:
            payload = canonical(envelope["checkpoint"])
        except (ValueError, TypeError, OverflowError) as exc:
            return deny(str(exc))
        key = envelope["witness_key_id"]
        if not isinstance(key, str) or not audit.HEX.fullmatch(key):
            return deny("invalid-receipt-witness-key-id")
        if key in seen_keys:
            return deny("duplicate-receipt-witness")
        seen_keys.add(key)
        if key in revoked_witnesses:
            return deny("receipt-witness-revoked")
        organization = witness_organizations.get(key)
        if organization is None:
            return deny("receipt-witness-not-allowed")
        if organization in seen_organizations:
            return deny("duplicate-receipt-witness-organization")
        seen_organizations.add(organization)
        if key in receipt_signers:
            return deny("receipt-signer-witness-role-collision")
        pub = witness_roots.get(key)
        if (not isinstance(pub, bytes) or len(pub) != 32
            or hashlib.sha256(pub).hexdigest() != key):
            return deny("untrusted-receipt-witness")
        encoded = envelope["signature_b64"]
        if not isinstance(encoded, str) or len(encoded) > 96:
            return deny("invalid-receipt-witness-signature-format")
        try:
            signature = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            return deny("invalid-receipt-witness-signature-format")
        if len(signature) != 64:
            return deny("invalid-receipt-witness-signature-format")
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(signature, DOMAIN + payload)
        except (InvalidSignature, ValueError):
            return deny("invalid-receipt-witness-signature")
        if envelope["checkpoint"] != expected:
            return deny("conflicting-receipt-audit-checkpoint")

    if len(seen_organizations) < required_organizations:
        return deny("insufficient-receipt-witness-organizations")
    return {**_out(), "witnessed_audit_valid": True, "state": "pending-review",
            "reason": "witnessed-receipt-audit-evidence-only-no-authority",
            "entries": checked["entries"], "head_hash": checked["head_hash"],
            "organizations": len(seen_organizations)}
