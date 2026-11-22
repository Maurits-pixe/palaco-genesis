#!/usr/bin/env python3
"""Verify a detached custodian custody statement bound to policy and receipt chain.

A signed custody *claim* is NOT actual external storage proof. Inputs include
independently authenticated custodian keys, trusted policy roots, and floors.
No issuing, publishing, restoring, deploying or authorization.
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
    "palaco_custody_statement_policy", Path(__file__).with_name("receipt_custody_policy.py"))
policy_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy_gate)

DOMAIN = b"PALACO-RECEIPT-CUSTODY-STATEMENT-V1\x00"
POLICY_REF_DOMAIN = b"PALACO-RECEIPT-CUSTODY-POLICY-ENVELOPE-V1\x00"
ANCHOR_REF_DOMAIN = b"PALACO-RECEIPT-CHAIN-ANCHOR-ENVELOPE-V1\x00"
HEX = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
STATEMENT_ID = re.compile(r"^[0-9a-f]{32}$")
FIELDS = {"schema_version", "custodian_id", "statement_id", "disposition",
          "policy_envelope_sha256", "anchor_envelope_sha256",
          "policy_revision", "receipt_entries", "receipt_head_sha256"}
ENVELOPE_FIELDS = {"statement", "custodian_key_id", "signature_b64"}
DISPOSITION = "held-for-independent-review"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(domain, value):
    return hashlib.sha256(domain + canonical(value)).hexdigest()


def canonical_statement(body):
    if not isinstance(body, dict) or set(body) != FIELDS:
        raise ValueError("invalid-custody-statement-schema")
    if body["schema_version"] != "0.1.0" or body["disposition"] != DISPOSITION:
        raise ValueError("invalid-custody-statement-purpose")
    if not isinstance(body["custodian_id"], str) or not ID.fullmatch(body["custodian_id"]):
        raise ValueError("invalid-custodian-id")
    if not isinstance(body["statement_id"], str) or not STATEMENT_ID.fullmatch(body["statement_id"]):
        raise ValueError("invalid-statement-id")
    if any(not isinstance(body[k], str) or not HEX.fullmatch(body[k])
           for k in ("policy_envelope_sha256", "anchor_envelope_sha256", "receipt_head_sha256")):
        raise ValueError("invalid-custody-statement-digest")
    if type(body["policy_revision"]) is not int or not 1 <= body["policy_revision"] <= 2147483647:
        raise ValueError("invalid-statement-policy-revision")
    if type(body["receipt_entries"]) is not int or not 1 <= body["receipt_entries"] <= policy_gate.anchor.audit.MAX_EVENTS:
        raise ValueError("invalid-statement-receipt-entries")
    return canonical(body)


def verify(receipt_db, signed_anchor, signed_policy, signed_statement,
           expected_custodian_id, trusted_custodian_key_ids,
           custodian_keys, revoked_custodians,
           governance_roots, revoked_governance,
           witness_roots, revoked_witnesses,
           minimum_policy_revision, minimum_external_events):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "custody_statement_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(expected_custodian_id, str) or not ID.fullmatch(expected_custodian_id):
        return deny("missing-expected-custodian")
    if (not isinstance(trusted_custodian_key_ids, dict)
        or not isinstance(custodian_keys, dict)
        or not isinstance(revoked_custodians, (set, frozenset))):
        return deny("missing-custodian-policy")
    if any(not isinstance(k, str) or not HEX.fullmatch(k) for k in revoked_custodians):
        return deny("invalid-custodian-revocations")
    if not isinstance(signed_statement, dict) or set(signed_statement) != ENVELOPE_FIELDS:
        return deny("invalid-statement-envelope")
    try:
        data = canonical_statement(signed_statement["statement"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    body = signed_statement["statement"]
    if body["custodian_id"] != expected_custodian_id:
        return deny("custodian-identity-mismatch")
    key_id = signed_statement["custodian_key_id"]
    if not isinstance(key_id, str) or not HEX.fullmatch(key_id):
        return deny("invalid-custodian-key-id")
    allowed = trusted_custodian_key_ids.get(expected_custodian_id)
    if not isinstance(allowed, (set, frozenset)) or key_id not in allowed:
        return deny("custodian-key-not-allowed")
    if key_id in revoked_custodians:
        return deny("custodian-revoked")
    if (isinstance(signed_policy, dict) and key_id == signed_policy.get("issuer_key_id")
        or isinstance(signed_anchor, dict) and key_id == signed_anchor.get("witness_key_id")):
        return deny("custodian-role-collision")
    public = custodian_keys.get(key_id)
    if not isinstance(public, bytes) or len(public) != 32 or hashlib.sha256(public).hexdigest() != key_id:
        return deny("untrusted-custodian-key")
    encoded = signed_statement["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-custodian-signature-format")
    try:
        sig = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-custodian-signature-format")
    if len(sig) != 64:
        return deny("invalid-custodian-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, DOMAIN + data)
    except (InvalidSignature, ValueError):
        return deny("invalid-custodian-signature")
    try:
        if (body["policy_envelope_sha256"] != digest(POLICY_REF_DOMAIN, signed_policy)
            or body["anchor_envelope_sha256"] != digest(ANCHOR_REF_DOMAIN, signed_anchor)):
            return deny("custody-statement-envelope-binding-failed")
    except (TypeError, ValueError, OverflowError):
        return deny("invalid-bound-envelope")
    checked = policy_gate.verify(
        receipt_db, signed_anchor, signed_policy, governance_roots,
        revoked_governance, witness_roots, revoked_witnesses,
        minimum_policy_revision, minimum_external_events)
    if not checked["custody_valid"]:
        return deny(checked["reason"])
    if (body["policy_revision"] != checked["policy_revision"]
        or body["receipt_entries"] != checked["entries"]
        or body["receipt_head_sha256"] != checked["anchor_head"]):
        return deny("custody-statement-state-mismatch")
    return {**base, "custody_statement_valid": True, "state": "pending-review",
            "reason": "signed-custody-claim-only-not-proof-of-physical-storage",
            "custodian_id": expected_custodian_id, "statement_id": body["statement_id"],
            "receipt_entries": checked["entries"]}
