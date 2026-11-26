#!/usr/bin/env python3
"""Issuer-signed offline custody policy for receipt audit witnesses; HOLD only.

The policy is not an external archive, trusted clock, global revocation service,
or release permission. Governance roots and minimum policy revision are
caller-supplied and must be pinned independently.
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
    "palaco_custody_receipt_anchor", Path(__file__).with_name("signed_receipt_chain_anchor.py"))
anchor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(anchor)

DOMAIN = b"PALACO-RECEIPT-CUSTODY-POLICY-V1\x00"
HEX = re.compile(r"^[0-9a-f]{64}$")
POLICY_FIELDS = {"schema_version", "revision", "witness_key_ids", "minimum_events"}
ENVELOPE_FIELDS = {"policy", "issuer_key_id", "signature_b64"}
MAX_WITNESSES = 32


def canonical_policy(policy):
    if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
        raise ValueError("invalid-custody-policy-schema")
    if policy["schema_version"] != "0.1.0":
        raise ValueError("unsupported-custody-policy-version")
    if type(policy["revision"]) is not int or not 1 <= policy["revision"] <= 2147483647:
        raise ValueError("invalid-custody-policy-revision")
    if type(policy["minimum_events"]) is not int or not 1 <= policy["minimum_events"] <= anchor.audit.MAX_EVENTS:
        raise ValueError("invalid-custody-policy-floor")
    ids = policy["witness_key_ids"]
    if (not isinstance(ids, list) or not 1 <= len(ids) <= MAX_WITNESSES
        or any(not isinstance(i, str) or not HEX.fullmatch(i) for i in ids)
        or ids != sorted(set(ids))):
        raise ValueError("invalid-witness-allowlist")
    return json.dumps(policy, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _signature(envelope, key_name, message, keys, revoked, label):
    key_id = envelope.get(key_name)
    if not isinstance(key_id, str) or not HEX.fullmatch(key_id):
        return "invalid-" + label + "-key"
    if key_id in revoked:
        return label + "-revoked"
    pub = keys.get(key_id)
    if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != key_id:
        return "untrusted-" + label
    text = envelope.get("signature_b64")
    if not isinstance(text, str) or len(text) > 96:
        return "invalid-" + label + "-signature"
    try:
        sig = base64.b64decode(text, validate=True)
        if len(sig) != 64:
            return "invalid-" + label + "-signature"
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
    except (InvalidSignature, ValueError, base64.binascii.Error):
        return "invalid-" + label + "-signature"
    return None


def verify(receipt_db, signed_anchor, signed_policy, governance_roots,
           revoked_governance, witness_roots, revoked_witnesses,
           minimum_policy_revision, minimum_external_events):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "custody_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if (not isinstance(governance_roots, dict) or not isinstance(witness_roots, dict)
        or not isinstance(revoked_governance, (set, frozenset))
        or not isinstance(revoked_witnesses, (set, frozenset))):
        return deny("missing-external-trust-policy")
    if any(not isinstance(i, str) or not HEX.fullmatch(i)
           for i in revoked_governance | revoked_witnesses):
        return deny("invalid-revocation-set")
    if type(minimum_policy_revision) is not int or minimum_policy_revision < 1:
        return deny("missing-trusted-policy-revision")
    if type(minimum_external_events) is not int or not 1 <= minimum_external_events <= anchor.audit.MAX_EVENTS:
        return deny("missing-trusted-event-floor")
    if not isinstance(signed_policy, dict) or set(signed_policy) != ENVELOPE_FIELDS:
        return deny("invalid-signed-policy-envelope")
    try:
        serialized = canonical_policy(signed_policy["policy"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    policy = signed_policy["policy"]
    if policy["revision"] < minimum_policy_revision:
        return deny("stale-custody-policy")
    problem = _signature(signed_policy, "issuer_key_id", DOMAIN + serialized,
                         governance_roots, revoked_governance, "governance")
    if problem:
        return deny(problem)
    if not isinstance(signed_anchor, dict) or set(signed_anchor) != anchor.ENVELOPE_FIELDS:
        return deny("invalid-receipt-anchor-envelope")
    witness_id = signed_anchor["witness_key_id"]
    if witness_id not in policy["witness_key_ids"]:
        return deny("witness-not-authorized-by-custody-policy")
    minimum = max(policy["minimum_events"], minimum_external_events)
    result = anchor.verify(receipt_db, signed_anchor, witness_roots, revoked_witnesses, minimum)
    if not result["anchor_valid"]:
        return deny(result["reason"])
    return {**base, "custody_valid": True, "state": "pending-review",
            "reason": "policy-and-anchor-match-no-external-custody-proof",
            "policy_revision": policy["revision"], "entries": result["entries"],
            "anchor_head": result["head_hash"]}
