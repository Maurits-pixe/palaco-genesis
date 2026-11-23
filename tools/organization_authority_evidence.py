#!/usr/bin/env python3
"""Verify signed assessor-scope delegation bound to organization identity evidence.

A delegation authorizes ONLY a bounded evidence-review role in the model,
not real-world representation, release, recovery, or legal identity status.
External trust roots, revocations, and minimum delegation revision required.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_authority_identity_evidence",
    Path(__file__).with_name("organization_identity_evidence.py"))
identity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(identity)

DOMAIN = b"PALACO-ORG-ASSESSOR-DELEGATION-V1\x00"
EVIDENCE_DOMAIN = b"PALACO-ORG-IDENTITY-ENVELOPE-V1\x00"
FIELDS = {"schema_version", "revision", "organization_id", "assessor_key_id",
          "registry_revision", "registry_envelope_sha256",
          "identity_envelope_sha256", "scope"}
ENVELOPE_FIELDS = {"delegation", "delegator_key_id", "signature_b64"}
SCOPE = "identity-evidence-review-only"
HEX = identity.HEX


def digest_evidence(envelope):
    return hashlib.sha256(EVIDENCE_DOMAIN + json.dumps(
        envelope, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def canonical_delegation(body):
    if not isinstance(body, dict) or set(body) != FIELDS:
        raise ValueError("invalid-delegation-schema")
    if body["schema_version"] != "0.1.0" or body["scope"] != SCOPE:
        raise ValueError("invalid-delegation-scope")
    if type(body["revision"]) is not int or not 1 <= body["revision"] <= 2147483647:
        raise ValueError("invalid-delegation-revision")
    if type(body["registry_revision"]) is not int or not 1 <= body["registry_revision"] <= 2147483647:
        raise ValueError("invalid-delegation-registry-revision")
    if not isinstance(body["organization_id"], str) or not identity.succession.registry.ORGANIZATION.fullmatch(body["organization_id"]):
        raise ValueError("invalid-delegation-organization")
    for name in ("assessor_key_id", "registry_envelope_sha256", "identity_envelope_sha256"):
        if not isinstance(body[name], str) or not HEX.fullmatch(body[name]):
            raise ValueError("invalid-delegation-digest")
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _result(**fields):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "delegation_valid": False, "state": "quarantined", **fields}


def verify(snapshots, records, signed_identity, signed_delegation,
           registry_issuer_roots, revoked_registry_issuers,
           assessor_roots, revoked_assessors, allowed_assessors,
           delegator_roots, revoked_delegators, allowed_delegators,
           trusted_genesis_digest, trusted_latest_record_digest,
           minimum_registry_revision, minimum_delegation_revision):
    def deny(reason):
        return _result(reason=reason)
    if (not isinstance(delegator_roots, dict)
        or not isinstance(revoked_delegators, (set, frozenset))
        or not isinstance(allowed_delegators, (set, frozenset))
        or any(not isinstance(x, str) or not HEX.fullmatch(x)
               for x in revoked_delegators | allowed_delegators)):
        return deny("missing-independent-delegator-policy")
    if type(minimum_delegation_revision) is not int or minimum_delegation_revision < 1:
        return deny("missing-independent-delegation-floor")
    checked = identity.verify(
        snapshots, records, signed_identity, registry_issuer_roots,
        revoked_registry_issuers, assessor_roots, revoked_assessors,
        allowed_assessors, trusted_genesis_digest,
        trusted_latest_record_digest, minimum_registry_revision)
    if not checked["identity_evidence_valid"]:
        return deny(checked["reason"])
    if not isinstance(signed_delegation, dict) or set(signed_delegation) != ENVELOPE_FIELDS:
        return deny("invalid-delegation-envelope")
    try:
        serialized = canonical_delegation(signed_delegation["delegation"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    body = signed_delegation["delegation"]
    if body["revision"] < minimum_delegation_revision:
        return deny("stale-delegation-revision")
    latest = snapshots[-1]
    if (body["organization_id"] != checked["organization_id"]
        or body["assessor_key_id"] != signed_identity["assessor_key_id"]
        or body["registry_revision"] != latest["registry"]["revision"]
        or body["registry_envelope_sha256"] != identity.succession.digest(latest)
        or body["identity_envelope_sha256"] != digest_evidence(signed_identity)):
        return deny("delegation-binding-mismatch")
    delegator = signed_delegation["delegator_key_id"]
    if not isinstance(delegator, str) or not HEX.fullmatch(delegator):
        return deny("invalid-delegator-id")
    if delegator in revoked_delegators:
        return deny("delegator-revoked")
    if delegator not in allowed_delegators:
        return deny("delegator-not-allowed")
    if (delegator == signed_identity["assessor_key_id"]
        or delegator in {s["issuer_key_id"] for s in snapshots}
        or delegator in {row["witness_key_id"] for snap in snapshots
                         for row in snap["registry"]["witnesses"]}):
        return deny("delegator-role-collision")
    public = delegator_roots.get(delegator)
    if not isinstance(public, bytes) or len(public) != 32 or hashlib.sha256(public).hexdigest() != delegator:
        return deny("untrusted-delegator")
    encoded = signed_delegation["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-delegation-signature-format")
    try:
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64:
            return deny("invalid-delegation-signature-format")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, DOMAIN + serialized)
    except (InvalidSignature, ValueError, base64.binascii.Error):
        return deny("invalid-delegation-signature")
    return {**_result(), "delegation_valid": True, "state": "pending-review",
            "reason": "authenticated-limited-assessor-delegation-claim-only",
            "organization_id": checked["organization_id"],
            "delegation_revision": body["revision"]}
