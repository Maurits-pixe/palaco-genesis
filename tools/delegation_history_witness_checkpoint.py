#!/usr/bin/env python3
"""Independent Ed25519 witness quorum over a pinned assessor-delegation history.

Evidence-only: never releases, authorizes, restores, signs or sends anything.
The caller independently authenticates the status-chain genesis/head, revision
floor, witness organizational roster, public keys and revocations.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_signed_delegation_history_source",
    Path(__file__).with_name("organization_delegation_history.py"))
history = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(history)

DOMAIN = b"PALACO-DELEGATION-HISTORY-WITNESS-V1\x00"
BODY_FIELDS = {"schema_version", "organization_id", "assessor_key_id",
               "delegation_sha256", "status_genesis_sha256",
               "status_head_sha256", "status_revision"}
ENVELOPE_FIELDS = {"checkpoint", "witness_key_id", "signature_b64"}
MAX_WITNESSES = 16
HISTORY_ARGS = {
    "snapshots", "registry_records", "signed_identity", "signed_delegation",
    "registry_issuer_roots", "revoked_registry_issuers",
    "assessor_roots", "revoked_assessors", "allowed_assessors",
    "delegator_roots", "revoked_delegators", "allowed_delegators",
    "status_issuer_roots", "revoked_status_issuers", "allowed_status_issuers",
    "trusted_registry_genesis", "trusted_registry_head",
    "minimum_registry_revision", "minimum_delegation_revision",
    "trusted_status_genesis", "trusted_status_head", "minimum_status_revision"
}


def canonical(body):
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise ValueError("invalid-delegation-checkpoint-schema")
    if body["schema_version"] != "0.1.0":
        raise ValueError("invalid-delegation-checkpoint-version")
    if not isinstance(body["organization_id"], str) or not history.authority.identity.succession.registry.ORGANIZATION.fullmatch(body["organization_id"]):
        raise ValueError("invalid-checkpoint-organization")
    if type(body["status_revision"]) is not int or not 1 <= body["status_revision"] <= 2147483647:
        raise ValueError("invalid-checkpoint-revision")
    for field in ("assessor_key_id", "delegation_sha256", "status_genesis_sha256", "status_head_sha256"):
        if not isinstance(body[field], str) or not history.HEX.fullmatch(body[field]):
            raise ValueError("invalid-checkpoint-digest")
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _out(**fields):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "automatic_restore": False, "recovery_approved": False,
            "checkpoint_quorum_valid": False, "state": "quarantined", **fields}


def verify(history_inputs, status_records, witness_envelopes, witness_roots,
           witness_organizations, revoked_witnesses, minimum_organizations):
    def deny(reason):
        return _out(reason=reason)
    if not isinstance(history_inputs, dict) or set(history_inputs) != HISTORY_ARGS:
        return deny("missing-trusted-history-inputs")
    if (not isinstance(witness_roots, dict)
        or not isinstance(witness_organizations, dict)
        or not isinstance(revoked_witnesses, (set, frozenset))
        or type(minimum_organizations) is not int
        or not 2 <= minimum_organizations <= MAX_WITNESSES):
        return deny("missing-independent-witness-policy")
    for key, organization in witness_organizations.items():
        if (not isinstance(key, str) or not history.HEX.fullmatch(key)
            or not isinstance(organization, str)
            or not history.authority.identity.succession.registry.ORGANIZATION.fullmatch(organization)):
            return deny("invalid-witness-organization-policy")
    if any(not isinstance(key, str) or not history.HEX.fullmatch(key)
           for key in revoked_witnesses):
        return deny("invalid-witness-revocations")
    eligible = set(witness_organizations) - revoked_witnesses
    if len({witness_organizations[key] for key in eligible}) < minimum_organizations:
        return deny("insufficient-eligible-organizations")
    if (not isinstance(witness_envelopes, list)
        or not minimum_organizations <= len(witness_envelopes) <= MAX_WITNESSES):
        return deny("invalid-witness-submission-count")
    # Revalidate all signature layers and independently pinned hash chain
    # before trusting any witness statement as corroborating history.
    checked = history.verify(status_records=status_records, **history_inputs)
    if not checked["delegation_history_valid"]:
        return deny(checked["reason"])
    delegation = history_inputs["signed_delegation"]["delegation"]
    expected = {
        "schema_version": "0.1.0",
        "organization_id": delegation["organization_id"],
        "assessor_key_id": delegation["assessor_key_id"],
        "delegation_sha256": history.delegation_digest(history_inputs["signed_delegation"]),
        "status_genesis_sha256": history_inputs["trusted_status_genesis"],
        "status_head_sha256": checked["head_hash"],
        "status_revision": checked["status_revision"]
    }
    previous_witnesses = set()
    previous_organizations = set()
    forbidden = {
        history_inputs["signed_identity"]["assessor_key_id"],
        history_inputs["signed_delegation"]["delegator_key_id"],
        *[snapshot["issuer_key_id"] for snapshot in history_inputs["snapshots"]],
        *[row["witness_key_id"] for snapshot in history_inputs["snapshots"]
          for row in snapshot["registry"]["witnesses"]],
        *[record["issuer_key_id"] for record in status_records]
    }
    for envelope in witness_envelopes:
        if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
            return deny("invalid-witness-envelope")
        try:
            data = canonical(envelope["checkpoint"])
        except (TypeError, ValueError, OverflowError) as exc:
            return deny(str(exc))
        if envelope["checkpoint"] != expected:
            return deny("conflicting-delegation-checkpoint")
        key = envelope["witness_key_id"]
        if not isinstance(key, str) or not history.HEX.fullmatch(key):
            return deny("invalid-witness-id")
        if key in previous_witnesses:
            return deny("duplicate-delegation-witness")
        previous_witnesses.add(key)
        if key in revoked_witnesses:
            return deny("delegation-witness-revoked")
        org = witness_organizations.get(key)
        if org is None:
            return deny("delegation-witness-not-allowed")
        if org in previous_organizations:
            return deny("duplicate-witness-organization")
        previous_organizations.add(org)
        if key in forbidden:
            return deny("witness-role-collision")
        pub = witness_roots.get(key)
        if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != key:
            return deny("untrusted-delegation-witness")
        encoded = envelope["signature_b64"]
        if not isinstance(encoded, str) or len(encoded) > 96:
            return deny("invalid-witness-signature-format")
        try:
            signature = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            return deny("invalid-witness-signature-format")
        if len(signature) != 64:
            return deny("invalid-witness-signature-format")
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(signature, DOMAIN + data)
        except (InvalidSignature, ValueError):
            return deny("invalid-delegation-witness-signature")
    if len(previous_organizations) < minimum_organizations:
        return deny("insufficient-distinct-witness-organizations")
    return {**_out(), "checkpoint_quorum_valid": True, "state": "pending-review",
            "reason": "witnessed-delegation-history-no-operational-authority",
            "organizations": len(previous_organizations),
            "status_revision": checked["status_revision"],
            "head_hash": checked["head_hash"]}
