#!/usr/bin/env python3
"""Issuer-signed witness organization registry for custody-ack evidence quorum.

A distinct key is not a proof of organizational independence. Organization
identifiers must be authenticated in governance outside this program.
Rotations and revocations are represented by signed register revisions.
No issuance, network lookup, key ceremony, authorization or deployment.
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
    "palaco_registry_witness_quorum", Path(__file__).with_name("custody_ack_witness_quorum.py"))
quorum = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(quorum)

DOMAIN = b"PALACO-CUSTODY-WITNESS-REGISTRY-V1\x00"
ORGANIZATION = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
FIELDS = {"schema_version", "revision", "minimum_organizations", "witnesses"}
ENVELOPE_FIELDS = {"registry", "issuer_key_id", "signature_b64"}
WITNESS_FIELDS = {"organization_id", "witness_key_id", "status"}
STATUSES = {"active", "revoked"}
MAX_RECORDS = 64


def canonical_registry(body):
    if not isinstance(body, dict) or set(body) != FIELDS:
        raise ValueError("invalid-registry-schema")
    if body["schema_version"] != "0.1.0":
        raise ValueError("invalid-registry-version")
    if type(body["revision"]) is not int or not 1 <= body["revision"] <= 2147483647:
        raise ValueError("invalid-registry-revision")
    threshold = body["minimum_organizations"]
    if type(threshold) is not int or not 2 <= threshold <= quorum.MAX_WITNESSES:
        raise ValueError("invalid-organization-threshold")
    witnesses = body["witnesses"]
    if not isinstance(witnesses, list) or not threshold <= len(witnesses) <= MAX_RECORDS:
        raise ValueError("invalid-registry-witnesses")
    seen_keys = set()
    active_organizations = set()
    previous = ""
    for row in witnesses:
        if not isinstance(row, dict) or set(row) != WITNESS_FIELDS:
            raise ValueError("invalid-witness-entry")
        org, key, status = row["organization_id"], row["witness_key_id"], row["status"]
        if not isinstance(org, str) or not ORGANIZATION.fullmatch(org):
            raise ValueError("invalid-witness-organization")
        if not isinstance(key, str) or not quorum.signed.chain.HEX.fullmatch(key):
            raise ValueError("invalid-witness-fingerprint")
        if not isinstance(status, str) or status not in STATUSES:
            raise ValueError("invalid-witness-status")
        if key in seen_keys:
            raise ValueError("witness-key-reused-across-organizations")
        if key <= previous:
            raise ValueError("registry-keys-not-sorted")
        if status == "active":
            if org in active_organizations:
                raise ValueError("multiple-active-keys-per-organization")
            active_organizations.add(org)
        previous = key
        seen_keys.add(key)
    if len(active_organizations) < threshold:
        raise ValueError("insufficient-active-organizations")
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _base(**kw):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "registry_quorum_valid": False, "state": "quarantined", **kw}


def verify(receipt_db, signed_registry, witness_envelopes, issuer_roots,
           revoked_issuers, witness_roots, externally_revoked_witnesses,
           minimum_registry_revision, minimum_events,
           minimum_organizations):
    def deny(reason):
        return _base(reason=reason)
    if (not isinstance(issuer_roots, dict) or not isinstance(witness_roots, dict)
        or not isinstance(revoked_issuers, (set, frozenset))
        or not isinstance(externally_revoked_witnesses, (set, frozenset))):
        return deny("missing-trusted-registry-policy")
    if any(not isinstance(x, str) or not quorum.signed.chain.HEX.fullmatch(x)
           for x in revoked_issuers | externally_revoked_witnesses):
        return deny("invalid-trusted-revocations")
    if (type(minimum_registry_revision) is not int or minimum_registry_revision < 1
        or type(minimum_organizations) is not int
        or not 2 <= minimum_organizations <= quorum.MAX_WITNESSES):
        return deny("missing-trusted-registry-floor")
    if not isinstance(signed_registry, dict) or set(signed_registry) != ENVELOPE_FIELDS:
        return deny("invalid-registry-envelope")
    try:
        canonical = canonical_registry(signed_registry["registry"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    registry = signed_registry["registry"]
    if registry["revision"] < minimum_registry_revision:
        return deny("stale-witness-registry")
    key_id = signed_registry["issuer_key_id"]
    if not isinstance(key_id, str) or not quorum.signed.chain.HEX.fullmatch(key_id):
        return deny("invalid-registry-issuer")
    if key_id in revoked_issuers:
        return deny("registry-issuer-revoked")
    public = issuer_roots.get(key_id)
    if not isinstance(public, bytes) or len(public) != 32 or hashlib.sha256(public).hexdigest() != key_id:
        return deny("untrusted-registry-issuer")
    encoded = signed_registry["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-registry-signature-format")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-registry-signature-format")
    if len(signature) != 64:
        return deny("invalid-registry-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, DOMAIN + canonical)
    except (InvalidSignature, ValueError):
        return deny("invalid-registry-signature")
    active = {row["witness_key_id"]: row["organization_id"] for row in registry["witnesses"]
              if row["status"] == "active"}
    if key_id in active:
        return deny("issuer-witness-role-collision")
    allowed = set(active) - externally_revoked_witnesses
    threshold = max(registry["minimum_organizations"], minimum_organizations)
    if len({active[k] for k in allowed}) < threshold:
        return deny("insufficient-eligible-organizations")
    if not isinstance(witness_envelopes, list):
        return deny("invalid-witness-submissions")
    organizations = set()
    for env in witness_envelopes:
        if not isinstance(env, dict) or set(env) != quorum.signed.ENVELOPE_FIELDS:
            return deny("invalid-witness-envelope")
        witness_id = env.get("witness_key_id")
        if witness_id not in active:
            return deny("witness-key-not-active-in-registry")
        org = active[witness_id]
        if org in organizations:
            return deny("duplicate-witness-organization")
        organizations.add(org)
    if len(organizations) < threshold:
        return deny("insufficient-distinct-organizations")
    checked = quorum.verify(receipt_db, witness_envelopes, witness_roots,
                            allowed, externally_revoked_witnesses,
                            threshold, minimum_events)
    if not checked["quorum_valid"]:
        return deny(checked["reason"])
    return {**_base(), "registry_quorum_valid": True, "state": "pending-review",
            "reason": "signed-registry-organizational-evidence-only",
            "revision": registry["revision"], "organizations": len(organizations),
            "entries": checked["entries"], "head_hash": checked["head_hash"]}
