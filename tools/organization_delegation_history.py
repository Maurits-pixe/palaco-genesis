#!/usr/bin/env python3
"""Offline signed succession ledger for assessor-delegation status assertions.

Only signed *claims* are checked; the final event can be ACTIVE or REVOKED.
Caller supplies independently pinned genesis/latest digests, revision floor,
authorized status-issuer keys and revocations. No permission is granted.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_delegation_succession_authority",
    Path(__file__).with_name("organization_authority_evidence.py"))
authority = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(authority)

DOMAIN = b"PALACO-ASSESSOR-DELEGATION-STATUS-V1\x00"
DIGEST_DOMAIN = b"PALACO-ASSESSOR-DELEGATION-ENVELOPE-V1\x00"
LINK_DOMAIN = b"PALACO-ASSESSOR-DELEGATION-STATUS-RECORD-V1\x00"
GENESIS = "0" * 64
MAX_RECORDS = 128
BODY_FIELDS = {"schema_version", "revision", "delegation_sha256", "organization_id",
               "assessor_key_id", "status", "previous_record_sha256"}
ENVELOPE_FIELDS = {"status", "issuer_key_id", "signature_b64"}
STATUSES = {"active", "revoked"}
HEX = authority.HEX


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def delegation_digest(envelope):
    return hashlib.sha256(DIGEST_DOMAIN + _json(envelope)).hexdigest()


def canonical(body):
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise ValueError("invalid-delegation-status-schema")
    if body["schema_version"] != "0.1.0" or body["status"] not in STATUSES:
        raise ValueError("invalid-delegation-status")
    if type(body["revision"]) is not int or not 1 <= body["revision"] <= 2147483647:
        raise ValueError("invalid-status-revision")
    org = body["organization_id"]
    if not isinstance(org, str) or not authority.identity.succession.registry.ORGANIZATION.fullmatch(org):
        raise ValueError("invalid-status-organization")
    for field in ("delegation_sha256", "assessor_key_id", "previous_record_sha256"):
        if not isinstance(body[field], str) or not HEX.fullmatch(body[field]):
            raise ValueError("invalid-status-digest")
    return _json(body)


def record_digest(envelope):
    return hashlib.sha256(LINK_DOMAIN + _json(envelope)).hexdigest()


def _result(**kw):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "automatic_restore": False, "recovery_approved": False,
            "delegation_history_valid": False, "state": "quarantined", **kw}


def verify(snapshots, registry_records, signed_identity, signed_delegation,
           status_records, registry_issuer_roots, revoked_registry_issuers,
           assessor_roots, revoked_assessors, allowed_assessors,
           delegator_roots, revoked_delegators, allowed_delegators,
           status_issuer_roots, revoked_status_issuers, allowed_status_issuers,
           trusted_registry_genesis, trusted_registry_head,
           minimum_registry_revision, minimum_delegation_revision,
           trusted_status_genesis, trusted_status_head, minimum_status_revision):
    def deny(reason):
        return _result(reason=reason)
    if (not isinstance(status_issuer_roots, dict)
        or not isinstance(revoked_status_issuers, (set, frozenset))
        or not isinstance(allowed_status_issuers, (set, frozenset))
        or any(not isinstance(k, str) or not HEX.fullmatch(k)
               for k in revoked_status_issuers | allowed_status_issuers)):
        return deny("missing-status-issuer-policy")
    if (not isinstance(trusted_status_genesis, str) or not HEX.fullmatch(trusted_status_genesis)
        or not isinstance(trusted_status_head, str) or not HEX.fullmatch(trusted_status_head)
        or type(minimum_status_revision) is not int or minimum_status_revision < 1):
        return deny("missing-trusted-delegation-history-pins")
    if (not isinstance(status_records, list)
        or not 1 <= len(status_records) <= MAX_RECORDS):
        return deny("invalid-status-history-length")
    delegation = authority.verify(
        snapshots, registry_records, signed_identity, signed_delegation,
        registry_issuer_roots, revoked_registry_issuers,
        assessor_roots, revoked_assessors, allowed_assessors,
        delegator_roots, revoked_delegators, allowed_delegators,
        trusted_registry_genesis, trusted_registry_head,
        minimum_registry_revision, minimum_delegation_revision)
    if not delegation["delegation_valid"]:
        return deny(delegation["reason"])
    target = delegation_digest(signed_delegation)
    organization = signed_delegation["delegation"]["organization_id"]
    assessor = signed_delegation["delegation"]["assessor_key_id"]
    previous = GENESIS
    previous_revision = None
    revoked_targets = set()
    current = None
    for position, envelope in enumerate(status_records):
        if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
            return deny("invalid-status-envelope")
        try:
            message = canonical(envelope["status"])
        except (ValueError, TypeError, OverflowError) as exc:
            return deny(str(exc))
        body = envelope["status"]
        if (body["organization_id"] != organization or body["assessor_key_id"] != assessor
            or body["delegation_sha256"] != target):
            return deny("status-delegation-binding-mismatch")
        if previous_revision is not None and body["revision"] != previous_revision + 1:
            return deny("status-revision-gap")
        if body["previous_record_sha256"] != previous:
            return deny("status-chain-link-mismatch")
        if position == 0 and record_digest(envelope) != trusted_status_genesis:
            return deny("untrusted-status-genesis")
        issuer = envelope["issuer_key_id"]
        if not isinstance(issuer, str) or not HEX.fullmatch(issuer):
            return deny("invalid-status-issuer")
        if issuer in revoked_status_issuers:
            return deny("status-issuer-revoked")
        if issuer not in allowed_status_issuers:
            return deny("status-issuer-not-allowed")
        if (issuer == assessor or issuer == signed_delegation["delegator_key_id"]
            or issuer in {snap["issuer_key_id"] for snap in snapshots}
            or issuer in {row["witness_key_id"] for snap in snapshots
                         for row in snap["registry"]["witnesses"]}):
            return deny("status-issuer-role-collision")
        pub = status_issuer_roots.get(issuer)
        if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != issuer:
            return deny("untrusted-status-issuer")
        text = envelope["signature_b64"]
        if not isinstance(text, str) or len(text) > 96:
            return deny("invalid-status-signature-format")
        try:
            signature = base64.b64decode(text, validate=True)
        except (ValueError, base64.binascii.Error):
            return deny("invalid-status-signature-format")
        if len(signature) != 64:
            return deny("invalid-status-signature-format")
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(signature, DOMAIN + message)
        except (InvalidSignature, ValueError):
            return deny("invalid-status-signature")
        if position == 0 and body["status"] != "active":
            return deny("status-history-not-activated")
        if target in revoked_targets and body["status"] == "active":
            return deny("revoked-delegation-resurrected")
        if body["status"] == "revoked":
            if target in revoked_targets:
                return deny("duplicate-revocation")
            revoked_targets.add(target)
        previous_revision = body["revision"]
        previous = record_digest(envelope)
        current = body["status"]
    if previous_revision < minimum_status_revision:
        return deny("status-history-rollback")
    if previous != trusted_status_head:
        return deny("status-history-head-mismatch")
    if current != "active":
        return deny("delegation-revoked")
    return {**_result(), "delegation_history_valid": True, "state": "pending-review",
            "reason": "signed-delegation-status-chain-only-no-authority",
            "status_revision": previous_revision, "head_hash": previous}
