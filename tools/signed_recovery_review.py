#!/usr/bin/env python3
"""Ed25519 signed recovery review declaration; never restores or grants authority.

Reviewer's key eligibility is checked against a separately issuer-signed reviewer
snapshot. Roots, revocation policy, time and revision floor MUST be authenticated
outside this prototype. Signature validity is not human consent or authorization.
"""
import base64
import hashlib
import importlib.util
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dossiers = _load("palaco_signed_review_dossiers", "recovery_review_dossier.py")
reviewers = _load("palaco_signed_review_registry", "signed_reviewer_registry.py")

DOMAIN = b"PALACO-RECOVERY-REVIEW-V1\x00"
FIELDS = {"schema_version", "dossier_sha256", "reviewer_id", "decision", "reason", "reviewed_at_utc"}
ENVELOPE = {"declaration", "key_id", "signature_b64"}
HEX = re.compile(r"^[0-9a-f]{64}$")


def canonical_declaration(declaration):
    if not isinstance(declaration, dict) or set(declaration) != FIELDS:
        raise ValueError("invalid-declaration-schema")
    if declaration["schema_version"] != "0.1.0":
        raise ValueError("unsupported-declaration-version")
    if not isinstance(declaration["dossier_sha256"], str) or not HEX.fullmatch(declaration["dossier_sha256"]):
        raise ValueError("invalid-dossier-digest")
    dossiers._review({k: declaration[k] for k in dossiers.REVIEW_FIELDS})
    return dossiers.canonical(declaration)


def verify_declaration(dossier, envelope, reviewer_public_keys, revoked_reviewer_keys,
                       signed_registry, issuer_roots, at_utc, minimum_revision):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "review_signature_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE:
        return deny("invalid-envelope")
    if not isinstance(reviewer_public_keys, dict) or not isinstance(revoked_reviewer_keys, (set, frozenset)):
        return deny("missing-reviewer-key-policy")
    if any(not isinstance(x, str) or not HEX.fullmatch(x) for x in revoked_reviewer_keys):
        return deny("invalid-revocation-list")
    try:
        signed = canonical_declaration(envelope["declaration"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    declaration = envelope["declaration"]
    digest = declaration["dossier_sha256"]
    if not dossiers.verify_dossier(dossier, digest):
        return deny("dossier-binding-failed")
    if any(declaration[k] != dossier["manual_review"][k] for k in dossiers.REVIEW_FIELDS):
        return deny("review-claim-binding-failed")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not HEX.fullmatch(key_id):
        return deny("invalid-key-id")
    if key_id in revoked_reviewer_keys:
        return deny("reviewer-key-revoked")
    eligibility = reviewers.evaluate(
        signed_registry, issuer_roots, declaration["reviewer_id"],
        key_id, at_utc, minimum_revision
    )
    if not eligibility["reviewer_eligible_for_manual_review"]:
        return deny(eligibility["reason"])
    public_key = reviewer_public_keys.get(key_id)
    if not isinstance(public_key, bytes) or len(public_key) != 32 or hashlib.sha256(public_key).hexdigest() != key_id:
        return deny("untrusted-reviewer-key")
    signature_b64 = envelope["signature_b64"]
    if not isinstance(signature_b64, str) or len(signature_b64) > 96:
        return deny("invalid-signature-format")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-signature-format")
    if len(signature) != 64:
        return deny("invalid-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, DOMAIN + signed)
    except (InvalidSignature, ValueError):
        return deny("invalid-review-signature")
    return {**base, "review_signature_valid": True, "state": "pending-review",
            "reason": "review-signature-valid-but-no-restore-authority",
            "dossier_sha256": digest, "reviewer_key_id": key_id}
