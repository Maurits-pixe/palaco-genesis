"""PALACO v14 portable governance proof bundle (draft, read-only).

The bundle can carry sensitive opaque receipts: keep it in an isolated test
environment until encryption, redaction and access policy are implemented.
No signed provenance, recovery permission or production release is granted.
"""
import hashlib
import json

from offline_stage import _canonical
from recovery_governance_v12 import GovernanceError, inspect_governance, replay_reviews
from secure_policy_recovery_v11 import approval_bytes, RestoreError

SCHEMA = "palaco-governance-proof-bundle/v14"
DOMAIN = b"PALACO-GOVERNANCE-PROOF-BUNDLE-v14:SHA256\x00"
MAX_BUNDLE_BYTES = 2_097_152


class ProofBundleError(ValueError):
    pass


def _validate_binding(plan, backup_bytes, evidence_bytes):
    if type(backup_bytes) is not bytes or type(evidence_bytes) is not bytes:
        raise ProofBundleError("INVALID_EVIDENCE_BYTES")
    if type(plan) is not dict:
        raise ProofBundleError("INVALID_PLAN")
    if hashlib.sha256(evidence_bytes).hexdigest() != plan.get("evidence_sha256"):
        raise ProofBundleError("EVIDENCE_DIGEST_MISMATCH")
    try:
        statement = approval_bytes(
            data=backup_bytes,
            destination_name=plan["destination_name"],
            sequence=plan["sequence"], head=plan["head"])
    except (RestoreError, KeyError, ValueError, TypeError) as exc:
        raise ProofBundleError("INVALID_RECOVERY_BINDING") from exc
    if hashlib.sha256(statement).hexdigest() != plan.get("proposal_sha256"):
        raise ProofBundleError("BACKUP_BINDING_MISMATCH")


def make_bundle(plan, reviews, *, backup_bytes, evidence_bytes):
    """Export strict canonical bytes. No external trust is asserted."""
    _validate_binding(plan, backup_bytes, evidence_bytes)
    try:
        head = replay_reviews(reviews, plan=plan)
    except GovernanceError as exc:
        raise ProofBundleError("INVALID_REVIEW_CHAIN") from exc
    if not reviews:
        raise ProofBundleError("EMPTY_REVIEW_HISTORY")
    data = {
        "schema": SCHEMA, "plan": plan,
        "reviews": list(reviews), "review_head": head,
        "review_count": len(reviews),
        "backup_sha256": hashlib.sha256(backup_bytes).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest()
    }
    encoded = _canonical(data)
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ProofBundleError("BUNDLE_TOO_LARGE")
    return encoded


def verify_bundle(bundle_bytes, *, backup_bytes, evidence_bytes,
                  verify_role=None, get_trusted_audit_anchor=None):
    """Verify bundle, exact source bytes, review chain and external trust.

    Any positive review result is diagnostic only; output stays DENY/HOLD.
    Neither the bundle nor its own hash can supply the trust anchor.
    """
    if type(bundle_bytes) is not bytes or not 1 <= len(bundle_bytes) <= MAX_BUNDLE_BYTES:
        raise ProofBundleError("INVALID_BUNDLE_SIZE")
    try:
        value = json.loads(bundle_bytes.decode("ascii"))
        if type(value) is not dict or set(value) != {
            "schema", "plan", "reviews", "review_head",
            "review_count", "backup_sha256", "evidence_sha256"
        } or value["schema"] != SCHEMA or type(value["reviews"]) is not list:
            raise ProofBundleError("INVALID_BUNDLE_SCHEMA")
        if _canonical(value) != bundle_bytes:
            raise ProofBundleError("NONCANONICAL_BUNDLE")
        _validate_binding(value["plan"], backup_bytes, evidence_bytes)
        if value["backup_sha256"] != hashlib.sha256(backup_bytes).hexdigest():
            raise ProofBundleError("BACKUP_DIGEST_MISMATCH")
        if value["evidence_sha256"] != hashlib.sha256(evidence_bytes).hexdigest():
            raise ProofBundleError("EVIDENCE_DIGEST_MISMATCH")
        head = replay_reviews(value["reviews"], plan=value["plan"])
        if (not value["reviews"] or type(value["review_count"]) is not int or
                value["review_count"] != len(value["reviews"]) or
                value["review_head"] != head):
            raise ProofBundleError("REVIEW_HEAD_MISMATCH")
        report = inspect_governance(
            value["reviews"], plan=value["plan"], verify_role=verify_role,
            get_trusted_audit_anchor=get_trusted_audit_anchor)
    except ProofBundleError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, GovernanceError) as exc:
        raise ProofBundleError("PROOF_NOT_VERIFIED") from exc
    return {
        "schema": "palaco-governance-proof-inspection/v14",
        "bundle_sha256": hashlib.sha256(DOMAIN + bundle_bytes).hexdigest(),
        "proposal_sha256": value["plan"]["proposal_sha256"],
        "review_head": head, "review_count": len(value["reviews"]),
        "candidate_review_complete": report["candidate_review_complete"],
        "external_callbacks_accepted": True,
        "authorization": "DENY", "release": "HOLD",
        "production_release_enabled": False
    }
