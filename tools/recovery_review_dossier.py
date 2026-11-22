#!/usr/bin/env python3
"""Immutable-shaped, hashable human recovery review dossier (HOLD).

No restore, authorization, signature issuance, or persistence. A supplied
operator assertion is descriptive only and is NOT a permission credential.
"""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "palaco_recovery_dossier_assessment", ROOT / "checkpoint_recovery_assessment.py")
assessment = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(assessment)

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
REVIEW_FIELDS = {"reviewer_id", "decision", "reason", "reviewed_at_utc"}
DECISIONS = {"request-review", "reject", "defer"}


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _review(review):
    if not isinstance(review, dict) or set(review) != REVIEW_FIELDS:
        raise ValueError("invalid-manual-review")
    if not isinstance(review["reviewer_id"], str) or not ID.fullmatch(review["reviewer_id"]):
        raise ValueError("invalid-reviewer-id")
    if review["decision"] not in DECISIONS:
        raise ValueError("unsupported-review-decision")
    if not isinstance(review["reason"], str) or not 1 <= len(review["reason"]) <= 256:
        raise ValueError("invalid-review-reason")
    if any(ord(ch) < 32 for ch in review["reason"]):
        raise ValueError("invalid-review-reason")
    # Require explicitly supplied UTC timestamp; not trusted wall-clock proof.
    assessment.checkpoint.audit  # no action; dependencies imported above
    from datetime import datetime
    value = review["reviewed_at_utc"]
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError("invalid-review-time")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("invalid-review-time") from exc


def prepare_dossier(evidence_db, checkpoint_db, witness, issuer_roots,
                    revoked_issuers, minimum_sequence, manual_review):
    """Read-only assessment and stable digest of a review *claim*.

    Caller input can be forged; no independently authenticated identity,
    signature, trusted clock, consent, or remote immutable logging exists.
    """
    _review(manual_review)
    result = assessment.assess(
        evidence_db, checkpoint_db, witness, issuer_roots,
        revoked_issuers, minimum_sequence
    )
    if not isinstance(witness, dict):
        witness_fingerprint = None
    else:
        try:
            witness_fingerprint = hashlib.sha256(canonical(witness)).hexdigest()
        except (TypeError, ValueError, OverflowError):
            witness_fingerprint = None
    record = {
        "schema_version": "0.1.0",
        "record_type": "local-recovery-review-dossier",
        "assessment_state": result["state"],
        "assessment_reason": result["reason"],
        "witness_sha256": witness_fingerprint,
        "issuer_key_id": witness.get("issuer_key_id") if isinstance(witness, dict)
            and isinstance(witness.get("issuer_key_id"), str)
            and HEX.fullmatch(witness["issuer_key_id"]) else None,
        "witness_sequence": result.get("witness_sequence"),
        "witness_head": result.get("witness_head"),
        "manual_review": dict(manual_review),
        "required_follow_up": (
            "independent-security-review" if result["state"] == "pending-review"
            else "investigate-and-quarantine"
        ),
    }
    digest = hashlib.sha256(b"PALACO-RECOVERY-DOSSIER-V1\x00" + canonical(record)).hexdigest()
    return {
        "release_gate": "HOLD", "authorization_granted": False,
        "recovery_approved": False, "automatic_restore": False,
        "dossier": record, "dossier_sha256": digest,
        "digest_is_authentication": False,
    }


def verify_dossier(dossier, expected_sha256):
    """Check canonical integrity only; never proof of signer or authority."""
    if not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256):
        return False
    if not isinstance(dossier, dict) or set(dossier) != {
        "schema_version", "record_type", "assessment_state", "assessment_reason",
        "witness_sha256", "issuer_key_id", "witness_sequence", "witness_head",
        "manual_review", "required_follow_up"
    }:
        return False
    try:
        _review(dossier["manual_review"])
        return hashlib.sha256(
            b"PALACO-RECOVERY-DOSSIER-V1\x00" + canonical(dossier)
        ).hexdigest() == expected_sha256
    except (ValueError, TypeError, OverflowError):
        return False
