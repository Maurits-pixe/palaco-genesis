"""Fail-closed signed-evidence submission gate for human recovery review.

The external verifier MUST cryptographically verify the signature, reviewer
identity, role, key revocation and challenge freshness using trusted data.
This module provides no signing key, signature algorithm, trust store or
authority to repair, reset, merge, publish or import PALACO records.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from protocol import TransferError
from recovery_evidence import RecoveryEvidence, verify_evidence

DOMAIN = b"PALACO:BT:RECOVERY-REVIEW:V1\0"
MAX_SIGNATURE_BYTES = 512
MAX_KEY_ID = 128


class ReviewDisposition(Enum):
    """A successfully checked submission is still HOLD, never authorization."""

    HOLD_REVIEWABLE = "hold_reviewable"


@dataclass(frozen=True)
class SignedReviewSubmission:
    evidence: RecoveryEvidence
    reviewer_key_id: str
    challenge: bytes
    signature: bytes


class TrustedReviewVerifier(Protocol):
    """Privileged external signature and access-control verifier."""

    def verify(
        self, reviewer_key_id: str, message: bytes, signature: bytes,
    ) -> bool:
        """Return true only when signature, reviewer role and freshness pass."""


def signing_message(evidence: RecoveryEvidence, challenge: bytes) -> bytes:
    """Domain-bind the exact evidence bytes to a fresh external challenge."""
    if not verify_evidence(evidence):
        raise TransferError("invalid recovery evidence")
    if not isinstance(challenge, bytes) or not 16 <= len(challenge) <= 64:
        raise TransferError("invalid challenge")
    raw = evidence.canonical_json.encode("ascii")
    return DOMAIN + len(challenge).to_bytes(2, "big") + challenge + len(raw).to_bytes(4, "big") + raw


def assess_review_submission(
    submission: SignedReviewSubmission, verifier: TrustedReviewVerifier,
) -> ReviewDisposition:
    """Allow review intake, NOT execution, only after external verification."""
    if type(submission) is not SignedReviewSubmission:
        raise TransferError("signed review submission required")
    key_id = submission.reviewer_key_id
    if (type(key_id) is not str or not 1 <= len(key_id) <= MAX_KEY_ID
            or any(not (c.isascii() and (c.isalnum() or c in "-_.")) for c in key_id)):
        raise TransferError("invalid reviewer key identifier")
    signature = submission.signature
    if not isinstance(signature, bytes) or not 32 <= len(signature) <= MAX_SIGNATURE_BYTES:
        raise TransferError("invalid signature bytes")
    if not callable(getattr(verifier, "verify", None)):
        raise TransferError("trusted verifier unavailable")
    message = signing_message(submission.evidence, submission.challenge)
    try:
        passed = verifier.verify(key_id, message, signature)
    except Exception as exc:
        raise TransferError("signature verification unavailable") from exc
    if type(passed) is not bool or not passed:
        raise TransferError("signed reviewer verification denied")
    return ReviewDisposition.HOLD_REVIEWABLE
