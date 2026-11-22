"""Offline end-to-end recovery review intake (HOLD-only).

Integrates independently anchored root-signed reviewer policies, genuine
Ed25519 signatures and one-time persisted challenges. No automatic recovery,
import or execution. The native host must independently secure the anchor,
clock, reviewer private keys and SQLite challenge ledger against rollback.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from protocol import TransferError
from protected_policy_gate import AnchoredReviewVerifier, ProtectedPolicyAnchor
from recovery_evidence import RecoveryEvidence
from review_challenges import PersistentReviewChallenges
from signed_review_gate import (
    ReviewDisposition, SignedReviewSubmission,
)
from signed_reviewer_policy import SignedReviewerPolicy


class RecoveryReviewIntake:
    """Explicit review-only integration; never grants authorization."""

    def __init__(
        self,
        signed_policy: SignedReviewerPolicy,
        trusted_policy_anchor: ProtectedPolicyAnchor,
        trusted_utc_clock: Callable[[], int],
        challenge_database: Path,
        *, create_new_registry: bool = False,
    ) -> None:
        if type(create_new_registry) is not bool:
            raise TransferError("explicit registry mode required")
        self._verifier = AnchoredReviewVerifier(
            signed_policy, trusted_policy_anchor, trusted_utc_clock,
        )
        if create_new_registry:
            self._challenges = PersistentReviewChallenges(
                challenge_database, trusted_utc_clock,
            )
        else:
            self._challenges = PersistentReviewChallenges.reopen(
                challenge_database, trusted_utc_clock,
            )

    def issue_challenge(
        self, evidence: RecoveryEvidence, reviewer_key_id: str,
    ) -> bytes:
        """Issue an evidence-bound one-shot challenge, never a grant."""
        return self._challenges.issue(evidence, reviewer_key_id)

    def submit(
        self, signed_submission: SignedReviewSubmission,
    ) -> ReviewDisposition:
        """Verify genuine signature then consume challenge; result always HOLD."""
        return self._challenges.submit(signed_submission, self._verifier)
