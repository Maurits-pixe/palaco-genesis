//! Deterministic, non-authorizing review receipts for offline orphan recovery.
//!
//! A recorded human *intent* is not a verified identity, authorization or cleanup permit.

use sha2::{Digest, Sha256};

use crate::{
    offline_orphan::OrphanState,
    offline_recovery_review::{RecoveryReview, RecoveryReviewState},
};

/// Human-facing intent; none of these values grants a filesystem capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryIntent {
    /// Keep the candidate unchanged for subsequent review.
    Defer,
    /// Reject any proposed cleanup.
    Reject,
    /// Ask a separate authorized operator to assess possible quarantine.
    RequestQuarantineReview,
}

/// Bounded, unauthenticated operator-provided attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewAttribution {
    /// External actor reference, not an authenticated identity proof.
    pub actor_reference: [u8; 32],
    /// One-time caller-provided evidence identifier; uniqueness is NOT enforced.
    pub evidence_nonce: [u8; 32],
}

/// A review-only receipt, never an executable permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryIntentReceipt {
    /// Sequence under review.
    pub sequence: u64,
    /// Recorded operator preference.
    pub intent: RecoveryIntent,
    /// Attribution supplied by the caller.
    pub attribution: ReviewAttribution,
    /// Domain-separated SHA-256 digest of the review statement.
    pub statement_sha256: [u8; 32],
    /// Always false: review receipts cannot authorize recovery.
    pub execution_allowed: bool,
}

/// A reason that an intent receipt cannot be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    /// Blank or inconsistent external identity/evidence markers.
    InvalidAttribution,
    /// Request would violate the review-only contract.
    UnsupportedIntent,
}

/// Produce a deterministic review statement, without persistence or mutations.
///
/// SHA-256 is a checksum over caller-provided values, not a signature. The
/// caller must authenticate the actor and replay-protect nonces elsewhere.
pub fn record_recovery_intent(
    review: &RecoveryReview,
    attribution: ReviewAttribution,
    intent: RecoveryIntent,
) -> Result<RecoveryIntentReceipt, ReceiptError> {
    if review.sequence == 0
        || attribution.actor_reference == [0; 32]
        || attribution.evidence_nonce == [0; 32]
    {
        return Err(ReceiptError::InvalidAttribution);
    }
    if review.execution_allowed {
        return Err(ReceiptError::UnsupportedIntent);
    }
    if intent == RecoveryIntent::RequestQuarantineReview
        && (review.state != RecoveryReviewState::MatchingPendingHold
            || review.observed != OrphanState::PendingOnly)
    {
        return Err(ReceiptError::UnsupportedIntent);
    }

    let state_tag: u8 = match review.state {
        RecoveryReviewState::NoPendingObserved => 0,
        RecoveryReviewState::MatchingPendingHold => 1,
        RecoveryReviewState::MissingExpectedEvidenceHold => 2,
        RecoveryReviewState::EvidenceMismatchHold => 3,
        RecoveryReviewState::InvalidInspectionHold => 4,
    };
    let observed_tag: u8 = match review.observed {
        OrphanState::NoPending => 0,
        OrphanState::PendingOnly => 1,
        OrphanState::PendingAndPublished => 2,
    };
    let intent_tag: u8 = match intent {
        RecoveryIntent::Defer => 0,
        RecoveryIntent::Reject => 1,
        RecoveryIntent::RequestQuarantineReview => 2,
    };
    let mut hash = Sha256::new();
    hash.update(b"PALACO/ORCH-047/RECOVERY-INTENT/V1");
    hash.update(review.sequence.to_be_bytes());
    hash.update([state_tag, observed_tag, intent_tag]);
    hash.update(attribution.actor_reference);
    hash.update(attribution.evidence_nonce);

    Ok(RecoveryIntentReceipt {
        sequence: review.sequence,
        intent,
        attribution,
        statement_sha256: hash.finalize().into(),
        execution_allowed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::{record_recovery_intent, ReceiptError, RecoveryIntent, ReviewAttribution};
    use crate::{
        offline_orphan::OrphanState,
        offline_recovery_review::{RecoveryReview, RecoveryReviewState},
    };

    fn review(state: RecoveryReviewState, observed: OrphanState) -> RecoveryReview {
        RecoveryReview {
            sequence: 7,
            observed,
            state,
            execution_allowed: false,
        }
    }

    fn actor() -> ReviewAttribution {
        ReviewAttribution {
            actor_reference: [4; 32],
            evidence_nonce: [5; 32],
        }
    }

    #[test]
    fn matching_pending_records_request_but_never_executes() {
        let result = record_recovery_intent(
            &review(RecoveryReviewState::MatchingPendingHold, OrphanState::PendingOnly),
            actor(),
            RecoveryIntent::RequestQuarantineReview,
        );
        assert!(matches!(result, Ok(value) if !value.execution_allowed));
    }

    #[test]
    fn checksum_is_deterministic_and_context_bound() {
        let candidate = review(RecoveryReviewState::MatchingPendingHold, OrphanState::PendingOnly);
        let first = record_recovery_intent(&candidate, actor(), RecoveryIntent::Defer);
        let second = record_recovery_intent(&candidate, actor(), RecoveryIntent::Defer);
        assert_eq!(first, second);
        let different = record_recovery_intent(&candidate, actor(), RecoveryIntent::Reject);
        assert!(matches!((first, different), (Ok(a), Ok(b)) if a.statement_sha256 != b.statement_sha256));
    }

    #[test]
    fn mismatch_cannot_request_quarantine() {
        let result = record_recovery_intent(
            &review(RecoveryReviewState::EvidenceMismatchHold, OrphanState::PendingOnly),
            actor(),
            RecoveryIntent::RequestQuarantineReview,
        );
        assert_eq!(result, Err(ReceiptError::UnsupportedIntent));
    }

    #[test]
    fn published_marker_cannot_request_quarantine() {
        let result = record_recovery_intent(
            &review(RecoveryReviewState::MatchingPendingHold, OrphanState::PendingAndPublished),
            actor(),
            RecoveryIntent::RequestQuarantineReview,
        );
        assert_eq!(result, Err(ReceiptError::UnsupportedIntent));
    }

    #[test]
    fn forged_execution_flag_and_blank_attribution_fail_closed() {
        let mut candidate = review(RecoveryReviewState::MatchingPendingHold, OrphanState::PendingOnly);
        candidate.execution_allowed = true;
        assert_eq!(
            record_recovery_intent(&candidate, actor(), RecoveryIntent::Defer),
            Err(ReceiptError::UnsupportedIntent)
        );
        candidate.execution_allowed = false;
        let mut blank = actor();
        blank.actor_reference = [0; 32];
        assert_eq!(
            record_recovery_intent(&candidate, blank, RecoveryIntent::Defer),
            Err(ReceiptError::InvalidAttribution)
        );
    }
}
