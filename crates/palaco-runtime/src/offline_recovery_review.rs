//! Pure, non-mutating review plan for abandoned offline candidate markers.
//!
//! This module does not grant approval, create receipts, or execute cleanup.

use crate::offline_orphan::{OrphanInspection, OrphanState};

/// Review-only outcome, never an execution permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReviewState {
    /// Nothing pending was observed; publication validity remains unproven.
    NoPendingObserved,
    /// Pending bytes match caller-provided expected evidence; human review required.
    MatchingPendingHold,
    /// Pending data exists, but trusted expected evidence was not provided.
    MissingExpectedEvidenceHold,
    /// Pending bytes disagree with the supplied expectation.
    EvidenceMismatchHold,
    /// Diagnostic receipt is internally inconsistent.
    InvalidInspectionHold,
}

/// Expected evidence must originate from a separately trusted manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedPending {
    /// Expected candidate sequence.
    pub sequence: u64,
    /// Expected pending byte count.
    pub bytes: u64,
    /// Expected SHA-256; a checksum alone is not authentication.
    pub sha256: [u8; 32],
}

/// Immutable proposed review, with no filesystem path or deletion capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryReview {
    /// Candidate sequence under examination.
    pub sequence: u64,
    /// Observed state of the candidate marker names.
    pub observed: OrphanState,
    /// Evidence assessment for a human operator.
    pub state: RecoveryReviewState,
    /// Explicitly denies all automated recovery actions.
    pub execution_allowed: bool,
}

/// Build a conservative review from a prior read-only diagnostic observation.
///
/// The caller must independently bind the inspection to the same trusted
/// generation and refresh the observation before any later governed operation.
/// This function intentionally has no filesystem or authority inputs.
#[must_use]
pub fn prepare_recovery_review(
    inspection: &OrphanInspection,
    expected: Option<&ExpectedPending>,
) -> RecoveryReview {
    let state = match inspection.state {
        OrphanState::NoPending
            if inspection.pending_bytes.is_none() && inspection.pending_sha256.is_none() =>
        {
            RecoveryReviewState::NoPendingObserved
        }
        OrphanState::NoPending => RecoveryReviewState::InvalidInspectionHold,
        OrphanState::PendingOnly | OrphanState::PendingAndPublished => {
            match (
                inspection.pending_bytes,
                inspection.pending_sha256,
                expected,
            ) {
                (Some(_), Some(_), None) => RecoveryReviewState::MissingExpectedEvidenceHold,
                (Some(bytes), Some(digest), Some(evidence))
                    if evidence.sequence == inspection.sequence
                        && evidence.bytes == bytes
                        && evidence.sha256 == digest =>
                {
                    RecoveryReviewState::MatchingPendingHold
                }
                (Some(_), Some(_), Some(_)) => RecoveryReviewState::EvidenceMismatchHold,
                _ => RecoveryReviewState::InvalidInspectionHold,
            }
        }
    };
    RecoveryReview {
        sequence: inspection.sequence,
        observed: inspection.state,
        state,
        execution_allowed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{prepare_recovery_review, ExpectedPending, RecoveryReviewState};
    use crate::offline_orphan::{OrphanInspection, OrphanState};

    fn pending(state: OrphanState) -> OrphanInspection {
        OrphanInspection {
            sequence: 7,
            state,
            pending_bytes: Some(4),
            pending_sha256: Some([9; 32]),
        }
    }

    fn expected() -> ExpectedPending {
        ExpectedPending {
            sequence: 7,
            bytes: 4,
            sha256: [9; 32],
        }
    }

    #[test]
    fn no_pending_does_not_grant_execution() {
        let observation = OrphanInspection {
            sequence: 7,
            state: OrphanState::NoPending,
            pending_bytes: None,
            pending_sha256: None,
        };
        let result = prepare_recovery_review(&observation, None);
        assert_eq!(result.state, RecoveryReviewState::NoPendingObserved);
        assert!(!result.execution_allowed);
    }

    #[test]
    fn matching_orphan_still_requires_review() {
        for state in [OrphanState::PendingOnly, OrphanState::PendingAndPublished] {
            let result = prepare_recovery_review(&pending(state), Some(&expected()));
            assert_eq!(result.state, RecoveryReviewState::MatchingPendingHold);
            assert!(!result.execution_allowed);
        }
    }

    #[test]
    fn missing_manifest_is_a_hold() {
        let result = prepare_recovery_review(&pending(OrphanState::PendingOnly), None);
        assert_eq!(
            result.state,
            RecoveryReviewState::MissingExpectedEvidenceHold
        );
        assert!(!result.execution_allowed);
    }

    #[test]
    fn mismatched_digest_or_sequence_is_a_hold() {
        let mut evidence = expected();
        evidence.sha256 = [8; 32];
        let result = prepare_recovery_review(&pending(OrphanState::PendingOnly), Some(&evidence));
        assert_eq!(result.state, RecoveryReviewState::EvidenceMismatchHold);
        evidence = expected();
        evidence.sequence = 8;
        let result = prepare_recovery_review(&pending(OrphanState::PendingOnly), Some(&evidence));
        assert_eq!(result.state, RecoveryReviewState::EvidenceMismatchHold);
    }

    #[test]
    fn inconsistent_diagnostic_is_never_actionable() {
        let mut observation = pending(OrphanState::PendingOnly);
        observation.pending_sha256 = None;
        let result = prepare_recovery_review(&observation, Some(&expected()));
        assert_eq!(result.state, RecoveryReviewState::InvalidInspectionHold);
        assert!(!result.execution_allowed);
        observation.state = OrphanState::NoPending;
        let result = prepare_recovery_review(&observation, None);
        assert_eq!(result.state, RecoveryReviewState::InvalidInspectionHold);
    }
}
