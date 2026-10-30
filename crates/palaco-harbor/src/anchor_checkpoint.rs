//! Independent checkpoint observation boundary for Harbor.
//!
//! This module describes the evidence states required before a local journal
//! may use an external minimum floor. It does not authenticate a signer,
//! contact a service, or grant admission, authorization, execution, release,
//! publication, or activation.

use crate::anchor_cas::{record_is_valid, AnchorRecord};

/// A candidate floor plus the source identity that supplied it.
///
/// The source identifier is provenance metadata only. The candidate still needs
/// independent authentication, freshness, rollback protection, and governance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFloorCandidate {
    /// Stable identifier for the independently governed source.
    pub source_id: String,
    /// Candidate minimum anchor record.
    pub record: AnchorRecord,
}

/// Observation returned by an independent checkpoint adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointObservation {
    /// One candidate was returned for later authentication and policy checks.
    Candidate(ExternalFloorCandidate),
    /// The source has no checkpoint; local state must not be used as a fallback.
    Missing,
    /// The source returned incompatible checkpoint evidence.
    Conflicting,
}

/// Source failures that are not safe to interpret as an absent floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointSourceError {
    /// The source could not be reached or opened.
    Unavailable,
    /// The source outcome is unknown, including an interrupted or ambiguous read.
    Uncertain,
    /// The source response could not be decoded as its contract.
    Malformed,
}

/// Closed reasons for withholding an external floor candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointHold {
    /// No external floor was present.
    Missing,
    /// Multiple or incompatible floor observations were returned.
    Conflicting,
    /// The source was unavailable.
    Unavailable,
    /// The source outcome was not safely known.
    Uncertain,
    /// The source response was malformed.
    Malformed,
    /// The candidate failed structural validation.
    InvalidCandidate,
}

/// Structural result only; this is not an authorization or trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointDecision {
    /// Candidate may proceed to independent authentication and policy checks.
    CandidateAccepted(ExternalFloorCandidate),
    /// Candidate is held and no local fallback is permitted.
    Hold(CheckpointHold),
}

/// An independently governed checkpoint source.
///
/// Implementations must authenticate the complete response and protect its
/// freshness and monotone floor outside this reference contract.
pub trait IndependentCheckpointSource {
    /// Read one complete observation without silently substituting local state.
    fn read(&self) -> Result<CheckpointObservation, CheckpointSourceError>;
}

fn source_id_valid(source_id: &str) -> bool {
    !source_id.is_empty()
        && source_id.len() <= 128
        && source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

/// Classify one external checkpoint observation with fail-closed semantics.
///
/// CandidateAccepted means only that the source identifier and anchor record
/// are structurally valid. It never means the candidate is trusted or
/// authorized.
#[must_use]
pub fn classify_checkpoint<S: IndependentCheckpointSource>(
    source: &S,
) -> CheckpointDecision {
    match source.read() {
        Ok(CheckpointObservation::Candidate(candidate)) => {
            if source_id_valid(&candidate.source_id) && record_is_valid(&candidate.record) {
                CheckpointDecision::CandidateAccepted(candidate)
            } else {
                CheckpointDecision::Hold(CheckpointHold::InvalidCandidate)
            }
        }
        Ok(CheckpointObservation::Missing) => CheckpointDecision::Hold(CheckpointHold::Missing),
        Ok(CheckpointObservation::Conflicting) => {
            CheckpointDecision::Hold(CheckpointHold::Conflicting)
        }
        Err(CheckpointSourceError::Unavailable) => {
            CheckpointDecision::Hold(CheckpointHold::Unavailable)
        }
        Err(CheckpointSourceError::Uncertain) => CheckpointDecision::Hold(CheckpointHold::Uncertain),
        Err(CheckpointSourceError::Malformed) => CheckpointDecision::Hold(CheckpointHold::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_checkpoint, CheckpointDecision, CheckpointHold, CheckpointObservation,
        CheckpointSourceError, ExternalFloorCandidate, IndependentCheckpointSource,
    };
    use crate::anchor_cas::AnchorRecord;
    use std::collections::BTreeSet;

    struct Script(Result<CheckpointObservation, CheckpointSourceError>);

    impl IndependentCheckpointSource for Script {
        fn read(&self) -> Result<CheckpointObservation, CheckpointSourceError> {
            self.0.clone()
        }
    }

    fn record() -> AnchorRecord {
        AnchorRecord {
            revision: 1,
            signer_epoch: 2,
            sequence: 3,
            chain_digest: [7; 32],
            signer_id: "signer-a".to_owned(),
            retired_signers: BTreeSet::new(),
        }
    }

    fn candidate() -> ExternalFloorCandidate {
        ExternalFloorCandidate {
            source_id: "checkpoint-a".to_owned(),
            record: record(),
        }
    }

    #[test]
    fn structurally_valid_candidate_is_not_yet_trusted() {
        assert_eq!(
            classify_checkpoint(&Script(Ok(CheckpointObservation::Candidate(
                candidate()
            )))),
            CheckpointDecision::CandidateAccepted(candidate())
        );
    }

    #[test]
    fn missing_checkpoint_never_falls_back_to_local_state() {
        assert_eq!(
            classify_checkpoint(&Script(Ok(CheckpointObservation::Missing))),
            CheckpointDecision::Hold(CheckpointHold::Missing)
        );
    }

    #[test]
    fn conflicting_checkpoint_is_held() {
        assert_eq!(
            classify_checkpoint(&Script(Ok(CheckpointObservation::Conflicting))),
            CheckpointDecision::Hold(CheckpointHold::Conflicting)
        );
    }

    #[test]
    fn source_failures_are_distinct_and_fail_closed() {
        let cases = [
            (
                CheckpointSourceError::Unavailable,
                CheckpointHold::Unavailable,
            ),
            (CheckpointSourceError::Uncertain, CheckpointHold::Uncertain),
            (CheckpointSourceError::Malformed, CheckpointHold::Malformed),
        ];
        for (error, expected) in cases {
            assert_eq!(
                classify_checkpoint(&Script(Err(error))),
                CheckpointDecision::Hold(expected)
            );
        }
    }

    #[test]
    fn malformed_candidate_is_held() {
        let mut bad = candidate();
        bad.source_id = "../snapshot".to_owned();
        assert_eq!(
            classify_checkpoint(&Script(Ok(CheckpointObservation::Candidate(bad)))),
            CheckpointDecision::Hold(CheckpointHold::InvalidCandidate)
        );
    }

    #[test]
    fn record_identity_and_epoch_are_required() {
        let mut bad = candidate();
        bad.record.signer_id.clear();
        assert_eq!(
            classify_checkpoint(&Script(Ok(CheckpointObservation::Candidate(bad)))),
            CheckpointDecision::Hold(CheckpointHold::InvalidCandidate)
        );
    }
}
