//! Non-authorizing anti-rollback checkpoint comparison for offline key review.
//!
//! Checkpoints are reproducible hashes, not signed or durable evidence. An
//! external authenticated, monotonic anchor is required before any decision
//! could be trusted across device restart or old-snapshot restoration.

use sha2::{Digest, Sha256};

/// Domain separation for the public revocation checkpoint format.
const DOMAIN: &[u8] = b"PALACO-ORCH-052-REVOCATION-CHECKPOINT-v1";

/// Public checkpoint metadata over a fixed registry state digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationCheckpoint {
    /// Strictly increasing revision, scoped to one externally governed registry.
    pub revision: u64,
    /// Registry policy epoch, not an assertion of trusted wall-clock time.
    pub policy_epoch: u64,
    /// Digest of the canonical registry state, supplied by its producer.
    pub registry_digest: [u8; 32],
    /// Domain-separated digest binding all checkpoint fields.
    pub commitment: [u8; 32],
}

impl RevocationCheckpoint {
    /// Bind a public registry digest to a revision and policy epoch.
    #[must_use]
    pub fn new(revision: u64, policy_epoch: u64, registry_digest: [u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(revision.to_be_bytes());
        hasher.update(policy_epoch.to_be_bytes());
        hasher.update(registry_digest);
        let commitment = hasher.finalize().into();
        Self {
            revision,
            policy_epoch,
            registry_digest,
            commitment,
        }
    }

    /// Reject any mutated or internally inconsistent checkpoint.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        Self::new(self.revision, self.policy_epoch, self.registry_digest).commitment
            == self.commitment
    }
}

/// An anchor observation obtained from a separately governed trusted store.
///
/// This module cannot verify the trustworthiness of this observation's origin.
/// A caller must not treat an untrusted or copied snapshot as a trusted anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAnchor {
    /// Last independently committed revision.
    pub revision: u64,
    /// Highest independently committed policy epoch.
    pub policy_epoch: u64,
    /// Commitment independently retained for the anchored revision.
    pub commitment: [u8; 32],
}

/// Explicit fail-closed classification for non-executing review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointAssessment {
    /// No independently observed anchor was provided.
    MissingAnchor,
    /// The candidate commitment is internally invalid.
    InvalidCandidate,
    /// Candidate is behind an observed revision or policy epoch.
    RollbackDetected,
    /// Equal revision must have identical commitment and epoch.
    ForkDetected,
    /// The candidate equals the observed anchor exactly.
    MatchesAnchor,
    /// A newer candidate needs an independently authenticated anchor update.
    RequiresAnchorUpdate,
}

/// Compare a candidate against an externally obtained observation.
///
/// This is a pure evidence check. In particular, `MatchesAnchor` does not
/// authorize key usage, recovery, writes, or execution.
#[must_use]
pub fn assess_checkpoint(
    candidate: &RevocationCheckpoint,
    observed: Option<&ExternalAnchor>,
) -> CheckpointAssessment {
    if !candidate.is_well_formed() {
        return CheckpointAssessment::InvalidCandidate;
    }
    let Some(anchor) = observed else {
        return CheckpointAssessment::MissingAnchor;
    };
    if candidate.revision < anchor.revision || candidate.policy_epoch < anchor.policy_epoch {
        return CheckpointAssessment::RollbackDetected;
    }
    if candidate.revision == anchor.revision {
        if candidate.policy_epoch == anchor.policy_epoch
            && candidate.commitment == anchor.commitment
        {
            return CheckpointAssessment::MatchesAnchor;
        }
        return CheckpointAssessment::ForkDetected;
    }
    CheckpointAssessment::RequiresAnchorUpdate
}

/// Prepare an anchor proposal without writing to any trusted store.
///
/// Callers must independently authenticate, persist, and re-read the proposal
/// before it can be relied upon; a proposal is never self-authorizing.
#[must_use]
pub fn propose_anchor(candidate: &RevocationCheckpoint) -> Option<ExternalAnchor> {
    if !candidate.is_well_formed() {
        return None;
    }
    Some(ExternalAnchor {
        revision: candidate.revision,
        policy_epoch: candidate.policy_epoch,
        commitment: candidate.commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        assess_checkpoint, propose_anchor, CheckpointAssessment, RevocationCheckpoint,
    };

    #[test]
    fn no_anchor_fails_closed() {
        let checkpoint = RevocationCheckpoint::new(3, 2, [1; 32]);
        assert_eq!(
            assess_checkpoint(&checkpoint, None),
            CheckpointAssessment::MissingAnchor
        );
    }

    #[test]
    fn exact_match_is_non_authorizing_evidence() -> Result<(), &'static str> {
        let checkpoint = RevocationCheckpoint::new(3, 2, [1; 32]);
        let anchor = propose_anchor(&checkpoint).ok_or("valid checkpoint")?;
        assert_eq!(
            assess_checkpoint(&checkpoint, Some(&anchor)),
            CheckpointAssessment::MatchesAnchor
        );
        Ok(())
    }

    #[test]
    fn old_snapshot_is_refused_against_newer_external_anchor() -> Result<(), &'static str> {
        let stale = RevocationCheckpoint::new(3, 2, [1; 32]);
        let latest = RevocationCheckpoint::new(4, 2, [2; 32]);
        let external = propose_anchor(&latest).ok_or("valid checkpoint")?;
        assert_eq!(
            assess_checkpoint(&stale, Some(&external)),
            CheckpointAssessment::RollbackDetected
        );
        Ok(())
    }

    #[test]
    fn epoch_rollback_is_refused_even_when_revision_increases() -> Result<(), &'static str> {
        let candidate = RevocationCheckpoint::new(5, 2, [3; 32]);
        let external = propose_anchor(&RevocationCheckpoint::new(4, 3, [4; 32]))
            .ok_or("valid checkpoint")?;
        assert_eq!(
            assess_checkpoint(&candidate, Some(&external)),
            CheckpointAssessment::RollbackDetected
        );
        Ok(())
    }

    #[test]
    fn same_revision_with_different_state_is_a_fork() -> Result<(), &'static str> {
        let candidate = RevocationCheckpoint::new(4, 3, [8; 32]);
        let external = propose_anchor(&RevocationCheckpoint::new(4, 3, [9; 32]))
            .ok_or("valid checkpoint")?;
        assert_eq!(
            assess_checkpoint(&candidate, Some(&external)),
            CheckpointAssessment::ForkDetected
        );
        Ok(())
    }

    #[test]
    fn tampering_invalidates_commitment() {
        let mut candidate = RevocationCheckpoint::new(4, 3, [8; 32]);
        candidate.registry_digest[0] ^= 1;
        assert_eq!(
            assess_checkpoint(&candidate, None),
            CheckpointAssessment::InvalidCandidate
        );
        assert!(propose_anchor(&candidate).is_none());
    }

    #[test]
    fn new_revision_requires_independent_anchor_update() -> Result<(), &'static str> {
        let candidate = RevocationCheckpoint::new(5, 3, [7; 32]);
        let external = propose_anchor(&RevocationCheckpoint::new(4, 3, [8; 32]))
            .ok_or("valid checkpoint")?;
        assert_eq!(
            assess_checkpoint(&candidate, Some(&external)),
            CheckpointAssessment::RequiresAnchorUpdate
        );
        Ok(())
    }
}
