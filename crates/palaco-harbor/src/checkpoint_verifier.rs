//! Signed independent floor verification boundary for Harbor.
//!
//! This reference verifier binds source identity, the complete anchor payload,
//! trust epoch, observation time, signature, and a monotone predecessor. It
//! does not provision a trusted key, clock, checkpoint service, or authority.

use crate::anchor_cas::{record_is_valid, AnchorRecord};
use crate::anchor_checkpoint::ExternalFloorCandidate;
use crate::remote_anchor_adapter::attestation_bytes;
use ed25519_dalek::{Signature, VerifyingKey};

const DOMAIN: &[u8] = b"PALACO-HARBOR-INDEPENDENT-FLOOR-v1\0";
const MAX_SOURCE_ID_BYTES: usize = 128;

/// A candidate floor signed by its claimed external source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFloorCandidate {
    /// Candidate record and its source provenance.
    pub candidate: ExternalFloorCandidate,
    /// Monotone trust-registry epoch asserted by the source.
    pub trust_epoch: u64,
    /// Source observation time in Unix milliseconds.
    pub observed_at_ms: u64,
    /// Signature over every field in the candidate.
    pub signature: [u8; 64],
}

/// Caller-supplied verification policy.
///
/// The key, source identity, minimum epoch, clock, and freshness window remain
/// untrusted inputs until an independent governance layer binds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorVerifierConfig {
    /// Exact source identifier permitted for this verification.
    pub expected_source_id: String,
    /// Public key pinned by the caller for this reference check.
    pub verifying_key: [u8; 32],
    /// Minimum accepted source trust epoch.
    pub minimum_trust_epoch: u64,
    /// Current trusted time in Unix milliseconds.
    pub now_ms: u64,
    /// Maximum permitted candidate age in milliseconds.
    pub max_age_ms: u64,
}

/// Evidence returned after cryptographic, temporal, and monotone checks.
///
/// This is verification evidence for the supplied policy, not an authority
/// token and not permission to admit, execute, publish, or activate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorVerification {
    /// Candidate that passed the supplied checks.
    pub candidate: ExternalFloorCandidate,
    /// Accepted trust epoch.
    pub trust_epoch: u64,
    /// Accepted source observation time.
    pub observed_at_ms: u64,
}

/// Fail-closed reasons for a signed floor candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorVerificationError {
    /// The verifier policy is structurally invalid.
    InvalidPolicy,
    /// The candidate source identifier is structurally invalid.
    InvalidSource,
    /// The candidate anchor record is structurally invalid.
    InvalidCandidate,
    /// The candidate source differs from the pinned source.
    SourceMismatch,
    /// The supplied public key is not a valid Ed25519 key.
    InvalidVerifyingKey,
    /// The signature does not cover the complete candidate.
    InvalidSignature,
    /// The candidate trust epoch is below the configured minimum.
    TrustEpochBelowMinimum,
    /// The current clock is earlier than the source observation.
    TemporalUncertain,
    /// The candidate is older than the configured freshness window.
    Stale,
    /// The candidate trust epoch regressed.
    TrustEpochRegression,
    /// The candidate floor regressed in revision, sequence, epoch, or revocations.
    FloorRegression,
    /// Two records claim one revision but contain different state.
    FloorConflict,
    /// Candidate observation time regressed.
    FreshnessRegression,
}

fn source_id_valid(source_id: &str) -> bool {
    !source_id.is_empty()
        && source_id.len() <= MAX_SOURCE_ID_BYTES
        && source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

/// Canonical bytes signed by the independent floor source.
///
/// The encoding binds the source identifier, full anchor record, trust epoch,
/// and observation time under a dedicated domain.
pub fn signed_floor_bytes(
    signed: &SignedFloorCandidate,
) -> Result<Vec<u8>, FloorVerificationError> {
    if !source_id_valid(&signed.candidate.source_id) {
        return Err(FloorVerificationError::InvalidSource);
    }
    if !record_is_valid(&signed.candidate.record) {
        return Err(FloorVerificationError::InvalidCandidate);
    }
    if signed.trust_epoch == 0 || signed.observed_at_ms == 0 {
        return Err(FloorVerificationError::InvalidCandidate);
    }
    let record_bytes = attestation_bytes(&signed.candidate.record)
        .map_err(|_| FloorVerificationError::InvalidCandidate)?;
    let source_len = u64::try_from(signed.candidate.source_id.len())
        .map_err(|_| FloorVerificationError::InvalidSource)?;
    let record_len =
        u64::try_from(record_bytes.len()).map_err(|_| FloorVerificationError::InvalidCandidate)?;
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&source_len.to_be_bytes());
    bytes.extend_from_slice(signed.candidate.source_id.as_bytes());
    bytes.extend_from_slice(&signed.trust_epoch.to_be_bytes());
    bytes.extend_from_slice(&signed.observed_at_ms.to_be_bytes());
    bytes.extend_from_slice(&record_len.to_be_bytes());
    bytes.extend_from_slice(&record_bytes);
    Ok(bytes)
}

/// Verify one signed floor against a pinned policy and optional prior evidence.
///
/// A successful result means only that this exact candidate passed the supplied
/// checks. It does not establish that the supplied key, clock, or source is
/// actually governed.
#[must_use]
pub fn verify_signed_floor(
    config: &FloorVerifierConfig,
    signed: &SignedFloorCandidate,
    previous: Option<&FloorVerification>,
) -> Result<FloorVerification, FloorVerificationError> {
    if !source_id_valid(&config.expected_source_id)
        || config.minimum_trust_epoch == 0
        || config.now_ms == 0
    {
        return Err(FloorVerificationError::InvalidPolicy);
    }
    if signed.candidate.source_id != config.expected_source_id {
        return Err(FloorVerificationError::SourceMismatch);
    }
    let message = signed_floor_bytes(signed)?;
    let verifying = VerifyingKey::from_bytes(&config.verifying_key)
        .map_err(|_| FloorVerificationError::InvalidVerifyingKey)?;
    verifying
        .verify_strict(&message, &Signature::from_bytes(&signed.signature))
        .map_err(|_| FloorVerificationError::InvalidSignature)?;
    if signed.trust_epoch < config.minimum_trust_epoch {
        return Err(FloorVerificationError::TrustEpochBelowMinimum);
    }
    if config.now_ms < signed.observed_at_ms {
        return Err(FloorVerificationError::TemporalUncertain);
    }
    if config.now_ms - signed.observed_at_ms > config.max_age_ms {
        return Err(FloorVerificationError::Stale);
    }
    if let Some(prior) = previous {
        if prior.candidate.source_id != config.expected_source_id {
            return Err(FloorVerificationError::SourceMismatch);
        }
        if signed.trust_epoch < prior.trust_epoch {
            return Err(FloorVerificationError::TrustEpochRegression);
        }
        let current = &signed.candidate.record;
        let floor = &prior.candidate.record;
        if current.revision < floor.revision
            || current.sequence < floor.sequence
            || current.signer_epoch < floor.signer_epoch
            || !floor.retired_signers.is_subset(&current.retired_signers)
        {
            return Err(FloorVerificationError::FloorRegression);
        }
        if current.revision == floor.revision && current != floor {
            return Err(FloorVerificationError::FloorConflict);
        }
        if signed.observed_at_ms < prior.observed_at_ms {
            return Err(FloorVerificationError::FreshnessRegression);
        }
    }
    Ok(FloorVerification {
        candidate: signed.candidate.clone(),
        trust_epoch: signed.trust_epoch,
        observed_at_ms: signed.observed_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        signed_floor_bytes, verify_signed_floor, FloorVerification, FloorVerificationError,
        FloorVerifierConfig, SignedFloorCandidate,
    };
    use crate::anchor_cas::AnchorRecord;
    use crate::anchor_checkpoint::ExternalFloorCandidate;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[61; 32])
    }

    fn config(key: &SigningKey) -> FloorVerifierConfig {
        FloorVerifierConfig {
            expected_source_id: "checkpoint-a".to_owned(),
            verifying_key: key.verifying_key().to_bytes(),
            minimum_trust_epoch: 5,
            now_ms: 2_000,
            max_age_ms: 1_000,
        }
    }

    fn signed(
        revision: u64,
        sequence: u64,
        trust_epoch: u64,
        observed_at_ms: u64,
    ) -> SignedFloorCandidate {
        let signing = key();
        let candidate = ExternalFloorCandidate {
            source_id: "checkpoint-a".to_owned(),
            record: AnchorRecord {
                revision,
                signer_epoch: 5,
                sequence,
                chain_digest: [revision as u8; 32],
                signer_id: "signer-a".to_owned(),
                retired_signers: BTreeSet::new(),
            },
        };
        let mut signed = SignedFloorCandidate {
            candidate,
            trust_epoch,
            observed_at_ms,
            signature: [0; 64],
        };
        let message = signed_floor_bytes(&signed).unwrap_or_else(|_| panic!("message"));
        signed.signature = signing.sign(&message).to_bytes();
        signed
    }

    #[test]
    fn valid_signature_time_and_source_are_accepted_as_evidence() {
        let signing = key();
        let result = verify_signed_floor(&config(&signing), &signed(1, 1, 6, 1_500), None);
        assert!(result.is_ok());
    }

    #[test]
    fn source_and_payload_are_bound_by_signature() {
        let signing = key();
        let mut changed = signed(1, 1, 6, 1_500);
        changed.candidate.record.sequence = 2;
        assert_eq!(
            verify_signed_floor(&config(&signing), &changed, None),
            Err(FloorVerificationError::InvalidSignature)
        );
        let mut wrong_source = signed(1, 1, 6, 1_500);
        wrong_source.candidate.source_id = "checkpoint-b".to_owned();
        assert_eq!(
            verify_signed_floor(&config(&signing), &wrong_source, None),
            Err(FloorVerificationError::SourceMismatch)
        );
    }

    #[test]
    fn wrong_key_and_time_fail_closed() {
        let signing = key();
        let wrong_key = SigningKey::from_bytes(&[62; 32]);
        assert_eq!(
            verify_signed_floor(&config(&wrong_key), &signed(1, 1, 6, 1_500), None),
            Err(FloorVerificationError::InvalidSignature)
        );
        assert_eq!(
            verify_signed_floor(&config(&signing), &signed(1, 1, 6, 2_500), None),
            Err(FloorVerificationError::TemporalUncertain)
        );
        assert_eq!(
            verify_signed_floor(&config(&signing), &signed(1, 1, 6, 500), None),
            Err(FloorVerificationError::Stale)
        );
    }

    #[test]
    fn minimum_and_monotone_epochs_are_required() {
        let signing = key();
        assert_eq!(
            verify_signed_floor(&config(&signing), &signed(1, 1, 4, 1_500), None),
            Err(FloorVerificationError::TrustEpochBelowMinimum)
        );
        let prior = verify_signed_floor(&config(&signing), &signed(1, 1, 7, 1_500), None)
            .unwrap_or_else(|_| panic!("prior"));
        assert_eq!(
            verify_signed_floor(&config(&signing), &signed(2, 2, 6, 1_600), Some(&prior)),
            Err(FloorVerificationError::TrustEpochRegression)
        );
    }

    #[test]
    fn floor_revision_and_revocations_cannot_regress_or_fork() {
        let signing = key();
        let prior = verify_signed_floor(&config(&signing), &signed(2, 2, 6, 1_500), None)
            .unwrap_or_else(|_| panic!("prior"));
        assert_eq!(
            verify_signed_floor(&config(&signing), &signed(1, 1, 6, 1_600), Some(&prior)),
            Err(FloorVerificationError::FloorRegression)
        );
        let mut fork = signed(2, 3, 6, 1_600);
        fork.candidate.record.chain_digest = [9; 32];
        let message = signed_floor_bytes(&fork).unwrap_or_else(|_| panic!("message"));
        fork.signature = key().sign(&message).to_bytes();
        assert_eq!(
            verify_signed_floor(&config(&signing), &fork, Some(&prior)),
            Err(FloorVerificationError::FloorConflict)
        );
    }

    #[test]
    fn freshness_and_policy_are_monotone() {
        let signing = key();
        let prior = verify_signed_floor(&config(&signing), &signed(1, 1, 6, 1_500), None)
            .unwrap_or_else(|_| panic!("prior"));
        assert_eq!(
            verify_signed_floor(&config(&signing), &signed(2, 2, 6, 1_400), Some(&prior)),
            Err(FloorVerificationError::FreshnessRegression)
        );
        let mut invalid = config(&signing);
        invalid.expected_source_id.clear();
        assert_eq!(
            verify_signed_floor(&invalid, &signed(1, 1, 6, 1_500), None),
            Err(FloorVerificationError::InvalidPolicy)
        );
    }

    #[test]
    fn verification_evidence_does_not_equal_authority() {
        let signing = key();
        let evidence = verify_signed_floor(&config(&signing), &signed(1, 1, 6, 1_500), None)
            .unwrap_or_else(|_| panic!("evidence"));
        assert_eq!(evidence.trust_epoch, 6);
        let _evidence_type: FloorVerification = evidence;
    }
}
