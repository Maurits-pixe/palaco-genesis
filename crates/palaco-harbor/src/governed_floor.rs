//! Governed trust-registry bridge for signed independent floor evidence.
//!
//! This module composes the v0.22 signed-floor verifier with a caller-provided
//! key registry and monotone trusted-time snapshot. It binds the expected
//! source and key identifiers, key lifecycle, registry epoch, observation
//! freshness, and the complete signed floor candidate.
//!
//! The registry and time snapshot remain external evidence. This bridge does
//! not enroll keys, establish a governance root, persist anti-rollback state,
//! or grant admission, authorization, execution, publication, release, or
//! activation.

use crate::checkpoint_verifier::{
    verify_signed_floor, FloorVerification, FloorVerificationError, FloorVerifierConfig,
    SignedFloorCandidate,
};
use crate::trust_registry::{KeyRegistry, RegistryError, TrustedTimeSnapshot};

const MAX_ID_BYTES: usize = 128;

/// A signed floor candidate annotated with the registry key used to verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedFloorCandidate {
    /// Exact key identifier resolved from the independently supplied registry.
    pub key_id: String,
    /// Complete source candidate, trust epoch, time, and signature.
    pub signed: SignedFloorCandidate,
}

/// Caller-supplied policy for this bridge invocation.
///
/// The expected source/key pair is an explicit binding. A production caller
/// must obtain this pair and the registry/time snapshot from independently
/// authenticated governance services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedFloorPolicy {
    /// Exact source identifier permitted for the floor candidate.
    pub expected_source_id: String,
    /// Exact registry key identifier permitted for the source.
    pub expected_key_id: String,
    /// Minimum trust epoch accepted by the caller.
    pub minimum_trust_epoch: u64,
    /// Monotone trusted-time evidence and registry epoch floor.
    pub time: TrustedTimeSnapshot,
    /// Maximum candidate age in milliseconds.
    pub max_age_ms: u64,
}

/// Evidence returned after the registry and signed-floor checks pass.
///
/// This is not a trust token or authorization result. Callers must retain the
/// registry/time evidence that justified the result and perform their own
/// admission and activation gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedFloorVerification {
    /// Key identifier resolved during this verification.
    pub key_id: String,
    /// Source identifier carried by the accepted candidate.
    pub source_id: String,
    /// Registry epoch of the resolved key record.
    pub registry_trust_epoch: u64,
    /// Evidence produced by the v0.22 floor verifier.
    pub floor: FloorVerification,
}

/// Fail-closed reasons for the registry bridge.
///
/// None of these variants authorizes a caller or activates a Harbor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedFloorError {
    /// The bridge policy is structurally invalid.
    InvalidPolicy,
    /// The candidate did not include a key identifier.
    MissingKeyId,
    /// The candidate key differs from the policy or predecessor.
    KeyMismatch,
    /// The registry could not be reached.
    RegistryUnavailable,
    /// The registry result was inconclusive.
    RegistryUncertain,
    /// No registry record exists for the requested key.
    UnknownKey,
    /// The registry record is internally inconsistent.
    InvalidRecord,
    /// The resolved key is revoked.
    Revoked,
    /// The key is not valid at the relevant time.
    NotYetValid,
    /// The key has expired at the relevant time.
    Expired,
    /// The signed observation predates the key validity window.
    ObservationBeforeKeyValidity,
    /// The signed observation is outside the key validity window.
    ObservationAfterKeyValidity,
    /// The supplied trusted clock moved backwards.
    TemporalUncertain,
    /// The registry key epoch regressed relative to prior evidence.
    RegistryEpochRegression,
    /// The signed-floor verifier rejected the candidate.
    Floor(FloorVerificationError),
}

fn id_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

/// Verify one signed floor against a governed-key lookup and monotone time.
///
/// The registry record, trusted time, source/key pair, signature, freshness,
/// and predecessor floor are checked before evidence is returned. The caller
/// still has to decide whether that evidence is sufficient for any separate
/// authorization gate.
pub fn verify_governed_floor<R: KeyRegistry>(
    registry: &R,
    policy: &GovernedFloorPolicy,
    candidate: &GovernedFloorCandidate,
    previous: Option<&GovernedFloorVerification>,
) -> Result<GovernedFloorVerification, GovernedFloorError> {
    if !id_valid(&policy.expected_source_id)
        || !id_valid(&policy.expected_key_id)
        || policy.minimum_trust_epoch == 0
        || policy.time.now_ms == 0
        || policy.time.highest_accepted_ms == 0
        || policy.time.minimum_trust_epoch == 0
    {
        return Err(GovernedFloorError::InvalidPolicy);
    }
    if candidate.key_id.is_empty() {
        return Err(GovernedFloorError::MissingKeyId);
    }
    if candidate.key_id != policy.expected_key_id {
        return Err(GovernedFloorError::KeyMismatch);
    }
    if let Some(prior) = previous {
        if prior.key_id != candidate.key_id {
            return Err(GovernedFloorError::KeyMismatch);
        }
    }

    let record = match registry.resolve(&candidate.key_id) {
        Ok(Some(record)) => record,
        Ok(None) => return Err(GovernedFloorError::UnknownKey),
        Err(RegistryError::Unavailable) => return Err(GovernedFloorError::RegistryUnavailable),
        Err(RegistryError::Uncertain) => return Err(GovernedFloorError::RegistryUncertain),
    };

    if record.key_id != candidate.key_id
        || record.trust_epoch == 0
        || record.valid_from_ms >= record.valid_until_ms
    {
        return Err(GovernedFloorError::InvalidRecord);
    }
    if record.revoked {
        return Err(GovernedFloorError::Revoked);
    }
    if policy.time.now_ms < policy.time.highest_accepted_ms {
        return Err(GovernedFloorError::TemporalUncertain);
    }
    if policy.time.now_ms < record.valid_from_ms {
        return Err(GovernedFloorError::NotYetValid);
    }
    if policy.time.now_ms >= record.valid_until_ms {
        return Err(GovernedFloorError::Expired);
    }
    if candidate.signed.observed_at_ms < record.valid_from_ms {
        return Err(GovernedFloorError::ObservationBeforeKeyValidity);
    }
    if candidate.signed.observed_at_ms >= record.valid_until_ms {
        return Err(GovernedFloorError::ObservationAfterKeyValidity);
    }
    if let Some(prior) = previous {
        if record.trust_epoch < prior.registry_trust_epoch {
            return Err(GovernedFloorError::RegistryEpochRegression);
        }
    }

    let minimum_trust_epoch = policy
        .minimum_trust_epoch
        .max(policy.time.minimum_trust_epoch)
        .max(record.trust_epoch);
    let floor = verify_signed_floor(
        &FloorVerifierConfig {
            expected_source_id: policy.expected_source_id.clone(),
            verifying_key: record.public_key,
            minimum_trust_epoch,
            now_ms: policy.time.now_ms,
            max_age_ms: policy.max_age_ms,
        },
        &candidate.signed,
        previous.map(|value| &value.floor),
    )
    .map_err(GovernedFloorError::Floor)?;

    Ok(GovernedFloorVerification {
        key_id: candidate.key_id.clone(),
        source_id: floor.candidate.source_id.clone(),
        registry_trust_epoch: record.trust_epoch,
        floor,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        verify_governed_floor, GovernedFloorCandidate, GovernedFloorError, GovernedFloorPolicy,
        GovernedFloorVerification,
    };
    use crate::anchor_cas::AnchorRecord;
    use crate::anchor_checkpoint::ExternalFloorCandidate;
    use crate::checkpoint_verifier::{
        signed_floor_bytes, FloorVerificationError, SignedFloorCandidate,
    };
    use crate::trust_registry::{KeyRecord, KeyRegistry, RegistryError, TrustedTimeSnapshot};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    struct ScriptedRegistry(Result<Option<KeyRecord>, RegistryError>);

    impl KeyRegistry for ScriptedRegistry {
        fn resolve(&self, _key_id: &str) -> Result<Option<KeyRecord>, RegistryError> {
            self.0.clone()
        }
    }

    fn signing() -> SigningKey {
        SigningKey::from_bytes(&[71_u8; 32])
    }

    fn key_record() -> KeyRecord {
        let key = signing();
        KeyRecord {
            key_id: "checkpoint-key-1".to_owned(),
            public_key: key.verifying_key().to_bytes(),
            trust_epoch: 8,
            valid_from_ms: 100,
            valid_until_ms: 300,
            revoked: false,
        }
    }

    fn policy() -> GovernedFloorPolicy {
        GovernedFloorPolicy {
            expected_source_id: "checkpoint-a".to_owned(),
            expected_key_id: "checkpoint-key-1".to_owned(),
            minimum_trust_epoch: 5,
            time: TrustedTimeSnapshot {
                now_ms: 200,
                highest_accepted_ms: 190,
                minimum_trust_epoch: 5,
            },
            max_age_ms: 100,
        }
    }

    fn candidate(
        revision: u64,
        sequence: u64,
        trust_epoch: u64,
        observed_at_ms: u64,
    ) -> GovernedFloorCandidate {
        let signed = SignedFloorCandidate {
            candidate: ExternalFloorCandidate {
                source_id: "checkpoint-a".to_owned(),
                record: AnchorRecord {
                    revision,
                    signer_epoch: 5,
                    sequence,
                    chain_digest: [revision as u8; 32],
                    signer_id: "signer-a".to_owned(),
                    retired_signers: BTreeSet::new(),
                },
            },
            trust_epoch,
            observed_at_ms,
            signature: [0; 64],
        };
        let mut candidate = GovernedFloorCandidate {
            key_id: "checkpoint-key-1".to_owned(),
            signed,
        };
        let bytes =
            signed_floor_bytes(&candidate.signed).unwrap_or_else(|_| panic!("signed floor bytes"));
        candidate.signed.signature = signing().sign(&bytes).to_bytes();
        candidate
    }

    fn registry() -> ScriptedRegistry {
        ScriptedRegistry(Ok(Some(key_record())))
    }

    #[test]
    fn registry_bound_signature_and_fresh_floor_return_evidence() {
        let result = verify_governed_floor(&registry(), &policy(), &candidate(1, 1, 8, 180), None);
        assert!(result.is_ok());
        if let Ok(evidence) = result {
            assert_eq!(evidence.key_id, "checkpoint-key-1");
            assert_eq!(evidence.source_id, "checkpoint-a");
            assert_eq!(evidence.registry_trust_epoch, 8);
        }
    }

    #[test]
    fn key_and_registry_failures_never_fall_back() {
        assert_eq!(
            verify_governed_floor(
                &ScriptedRegistry(Ok(None)),
                &policy(),
                &candidate(1, 1, 8, 180),
                None,
            ),
            Err(GovernedFloorError::UnknownKey)
        );
        assert_eq!(
            verify_governed_floor(
                &ScriptedRegistry(Err(RegistryError::Unavailable)),
                &policy(),
                &candidate(1, 1, 8, 180),
                None,
            ),
            Err(GovernedFloorError::RegistryUnavailable)
        );
        assert_eq!(
            verify_governed_floor(
                &ScriptedRegistry(Err(RegistryError::Uncertain)),
                &policy(),
                &candidate(1, 1, 8, 180),
                None,
            ),
            Err(GovernedFloorError::RegistryUncertain)
        );
    }

    #[test]
    fn revocation_and_clock_rollback_win_closed() {
        let mut revoked = key_record();
        revoked.revoked = true;
        assert_eq!(
            verify_governed_floor(
                &ScriptedRegistry(Ok(Some(revoked))),
                &policy(),
                &candidate(1, 1, 8, 180),
                None,
            ),
            Err(GovernedFloorError::Revoked)
        );
        let mut rolled_back = policy();
        rolled_back.time.now_ms = 180;
        assert_eq!(
            verify_governed_floor(&registry(), &rolled_back, &candidate(1, 1, 8, 180), None,),
            Err(GovernedFloorError::TemporalUncertain)
        );
    }

    #[test]
    fn key_validity_and_epoch_are_enforced() {
        let mut too_old = policy();
        too_old.time.now_ms = 150;
        too_old.time.highest_accepted_ms = 150;
        assert_eq!(
            verify_governed_floor(&registry(), &too_old, &candidate(1, 1, 8, 90), None,),
            Err(GovernedFloorError::ObservationBeforeKeyValidity)
        );
        let mut expired = policy();
        expired.time.now_ms = 300;
        expired.time.highest_accepted_ms = 300;
        assert_eq!(
            verify_governed_floor(&registry(), &expired, &candidate(1, 1, 8, 220), None,),
            Err(GovernedFloorError::Expired)
        );
        assert_eq!(
            verify_governed_floor(&registry(), &policy(), &candidate(1, 1, 7, 180), None,),
            Err(GovernedFloorError::Floor(
                FloorVerificationError::TrustEpochBelowMinimum
            ))
        );
    }

    #[test]
    fn key_binding_and_policy_shape_are_required() {
        let mut bad = candidate(1, 1, 8, 180);
        bad.key_id = "other-key".to_owned();
        assert_eq!(
            verify_governed_floor(&registry(), &policy(), &bad, None),
            Err(GovernedFloorError::KeyMismatch)
        );
        let mut empty = policy();
        empty.expected_source_id.clear();
        assert_eq!(
            verify_governed_floor(&registry(), &empty, &candidate(1, 1, 8, 180), None),
            Err(GovernedFloorError::InvalidPolicy)
        );
    }

    #[test]
    fn predecessor_registry_epoch_and_floor_are_monotone() {
        let first = verify_governed_floor(&registry(), &policy(), &candidate(1, 1, 8, 180), None)
            .unwrap_or_else(|_| panic!("first evidence"));
        let second = verify_governed_floor(
            &registry(),
            &policy(),
            &candidate(2, 2, 8, 190),
            Some(&first),
        );
        assert!(second.is_ok());

        let mut old_key = key_record();
        old_key.trust_epoch = 7;
        assert_eq!(
            verify_governed_floor(
                &ScriptedRegistry(Ok(Some(old_key))),
                &policy(),
                &candidate(2, 2, 8, 190),
                Some(&first),
            ),
            Err(GovernedFloorError::RegistryEpochRegression)
        );

        assert_eq!(
            verify_governed_floor(
                &registry(),
                &policy(),
                &candidate(1, 1, 8, 190),
                Some(&second),
            ),
            Err(GovernedFloorError::Floor(
                FloorVerificationError::FloorRegression
            ))
        );
    }

    #[test]
    fn result_is_evidence_not_authority() {
        let evidence =
            verify_governed_floor(&registry(), &policy(), &candidate(1, 1, 8, 180), None)
                .unwrap_or_else(|_| panic!("evidence"));
        let _: GovernedFloorVerification = evidence;
    }
}
