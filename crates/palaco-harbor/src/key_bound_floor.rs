//! Optional key-ID-bound signature envelope for Harbor floor evidence.
//!
//! v0.22/v0.23 signatures bind the complete floor candidate, while the
//! registry key identifier is policy metadata. This additive envelope keeps
//! the existing evidence contract and adds a second signature over the exact
//! key identifier plus the complete signed candidate.
//!
//! The envelope remains evidence-only. It does not enroll keys, establish a
//! source-to-key authority mapping, persist a trust floor, or authorize runtime
//! behavior.

use crate::checkpoint_verifier::{
    signed_floor_bytes, FloorVerificationError, SignedFloorCandidate,
};
use crate::governed_floor::{
    verify_governed_floor, GovernedFloorCandidate, GovernedFloorError, GovernedFloorPolicy,
    GovernedFloorVerification,
};
use crate::trust_registry::{KeyRecord, KeyRegistry, RegistryError};
use ed25519_dalek::{Signature, VerifyingKey};

const DOMAIN: &[u8] = b"PALACO-HARBOR-KEY-BOUND-FLOOR-v1\0";
const MAX_ID_BYTES: usize = 128;

/// A v0.23 floor candidate with an additional signature over its key label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBoundGovernedFloorCandidate {
    /// Exact registry key identifier used for the candidate.
    pub key_id: String,
    /// Existing source-signed floor candidate.
    pub signed: SignedFloorCandidate,
    /// Signature over the key identifier and the complete signed candidate.
    pub key_binding_signature: [u8; 64],
}

/// Fail-closed outcomes for the optional key-bound envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBoundFloorError {
    /// The underlying governed-floor evidence failed.
    Governed(GovernedFloorError),
    /// The additional key-ID-bound signature failed.
    InvalidKeyBindingSignature,
}

fn id_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

/// Canonical bytes for the additional key-ID binding signature.
///
/// The existing v0.22 signature remains inside the candidate. This envelope
/// signs the external key label and the full v0.22 signed payload together.
pub fn key_bound_floor_bytes(
    key_id: &str,
    signed: &SignedFloorCandidate,
) -> Result<Vec<u8>, KeyBoundFloorError> {
    if !id_valid(key_id) {
        return Err(KeyBoundFloorError::Governed(
            GovernedFloorError::InvalidPolicy,
        ));
    }
    let floor_bytes = signed_floor_bytes(signed)
        .map_err(|error| KeyBoundFloorError::Governed(GovernedFloorError::Floor(error)))?;
    let key_len = u64::try_from(key_id.len())
        .map_err(|_| KeyBoundFloorError::Governed(GovernedFloorError::InvalidPolicy))?;
    let floor_len = u64::try_from(floor_bytes.len()).map_err(|_| {
        KeyBoundFloorError::Governed(GovernedFloorError::Floor(
            FloorVerificationError::InvalidCandidate,
        ))
    })?;
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&key_len.to_be_bytes());
    bytes.extend_from_slice(key_id.as_bytes());
    bytes.extend_from_slice(&floor_len.to_be_bytes());
    bytes.extend_from_slice(&floor_bytes);
    Ok(bytes)
}

#[derive(Clone)]
struct PinnedRegistry {
    record: KeyRecord,
}

impl KeyRegistry for PinnedRegistry {
    fn resolve(&self, key_id: &str) -> Result<Option<KeyRecord>, RegistryError> {
        if self.record.key_id == key_id {
            Ok(Some(self.record.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Verify the governed floor and the additional key-ID-bound signature.
///
/// A single pinned registry record is used for both the underlying v0.23
/// checks and the additional signature, preventing a mutable registry lookup
/// from changing between those checks.
pub fn verify_key_bound_floor<R: KeyRegistry>(
    registry: &R,
    policy: &GovernedFloorPolicy,
    candidate: &KeyBoundGovernedFloorCandidate,
    previous: Option<&GovernedFloorVerification>,
) -> Result<GovernedFloorVerification, KeyBoundFloorError> {
    if candidate.key_id.is_empty() {
        return Err(KeyBoundFloorError::Governed(
            GovernedFloorError::MissingKeyId,
        ));
    }

    let record = match registry.resolve(&candidate.key_id) {
        Ok(Some(record)) => record,
        Ok(None) => return Err(KeyBoundFloorError::Governed(GovernedFloorError::UnknownKey)),
        Err(RegistryError::Unavailable) => {
            return Err(KeyBoundFloorError::Governed(
                GovernedFloorError::RegistryUnavailable,
            ))
        }
        Err(RegistryError::Uncertain) => {
            return Err(KeyBoundFloorError::Governed(
                GovernedFloorError::RegistryUncertain,
            ))
        }
    };

    let pinned = PinnedRegistry {
        record: record.clone(),
    };
    let evidence = verify_governed_floor(
        &pinned,
        policy,
        &GovernedFloorCandidate {
            key_id: candidate.key_id.clone(),
            signed: candidate.signed.clone(),
        },
        previous,
    )
    .map_err(KeyBoundFloorError::Governed)?;

    let bytes = key_bound_floor_bytes(&candidate.key_id, &candidate.signed)?;
    let verifying = VerifyingKey::from_bytes(&record.public_key).map_err(|_| {
        KeyBoundFloorError::Governed(GovernedFloorError::Floor(
            FloorVerificationError::InvalidVerifyingKey,
        ))
    })?;
    verifying
        .verify_strict(
            &bytes,
            &Signature::from_bytes(&candidate.key_binding_signature),
        )
        .map_err(|_| KeyBoundFloorError::InvalidKeyBindingSignature)?;

    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::{
        key_bound_floor_bytes, verify_key_bound_floor, KeyBoundFloorError,
        KeyBoundGovernedFloorCandidate,
    };
    use crate::anchor_cas::AnchorRecord;
    use crate::anchor_checkpoint::ExternalFloorCandidate;
    use crate::checkpoint_verifier::{
        signed_floor_bytes, FloorVerificationError, SignedFloorCandidate,
    };
    use crate::governed_floor::{
        GovernedFloorError, GovernedFloorPolicy, GovernedFloorVerification,
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
        SigningKey::from_bytes(&[73_u8; 32])
    }

    fn record() -> KeyRecord {
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
        observed_at_ms: u64,
    ) -> KeyBoundGovernedFloorCandidate {
        let mut signed = SignedFloorCandidate {
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
            trust_epoch: 8,
            observed_at_ms,
            signature: [0; 64],
        };
        let floor_bytes = signed_floor_bytes(&signed).unwrap_or_else(|_| panic!("floor bytes"));
        signed.signature = signing().sign(&floor_bytes).to_bytes();
        let binding_bytes = key_bound_floor_bytes("checkpoint-key-1", &signed)
            .unwrap_or_else(|_| panic!("binding bytes"));
        KeyBoundGovernedFloorCandidate {
            key_id: "checkpoint-key-1".to_owned(),
            signed,
            key_binding_signature: signing().sign(&binding_bytes).to_bytes(),
        }
    }

    fn registry() -> ScriptedRegistry {
        ScriptedRegistry(Ok(Some(record())))
    }

    #[test]
    fn key_bound_candidate_returns_evidence() {
        let result = verify_key_bound_floor(&registry(), &policy(), &candidate(1, 1, 180), None);
        assert!(result.is_ok());
    }

    #[test]
    fn key_label_is_cryptographically_bound() {
        let original = candidate(1, 1, 180);
        let mut alias = original.clone();
        alias.key_id = "checkpoint-key-alias".to_owned();
        let mut alias_record = record();
        alias_record.key_id = alias.key_id.clone();
        let mut alias_policy = policy();
        alias_policy.expected_key_id = alias.key_id.clone();
        assert_eq!(
            verify_key_bound_floor(
                &ScriptedRegistry(Ok(Some(alias_record))),
                &alias_policy,
                &alias,
                None,
            ),
            Err(KeyBoundFloorError::InvalidKeyBindingSignature)
        );
    }

    #[test]
    fn changed_floor_payload_fails_before_binding_check() {
        let mut changed = candidate(1, 1, 180);
        changed.signed.candidate.record.sequence = 2;
        assert_eq!(
            verify_key_bound_floor(&registry(), &policy(), &changed, None),
            Err(KeyBoundFloorError::Governed(GovernedFloorError::Floor(
                FloorVerificationError::InvalidSignature
            )))
        );
    }

    #[test]
    fn wrong_binding_signature_fails_closed() {
        let mut changed = candidate(1, 1, 180);
        changed.key_binding_signature[0] ^= 1;
        assert_eq!(
            verify_key_bound_floor(&registry(), &policy(), &changed, None),
            Err(KeyBoundFloorError::InvalidKeyBindingSignature)
        );
    }

    #[test]
    fn registry_outage_and_unknown_key_never_fall_back() {
        assert_eq!(
            verify_key_bound_floor(
                &ScriptedRegistry(Ok(None)),
                &policy(),
                &candidate(1, 1, 180),
                None,
            ),
            Err(KeyBoundFloorError::Governed(GovernedFloorError::UnknownKey))
        );
        assert_eq!(
            verify_key_bound_floor(
                &ScriptedRegistry(Err(RegistryError::Unavailable)),
                &policy(),
                &candidate(1, 1, 180),
                None,
            ),
            Err(KeyBoundFloorError::Governed(
                GovernedFloorError::RegistryUnavailable
            ))
        );
    }

    #[test]
    fn evidence_remains_distinct_from_authority() {
        let evidence = verify_key_bound_floor(&registry(), &policy(), &candidate(1, 1, 180), None)
            .unwrap_or_else(|_| panic!("evidence"));
        let _: GovernedFloorVerification = evidence;
    }
}
