//! Independent checkpoint reconciliation gate (reference contract only).
//!
//! The backend must independently authenticate its transport, durable state,
//! authorization root, and freshness. No network client or authority is supplied.
//! A matching signature proves only possession of the configured private key.

use crate::anchor_cas::AnchorRecord;
use crate::remote_anchor_adapter::{attestation_bytes, AttestedAnchor};
use ed25519_dalek::{Signature, VerifyingKey};

/// Provider failure must never be treated as an empty checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointError {
    Unavailable,
    Timeout,
    InvalidResponse,
}

/// An independently operated backend. This trait does not provide independence.
pub trait IndependentCheckpoint {
    fn read(&self) -> Result<Option<AttestedAnchor>, CheckpointError>;
}

/// An exact match is only a prerequisite for a separate human-governed transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointGate {
    Matched,
    MissingLocal,
    MissingIndependent,
    Uninitialized,
    LocalBehind,
    IndependentBehind,
    ConflictingState,
    InvalidSignature,
    Unavailable,
    Uncertain,
}

fn validate(
    attested: AttestedAnchor,
    pinned_key: &[u8; 32],
) -> Result<AnchorRecord, CheckpointGate> {
    let key = VerifyingKey::from_bytes(pinned_key).map_err(|_| CheckpointGate::InvalidSignature)?;
    let bytes =
        attestation_bytes(&attested.record).map_err(|_| CheckpointGate::InvalidSignature)?;
    key.verify_strict(&bytes, &Signature::from_bytes(&attested.signature))
        .map_err(|_| CheckpointGate::InvalidSignature)?;
    Ok(attested.record)
}

/// Read both sides, reject ambiguity, and compare the *complete* signed record.
/// The local candidate must itself have been verified during journal recovery.
/// Never automatically promote one side to match the other.
pub fn reconcile<P: IndependentCheckpoint>(
    local: Result<Option<AnchorRecord>, CheckpointError>,
    provider: &P,
    pinned_key: &[u8; 32],
) -> CheckpointGate {
    let local = match local {
        Ok(value) => value,
        Err(CheckpointError::Timeout) => return CheckpointGate::Uncertain,
        Err(_) => return CheckpointGate::Unavailable,
    };
    let remote = match provider.read() {
        Ok(Some(attested)) => match validate(attested, pinned_key) {
            Ok(record) => Some(record),
            Err(error) => return error,
        },
        Ok(None) => None,
        Err(CheckpointError::Timeout) => return CheckpointGate::Uncertain,
        Err(_) => return CheckpointGate::Unavailable,
    };
    match (local, remote) {
        (None, None) => CheckpointGate::Uninitialized,
        (None, Some(_)) => CheckpointGate::MissingLocal,
        (Some(_), None) => CheckpointGate::MissingIndependent,
        (Some(local), Some(remote)) if local == remote => CheckpointGate::Matched,
        (Some(local), Some(remote)) if local.revision < remote.revision => {
            CheckpointGate::LocalBehind
        }
        (Some(local), Some(remote)) if local.revision > remote.revision => {
            CheckpointGate::IndependentBehind
        }
        _ => CheckpointGate::ConflictingState,
    }
}

#[cfg(test)]
mod tests {
    use super::{reconcile, CheckpointError, CheckpointGate, IndependentCheckpoint};
    use crate::anchor_cas::AnchorRecord;
    use crate::remote_anchor_adapter::{attestation_bytes, AttestedAnchor};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    struct FakeCheckpoint {
        value: Result<Option<AttestedAnchor>, CheckpointError>,
    }
    impl IndependentCheckpoint for FakeCheckpoint {
        fn read(&self) -> Result<Option<AttestedAnchor>, CheckpointError> {
            self.value.clone()
        }
    }
    fn record(revision: u64) -> AnchorRecord {
        AnchorRecord {
            revision,
            signer_epoch: 5,
            sequence: revision,
            chain_digest: [revision as u8; 32],
            signer_id: "signer-a".to_owned(),
            retired_signers: BTreeSet::new(),
        }
    }
    fn signed(record: AnchorRecord, key: &SigningKey) -> AttestedAnchor {
        let bytes = attestation_bytes(&record).unwrap_or_else(|_| panic!("encode"));
        AttestedAnchor {
            record,
            signature: key.sign(&bytes).to_bytes(),
        }
    }
    fn test(
        local: Option<AnchorRecord>,
        remote: Result<Option<AttestedAnchor>, CheckpointError>,
        key: &SigningKey,
    ) -> CheckpointGate {
        reconcile(
            Ok(local),
            &FakeCheckpoint { value: remote },
            &key.verifying_key().to_bytes(),
        )
    }

    #[test]
    fn complete_signed_match_is_only_precondition() {
        let key = SigningKey::from_bytes(&[51; 32]);
        assert_eq!(
            test(Some(record(2)), Ok(Some(signed(record(2), &key))), &key),
            CheckpointGate::Matched
        );
    }

    #[test]
    fn missing_and_uninitialized_states_never_pass() {
        let key = SigningKey::from_bytes(&[51; 32]);
        assert_eq!(test(None, Ok(None), &key), CheckpointGate::Uninitialized);
        assert_eq!(
            test(None, Ok(Some(signed(record(1), &key))), &key),
            CheckpointGate::MissingLocal
        );
        assert_eq!(
            test(Some(record(1)), Ok(None), &key),
            CheckpointGate::MissingIndependent
        );
    }

    #[test]
    fn replay_and_divergent_signatures_never_pass() {
        let key = SigningKey::from_bytes(&[51; 32]);
        assert_eq!(
            test(Some(record(1)), Ok(Some(signed(record(2), &key))), &key),
            CheckpointGate::LocalBehind
        );
        assert_eq!(
            test(Some(record(3)), Ok(Some(signed(record(2), &key))), &key),
            CheckpointGate::IndependentBehind
        );
        let mut fork = record(2);
        fork.chain_digest = [7; 32];
        assert_eq!(
            test(Some(record(2)), Ok(Some(signed(fork, &key))), &key),
            CheckpointGate::ConflictingState
        );
    }

    #[test]
    fn wrong_key_or_tampered_record_is_rejected() {
        let key = SigningKey::from_bytes(&[51; 32]);
        let wrong = SigningKey::from_bytes(&[52; 32]);
        assert_eq!(
            test(Some(record(1)), Ok(Some(signed(record(1), &wrong))), &key),
            CheckpointGate::InvalidSignature
        );
        let mut attested = signed(record(1), &key);
        attested.record.revision = 2;
        assert_eq!(
            test(Some(record(1)), Ok(Some(attested)), &key),
            CheckpointGate::InvalidSignature
        );
    }

    #[test]
    fn timeouts_errors_and_local_uncertainty_hold() {
        let key = SigningKey::from_bytes(&[51; 32]);
        assert_eq!(
            test(Some(record(1)), Err(CheckpointError::Timeout), &key),
            CheckpointGate::Uncertain
        );
        assert_eq!(
            test(Some(record(1)), Err(CheckpointError::Unavailable), &key),
            CheckpointGate::Unavailable
        );
        assert_eq!(
            reconcile(
                Err(CheckpointError::Timeout),
                &FakeCheckpoint { value: Ok(None) },
                &key.verifying_key().to_bytes()
            ),
            CheckpointGate::Uncertain
        );
    }
}
