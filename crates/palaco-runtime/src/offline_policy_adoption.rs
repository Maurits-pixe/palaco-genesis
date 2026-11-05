//! Explicit staged policy adoption protocol over an independent pin backend.
//!
//! Backend implementers must supply authenticated durable linearizable pin
//! operations outside the policy filesystem's rollback domain. No production
//! backend or governance authorization is supplied by this protocol.

use crate::offline_anchor_signature::AnchorReviewPolicy;
use crate::offline_policy_store::{
    read_pinned_policy, stage_policy_advance, PolicyPin, PolicyStoreError,
};
use std::path::Path;

/// Backend failure; writes may have committed despite an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinBackendError {
    /// Independent storage is missing or inaccessible.
    Unavailable,
    /// Another actor changed the expected pin.
    Conflict,
    /// The write outcome cannot be determined from its response.
    Indeterminate,
}

/// Independent durable pin storage for one governed registry.
///
/// Reads must be current/linearizable, authenticated, and rollback resistant.
/// compare_exchange must atomically replace only the exact expected pin and
/// durably retain it across restart before reporting success. This trait cannot
/// enforce those properties; an ordinary local file or volatile map is not a
/// conforming production implementation. Authorization belongs to the backend.
pub trait PolicyPinBackend {
    /// Read the independently retained current pin; None is not bootstrap permission.
    fn read_current(&mut self) -> Result<Option<PolicyPin>, PinBackendError>;

    /// Atomically compare and persist a one-version advance.
    ///
    /// Errors can have an uncertain outcome; callers must re-read before deciding.
    fn compare_exchange(
        &mut self,
        expected: &PolicyPin,
        proposed: &PolicyPin,
    ) -> Result<(), PinBackendError>;
}

/// Safe default when no independent backend has been provisioned.
pub struct UnavailablePinBackend;

impl PolicyPinBackend for UnavailablePinBackend {
    fn read_current(&mut self) -> Result<Option<PolicyPin>, PinBackendError> {
        Err(PinBackendError::Unavailable)
    }

    fn compare_exchange(
        &mut self,
        _expected: &PolicyPin,
        _proposed: &PolicyPin,
    ) -> Result<(), PinBackendError> {
        Err(PinBackendError::Unavailable)
    }
}

/// Preparation or pre-write verification failure.
#[derive(Debug)]
pub enum PolicyAdoptionError {
    /// Backend cannot provide trustworthy current state.
    Backend(PinBackendError),
    /// No independent current pin exists; bootstrap requires separate governance.
    MissingCurrentPin,
    /// A policy record is invalid, unavailable or mismatched.
    Store(PolicyStoreError),
    /// A staged transition is not an exact one-version nondecreasing advance.
    InvalidTransition,
}

/// A staged transition; constructing this value never changes the current pin.
pub struct PreparedPolicyTransition {
    previous: PolicyPin,
    proposed: PolicyPin,
}

/// Observed state after attempting adoption; never an execution grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAdoptionOutcome {
    /// Current backend pin and readable policy equal the proposed next state.
    /// Another actor may have adopted the same state; actor attribution is absent.
    ObservedNext,
    /// Backend still reports the previous pin; no automatic retry is performed.
    ObservedPrevious,
    /// Backend reports a different pin, or its record is missing/mismatched.
    Conflict,
    /// Current state cannot be read after the write attempt.
    Unknown,
}

/// Read the current backend pin and its exact policy, never a directory fallback.
pub fn read_current_policy<B: PolicyPinBackend>(
    root: &Path,
    backend: &mut B,
) -> Result<AnchorReviewPolicy, PolicyAdoptionError> {
    let pin = backend
        .read_current()
        .map_err(PolicyAdoptionError::Backend)?
        .ok_or(PolicyAdoptionError::MissingCurrentPin)?;
    read_pinned_policy(root, Some(&pin)).map_err(PolicyAdoptionError::Store)
}

/// Stage and reopen a nondecreasing advance without modifying independent state.
///
/// Interrupted preparation leaves the previous pin current and the staged file
/// preserved. Existing staged files require explicit inspection, not overwrite.
pub fn prepare_policy_transition<B: PolicyPinBackend>(
    root: &Path,
    backend: &mut B,
    next: &AnchorReviewPolicy,
) -> Result<PreparedPolicyTransition, PolicyAdoptionError> {
    let previous = backend
        .read_current()
        .map_err(PolicyAdoptionError::Backend)?
        .ok_or(PolicyAdoptionError::MissingCurrentPin)?;
    let proposed =
        stage_policy_advance(root, &previous, next).map_err(PolicyAdoptionError::Store)?;
    read_pinned_policy(root, Some(&proposed)).map_err(PolicyAdoptionError::Store)?;
    Ok(PreparedPolicyTransition { previous, proposed })
}

/// Explicitly attempt adoption of staged policy, then independently read back.
///
/// Requires separately authorized use of a conforming backend. No policy files
/// are deleted, rewritten or automatically retried. A successful backend return
/// alone is insufficient: observed pin and policy must match after the attempt.
pub fn adopt_prepared_policy<B: PolicyPinBackend>(
    root: &Path,
    backend: &mut B,
    prepared: &PreparedPolicyTransition,
) -> Result<PolicyAdoptionOutcome, PolicyAdoptionError> {
    let previous = read_pinned_policy(root, Some(&prepared.previous))
        .map_err(PolicyAdoptionError::Store)?;
    let next = read_pinned_policy(root, Some(&prepared.proposed))
        .map_err(PolicyAdoptionError::Store)?;
    if prepared.previous.version.checked_add(1) != Some(prepared.proposed.version)
        || previous.registry_id != next.registry_id
        || previous.pinned_public_key != next.pinned_public_key
        || next.minimum_revision < previous.minimum_revision
        || next.minimum_policy_epoch < previous.minimum_policy_epoch
    {
        return Err(PolicyAdoptionError::InvalidTransition);
    }
    let current = backend.read_current().map_err(PolicyAdoptionError::Backend)?;
    if current == Some(prepared.proposed) {
        return Ok(PolicyAdoptionOutcome::ObservedNext);
    }
    if current != Some(prepared.previous) {
        return Ok(PolicyAdoptionOutcome::Conflict);
    }
    // A backend error may mean a committed write with a lost response.
    let _ = backend.compare_exchange(&prepared.previous, &prepared.proposed);
    match backend.read_current() {
        Ok(Some(pin)) if pin == prepared.proposed => {
            if read_pinned_policy(root, Some(&pin)).is_ok() {
                Ok(PolicyAdoptionOutcome::ObservedNext)
            } else {
                Ok(PolicyAdoptionOutcome::Conflict)
            }
        }
        Ok(Some(pin)) if pin == prepared.previous => Ok(PolicyAdoptionOutcome::ObservedPrevious),
        Ok(_) => Ok(PolicyAdoptionOutcome::Conflict),
        Err(_) => Ok(PolicyAdoptionOutcome::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_policy_store::{policy_pin, stage_policy_record};
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;

    // Volatile fault-injection double only; not a production backend.
    struct FixtureBackend {
        current: Option<PolicyPin>,
        mode: u8,
        attempted: bool,
    }

    impl PolicyPinBackend for FixtureBackend {
        fn read_current(&mut self) -> Result<Option<PolicyPin>, PinBackendError> {
            if self.attempted && self.mode == 3 {
                return Err(PinBackendError::Unavailable);
            }
            Ok(self.current)
        }

        fn compare_exchange(
            &mut self,
            expected: &PolicyPin,
            proposed: &PolicyPin,
        ) -> Result<(), PinBackendError> {
            self.attempted = true;
            if self.current != Some(*expected) {
                return Err(PinBackendError::Conflict);
            }
            if self.mode == 2 || self.mode == 3 {
                return Err(PinBackendError::Indeterminate);
            }
            self.current = Some(*proposed);
            if self.mode == 1 {
                return Err(PinBackendError::Indeterminate);
            }
            Ok(())
        }
    }

    fn fixture() -> Result<(PathBuf, AnchorReviewPolicy, FixtureBackend), std::io::Error> {
        let root = std::env::temp_dir().join(format!("palaco-orch058-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        let policy = AnchorReviewPolicy {
            registry_id: [8; 32],
            pinned_public_key: SigningKey::from_bytes(&[58; 32]).verifying_key().to_bytes(),
            minimum_revision: 4,
            minimum_policy_epoch: 2,
        };
        assert!(stage_policy_record(&root, 1, &policy).is_ok());
        let backend = FixtureBackend {
            current: Some(policy_pin(1, &policy)),
            mode: 0,
            attempted: false,
        };
        Ok((root, policy, backend))
    }

    #[test]
    fn unavailable_backend_never_falls_back_to_local_files() -> Result<(), std::io::Error> {
        let (root, next, _) = fixture()?;
        let mut backend = UnavailablePinBackend;
        assert!(read_current_policy(&root, &mut backend).is_err());
        assert!(prepare_policy_transition(&root, &mut backend, &next).is_err());
        assert!(!root.join("policy_2.bin").exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn preparation_keeps_previous_policy_current() -> Result<(), std::io::Error> {
        let (root, policy, mut backend) = fixture()?;
        let mut next = policy;
        next.minimum_revision = 5;
        assert!(prepare_policy_transition(&root, &mut backend, &next).is_ok());
        assert_eq!(backend.current, Some(policy_pin(1, &policy)));
        assert!(!backend.attempted);
        assert!(matches!(read_current_policy(&root, &mut backend), Ok(value) if value == policy));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn adoption_requires_readback_and_is_idempotently_observable() -> Result<(), std::io::Error> {
        let (root, mut policy, mut backend) = fixture()?;
        policy.minimum_revision = 5;
        let prepared = prepare_policy_transition(&root, &mut backend, &policy)
            .map_err(|_| std::io::Error::other("prepare failed"))?;
        assert!(matches!(
            adopt_prepared_policy(&root, &mut backend, &prepared),
            Ok(PolicyAdoptionOutcome::ObservedNext)
        ));
        backend.attempted = false;
        assert!(matches!(
            adopt_prepared_policy(&root, &mut backend, &prepared),
            Ok(PolicyAdoptionOutcome::ObservedNext)
        ));
        assert!(!backend.attempted);
        assert!(matches!(read_current_policy(&root, &mut backend), Ok(value) if value == policy));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn lost_write_response_is_resolved_only_by_readback() -> Result<(), std::io::Error> {
        for (mode, expected) in [
            (1, PolicyAdoptionOutcome::ObservedNext),
            (2, PolicyAdoptionOutcome::ObservedPrevious),
            (3, PolicyAdoptionOutcome::Unknown),
        ] {
            let (root, mut policy, mut backend) = fixture()?;
            policy.minimum_revision = 5;
            backend.mode = mode;
            let prepared = prepare_policy_transition(&root, &mut backend, &policy)
                .map_err(|_| std::io::Error::other("prepare failed"))?;
            assert!(matches!(
                adopt_prepared_policy(&root, &mut backend, &prepared),
                Ok(value) if value == expected
            ));
            assert!(backend.attempted);
            assert!(root.join("policy_1.bin").exists());
            assert!(root.join("policy_2.bin").exists());
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn competing_pin_change_prevents_write() -> Result<(), std::io::Error> {
        let (root, mut policy, mut backend) = fixture()?;
        policy.minimum_revision = 5;
        let prepared = prepare_policy_transition(&root, &mut backend, &policy)
            .map_err(|_| std::io::Error::other("prepare failed"))?;
        backend.current = Some(PolicyPin {
            version: 7,
            digest: [9; 32],
        });
        assert!(matches!(
            adopt_prepared_policy(&root, &mut backend, &prepared),
            Ok(PolicyAdoptionOutcome::Conflict)
        ));
        assert!(!backend.attempted);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_staged_record_blocks_adoption_before_write() -> Result<(), std::io::Error> {
        let (root, mut policy, mut backend) = fixture()?;
        policy.minimum_revision = 5;
        let prepared = prepare_policy_transition(&root, &mut backend, &policy)
            .map_err(|_| std::io::Error::other("prepare failed"))?;
        std::fs::remove_file(root.join("policy_2.bin"))?;
        assert!(adopt_prepared_policy(&root, &mut backend, &prepared).is_err());
        assert!(!backend.attempted);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn backend_pin_without_matching_file_never_falls_back() -> Result<(), std::io::Error> {
        let (root, mut policy, mut backend) = fixture()?;
        policy.minimum_revision = 5;
        backend.current = Some(policy_pin(2, &policy));
        assert!(read_current_policy(&root, &mut backend).is_err());
        assert!(!backend.attempted);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn absent_pin_requires_separate_bootstrap() -> Result<(), std::io::Error> {
        let (root, policy, mut backend) = fixture()?;
        backend.current = None;
        assert!(matches!(
            prepare_policy_transition(&root, &mut backend, &policy),
            Err(PolicyAdoptionError::MissingCurrentPin)
        ));
        assert!(!backend.attempted);
        assert!(!root.join("policy_2.bin").exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
