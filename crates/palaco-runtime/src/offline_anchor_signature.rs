//! Signature-authenticated checkpoint evidence for non-executing offline review.
//!
//! Pinned keys, registry identity and monotonic floors must be provisioned
//! independently. A valid signature does not prove freshness or authority.

use crate::offline_checkpoint_store::{read_checkpoint, CheckpointStoreError};
use crate::offline_ed25519::Ed25519ReviewVerifier;
use crate::offline_recovery_signed::SignedReceiptVerifier;
use crate::offline_revocation_checkpoint::{
    assess_checkpoint, CheckpointAssessment, ExternalAnchor, RevocationCheckpoint,
};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Untrusted transport for a signature over one registry's checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedCheckpointAnchor {
    /// Explicit registry identity, provisioned separately from candidate files.
    pub registry_id: [u8; 32],
    /// Exact checkpoint covered by the signature.
    pub checkpoint: RevocationCheckpoint,
    /// SHA-256 reference of the externally pinned signing public key.
    pub signer_key_id: [u8; 32],
    /// Ed25519 signature over the domain-separated signing digest.
    pub signature: [u8; 64],
}

/// Externally supplied review policy; this module cannot authenticate its origin.
///
/// Restoring this policy with old floors can admit an old signed receipt.
/// Never load the pinned key or floors from the same untrusted receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorReviewPolicy {
    /// Expected nonzero registry identity.
    pub registry_id: [u8; 32],
    /// Public key pinned through a separate governed provisioning path.
    pub pinned_public_key: [u8; 32],
    /// Independently retained minimum acceptable checkpoint revision.
    pub minimum_revision: u64,
    /// Independently retained minimum acceptable policy epoch.
    pub minimum_policy_epoch: u64,
}

/// Signature review failure; none of these outcomes permit recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorReviewError {
    /// Missing or different registry identity.
    RegistryMismatch,
    /// Invalid checkpoint commitment or zero revision.
    InvalidCheckpoint,
    /// Receipt is behind externally supplied monotonic floors.
    BelowFloor,
    /// Pinned public key cannot be parsed.
    InvalidPinnedKey,
    /// Signature or pinned key reference does not match.
    InvalidSignature,
}

/// Evidence with a verified signature; private fields prevent unchecked creation.
///
/// This is not a grant, a trusted clock, or proof that an anchor is current.
pub struct SignatureCheckedAnchor {
    observation: ExternalAnchor,
}

impl SignatureCheckedAnchor {
    /// Compare one candidate using this signature-checked observation.
    ///
    /// An exact match remains review evidence only, never execution authority.
    #[must_use]
    pub fn assess(&self, candidate: &RevocationCheckpoint) -> CheckpointAssessment {
        assess_checkpoint(candidate, Some(&self.observation))
    }
}

/// Compute the v1 statement digest without asserting that it is trustworthy.
///
/// Encoding: domain, 32-byte registry ID, checkpoint commitment, 32-byte key ID.
/// The commitment binds revision, policy epoch and registry state digest.
#[must_use]
pub fn anchor_signing_digest(receipt: &SignedCheckpointAnchor) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PALACO-ORCH-056-SIGNED-CHECKPOINT-ANCHOR-v1");
    hasher.update(receipt.registry_id);
    hasher.update(receipt.checkpoint.commitment);
    hasher.update(receipt.signer_key_id);
    hasher.finalize().into()
}

/// Verify exact receipt bytes against independently supplied identity/key/floors.
///
/// No key enrollment, revocation lookup, trusted time, durable floor update,
/// replay reservation, network request or execution is performed.
pub fn verify_anchor(
    receipt: &SignedCheckpointAnchor,
    policy: &AnchorReviewPolicy,
) -> Result<SignatureCheckedAnchor, AnchorReviewError> {
    if policy.registry_id == [0; 32] || receipt.registry_id != policy.registry_id {
        return Err(AnchorReviewError::RegistryMismatch);
    }
    if receipt.checkpoint.revision == 0 || !receipt.checkpoint.is_well_formed() {
        return Err(AnchorReviewError::InvalidCheckpoint);
    }
    if receipt.checkpoint.revision < policy.minimum_revision
        || receipt.checkpoint.policy_epoch < policy.minimum_policy_epoch
    {
        return Err(AnchorReviewError::BelowFloor);
    }
    let verifier = Ed25519ReviewVerifier::from_public_key(&policy.pinned_public_key)
        .ok_or(AnchorReviewError::InvalidPinnedKey)?;
    if !verifier.verify(
        &anchor_signing_digest(receipt),
        &receipt.signer_key_id,
        &receipt.signature,
    ) {
        return Err(AnchorReviewError::InvalidSignature);
    }
    Ok(SignatureCheckedAnchor {
        observation: ExternalAnchor {
            revision: receipt.checkpoint.revision,
            policy_epoch: receipt.checkpoint.policy_epoch,
            commitment: receipt.checkpoint.commitment,
        },
    })
}

/// Combined non-executing stored-candidate review failure.
#[derive(Debug)]
pub enum StoredAnchorReviewError {
    /// Signature, registry or policy evidence failed.
    Anchor(AnchorReviewError),
    /// The stored candidate could not be read and validated.
    Store(CheckpointStoreError),
}

/// Authenticate supplied evidence, then inspect the explicitly requested file.
///
/// Signature success cannot change a file, update a floor or approve recovery.
pub fn assess_stored_checkpoint(
    root: &Path,
    revision: u64,
    receipt: &SignedCheckpointAnchor,
    policy: &AnchorReviewPolicy,
) -> Result<CheckpointAssessment, StoredAnchorReviewError> {
    let anchor = verify_anchor(receipt, policy).map_err(StoredAnchorReviewError::Anchor)?;
    let checkpoint = read_checkpoint(root, revision).map_err(StoredAnchorReviewError::Store)?;
    Ok(anchor.assess(&checkpoint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_checkpoint_store::persist_checkpoint;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (SigningKey, SignedCheckpointAnchor, AnchorReviewPolicy) {
        let signer = SigningKey::from_bytes(&[56; 32]);
        let public = signer.verifying_key().to_bytes();
        let policy = AnchorReviewPolicy {
            registry_id: [7; 32],
            pinned_public_key: public,
            minimum_revision: 4,
            minimum_policy_epoch: 2,
        };
        let mut receipt = SignedCheckpointAnchor {
            registry_id: policy.registry_id,
            checkpoint: RevocationCheckpoint::new(4, 2, [8; 32]),
            signer_key_id: Sha256::digest(public).into(),
            signature: [0; 64],
        };
        receipt.signature = signer.sign(&anchor_signing_digest(&receipt)).to_bytes();
        (signer, receipt, policy)
    }

    #[test]
    fn exact_signed_anchor_is_only_comparison_evidence() -> Result<(), AnchorReviewError> {
        let (_, receipt, policy) = fixture();
        let checked = verify_anchor(&receipt, &policy)?;
        assert_eq!(
            checked.assess(&receipt.checkpoint),
            CheckpointAssessment::MatchesAnchor
        );
        assert_eq!(
            checked.assess(&RevocationCheckpoint::new(3, 2, [8; 32])),
            CheckpointAssessment::RollbackDetected
        );
        assert_eq!(
            checked.assess(&RevocationCheckpoint::new(4, 2, [9; 32])),
            CheckpointAssessment::ForkDetected
        );
        Ok(())
    }

    #[test]
    fn registry_substitution_is_denied_even_with_valid_signature() {
        let (_, receipt, mut policy) = fixture();
        policy.registry_id = [9; 32];
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::RegistryMismatch)
        ));
    }

    #[test]
    fn receipt_mutation_requires_a_new_signature() {
        let (_, mut receipt, policy) = fixture();
        receipt.checkpoint = RevocationCheckpoint::new(5, 2, [9; 32]);
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::InvalidSignature)
        ));
    }

    #[test]
    fn different_signer_and_key_reference_are_denied() {
        let (_, mut receipt, policy) = fixture();
        let other = SigningKey::from_bytes(&[57; 32]);
        receipt.signature = other.sign(&anchor_signing_digest(&receipt)).to_bytes();
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::InvalidSignature)
        ));
        let (_, mut receipt, policy) = fixture();
        receipt.signer_key_id = [0; 32];
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::InvalidSignature)
        ));
    }

    #[test]
    fn valid_old_signature_is_denied_by_each_external_floor() {
        let (_, receipt, mut policy) = fixture();
        policy.minimum_revision = 5;
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::BelowFloor)
        ));
        policy.minimum_revision = 4;
        policy.minimum_policy_epoch = 3;
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::BelowFloor)
        ));
    }

    #[test]
    fn malformed_checkpoint_is_denied_before_signature_review() {
        let (_, mut receipt, policy) = fixture();
        receipt.checkpoint.registry_digest[0] ^= 1;
        assert!(matches!(
            verify_anchor(&receipt, &policy),
            Err(AnchorReviewError::InvalidCheckpoint)
        ));
    }

    #[test]
    fn rolled_back_policy_limitation_is_explicit() {
        let (_, receipt, mut policy) = fixture();
        policy.minimum_revision = 5;
        assert!(verify_anchor(&receipt, &policy).is_err());
        policy.minimum_revision = 4;
        // Signatures alone cannot detect restoration of their trust policy.
        assert!(verify_anchor(&receipt, &policy).is_ok());
    }

    #[test]
    fn persisted_candidate_uses_separately_supplied_signed_evidence() -> Result<(), std::io::Error> {
        let root = std::env::temp_dir().join(format!("palaco-orch056-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        let (_, receipt, policy) = fixture();
        assert!(persist_checkpoint(&root, &receipt.checkpoint).is_ok());
        assert!(matches!(
            assess_stored_checkpoint(&root, 4, &receipt, &policy),
            Ok(CheckpointAssessment::MatchesAnchor)
        ));
        let old = RevocationCheckpoint::new(3, 2, [8; 32]);
        assert!(persist_checkpoint(&root, &old).is_ok());
        assert!(matches!(
            assess_stored_checkpoint(&root, 3, &receipt, &policy),
            Ok(CheckpointAssessment::RollbackDetected)
        ));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
