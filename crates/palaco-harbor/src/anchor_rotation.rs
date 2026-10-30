//! Governed signer-rotation and exact-head checkpoint reference boundary.
//!
//! No actual independent checkpoint authority or key custodian is provided.
//! A snapshot must be authenticated, atomic, and rollback-resistant outside
//! this module. A valid signature cannot grant admission or execution.

use crate::journal_integrity::{chain_digest, IntegrityError};
use crate::trust_recovery::{
    recover_frames, JournalError, RecoveryError, RecoveryFloor, TrustFrame, TrustJournal,
};
use ed25519_dalek::{Signature, VerifyingKey};

const DOMAIN: &[u8] = b"PALACO-HARBOR-ROTATING-ANCHOR-v1\0";

/// A checkpoint whose signer identifier and epoch are signed with the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatingAnchor {
    pub signer_id: String,
    pub signer_epoch: u64,
    pub sequence: u64,
    pub chain_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// Independently governed signer data at the same policy revision as anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRecord {
    pub signer_id: String,
    pub epoch: u64,
    pub public_key: [u8; 32],
    pub revoked: bool,
}

/// A single atomic policy-and-anchor snapshot from independent governance.
///
/// The minimum epoch must be persistently monotone, including across rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedSnapshot {
    pub anchor: RotatingAnchor,
    pub signer: SignerRecord,
    pub minimum_signer_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceError {
    Unavailable,
    Uncertain,
}

/// Production implementations must authenticate the *whole* snapshot and
/// independently protect its monotone minimum epoch.
pub trait GovernedAnchorSource {
    fn load_snapshot(&self) -> Result<GovernedSnapshot, GovernanceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationError {
    Governance(GovernanceError),
    Recovery(RecoveryError),
    Journal(JournalError),
    Integrity(IntegrityError),
    InvalidIdentity,
    InvalidEpoch,
    RevokedSigner,
    InvalidPublicKey,
    InvalidSignature,
    SequenceMismatch,
    DigestMismatch,
}

/// Exact bytes of a signed checkpoint, including the selected signer and
/// signer epoch. No code path automatically trusts a newly presented key.
pub fn signed_checkpoint_bytes(anchor: &RotatingAnchor) -> Result<Vec<u8>, RotationError> {
    if anchor.signer_id.is_empty()
        || anchor.signer_id.len() > 128
        || !anchor.signer_id.is_ascii()
        || anchor.signer_epoch == 0
        || anchor.sequence == 0
    {
        return Err(RotationError::InvalidIdentity);
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 1 + 128 + 8 + 8 + 32);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(u8::try_from(anchor.signer_id.len()).map_err(|_| RotationError::InvalidIdentity)?);
    bytes.extend_from_slice(anchor.signer_id.as_bytes());
    bytes.extend_from_slice(&anchor.signer_epoch.to_be_bytes());
    bytes.extend_from_slice(&anchor.sequence.to_be_bytes());
    bytes.extend_from_slice(&anchor.chain_digest);
    Ok(bytes)
}

/// Verify against one captured journal snapshot and one governed policy
/// snapshot. This produces no authorization or permission decision.
pub fn verify_rotating_checkpoint<J: TrustJournal, G: GovernedAnchorSource>(
    journal: &J,
    governance: &G,
    floor: RecoveryFloor,
) -> Result<TrustFrame, RotationError> {
    let snapshot = governance
        .load_snapshot()
        .map_err(RotationError::Governance)?;
    let anchor = &snapshot.anchor;
    let signer = &snapshot.signer;
    if signer.signer_id != anchor.signer_id || signer.signer_id.is_empty() {
        return Err(RotationError::InvalidIdentity);
    }
    if signer.epoch == 0
        || snapshot.minimum_signer_epoch == 0
        || signer.epoch != anchor.signer_epoch
        || signer.epoch < snapshot.minimum_signer_epoch
    {
        return Err(RotationError::InvalidEpoch);
    }
    if signer.revoked {
        return Err(RotationError::RevokedSigner);
    }
    let key = VerifyingKey::from_bytes(&signer.public_key)
        .map_err(|_| RotationError::InvalidPublicKey)?;
    let message = signed_checkpoint_bytes(anchor)?;
    key.verify_strict(&message, &Signature::from_bytes(&anchor.signature))
        .map_err(|_| RotationError::InvalidSignature)?;

    let frames = journal.load().map_err(RotationError::Journal)?;
    let latest = recover_frames(&frames, floor).map_err(RotationError::Recovery)?;
    if anchor.sequence != latest.sequence {
        return Err(RotationError::SequenceMismatch);
    }
    if chain_digest(&frames).map_err(RotationError::Integrity)? != anchor.chain_digest {
        return Err(RotationError::DigestMismatch);
    }
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::{
        signed_checkpoint_bytes, verify_rotating_checkpoint, GovernanceError, GovernedAnchorSource,
        GovernedSnapshot, RotatingAnchor, RotationError, SignerRecord,
    };
    use crate::journal_integrity::chain_digest;
    use crate::trust_recovery::{JournalError, RecoveryFloor, TrustFrame, TrustJournal};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    struct Frames(Vec<TrustFrame>);

    impl TrustJournal for Frames {
        fn load(&self) -> Result<Vec<TrustFrame>, JournalError> {
            Ok(self.0.clone())
        }

        fn append_sync(&mut self, _frame: &TrustFrame) -> Result<(), JournalError> {
            Err(JournalError::Unavailable)
        }
    }

    struct Governance(Result<GovernedSnapshot, GovernanceError>);

    impl GovernedAnchorSource for Governance {
        fn load_snapshot(&self) -> Result<GovernedSnapshot, GovernanceError> {
            self.0.clone()
        }
    }

    fn frames() -> Frames {
        Frames(vec![TrustFrame {
            sequence: 1,
            trust_epoch: 7,
            highest_trusted_time_ms: 100,
            revoked_keys: BTreeSet::new(),
        }])
    }

    fn floor() -> RecoveryFloor {
        RecoveryFloor {
            minimum_sequence: 1,
            minimum_trust_epoch: 7,
            minimum_trusted_time_ms: 100,
        }
    }

    fn fixture(epoch: u64) -> Governance {
        let signing = SigningKey::from_bytes(&[31_u8; 32]);
        let mut anchor = RotatingAnchor {
            signer_id: "custodian-a".to_owned(),
            signer_epoch: epoch,
            sequence: 1,
            chain_digest: chain_digest(&frames().0).unwrap_or_else(|_| panic!("digest")),
            signature: [0; 64],
        };
        anchor.signature = signing
            .sign(&signed_checkpoint_bytes(&anchor).unwrap_or_else(|_| panic!("message")))
            .to_bytes();
        Governance(Ok(GovernedSnapshot {
            signer: SignerRecord {
                signer_id: anchor.signer_id.clone(),
                epoch,
                public_key: signing.verifying_key().to_bytes(),
                revoked: false,
            },
            anchor,
            minimum_signer_epoch: epoch,
        }))
    }

    #[test]
    fn matching_governed_snapshot_checks() {
        assert_eq!(
            verify_rotating_checkpoint(&frames(), &fixture(8), floor()),
            Ok(frames().0[0].clone())
        );
    }

    #[test]
    fn prior_epoch_cannot_reenter_after_rotation() {
        let mut old = fixture(8);
        if let Ok(ref mut snapshot) = old.0 {
            snapshot.minimum_signer_epoch = 9;
        }
        assert_eq!(
            verify_rotating_checkpoint(&frames(), &old, floor()),
            Err(RotationError::InvalidEpoch)
        );
        assert!(verify_rotating_checkpoint(&frames(), &fixture(9), floor()).is_ok());
    }

    #[test]
    fn revoked_or_mismatched_signer_is_denied() {
        let mut revoked = fixture(8);
        if let Ok(ref mut snapshot) = revoked.0 {
            snapshot.signer.revoked = true;
        }
        assert_eq!(
            verify_rotating_checkpoint(&frames(), &revoked, floor()),
            Err(RotationError::RevokedSigner)
        );
        let mut mismatch = fixture(8);
        if let Ok(ref mut snapshot) = mismatch.0 {
            snapshot.signer.signer_id = "other".to_owned();
        }
        assert_eq!(
            verify_rotating_checkpoint(&frames(), &mismatch, floor()),
            Err(RotationError::InvalidIdentity)
        );
    }

    #[test]
    fn signed_epoch_and_identity_cannot_be_modified() {
        let mut changed = fixture(8);
        if let Ok(ref mut snapshot) = changed.0 {
            snapshot.anchor.signer_epoch = 9;
            snapshot.signer.epoch = 9;
            snapshot.minimum_signer_epoch = 9;
        }
        assert_eq!(
            verify_rotating_checkpoint(&frames(), &changed, floor()),
            Err(RotationError::InvalidSignature)
        );
        let mut changed = fixture(8);
        if let Ok(ref mut snapshot) = changed.0 {
            snapshot.anchor.signer_id = "custodian-b".to_owned();
            snapshot.signer.signer_id = "custodian-b".to_owned();
        }
        assert_eq!(
            verify_rotating_checkpoint(&frames(), &changed, floor()),
            Err(RotationError::InvalidSignature)
        );
    }

    #[test]
    fn journal_drift_and_governance_outage_fail_closed() {
        let mut changed = frames();
        changed.0[0].highest_trusted_time_ms = 101;
        assert_eq!(
            verify_rotating_checkpoint(&changed, &fixture(8), floor()),
            Err(RotationError::DigestMismatch)
        );
        assert_eq!(
            verify_rotating_checkpoint(
                &frames(),
                &Governance(Err(GovernanceError::Unavailable)),
                floor()
            ),
            Err(RotationError::Governance(GovernanceError::Unavailable))
        );
    }
}
