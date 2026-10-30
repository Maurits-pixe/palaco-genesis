//! Domain-separated chain hashing and signed external anchor verification.
//!
//! This is a fail-closed verification boundary. The signer public key and
//! anchor MUST be independently governed, authenticated and rollback-resistant.
//! Supplying a self-signed local anchor or untrusted key proves no authority.
//! No production anchor source, key provisioning or authorization is included.

use crate::trust_recovery::{
    recover, JournalError, RecoveryError, RecoveryFloor, TrustFrame, TrustJournal,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const FRAME_DOMAIN: &[u8] = b"PALACO-HARBOR-TRUST-FRAME-v1\0";
const ANCHOR_DOMAIN: &[u8] = b"PALACO-HARBOR-TRUST-ANCHOR-v1\0";
const MAX_FRAMES: usize = 10_000;

/// Signed exact-head checkpoint; not trusted until independently sourced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAnchor {
    pub sequence: u64,
    pub chain_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// An independently controlled source. A disk file beside the journal is not
/// sufficient as a rollback-resistant implementation.
pub trait AnchorSource {
    fn load_anchor(&self) -> Result<SignedAnchor, AnchorError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    Unavailable,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    Recovery(RecoveryError),
    Journal(JournalError),
    Anchor(AnchorError),
    InvalidAnchor,
    InvalidSigner,
    InvalidSignature,
    SequenceMismatch,
    DigestMismatch,
    TooManyFrames,
}

/// Hash every full-state frame using an unambiguous fixed-width encoding.
/// This digest is a checksum and chain commitment, not authentication.
pub fn chain_digest(frames: &[TrustFrame]) -> Result<[u8; 32], IntegrityError> {
    if frames.is_empty() || frames.len() > MAX_FRAMES {
        return Err(IntegrityError::TooManyFrames);
    }
    let mut previous = [0_u8; 32];
    for frame in frames {
        let mut hasher = Sha256::new();
        hasher.update(FRAME_DOMAIN);
        hasher.update(previous);
        hasher.update(frame.sequence.to_be_bytes());
        hasher.update(frame.trust_epoch.to_be_bytes());
        hasher.update(frame.highest_trusted_time_ms.to_be_bytes());
        let count =
            u64::try_from(frame.revoked_keys.len()).map_err(|_| IntegrityError::TooManyFrames)?;
        hasher.update(count.to_be_bytes());
        for key in &frame.revoked_keys {
            let key_bytes = key.as_bytes();
            let length =
                u64::try_from(key_bytes.len()).map_err(|_| IntegrityError::TooManyFrames)?;
            hasher.update(length.to_be_bytes());
            hasher.update(key_bytes);
        }
        previous = hasher.finalize().into();
    }
    Ok(previous)
}

fn anchor_message(anchor: &SignedAnchor) -> Vec<u8> {
    let mut message = Vec::with_capacity(ANCHOR_DOMAIN.len() + 8 + 32);
    message.extend_from_slice(ANCHOR_DOMAIN);
    message.extend_from_slice(&anchor.sequence.to_be_bytes());
    message.extend_from_slice(&anchor.chain_digest);
    message
}

/// Fail closed if journal and separately supplied signed anchor disagree.
///
/// A signer key supplied by the caller is not automatically an authorized
/// governance root. Freshness/rollback protection of the anchor is external.
pub fn verify_anchored_recovery<J: TrustJournal, A: AnchorSource>(
    journal: &J,
    source: &A,
    signer_public_key: &[u8; 32],
    floor: RecoveryFloor,
) -> Result<TrustFrame, IntegrityError> {
    let anchor = source.load_anchor().map_err(IntegrityError::Anchor)?;
    if anchor.sequence == 0 {
        return Err(IntegrityError::InvalidAnchor);
    }
    let key =
        VerifyingKey::from_bytes(signer_public_key).map_err(|_| IntegrityError::InvalidSigner)?;
    key.verify_strict(
        &anchor_message(&anchor),
        &Signature::from_bytes(&anchor.signature),
    )
    .map_err(|_| IntegrityError::InvalidSignature)?;

    // Check monotonic semantics before treating the signed checksum as useful.
    let latest = recover(journal, floor).map_err(IntegrityError::Recovery)?;
    if anchor.sequence != latest.sequence {
        return Err(IntegrityError::SequenceMismatch);
    }
    let frames = journal.load().map_err(IntegrityError::Journal)?;
    if frames.len()
        != usize::try_from(latest.sequence).map_err(|_| IntegrityError::TooManyFrames)?
    {
        return Err(IntegrityError::SequenceMismatch);
    }
    if chain_digest(&frames)? != anchor.chain_digest {
        return Err(IntegrityError::DigestMismatch);
    }
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::{
        anchor_message, chain_digest, verify_anchored_recovery, AnchorError, AnchorSource,
        IntegrityError, SignedAnchor,
    };
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

    struct Source(Result<SignedAnchor, AnchorError>);

    impl AnchorSource for Source {
        fn load_anchor(&self) -> Result<SignedAnchor, AnchorError> {
            self.0
        }
    }

    fn sample() -> Frames {
        let first = TrustFrame {
            sequence: 1,
            trust_epoch: 5,
            highest_trusted_time_ms: 100,
            revoked_keys: BTreeSet::new(),
        };
        let mut second = first.clone();
        second.sequence = 2;
        second.highest_trusted_time_ms = 150;
        second.revoked_keys.insert("key-7".to_owned());
        Frames(vec![first, second])
    }

    fn floor() -> RecoveryFloor {
        RecoveryFloor {
            minimum_sequence: 1,
            minimum_trust_epoch: 5,
            minimum_trusted_time_ms: 100,
        }
    }

    fn signed(frames: &Frames) -> (Source, [u8; 32]) {
        // Deterministic test-only signer; never a production trust root.
        let signing = SigningKey::from_bytes(&[23_u8; 32]);
        let mut anchor = SignedAnchor {
            sequence: frames.0.last().map_or(0, |frame| frame.sequence),
            chain_digest: chain_digest(&frames.0).unwrap_or_else(|_| panic!("digest")),
            signature: [0; 64],
        };
        anchor.signature = signing.sign(&anchor_message(&anchor)).to_bytes();
        (Source(Ok(anchor)), signing.verifying_key().to_bytes())
    }

    #[test]
    fn exact_signed_head_checks() {
        let frames = sample();
        let (source, key) = signed(&frames);
        let result = verify_anchored_recovery(&frames, &source, &key, floor());
        assert_eq!(result, Ok(frames.0[1].clone()));
    }

    #[test]
    fn changed_revocation_or_time_is_detected() {
        let frames = sample();
        let (source, key) = signed(&frames);
        let mut modified = sample();
        modified.0[1].revoked_keys.insert("key-8".to_owned());
        assert_eq!(
            verify_anchored_recovery(&modified, &source, &key, floor()),
            Err(IntegrityError::DigestMismatch)
        );
        modified = sample();
        modified.0[1].highest_trusted_time_ms = 151;
        assert_eq!(
            verify_anchored_recovery(&modified, &source, &key, floor()),
            Err(IntegrityError::DigestMismatch)
        );
    }

    #[test]
    fn truncation_and_unanchored_append_are_denied() {
        let frames = sample();
        let (source, key) = signed(&frames);
        let mut truncated = sample();
        truncated.0.pop();
        assert_eq!(
            verify_anchored_recovery(&truncated, &source, &key, floor()),
            Err(IntegrityError::SequenceMismatch)
        );
        let mut appended = sample();
        let mut third = appended.0[1].clone();
        third.sequence = 3;
        appended.0.push(third);
        assert_eq!(
            verify_anchored_recovery(&appended, &source, &key, floor()),
            Err(IntegrityError::SequenceMismatch)
        );
    }

    #[test]
    fn invalid_signature_and_wrong_signer_fail() {
        let frames = sample();
        let (source, key) = signed(&frames);
        let wrong = SigningKey::from_bytes(&[24_u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_anchored_recovery(&frames, &source, &wrong, floor()),
            Err(IntegrityError::InvalidSignature)
        );
        let mut bad = match source.0 {
            Ok(anchor) => anchor,
            Err(_) => panic!("test anchor"),
        };
        bad.signature[0] ^= 1;
        assert_eq!(
            verify_anchored_recovery(&frames, &Source(Ok(bad)), &key, floor()),
            Err(IntegrityError::InvalidSignature)
        );
    }

    #[test]
    fn missing_or_uncertain_anchor_fails_closed() {
        let frames = sample();
        let (_, key) = signed(&frames);
        assert_eq!(
            verify_anchored_recovery(
                &frames,
                &Source(Err(AnchorError::Unavailable)),
                &key,
                floor()
            ),
            Err(IntegrityError::Anchor(AnchorError::Unavailable))
        );
        assert_eq!(
            verify_anchored_recovery(&frames, &Source(Err(AnchorError::Uncertain)), &key, floor()),
            Err(IntegrityError::Anchor(AnchorError::Uncertain))
        );
    }
}
