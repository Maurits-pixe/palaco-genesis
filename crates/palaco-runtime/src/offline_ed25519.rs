//! Ed25519 signature verification for non-executing offline recovery review.
//!
//! This verifies bytes only. A configured public key is not by itself a grant,
//! identity, revocation check, replay defense or recovery authorization.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::offline_recovery_signed::SignedReceiptVerifier;

/// A single externally provisioned public key for signature-byte inspection.
///
/// Only a separately governed trust registry may decide whether this key is
/// eligible for any particular PALACO approval at a particular trusted time.
pub struct Ed25519ReviewVerifier {
    key: VerifyingKey,
    key_id: [u8; 32],
}

impl Ed25519ReviewVerifier {
    /// Parse a public key and derive an unambiguous SHA-256 key reference.
    pub fn from_public_key(public_key: &[u8; 32]) -> Option<Self> {
        let key = VerifyingKey::from_bytes(public_key).ok()?;
        let key_id = Sha256::digest(public_key).into();
        Some(Self { key, key_id })
    }

    /// Derived public-key reference, without any claim of active authority.
    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
}

impl SignedReceiptVerifier for Ed25519ReviewVerifier {
    fn verify(&self, digest: &[u8; 32], key_id: &[u8; 32], signature: &[u8; 64]) -> bool {
        if self.key_id != *key_id {
            return false;
        }
        let signature = Signature::from_bytes(signature);
        self.key.verify_strict(digest, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Ed25519ReviewVerifier;
    use crate::offline_recovery_signed::SignedReceiptVerifier;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> Result<(SigningKey, Ed25519ReviewVerifier), &'static str> {
        let signer = SigningKey::from_bytes(&[42; 32]);
        let public = signer.verifying_key().to_bytes();
        let verifier = Ed25519ReviewVerifier::from_public_key(&public)
            .ok_or("fixture public key must parse")?;
        Ok((signer, verifier))
    }

    #[test]
    fn real_signature_verifies_only_correct_statement() -> Result<(), &'static str> {
        let (signer, verifier) = fixture()?;
        let message = [4; 32];
        let signature = signer.sign(&message).to_bytes();
        assert!(verifier.verify(&message, &verifier.key_id(), &signature));
        assert!(!verifier.verify(&[5; 32], &verifier.key_id(), &signature));
        Ok(())
    }

    #[test]
    fn wrong_key_reference_is_rejected() -> Result<(), &'static str> {
        let (signer, verifier) = fixture()?;
        let digest = [9; 32];
        let signature = signer.sign(&digest).to_bytes();
        assert!(!verifier.verify(&digest, &[0; 32], &signature));
        Ok(())
    }

    #[test]
    fn modified_signature_is_rejected() -> Result<(), &'static str> {
        let (signer, verifier) = fixture()?;
        let digest = [3; 32];
        let mut signature = signer.sign(&digest).to_bytes();
        signature[0] ^= 1;
        assert!(!verifier.verify(&digest, &verifier.key_id(), &signature));
        Ok(())
    }

    #[test]
    fn different_signer_cannot_impersonate_key() -> Result<(), &'static str> {
        let (_, verifier) = fixture()?;
        let attacker = SigningKey::from_bytes(&[43; 32]);
        let digest = [3; 32];
        let signature = attacker.sign(&digest).to_bytes();
        assert!(!verifier.verify(&digest, &verifier.key_id(), &signature));
        Ok(())
    }
}
