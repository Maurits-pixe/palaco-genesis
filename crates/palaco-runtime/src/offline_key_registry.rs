//! Bounded offline public-key registry for non-executing review preflight.
//!
//! This is volatile policy evidence, not an authenticated registry or durable
//! anti-rollback store. Restoring an older snapshot can restore old key state.
//! A matching signature or active entry never grants recovery authority.

use crate::offline_ed25519::Ed25519ReviewVerifier;

/// Maximum number of public keys retained in one offline review registry.
pub const MAX_REVIEW_KEYS: usize = 32;

/// Registry mutation or integrity failure; all failures must deny preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// Key bytes cannot be parsed as an Ed25519 verifying key.
    InvalidKey,
    /// The same public key is already present, active or revoked.
    DuplicateKey,
    /// The bounded registry has no remaining capacity.
    CapacityExceeded,
    /// The key reference is absent.
    UnknownKey,
    /// A revoked key cannot be reinstated in this instance.
    RevokedKey,
    /// An epoch may never move backward.
    EpochRollback,
}

/// Local state of a registered public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// The key may be used for signature-byte inspection, not authorization.
    Active,
    /// Terminal for the lifetime of this registry instance.
    Revoked,
}

/// Read-only public metadata for a registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyEntry {
    /// SHA-256 of the exact public-key bytes.
    pub key_id: [u8; 32],
    /// Caller-controlled policy epoch recorded upon registration.
    pub epoch: u64,
    /// Current local status.
    pub state: KeyState,
}

struct StoredKey {
    public_key: [u8; 32],
    entry: PublicKeyEntry,
}

/// Volatile bounded registry with fail-closed key selection.
///
/// Epochs are supplied by the caller. They are not trusted monotonic time or
/// durable evidence; external authenticated policy and persistence are absent.
pub struct OfflineReviewKeyRegistry {
    keys: Vec<StoredKey>,
    minimum_epoch: u64,
}

impl OfflineReviewKeyRegistry {
    /// Start an empty registry requiring at least the supplied policy epoch.
    #[must_use]
    pub fn new(minimum_epoch: u64) -> Self {
        Self {
            keys: Vec::new(),
            minimum_epoch,
        }
    }

    /// Raise (never lower) the local minimum acceptable epoch.
    pub fn advance_minimum_epoch(&mut self, epoch: u64) -> Result<(), RegistryError> {
        if epoch < self.minimum_epoch {
            return Err(RegistryError::EpochRollback);
        }
        self.minimum_epoch = epoch;
        Ok(())
    }

    /// Register a public key once; revoked entries retain their reserved IDs.
    pub fn register(
        &mut self,
        public_key: [u8; 32],
        epoch: u64,
    ) -> Result<[u8; 32], RegistryError> {
        let verifier = Ed25519ReviewVerifier::from_public_key(&public_key)
            .ok_or(RegistryError::InvalidKey)?;
        let key_id = verifier.key_id();
        if self.keys.iter().any(|key| key.entry.key_id == key_id) {
            return Err(RegistryError::DuplicateKey);
        }
        if epoch < self.minimum_epoch {
            return Err(RegistryError::EpochRollback);
        }
        if self.keys.len() >= MAX_REVIEW_KEYS {
            return Err(RegistryError::CapacityExceeded);
        }
        self.keys.push(StoredKey {
            public_key,
            entry: PublicKeyEntry {
                key_id,
                epoch,
                state: KeyState::Active,
            },
        });
        Ok(key_id)
    }

    /// Revoke a key irreversibly for this registry instance.
    pub fn revoke(&mut self, key_id: &[u8; 32]) -> Result<(), RegistryError> {
        let key = self
            .keys
            .iter_mut()
            .find(|key| key.entry.key_id == *key_id)
            .ok_or(RegistryError::UnknownKey)?;
        if key.entry.state == KeyState::Revoked {
            return Err(RegistryError::RevokedKey);
        }
        key.entry.state = KeyState::Revoked;
        Ok(())
    }

    /// Inspect public metadata; missing entries are not implicitly accepted.
    #[must_use]
    pub fn entry(&self, key_id: &[u8; 32]) -> Option<PublicKeyEntry> {
        self.keys
            .iter()
            .find(|key| key.entry.key_id == *key_id)
            .map(|key| key.entry)
    }

    /// Select a verifier only for a locally active, sufficiently recent key.
    ///
    /// The caller's floor cannot weaken the registry-wide floor. Returning a
    /// verifier permits only byte verification, never approval or execution.
    #[must_use]
    pub fn review_verifier(
        &self,
        key_id: &[u8; 32],
        caller_minimum_epoch: u64,
    ) -> Option<Ed25519ReviewVerifier> {
        let key = self.keys.iter().find(|key| key.entry.key_id == *key_id)?;
        if key.entry.state != KeyState::Active
            || key.entry.epoch < self.minimum_epoch
            || key.entry.epoch < caller_minimum_epoch
        {
            return None;
        }
        let verifier = Ed25519ReviewVerifier::from_public_key(&key.public_key)?;
        (verifier.key_id() == *key_id).then_some(verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyState, OfflineReviewKeyRegistry, RegistryError, MAX_REVIEW_KEYS};
    use crate::offline_recovery_signed::SignedReceiptVerifier;
    use ed25519_dalek::{Signer, SigningKey};

    fn public_key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn active_key_checks_real_signature_without_authority() -> Result<(), RegistryError> {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let mut registry = OfflineReviewKeyRegistry::new(10);
        let id = registry.register(signer.verifying_key().to_bytes(), 10)?;
        let verifier = registry
            .review_verifier(&id, 10)
            .ok_or(RegistryError::UnknownKey)?;
        let digest = [11; 32];
        assert!(verifier.verify(&digest, &id, &signer.sign(&digest).to_bytes()));
        assert!(!verifier.verify(&[12; 32], &id, &signer.sign(&digest).to_bytes()));
        assert_eq!(registry.entry(&id).map(|entry| entry.state), Some(KeyState::Active));
        Ok(())
    }

    #[test]
    fn revoke_is_terminal_even_after_reregistration_attempt() -> Result<(), RegistryError> {
        let mut registry = OfflineReviewKeyRegistry::new(1);
        let key = public_key(8);
        let id = registry.register(key, 1)?;
        registry.revoke(&id)?;
        assert!(registry.review_verifier(&id, 1).is_none());
        assert_eq!(registry.revoke(&id), Err(RegistryError::RevokedKey));
        assert_eq!(registry.register(key, 9), Err(RegistryError::DuplicateKey));
        assert_eq!(registry.entry(&id).map(|entry| entry.state), Some(KeyState::Revoked));
        Ok(())
    }

    #[test]
    fn epoch_floor_cannot_be_lowered_or_bypassed() -> Result<(), RegistryError> {
        let mut registry = OfflineReviewKeyRegistry::new(4);
        assert_eq!(registry.register(public_key(1), 3), Err(RegistryError::EpochRollback));
        let id = registry.register(public_key(2), 4)?;
        assert!(registry.review_verifier(&id, 5).is_none());
        registry.advance_minimum_epoch(5)?;
        assert!(registry.review_verifier(&id, 4).is_none());
        assert_eq!(registry.advance_minimum_epoch(4), Err(RegistryError::EpochRollback));
        assert_eq!(registry.register(public_key(3), 4), Err(RegistryError::EpochRollback));
        Ok(())
    }

    #[test]
    fn unknown_key_is_denied_and_cannot_be_revoked() {
        let mut registry = OfflineReviewKeyRegistry::new(0);
        assert!(registry.review_verifier(&[0; 32], 0).is_none());
        assert_eq!(registry.revoke(&[0; 32]), Err(RegistryError::UnknownKey));
    }

    #[test]
    fn capacity_is_bounded_and_duplicate_is_not_replaced() -> Result<(), RegistryError> {
        let mut registry = OfflineReviewKeyRegistry::new(0);
        for seed in 1..=MAX_REVIEW_KEYS {
            let seed = u8::try_from(seed).map_err(|_| RegistryError::CapacityExceeded)?;
            registry.register(public_key(seed), 0)?;
        }
        assert_eq!(registry.register(public_key(1), 0), Err(RegistryError::DuplicateKey));
        assert_eq!(registry.register(public_key(99), 0), Err(RegistryError::CapacityExceeded));
        Ok(())
    }

    #[test]
    fn snapshot_replay_limitation_is_explicit() -> Result<(), RegistryError> {
        let mut old_snapshot = OfflineReviewKeyRegistry::new(1);
        let key = public_key(20);
        let id = old_snapshot.register(key, 1)?;
        let mut current = OfflineReviewKeyRegistry::new(1);
        let current_id = current.register(key, 1)?;
        current.revoke(&current_id)?;
        assert!(current.review_verifier(&id, 1).is_none());
        // Without authenticated durable anti-rollback storage, an older
        // instance still accepts the key. Production MUST remain HOLD.
        assert!(old_snapshot.review_verifier(&id, 1).is_some());
        Ok(())
    }
}
