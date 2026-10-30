//! Governed-key lookup boundary for detached Harbor evidence signatures.
//!
//! This is a reference contract, not a provisioned trust-root service. The
//! caller must obtain registry state, monotone epoch, and time/high-water
//! snapshots from independently authenticated, durable authorities. Supplying
//! fabricated snapshots can defeat these checks. Signature validity never
//! grants access, execution, consent, or admission authority.

use crate::detached_signature::{verify_detached_signature, SignatureCheckError};

/// An unavailable or inconclusive independently governed registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    Unavailable,
    Uncertain,
}

/// Only an authenticated registry may implement this contract in production.
pub trait KeyRegistry {
    /// Resolve one exact identifier; absence is not an implicit trust grant.
    fn resolve(&self, key_id: &str) -> Result<Option<KeyRecord>, RegistryError>;
}

/// Registry data whose integrity, freshness and revocation state must be
/// independently attested by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub trust_epoch: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub revoked: bool,
}

/// A snapshot from an independent trusted monotone-time authority.
///
/// A process clock or recovered old snapshot is insufficient. In particular,
/// the highest accepted time and epoch must never roll back after a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedTimeSnapshot {
    pub now_ms: u64,
    pub highest_accepted_ms: u64,
    pub minimum_trust_epoch: u64,
}

/// Fail-closed reasons. None are an approval or authorization outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    MissingKeyId,
    UnknownKey,
    RegistryUnavailable,
    RegistryUncertain,
    InvalidRecord,
    Revoked,
    Expired,
    NotYetValid,
    TemporalUncertain,
    StaleEpoch,
    Signature(SignatureCheckError),
}

/// Check registry identity, revocation, epoch and temporal bounds before
/// verifying the exact detached signature bytes.
///
/// Success proves only that the supplied independent assertions and signature
/// are internally consistent. It is not an authorization decision.
pub fn verify_with_trust_registry<R: KeyRegistry>(
    registry: &R,
    key_id: &str,
    evidence_bytes: &[u8],
    signature_bytes: &[u8; 64],
    time: TrustedTimeSnapshot,
) -> Result<(), TrustError> {
    if key_id.is_empty() {
        return Err(TrustError::MissingKeyId);
    }

    let record = match registry.resolve(key_id) {
        Ok(Some(record)) => record,
        Ok(None) => return Err(TrustError::UnknownKey),
        Err(RegistryError::Unavailable) => return Err(TrustError::RegistryUnavailable),
        Err(RegistryError::Uncertain) => return Err(TrustError::RegistryUncertain),
    };

    if record.key_id != key_id
        || record.trust_epoch == 0
        || time.minimum_trust_epoch == 0
        || record.valid_from_ms >= record.valid_until_ms
    {
        return Err(TrustError::InvalidRecord);
    }

    // Explicit revocation takes precedence over all temporal conditions.
    if record.revoked {
        return Err(TrustError::Revoked);
    }
    if time.now_ms < time.highest_accepted_ms {
        return Err(TrustError::TemporalUncertain);
    }
    if record.trust_epoch < time.minimum_trust_epoch {
        return Err(TrustError::StaleEpoch);
    }
    if time.now_ms < record.valid_from_ms {
        return Err(TrustError::NotYetValid);
    }
    if time.now_ms >= record.valid_until_ms {
        return Err(TrustError::Expired);
    }

    verify_detached_signature(&record.public_key, evidence_bytes, signature_bytes)
        .map_err(TrustError::Signature)
}

#[cfg(test)]
mod tests {
    use super::{
        verify_with_trust_registry, KeyRecord, KeyRegistry, RegistryError, TrustError,
        TrustedTimeSnapshot,
    };
    use crate::detached_signature::SignatureCheckError;
    use ed25519_dalek::{Signer, SigningKey};

    struct ScriptedRegistry(Result<Option<KeyRecord>, RegistryError>);

    impl KeyRegistry for ScriptedRegistry {
        fn resolve(&self, _key_id: &str) -> Result<Option<KeyRecord>, RegistryError> {
            self.0.clone()
        }
    }

    fn record() -> KeyRecord {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        KeyRecord {
            key_id: "test-key-1".to_owned(),
            public_key: signing.verifying_key().to_bytes(),
            trust_epoch: 8,
            valid_from_ms: 100,
            valid_until_ms: 300,
            revoked: false,
        }
    }

    fn time() -> TrustedTimeSnapshot {
        TrustedTimeSnapshot {
            now_ms: 200,
            highest_accepted_ms: 190,
            minimum_trust_epoch: 8,
        }
    }

    fn signature(payload: &[u8]) -> [u8; 64] {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let mut message = b"PALACO-HARBOR-ED25519-EVIDENCE-v1\0".to_vec();
        message.extend_from_slice(payload);
        signing.sign(&message).to_bytes()
    }

    fn check(registry: &ScriptedRegistry, time: TrustedTimeSnapshot) -> Result<(), TrustError> {
        let payload = b"test-bound-evidence";
        verify_with_trust_registry(registry, "test-key-1", payload, &signature(payload), time)
    }

    #[test]
    fn matching_active_record_only_checks_signature() {
        assert_eq!(check(&ScriptedRegistry(Ok(Some(record()))), time()), Ok(()));
    }

    #[test]
    fn unknown_and_missing_key_fail_closed() {
        let registry = ScriptedRegistry(Ok(None));
        assert_eq!(check(&registry, time()), Err(TrustError::UnknownKey));
        assert_eq!(
            verify_with_trust_registry(&registry, "", b"e", &[0; 64], time()),
            Err(TrustError::MissingKeyId)
        );
    }

    #[test]
    fn registry_outage_or_uncertainty_never_falls_back() {
        assert_eq!(
            check(&ScriptedRegistry(Err(RegistryError::Unavailable)), time()),
            Err(TrustError::RegistryUnavailable)
        );
        assert_eq!(
            check(&ScriptedRegistry(Err(RegistryError::Uncertain)), time()),
            Err(TrustError::RegistryUncertain)
        );
    }

    #[test]
    fn revoked_record_denied_even_with_time_rollback() {
        let mut key = record();
        key.revoked = true;
        let mut clock = time();
        clock.now_ms = 10;
        assert_eq!(
            check(&ScriptedRegistry(Ok(Some(key))), clock),
            Err(TrustError::Revoked)
        );
    }

    #[test]
    fn expired_and_future_keys_denied_at_boundaries() {
        let registry = ScriptedRegistry(Ok(Some(record())));
        let mut clock = time();
        clock.now_ms = 300;
        clock.highest_accepted_ms = 300;
        assert_eq!(check(&registry, clock), Err(TrustError::Expired));
        clock.now_ms = 99;
        clock.highest_accepted_ms = 99;
        assert_eq!(check(&registry, clock), Err(TrustError::NotYetValid));
    }

    #[test]
    fn clock_rollback_and_stale_epoch_denied() {
        let registry = ScriptedRegistry(Ok(Some(record())));
        let mut clock = time();
        clock.now_ms = 180;
        clock.highest_accepted_ms = 190;
        assert_eq!(check(&registry, clock), Err(TrustError::TemporalUncertain));
        clock = time();
        clock.minimum_trust_epoch = 9;
        assert_eq!(check(&registry, clock), Err(TrustError::StaleEpoch));
    }

    #[test]
    fn malformed_registry_record_denied() {
        let mut key = record();
        key.key_id = "another-key".to_owned();
        assert_eq!(
            check(&ScriptedRegistry(Ok(Some(key))), time()),
            Err(TrustError::InvalidRecord)
        );
        let mut key = record();
        key.valid_until_ms = key.valid_from_ms;
        assert_eq!(
            check(&ScriptedRegistry(Ok(Some(key))), time()),
            Err(TrustError::InvalidRecord)
        );
    }

    #[test]
    fn signature_mismatch_still_denied() {
        let payload = b"test-bound-evidence";
        let registry = ScriptedRegistry(Ok(Some(record())));
        assert_eq!(
            verify_with_trust_registry(
                &registry,
                "test-key-1",
                b"altered-evidence",
                &signature(payload),
                time(),
            ),
            Err(TrustError::Signature(SignatureCheckError::InvalidSignature))
        );
    }
}
