//! Offline publisher key and time policy preflight.
//!
//! This module DOES NOT validate cryptographic signatures or persist trusted
//! epochs. It can only reject policy-invalid candidates before verification.

/// Local status of a publisher key, provisioned by a separate trusted process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherStatus {
    /// Key is locally permitted for candidate validation.
    Active,
    /// Key must never be accepted.
    Revoked,
}

/// A locally provisioned publisher identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherRecord {
    /// Non-secret key identifier.
    pub key_id: String,
    /// Local disposition.
    pub status: PublisherStatus,
    /// Minimum accepted security-policy epoch for this key.
    pub minimum_epoch: u64,
}

/// Claim made by a signed manifest; all fields are UNTRUSTED until verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherClaim {
    /// Key identifier referenced in the signature envelope.
    pub key_id: String,
    /// Claimed security epoch.
    pub epoch: u64,
    /// Claimed expiry in integer Unix seconds.
    pub expires_at_unix: u64,
}

/// Trusted time supplied by an independently verified source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockEvidence {
    /// Local time has no valid trusted anchor.
    Uncertain,
    /// Independently established lower-bound trusted time.
    TrustedUnix(u64),
}

/// Policy preflight failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherPolicyError {
    /// Key registry or claim is malformed or ambiguous.
    InvalidPolicy,
    /// No matching pre-provisioned publisher.
    UnknownPublisher,
    /// Revoked publisher must remain rejected.
    RevokedPublisher,
    /// Claim is older than the minimum accepted epoch.
    EpochRollback,
    /// Trusted time is absent.
    UncertainTime,
    /// Claim has expired relative to trusted time.
    ExpiredClaim,
}

/// Rejection-only publisher policy check.
///
/// Success means solely that static policy did not reject; it is NOT a grant
/// and does not establish signature validity or trusted source provenance.
pub fn preflight_publisher(
    records: &[PublisherRecord],
    claim: &PublisherClaim,
    clock: ClockEvidence,
) -> Result<(), PublisherPolicyError> {
    if records.is_empty()
        || records.len() > 128
        || !valid_id(&claim.key_id)
        || claim.epoch == 0
        || claim.expires_at_unix == 0
    {
        return Err(PublisherPolicyError::InvalidPolicy);
    }

    let mut found: Option<&PublisherRecord> = None;
    for record in records {
        if !valid_id(&record.key_id) || record.minimum_epoch == 0 {
            return Err(PublisherPolicyError::InvalidPolicy);
        }
        if records
            .iter()
            .filter(|candidate| candidate.key_id == record.key_id)
            .count()
            != 1
        {
            return Err(PublisherPolicyError::InvalidPolicy);
        }
        if record.key_id == claim.key_id {
            found = Some(record);
        }
    }

    let publisher = found.ok_or(PublisherPolicyError::UnknownPublisher)?;
    if publisher.status == PublisherStatus::Revoked {
        return Err(PublisherPolicyError::RevokedPublisher);
    }
    if claim.epoch < publisher.minimum_epoch {
        return Err(PublisherPolicyError::EpochRollback);
    }
    match clock {
        ClockEvidence::Uncertain => Err(PublisherPolicyError::UncertainTime),
        ClockEvidence::TrustedUnix(timestamp) if timestamp >= claim.expires_at_unix => {
            Err(PublisherPolicyError::ExpiredClaim)
        }
        ClockEvidence::TrustedUnix(_) => Ok(()),
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{
        preflight_publisher, ClockEvidence, PublisherClaim, PublisherPolicyError, PublisherRecord,
        PublisherStatus,
    };

    fn records() -> Vec<PublisherRecord> {
        vec![PublisherRecord {
            key_id: "publisher-1".to_string(),
            status: PublisherStatus::Active,
            minimum_epoch: 7,
        }]
    }

    fn claim() -> PublisherClaim {
        PublisherClaim {
            key_id: "publisher-1".to_string(),
            epoch: 7,
            expires_at_unix: 200,
        }
    }

    #[test]
    fn matching_preflight_is_not_signature_authentication() {
        assert_eq!(
            preflight_publisher(&records(), &claim(), ClockEvidence::TrustedUnix(100)),
            Ok(())
        );
    }

    #[test]
    fn revoked_key_is_rejected() {
        let mut configured = records();
        configured[0].status = PublisherStatus::Revoked;
        assert_eq!(
            preflight_publisher(&configured, &claim(), ClockEvidence::TrustedUnix(100)),
            Err(PublisherPolicyError::RevokedPublisher)
        );
    }

    #[test]
    fn epoch_rollback_is_rejected() {
        let mut incoming = claim();
        incoming.epoch = 6;
        assert_eq!(
            preflight_publisher(&records(), &incoming, ClockEvidence::TrustedUnix(100)),
            Err(PublisherPolicyError::EpochRollback)
        );
    }

    #[test]
    fn local_clock_uncertainty_holds() {
        assert_eq!(
            preflight_publisher(&records(), &claim(), ClockEvidence::Uncertain),
            Err(PublisherPolicyError::UncertainTime)
        );
    }

    #[test]
    fn expiry_at_boundary_is_rejected() {
        assert_eq!(
            preflight_publisher(&records(), &claim(), ClockEvidence::TrustedUnix(200)),
            Err(PublisherPolicyError::ExpiredClaim)
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let mut incoming = claim();
        incoming.key_id = "other".to_string();
        assert_eq!(
            preflight_publisher(&records(), &incoming, ClockEvidence::TrustedUnix(100)),
            Err(PublisherPolicyError::UnknownPublisher)
        );
    }

    #[test]
    fn duplicate_registry_is_rejected() {
        let configured = [records()[0].clone(), records()[0].clone()];
        assert_eq!(
            preflight_publisher(&configured, &claim(), ClockEvidence::TrustedUnix(100)),
            Err(PublisherPolicyError::InvalidPolicy)
        );
    }
}
