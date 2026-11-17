//! Keyed SHA-256 authentication of scoped ORCHEASTRA recovery checkpoints.
//!
//! This adapter verifies HMAC-SHA-256 tags using a separately provisioned
//! 256-bit key and a separate monotonic generation authority. It does not
//! manage keys, attest the key owner, publish anchors or execute any task.

use palaco_runtime::orcheastra::{
    persistence::TrustedRecoveryAnchor,
    recovery::RecoveryCheckpoint,
};
use sha2::{Digest, Sha256};

use super::{AnchorError, AuditAnchorVerifier};

/// Version of the checkpoint authentication protocol.
pub const MAC_FORMAT_VERSION: u8 = 1;

/// A scoped, keyed integrity proof for a single checkpoint.
///
/// The key identifier is only a selector; the actual secret MUST be obtained
/// through an independently authenticated key service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCheckpoint {
    /// The authenticated protocol version.
    pub version: u8,
    /// Exact journal identifier bound to this checkpoint.
    pub journal_id: String,
    /// Identifier of the pinned, trusted verification key.
    pub key_id: String,
    /// Checkpoint and monotonic generation bound by the MAC.
    pub anchor: TrustedRecoveryAnchor,
    /// HMAC-SHA-256 authentication tag.
    pub tag: [u8; 32],
}

/// Independently trusted checkpoint transport, which supplies untrusted data.
pub trait MacCheckpointSource {
    /// Fetch the latest signed-by-MAC record for the named journal.
    fn checkpoint(&self, journal_id: &str) -> Result<MacCheckpoint, AnchorError>;
}

/// Separate high-water-mark authority. A local signed record is never
/// accepted as evidence that its own generation is the latest.
pub trait GenerationAuthority {
    /// Read the latest authenticated generation for an exact journal.
    fn latest_generation(&self, journal_id: &str) -> Result<u64, AnchorError>;
}

/// Immutable verifier configured with a separately provisioned secret.
///
/// A production application must use a trusted key provisioner, rotate keys
/// through policy, prevent secret exposure, and never accept caller-provided
/// verification keys from the same untrusted checkpoint source.
pub struct HmacAnchorVerifier<'a, S, G> {
    /// Source of untrusted MAC-checkpoint records.
    pub source: &'a S,
    /// Independent latest-generation authority.
    pub generations: &'a G,
    /// Pinned key identifier.
    pub key_id: &'a str,
    /// Independent 32-byte secret verification key.
    pub key: &'a [u8; 32],
}

fn write_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn authenticated_bytes(
    journal_id: &str,
    key_id: &str,
    anchor: &TrustedRecoveryAnchor,
) -> Vec<u8> {
    let mut bytes = b"PALACO-ORCHEASTRA-AUDIT-HMAC-V1".to_vec();
    bytes.push(MAC_FORMAT_VERSION);
    write_field(&mut bytes, journal_id.as_bytes());
    write_field(&mut bytes, key_id.as_bytes());
    bytes.extend_from_slice(&anchor.generation.to_be_bytes());
    let checkpoint = &anchor.checkpoint;
    bytes.extend_from_slice(&checkpoint.plan_hash);
    bytes.extend_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.head);
    bytes
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    // RFC 2104 / FIPS 198-1 HMAC using SHA-256, block size 64 bytes.
    // The secret key is 32 bytes, so no key pre-hashing is required.
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn equal_tag(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Produce an HMAC-SHA-256 checkpoint proof with an externally provisioned key.
///
/// This function does not securely store the proof or update the independent
/// monotonic generation source. The integration must coordinate those actions.
#[must_use]
pub fn authenticate_checkpoint(
    journal_id: &str,
    key_id: &str,
    anchor: TrustedRecoveryAnchor,
    key: &[u8; 32],
) -> MacCheckpoint {
    let message = authenticated_bytes(journal_id, key_id, &anchor);
    MacCheckpoint {
        version: MAC_FORMAT_VERSION,
        journal_id: journal_id.to_owned(),
        key_id: key_id.to_owned(),
        anchor,
        tag: hmac_sha256(key, &message),
    }
}

impl<S: MacCheckpointSource, G: GenerationAuthority> AuditAnchorVerifier
    for HmacAnchorVerifier<'_, S, G>
{
    fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
        if journal_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.key.iter().all(|byte| *byte == 0)
        {
            return Err(AnchorError::Unauthenticated);
        }
        let record = self.source.checkpoint(journal_id)?;
        if record.version != MAC_FORMAT_VERSION
            || record.journal_id != journal_id
            || record.key_id != self.key_id
        {
            return Err(AnchorError::Unauthenticated);
        }
        let expected = hmac_sha256(
            self.key,
            &authenticated_bytes(&record.journal_id, &record.key_id, &record.anchor),
        );
        if !equal_tag(&record.tag, &expected) {
            return Err(AnchorError::Unauthenticated);
        }
        let latest = self.generations.latest_generation(journal_id)?;
        if record.anchor.generation != latest {
            return Err(AnchorError::Stale);
        }
        Ok(record.anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::AuditAnchorVerifier;

    const TEST_KEY: [u8; 32] = [0x71; 32];

    struct Source {
        record: MacCheckpoint,
    }

    impl MacCheckpointSource for Source {
        fn checkpoint(&self, _: &str) -> Result<MacCheckpoint, AnchorError> {
            Ok(self.record.clone())
        }
    }

    struct Generation(u64);
    impl GenerationAuthority for Generation {
        fn latest_generation(&self, _: &str) -> Result<u64, AnchorError> {
            Ok(self.0)
        }
    }

    fn anchor(generation: u64) -> TrustedRecoveryAnchor {
        TrustedRecoveryAnchor {
            generation,
            checkpoint: RecoveryCheckpoint {
                plan_hash: [1u8; 32],
                sequence: 2,
                head: [3u8; 32],
            },
        }
    }

    #[test]
    fn valid_mac_and_independent_generation_pass() {
        let source = Source {
            record: authenticate_checkpoint("rio", "audit-key-v1", anchor(7), &TEST_KEY),
        };
        let generation = Generation(7);
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &generation,
            key_id: "audit-key-v1",
            key: &TEST_KEY,
        };
        assert_eq!(verifier.latest_anchor("rio"), Ok(anchor(7)));
    }

    #[test]
    fn wrong_journal_or_modified_checkpoint_fails() {
        let source = Source {
            record: authenticate_checkpoint("rio", "audit-key-v1", anchor(7), &TEST_KEY),
        };
        let generation = Generation(7);
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &generation,
            key_id: "audit-key-v1",
            key: &TEST_KEY,
        };
        assert_eq!(verifier.latest_anchor("one"), Err(AnchorError::Unauthenticated));
        let mut changed = source.record.clone();
        changed.anchor.checkpoint.head = [8u8; 32];
        let tampered_source = Source { record: changed };
        let tampered = HmacAnchorVerifier {
            source: &tampered_source,
            generations: &generation,
            key_id: "audit-key-v1",
            key: &TEST_KEY,
        };
        assert_eq!(tampered.latest_anchor("rio"), Err(AnchorError::Unauthenticated));
    }

    #[test]
    fn rollback_and_key_substitution_fail() {
        let source = Source {
            record: authenticate_checkpoint("rio", "audit-key-v1", anchor(7), &TEST_KEY),
        };
        let generation = Generation(8);
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &generation,
            key_id: "audit-key-v1",
            key: &TEST_KEY,
        };
        assert_eq!(verifier.latest_anchor("rio"), Err(AnchorError::Stale));
        let wrong_key = [0x72u8; 32];
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &Generation(7),
            key_id: "audit-key-v1",
            key: &wrong_key,
        };
        assert_eq!(verifier.latest_anchor("rio"), Err(AnchorError::Unauthenticated));
    }

    #[test]
    fn empty_or_zero_verification_configuration_is_rejected() {
        let source = Source {
            record: authenticate_checkpoint("rio", "audit-key-v1", anchor(7), &TEST_KEY),
        };
        let generation = Generation(7);
        let zero_key = [0u8; 32];
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &generation,
            key_id: "audit-key-v1",
            key: &zero_key,
        };
        assert_eq!(verifier.latest_anchor("rio"), Err(AnchorError::Unauthenticated));
    }
}
