//! Domain-separated payload hashing for read-only ORCHEASTRA restart review.
//!
//! This protects against accidental or adversarial payload mismatch only when
//! the expected digest and anchor are supplied through a trusted channel.
//! It does not verify signatures, authenticate the anchor, or grant authority.

use sha2::{Digest, Sha256};

use crate::orcheastra_restart::{
    inspect_restart, RestartAnchor, RestartCheckpoint, RestartInspection,
};

/// Maximum snapshot input accepted by the read-only verifier (one MiB).
pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;

const DOMAIN: &[u8] = b"PALACO-ORCHEASTRA-RESTART-SNAPSHOT-V1\0";

/// Calculates the SHA-256 digest of a bounded snapshot and its chain context.
///
/// Includes a domain separator, sequence, predecessor digest, byte length, and
/// exact payload bytes. Returns `None` if the input exceeds the size bound.
#[must_use]
pub fn digest_snapshot(
    sequence: u64,
    predecessor_digest: &[u8; 32],
    payload: &[u8],
) -> Option<[u8; 32]> {
    if sequence == 0 || predecessor_digest == &[0; 32] || payload.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let length = u64::try_from(payload.len()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(sequence.to_be_bytes());
    hasher.update(predecessor_digest);
    hasher.update(length.to_be_bytes());
    hasher.update(payload);
    Some(hasher.finalize().into())
}

/// Matches a checkpoint against actual payload bytes and the supplied anchor.
///
/// Runs the existing fail-closed checkpoint inspection first. A positive
/// outcome is for additional review only; it is never permission to execute.
/// In particular, `externally_verified` is merely an untrusted caller field.
#[must_use]
pub fn inspect_restart_payload(
    checkpoint: Option<&RestartCheckpoint>,
    anchor: Option<&RestartAnchor>,
    payload: &[u8],
) -> RestartInspection {
    if inspect_restart(checkpoint, anchor) != RestartInspection::ReviewOnly {
        return RestartInspection::Deny;
    }

    let Some(checkpoint) = checkpoint else {
        return RestartInspection::Deny;
    };
    let Some(digest) = digest_snapshot(
        checkpoint.sequence,
        &checkpoint.predecessor_digest,
        payload,
    ) else {
        return RestartInspection::Deny;
    };

    if digest != checkpoint.snapshot_digest {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{digest_snapshot, inspect_restart_payload, MAX_SNAPSHOT_BYTES};
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint, RestartInspection};

    fn fixture() -> (RestartCheckpoint, RestartAnchor) {
        let digest = digest_snapshot(8, &[7; 32], b"committed snapshot").unwrap_or([0; 32]);
        (
            RestartCheckpoint {
                sequence: 8,
                predecessor_digest: [7; 32],
                snapshot_digest: digest,
                committed: true,
                hold: false,
                revoked: false,
            },
            RestartAnchor {
                sequence: 8,
                predecessor_digest: [7; 32],
                snapshot_digest: digest,
                externally_verified: true,
            },
        )
    }

    #[test]
    fn exact_payload_is_review_only() {
        let (checkpoint, anchor) = fixture();
        assert_eq!(
            inspect_restart_payload(Some(&checkpoint), Some(&anchor), b"committed snapshot"),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn tampered_payload_is_denied() {
        let (checkpoint, anchor) = fixture();
        assert_eq!(
            inspect_restart_payload(Some(&checkpoint), Some(&anchor), b"committed snapshoT"),
            RestartInspection::Deny
        );
    }

    #[test]
    fn hold_and_unverified_anchor_are_denied_even_with_matching_payload() {
        let (mut checkpoint, mut anchor) = fixture();
        checkpoint.hold = true;
        assert_eq!(
            inspect_restart_payload(Some(&checkpoint), Some(&anchor), b"committed snapshot"),
            RestartInspection::Deny
        );
        checkpoint.hold = false;
        anchor.externally_verified = false;
        assert_eq!(
            inspect_restart_payload(Some(&checkpoint), Some(&anchor), b"committed snapshot"),
            RestartInspection::Deny
        );
    }

    #[test]
    fn domain_context_changes_digest() {
        let one = digest_snapshot(8, &[7; 32], b"committed snapshot");
        let changed_sequence = digest_snapshot(9, &[7; 32], b"committed snapshot");
        let changed_predecessor = digest_snapshot(8, &[8; 32], b"committed snapshot");
        assert_ne!(one, changed_sequence);
        assert_ne!(one, changed_predecessor);
    }

    #[test]
    fn oversized_payload_and_invalid_context_are_rejected() {
        let (checkpoint, anchor) = fixture();
        let oversized = vec![0; MAX_SNAPSHOT_BYTES + 1];
        assert_eq!(digest_snapshot(8, &[7; 32], &oversized), None);
        assert_eq!(digest_snapshot(0, &[7; 32], b"x"), None);
        assert_eq!(digest_snapshot(8, &[0; 32], b"x"), None);
        assert_eq!(
            inspect_restart_payload(Some(&checkpoint), Some(&anchor), &oversized),
            RestartInspection::Deny
        );
    }
}
