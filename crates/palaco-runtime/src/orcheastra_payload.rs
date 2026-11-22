//! Domain-separated payload hashing for read-only ORCHEASTRA restart review.
//!
//! This protects against accidental or adversarial payload mismatch only when
//! the expected digest and anchor are supplied through a trusted channel.
//! It does not verify signatures, authenticate the anchor, or grant authority.

use sha2::{Digest, Sha256};

use crate::orcheastra_restart::{
    inspect_restart, inspect_restart_chain, RestartAnchor, RestartCheckpoint, RestartInspection,
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
    let Some(digest) =
        digest_snapshot(checkpoint.sequence, &checkpoint.predecessor_digest, payload)
    else {
        return RestartInspection::Deny;
    };

    if digest != checkpoint.snapshot_digest {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

/// Maximum chain length accepted in a single bounded inspection.
pub const MAX_CHAIN_CHECKPOINTS: usize = 256;

/// Checks the actual snapshot bytes of every checkpoint in an in-memory chain.
///
/// Requires exactly one payload per checkpoint, rejects empty or oversized
/// chains and validates each SHA-256 digest against its payload and context.
/// The initial predecessor and the caller-provided anchor still require
/// independent authentication outside this module. This never authorizes work.
#[must_use]
pub fn inspect_restart_chain_payloads(
    checkpoints: &[RestartCheckpoint],
    payloads: &[&[u8]],
    anchor: Option<&RestartAnchor>,
) -> RestartInspection {
    if checkpoints.is_empty()
        || checkpoints.len() > MAX_CHAIN_CHECKPOINTS
        || checkpoints.len() != payloads.len()
        || inspect_restart_chain(checkpoints, anchor) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    for (checkpoint, payload) in checkpoints.iter().zip(payloads.iter()) {
        let Some(digest) =
            digest_snapshot(checkpoint.sequence, &checkpoint.predecessor_digest, payload)
        else {
            return RestartInspection::Deny;
        };

        if digest != checkpoint.snapshot_digest {
            return RestartInspection::Deny;
        }
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{
        digest_snapshot, inspect_restart_chain_payloads, inspect_restart_payload,
        MAX_CHAIN_CHECKPOINTS, MAX_SNAPSHOT_BYTES,
    };
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

    fn chain_fixture() -> (Vec<RestartCheckpoint>, RestartAnchor) {
        let first = digest_snapshot(7, &[6; 32], b"first").unwrap_or([0; 32]);
        let second = digest_snapshot(8, &first, b"second").unwrap_or([0; 32]);
        let checkpoints = vec![
            RestartCheckpoint {
                sequence: 7,
                predecessor_digest: [6; 32],
                snapshot_digest: first,
                committed: true,
                hold: false,
                revoked: false,
            },
            RestartCheckpoint {
                sequence: 8,
                predecessor_digest: first,
                snapshot_digest: second,
                committed: true,
                hold: false,
                revoked: false,
            },
        ];
        let anchor = RestartAnchor {
            sequence: 8,
            predecessor_digest: first,
            snapshot_digest: second,
            externally_verified: true,
        };
        (checkpoints, anchor)
    }

    #[test]
    fn all_snapshots_match_for_review_only() {
        let (checkpoints, anchor) = chain_fixture();
        assert_eq!(
            inspect_restart_chain_payloads(&checkpoints, &[b"first", b"second"], Some(&anchor)),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn altered_earlier_payload_is_denied() {
        let (checkpoints, anchor) = chain_fixture();
        assert_eq!(
            inspect_restart_chain_payloads(&checkpoints, &[b"FIRST", b"second"], Some(&anchor)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn missing_extra_and_empty_payload_sets_are_denied() {
        let (checkpoints, anchor) = chain_fixture();
        assert_eq!(
            inspect_restart_chain_payloads(&checkpoints, &[b"first"], Some(&anchor)),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_restart_chain_payloads(
                &checkpoints,
                &[b"first", b"second", b"extra"],
                Some(&anchor)
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_restart_chain_payloads(&[], &[], Some(&anchor)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn oversized_chain_is_denied_before_hashing() {
        let (checkpoints, anchor) = chain_fixture();
        let repeated = vec![checkpoints[0]; MAX_CHAIN_CHECKPOINTS + 1];
        let payloads = vec![b"first".as_slice(); MAX_CHAIN_CHECKPOINTS + 1];
        assert_eq!(
            inspect_restart_chain_payloads(&repeated, &payloads, Some(&anchor)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn revoked_intermediate_checkpoint_is_denied() {
        let (mut checkpoints, anchor) = chain_fixture();
        checkpoints[0].revoked = true;
        assert_eq!(
            inspect_restart_chain_payloads(&checkpoints, &[b"first", b"second"], Some(&anchor)),
            RestartInspection::Deny
        );
    }

}
