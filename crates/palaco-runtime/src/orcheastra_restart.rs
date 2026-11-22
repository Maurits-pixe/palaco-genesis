//! Pure fail-closed restart inspection for ORCHEASTRA.
//!
//! This module does not persist records, authenticate digests, grant authority,
//! authorize execution, or claim protection against rollback of local storage.

/// A recorded local checkpoint supplied by an untrusted caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCheckpoint {
    /// Monotonically increasing local sequence number.
    pub sequence: u64,
    /// Digest of the committed snapshot, as supplied by the caller.
    pub snapshot_digest: [u8; 32],
    /// Digest of the preceding checkpoint, as supplied by the caller.
    pub predecessor_digest: [u8; 32],
    /// Whether the snapshot was fully committed.
    pub committed: bool,
    /// Whether an active HOLD was recorded.
    pub hold: bool,
    /// Whether revocation was recorded.
    pub revoked: bool,
}

/// An independently supplied checkpoint expectation. This structure alone
/// does not make its values trustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartAnchor {
    /// Expected sequence number.
    pub sequence: u64,
    /// Expected snapshot digest.
    pub snapshot_digest: [u8; 32],
    /// Expected predecessor digest.
    pub predecessor_digest: [u8; 32],
    /// True only when an independent, trusted verifier confirmed this anchor.
    pub externally_verified: bool,
}

/// Inspection outcome. Neither variant authorizes execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartInspection {
    /// Evidence is coherent enough for a further human or trusted review.
    ReviewOnly,
    /// Evidence is incomplete, untrusted, rolled back, or blocked.
    Deny,
}

/// Inspects a local checkpoint against an independently checked anchor.
///
/// Safe behavior is DENY on absence, mismatch, revocation, HOLD, a pending
/// commit, an unverified anchor, or a zero digest. A successful inspection is
/// still only a review candidate, never an authorization.
#[must_use]
pub fn inspect_restart(
    checkpoint: Option<&RestartCheckpoint>,
    anchor: Option<&RestartAnchor>,
) -> RestartInspection {
    let (Some(checkpoint), Some(anchor)) = (checkpoint, anchor) else {
        return RestartInspection::Deny;
    };

    if !anchor.externally_verified
        || !checkpoint.committed
        || checkpoint.hold
        || checkpoint.revoked
        || checkpoint.sequence == 0
        || checkpoint.snapshot_digest == [0; 32]
        || checkpoint.predecessor_digest == [0; 32]
    {
        return RestartInspection::Deny;
    }

    if checkpoint.sequence != anchor.sequence
        || checkpoint.snapshot_digest != anchor.snapshot_digest
        || checkpoint.predecessor_digest != anchor.predecessor_digest
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{inspect_restart, RestartAnchor, RestartCheckpoint, RestartInspection};

    fn fixture() -> (RestartCheckpoint, RestartAnchor) {
        (
            RestartCheckpoint {
                sequence: 7,
                snapshot_digest: [7; 32],
                predecessor_digest: [6; 32],
                committed: true,
                hold: false,
                revoked: false,
            },
            RestartAnchor {
                sequence: 7,
                snapshot_digest: [7; 32],
                predecessor_digest: [6; 32],
                externally_verified: true,
            },
        )
    }

    #[test]
    fn matching_independently_verified_checkpoint_is_review_only() {
        let (checkpoint, anchor) = fixture();
        assert_eq!(
            inspect_restart(Some(&checkpoint), Some(&anchor)),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn missing_evidence_is_denied() {
        let (checkpoint, anchor) = fixture();
        assert_eq!(inspect_restart(None, Some(&anchor)), RestartInspection::Deny);
        assert_eq!(inspect_restart(Some(&checkpoint), None), RestartInspection::Deny);
    }

    #[test]
    fn hold_and_revocation_override_matches() {
        let (mut checkpoint, anchor) = fixture();
        checkpoint.hold = true;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
        checkpoint.hold = false;
        checkpoint.revoked = true;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
    }

    #[test]
    fn pending_commit_and_unverified_anchor_are_denied() {
        let (mut checkpoint, mut anchor) = fixture();
        checkpoint.committed = false;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
        checkpoint.committed = true;
        anchor.externally_verified = false;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
    }

    #[test]
    fn sequence_rollback_and_digest_changes_are_denied() {
        let (mut checkpoint, anchor) = fixture();
        checkpoint.sequence -= 1;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
        checkpoint.sequence += 1;
        checkpoint.snapshot_digest[0] ^= 1;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
        checkpoint.snapshot_digest[0] ^= 1;
        checkpoint.predecessor_digest[0] ^= 1;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
    }

    #[test]
    fn zero_digest_and_genesis_sequence_are_denied() {
        let (mut checkpoint, anchor) = fixture();
        checkpoint.snapshot_digest = [0; 32];
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
        checkpoint.snapshot_digest = [7; 32];
        checkpoint.predecessor_digest = [0; 32];
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
        checkpoint.predecessor_digest = [6; 32];
        checkpoint.sequence = 0;
        assert_eq!(inspect_restart(Some(&checkpoint), Some(&anchor)), RestartInspection::Deny);
    }
}
