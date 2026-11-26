//! Read-only binding between hash-linked audit records and recovery receipts.
//!
//! This confirms local consistency only. A review receipt is not a signature;
//! the expected chain endpoints and underlying receipts must be authenticated
//! independently before the result can be treated as trusted evidence.

use crate::orcheastra_audit_chain::{
    inspect_audit_chain, AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS,
};
use crate::orcheastra_payload::MAX_CHAIN_CHECKPOINTS;
use crate::orcheastra_restart::RestartInspection;
use crate::orcheastra_review_receipt::ReviewReceipt;

/// Checks audit-link digests against their corresponding review receipts.
///
/// In addition to the existing hash-chain checks, requires a one-to-one receipt
/// match, gapless non-overlapping recovery checkpoint intervals, nondecreasing
/// key registry revisions, and bounded nonempty checkpoint counts. All receipts
/// remain caller-supplied and unauthenticated by this function.
#[must_use]
pub fn inspect_bound_audit_receipts(
    links: &[AuditLink],
    receipts: &[ReviewReceipt],
    expected: Option<&AuditChainExpectation>,
) -> RestartInspection {
    if links.is_empty()
        || links.len() > MAX_AUDIT_LINKS
        || links.len() != receipts.len()
        || inspect_audit_chain(links, expected) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    let mut prior_checkpoint_sequence = None;
    let mut prior_registry_sequence = 0;
    for (link, receipt) in links.iter().zip(receipts.iter()) {
        if receipt.digest == [0; 32]
            || link.receipt_digest != receipt.digest
            || receipt.checkpoint_sequence == 0
            || receipt.registry_sequence == 0
            || receipt.registry_sequence < prior_registry_sequence
            || receipt.checkpoint_count == 0
            || receipt.checkpoint_count > MAX_CHAIN_CHECKPOINTS
        {
            return RestartInspection::Deny;
        }
        let Some(count) = u64::try_from(receipt.checkpoint_count).ok() else {
            return RestartInspection::Deny;
        };
        // Each receipt spans [end - count + 1, end]. The initial receipt
        // must have a feasible nonzero start. Subsequent receipts must begin
        // exactly after the previous receipt's end (no gaps or overlap).
        let Some(predecessor) = receipt.checkpoint_sequence.checked_sub(count) else {
            return RestartInspection::Deny;
        };
        if let Some(previous) = prior_checkpoint_sequence {
            if predecessor != previous {
                return RestartInspection::Deny;
            }
        }
        prior_checkpoint_sequence = Some(receipt.checkpoint_sequence);
        prior_registry_sequence = receipt.registry_sequence;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::inspect_bound_audit_receipts;
    use crate::orcheastra_audit_chain::{audit_link_digest, AuditChainExpectation, AuditLink};
    use crate::orcheastra_restart::RestartInspection;
    use crate::orcheastra_review_receipt::ReviewReceipt;

    fn fixture() -> (Vec<AuditLink>, Vec<ReviewReceipt>, AuditChainExpectation) {
        let receipts = vec![
            ReviewReceipt {
                digest: [1; 32],
                checkpoint_sequence: 20,
                registry_sequence: 3,
                checkpoint_count: 2,
            },
            ReviewReceipt {
                digest: [2; 32],
                checkpoint_sequence: 22,
                registry_sequence: 4,
                checkpoint_count: 2,
            },
        ];
        let first = audit_link_digest(7, &[6; 32], &receipts[0].digest).unwrap_or([0; 32]);
        let second = audit_link_digest(8, &first, &receipts[1].digest).unwrap_or([0; 32]);
        let links = vec![
            AuditLink {
                sequence: 7,
                predecessor_digest: [6; 32],
                receipt_digest: receipts[0].digest,
                link_digest: first,
            },
            AuditLink {
                sequence: 8,
                predecessor_digest: first,
                receipt_digest: receipts[1].digest,
                link_digest: second,
            },
        ];
        let expected = AuditChainExpectation {
            first_sequence: 7,
            predecessor_digest: [6; 32],
            last_sequence: 8,
            final_digest: second,
        };
        (links, receipts, expected)
    }

    #[test]
    fn correctly_bound_receipts_are_review_only() {
        let (links, receipts, expected) = fixture();
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn mismatched_missing_and_reordered_receipts_deny() {
        let (links, mut receipts, expected) = fixture();
        receipts.swap(0, 1);
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        let (links, receipts, expected) = fixture();
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts[..1], Some(&expected)),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, None),
            RestartInspection::Deny
        );
    }

    #[test]
    fn checkpoint_rollback_or_duplicate_denies() {
        let (links, mut receipts, expected) = fixture();
        receipts[1].checkpoint_sequence = 20;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        receipts[1].checkpoint_sequence = 19;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn overlapping_or_gapped_receipt_intervals_are_denied() {
        let (links, mut receipts, expected) = fixture();
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::ReviewOnly
        );
        receipts[1].checkpoint_sequence = 21;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        receipts[1].checkpoint_sequence = 23;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        receipts[1].checkpoint_sequence = 22;
        receipts[1].checkpoint_count = 3;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        receipts[1].checkpoint_count = 2;
        receipts[0].checkpoint_count = 21;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn registry_rollback_denies() {
        let (links, mut receipts, expected) = fixture();
        receipts[1].registry_sequence = 2;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn invalid_count_and_zero_digest_deny() {
        let (links, mut receipts, expected) = fixture();
        receipts[0].checkpoint_count = 0;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        receipts[0].checkpoint_count = 257;
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
        receipts[0].checkpoint_count = 2;
        receipts[0].digest = [0; 32];
        assert_eq!(
            inspect_bound_audit_receipts(&links, &receipts, Some(&expected)),
            RestartInspection::Deny
        );
    }
}
