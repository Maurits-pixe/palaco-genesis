//! Bounded, read-only linkage verification for ORCHEASTRA review receipts.
//!
//! A hash chain is not an authenticated ledger. The first predecessor and
//! expected final head must come from an independent trusted custodian.
//! Nothing here grants execution, publication, or recovery authority.

use sha2::{Digest, Sha256};

use crate::orcheastra_restart::RestartInspection;

/// Maximum number of audit links accepted in one local inspection.
pub const MAX_AUDIT_LINKS: usize = 256;

const DOMAIN: &[u8] = b"PALACO-ORCHEASTRA-REVIEW-AUDIT-LINK-V1\0";

/// Hash-linked review record supplied by an untrusted caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLink {
    /// Monotonically increasing sequence, beginning above zero.
    pub sequence: u64,
    /// Digest of the preceding link or externally pinned predecessor.
    pub predecessor_digest: [u8; 32],
    /// Digest of a separate recovery review receipt.
    pub receipt_digest: [u8; 32],
    /// Domain-separated digest of this audit link.
    pub link_digest: [u8; 32],
}

/// Independently supplied expectations for a complete audit segment.
///
/// Populating this struct does not establish trust: callers must authenticate
/// it against persistent, rollback-resistant external evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditChainExpectation {
    /// First expected sequence.
    pub first_sequence: u64,
    /// Expected predecessor of the first link.
    pub predecessor_digest: [u8; 32],
    /// Last expected sequence.
    pub last_sequence: u64,
    /// Expected digest of the final link.
    pub final_digest: [u8; 32],
}

/// Returns the bounded number of links described by a custody expectation.
///
/// This is structural range validation only, not authentication of endpoints.
/// Rejects empty, reversed, zero-based and overlong ranges without allocation.
#[must_use]
pub fn audit_expectation_link_count(expected: &AuditChainExpectation) -> Option<usize> {
    if expected.first_sequence == 0 {
        return None;
    }
    let span = expected
        .last_sequence
        .checked_sub(expected.first_sequence)?;
    let count = span.checked_add(1)?;
    let count = usize::try_from(count).ok()?;
    if count > MAX_AUDIT_LINKS {
        return None;
    }
    Some(count)
}

/// Recomputes the canonical SHA-256 digest of one proposed audit link.
///
/// Inputs are domain-separated, fixed-length and sequence-bound. Returns None
/// for invalid sequence or zero digests. Hashing alone proves no authenticity.
#[must_use]
pub fn audit_link_digest(
    sequence: u64,
    predecessor_digest: &[u8; 32],
    receipt_digest: &[u8; 32],
) -> Option<[u8; 32]> {
    if sequence == 0 || *predecessor_digest == [0; 32] || *receipt_digest == [0; 32] {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(sequence.to_be_bytes());
    hasher.update(predecessor_digest);
    hasher.update(receipt_digest);
    Some(hasher.finalize().into())
}

/// Reviews a complete bounded segment against independently pinned endpoints.
///
/// All supplied links must be consecutive, cryptographically hash-consistent,
/// and joined by their predecessor fields. An attacker controlling both links
/// and expected endpoints can forge a consistent chain. The expected sequence
/// span must exactly equal the supplied link count before any SHA-256 work.
/// Success is review-only.
#[must_use]
pub fn inspect_audit_chain(
    links: &[AuditLink],
    expected: Option<&AuditChainExpectation>,
) -> RestartInspection {
    let Some(expected) = expected else {
        return RestartInspection::Deny;
    };
    if links.is_empty()
        || links.len() > MAX_AUDIT_LINKS
        || audit_expectation_link_count(expected) != Some(links.len())
        || expected.predecessor_digest == [0; 32]
        || expected.final_digest == [0; 32]
    {
        return RestartInspection::Deny;
    }

    let mut next_sequence = expected.first_sequence;
    let mut predecessor = expected.predecessor_digest;
    for (index, link) in links.iter().enumerate() {
        let Some(computed) = audit_link_digest(
            link.sequence,
            &link.predecessor_digest,
            &link.receipt_digest,
        ) else {
            return RestartInspection::Deny;
        };
        if link.sequence != next_sequence
            || link.predecessor_digest != predecessor
            || link.link_digest != computed
        {
            return RestartInspection::Deny;
        }
        predecessor = link.link_digest;
        if index + 1 < links.len() {
            let Some(next) = next_sequence.checked_add(1) else {
                return RestartInspection::Deny;
            };
            next_sequence = next;
        }
    }

    let Some(last) = links.last() else {
        return RestartInspection::Deny;
    };
    if last.sequence != expected.last_sequence || last.link_digest != expected.final_digest {
        return RestartInspection::Deny;
    }
    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{
        audit_expectation_link_count, audit_link_digest, inspect_audit_chain,
        AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS,
    };
    use crate::orcheastra_restart::RestartInspection;

    fn fixture() -> (Vec<AuditLink>, AuditChainExpectation) {
        let first = audit_link_digest(10, &[9; 32], &[1; 32]).unwrap_or([0; 32]);
        let second = audit_link_digest(11, &first, &[2; 32]).unwrap_or([0; 32]);
        let links = vec![
            AuditLink {
                sequence: 10,
                predecessor_digest: [9; 32],
                receipt_digest: [1; 32],
                link_digest: first,
            },
            AuditLink {
                sequence: 11,
                predecessor_digest: first,
                receipt_digest: [2; 32],
                link_digest: second,
            },
        ];
        let expected = AuditChainExpectation {
            first_sequence: 10,
            predecessor_digest: [9; 32],
            last_sequence: 11,
            final_digest: second,
        };
        (links, expected)
    }

    #[test]
    fn linked_audit_segment_is_review_only() {
        let (links, expected) = fixture();
        assert_eq!(
            inspect_audit_chain(&links, Some(&expected)),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn missing_and_modified_receipts_are_denied() {
        let (mut links, expected) = fixture();
        assert_eq!(
            inspect_audit_chain(&[], Some(&expected)),
            RestartInspection::Deny
        );
        assert_eq!(inspect_audit_chain(&links, None), RestartInspection::Deny);
        links[0].receipt_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_chain(&links, Some(&expected)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn gap_and_reordered_sequence_are_denied() {
        let (mut links, expected) = fixture();
        links[1].sequence = 12;
        assert_eq!(
            inspect_audit_chain(&links, Some(&expected)),
            RestartInspection::Deny
        );
        let (mut links, expected) = fixture();
        links.reverse();
        assert_eq!(
            inspect_audit_chain(&links, Some(&expected)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn independently_pinned_endpoints_are_required() {
        let (links, mut expected) = fixture();
        expected.final_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_chain(&links, Some(&expected)),
            RestartInspection::Deny
        );
        let (links, mut expected) = fixture();
        expected.predecessor_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_chain(&links, Some(&expected)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn expectation_range_is_bounded_and_must_match_supplied_links() {
        let (links, expected) = fixture();
        assert_eq!(audit_expectation_link_count(&expected), Some(2));

        let single = AuditChainExpectation {
            last_sequence: expected.first_sequence,
            ..expected
        };
        assert_eq!(audit_expectation_link_count(&single), Some(1));
        assert_eq!(
            inspect_audit_chain(&links, Some(&single)),
            RestartInspection::Deny
        );

        let exactly_max = AuditChainExpectation {
            first_sequence: 1,
            last_sequence: u64::try_from(MAX_AUDIT_LINKS).unwrap_or(0),
            ..expected
        };
        assert_eq!(
            audit_expectation_link_count(&exactly_max),
            Some(MAX_AUDIT_LINKS)
        );
        let over_max = AuditChainExpectation {
            last_sequence: exactly_max.last_sequence + 1,
            ..exactly_max
        };
        assert_eq!(audit_expectation_link_count(&over_max), None);
        assert_eq!(
            inspect_audit_chain(&links, Some(&over_max)),
            RestartInspection::Deny
        );

        let zero_start = AuditChainExpectation {
            first_sequence: 0,
            ..expected
        };
        let reversed = AuditChainExpectation {
            last_sequence: expected.first_sequence - 1,
            ..expected
        };
        assert_eq!(audit_expectation_link_count(&zero_start), None);
        assert_eq!(audit_expectation_link_count(&reversed), None);

        let near_u64_max = AuditChainExpectation {
            first_sequence: u64::MAX - 1,
            last_sequence: u64::MAX,
            ..expected
        };
        assert_eq!(audit_expectation_link_count(&near_u64_max), Some(2));
    }

    #[test]
    fn bounds_and_zero_inputs_are_denied() {
        let (links, expected) = fixture();
        let overlong = vec![links[0]; MAX_AUDIT_LINKS + 1];
        assert_eq!(
            inspect_audit_chain(&overlong, Some(&expected)),
            RestartInspection::Deny
        );
        assert_eq!(audit_link_digest(0, &[9; 32], &[1; 32]), None);
        assert_eq!(audit_link_digest(10, &[0; 32], &[1; 32]), None);
        assert_eq!(audit_link_digest(10, &[9; 32], &[0; 32]), None);
    }
}
