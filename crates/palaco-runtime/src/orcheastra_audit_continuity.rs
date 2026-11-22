//! Fail-closed continuity inspection between two witnessed audit segments.
//!
//! A matching hash chain is NOT independent proof of custody. Both segment
//! expectations must be authenticated by a separately trusted, rollback-safe
//! witness. ReviewOnly never grants execution or publishing rights.

use crate::orcheastra_audit_chain::{AuditChainExpectation, AuditLink};
use crate::orcheastra_audit_custody::{inspect_custodied_audit_chain, AuditCustodyWitness};
use crate::orcheastra_restart::RestartInspection;

/// Checks two complete witnessed audit segments and their exact junction.
///
/// Requires contiguous sequence numbers, an exact predecessor-to-head match,
/// and successful independent witness checks on both segment expectations.
/// No caller-supplied witness implementation is trusted merely by this API.
/// The function does not create, store, or authorize audit records.
#[must_use]
pub fn inspect_audit_continuity(
    previous_links: &[AuditLink],
    previous_expected: Option<&AuditChainExpectation>,
    current_links: &[AuditLink],
    current_expected: Option<&AuditChainExpectation>,
    witness: Option<&impl AuditCustodyWitness>,
) -> RestartInspection {
    let (Some(previous), Some(current), Some(witness)) =
        (previous_expected, current_expected, witness)
    else {
        return RestartInspection::Deny;
    };
    let Some(next_sequence) = previous.last_sequence.checked_add(1) else {
        return RestartInspection::Deny;
    };
    if current.first_sequence != next_sequence
        || current.predecessor_digest != previous.final_digest
        || inspect_custodied_audit_chain(previous_links, Some(previous), Some(witness))
            != RestartInspection::ReviewOnly
        || inspect_custodied_audit_chain(current_links, Some(current), Some(witness))
            != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::inspect_audit_continuity;
    use crate::orcheastra_audit_chain::{audit_link_digest, AuditChainExpectation, AuditLink};
    use crate::orcheastra_audit_custody::{AuditCustodyWitness, CustodyVerdict};
    use crate::orcheastra_restart::RestartInspection;

    // Test-only witness: no authentication or durable custody.
    struct TestWitness([AuditChainExpectation; 2]);
    impl AuditCustodyWitness for TestWitness {
        fn verify_expectation(&self, expected: &AuditChainExpectation) -> CustodyVerdict {
            if self.0.contains(expected) {
                CustodyVerdict::Verified
            } else {
                CustodyVerdict::Denied
            }
        }
    }

    struct RejectAll;
    impl AuditCustodyWitness for RejectAll {
        fn verify_expectation(&self, _expected: &AuditChainExpectation) -> CustodyVerdict {
            CustodyVerdict::Denied
        }
    }

    fn fixture() -> (
        [AuditLink; 1],
        AuditChainExpectation,
        [AuditLink; 1],
        AuditChainExpectation,
    ) {
        let first_digest = audit_link_digest(10, &[9; 32], &[3; 32]).unwrap_or([0; 32]);
        let second_digest = audit_link_digest(11, &first_digest, &[4; 32]).unwrap_or([0; 32]);
        let previous_links = [AuditLink {
            sequence: 10,
            predecessor_digest: [9; 32],
            receipt_digest: [3; 32],
            link_digest: first_digest,
        }];
        let current_links = [AuditLink {
            sequence: 11,
            predecessor_digest: first_digest,
            receipt_digest: [4; 32],
            link_digest: second_digest,
        }];
        let previous = AuditChainExpectation {
            first_sequence: 10,
            predecessor_digest: [9; 32],
            last_sequence: 10,
            final_digest: first_digest,
        };
        let current = AuditChainExpectation {
            first_sequence: 11,
            predecessor_digest: first_digest,
            last_sequence: 11,
            final_digest: second_digest,
        };
        (previous_links, previous, current_links, current)
    }

    #[test]
    fn witnessed_adjacent_segments_are_review_only() {
        let (prev_links, prev, next_links, next) = fixture();
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn missing_or_refusing_witness_denies() {
        let (prev_links, prev, next_links, next) = fixture();
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                None::<&RejectAll>,
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&RejectAll),
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                None,
                &next_links,
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::Deny
        );
    }

    #[test]
    fn gap_and_replay_deny() {
        let (prev_links, prev, next_links, mut next) = fixture();
        let witness = TestWitness([prev, next]);
        next.first_sequence += 1;
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&witness),
            ),
            RestartInspection::Deny
        );
        let (prev_links, prev, next_links, mut next) = fixture();
        next.first_sequence = prev.last_sequence;
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::Deny
        );
    }

    #[test]
    fn wrong_predecessor_or_changed_prior_receipt_denies() {
        let (mut prev_links, prev, next_links, next) = fixture();
        let mut altered = next;
        altered.predecessor_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&altered),
                Some(&TestWitness([prev, altered])),
            ),
            RestartInspection::Deny
        );
        prev_links[0].receipt_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::Deny
        );
    }

    #[test]
    fn sequence_overflow_and_missing_segment_deny() {
        let (prev_links, mut prev, next_links, next) = fixture();
        prev.last_sequence = u64::MAX;
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::Deny
        );
        let (prev_links, prev, next_links, next) = fixture();
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &[],
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_continuity(
                &[],
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&TestWitness([prev, next])),
            ),
            RestartInspection::Deny
        );
    }
}
