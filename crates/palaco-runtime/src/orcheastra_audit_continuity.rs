//! Fail-closed continuity inspection between two witnessed audit segments.
//!
//! A matching hash chain is NOT independent proof of custody. Both segment
//! expectations must be authenticated by a separately trusted, rollback-safe
//! witness. ReviewOnly never grants execution or publishing rights.

use crate::orcheastra_audit_chain::{
    inspect_audit_chain, AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS,
};
use crate::orcheastra_audit_custody::{inspect_custodied_audit_chain, AuditCustodyWitness};
use crate::orcheastra_restart::RestartInspection;

/// Checks two complete witnessed audit segments and their exact junction.
///
/// Requires contiguous sequence numbers, an exact predecessor-to-head match,
/// and successful independent witness checks on both segment expectations.
/// A combined maximum of 256 audit links applies across both segments, even
/// if each is individually within its limit. Both local audit chains are
/// validated before calling either external witness.
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
    // Share the composite transition's cumulative link budget even when
    // this standalone custody gate is invoked directly.
    let Some(total_links) = previous_links.len().checked_add(current_links.len()) else {
        return RestartInspection::Deny;
    };
    if previous_links.is_empty() || current_links.is_empty() || total_links > MAX_AUDIT_LINKS {
        return RestartInspection::Deny;
    }
    let Some(next_sequence) = previous.last_sequence.checked_add(1) else {
        return RestartInspection::Deny;
    };
    // Validate both complete local chains before either external witness call.
    if current.first_sequence != next_sequence
        || current.predecessor_digest != previous.final_digest
        || inspect_audit_chain(previous_links, Some(previous)) != RestartInspection::ReviewOnly
        || inspect_audit_chain(current_links, Some(current)) != RestartInspection::ReviewOnly
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

    // Counts potentially side-effecting custody calls without locks or panic.
    struct CountingWitness(std::cell::Cell<usize>);
    impl AuditCustodyWitness for CountingWitness {
        fn verify_expectation(&self, _expected: &AuditChainExpectation) -> CustodyVerdict {
            self.0.set(self.0.get() + 1);
            CustodyVerdict::Verified
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
    fn both_chains_preflight_before_any_external_witness() {
        let (prev_links, prev, next_links, next) = fixture();
        let witness = CountingWitness(std::cell::Cell::new(0));
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&witness),
            ),
            RestartInspection::ReviewOnly
        );
        assert_eq!(witness.0.get(), 2);

        witness.0.set(0);
        let mut tampered_current = next_links;
        tampered_current[0].receipt_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_continuity(
                &prev_links,
                Some(&prev),
                &tampered_current,
                Some(&next),
                Some(&witness),
            ),
            RestartInspection::Deny
        );
        assert_eq!(witness.0.get(), 0);

        let mut tampered_previous = prev_links;
        tampered_previous[0].link_digest[0] ^= 1;
        assert_eq!(
            inspect_audit_continuity(
                &tampered_previous,
                Some(&prev),
                &next_links,
                Some(&next),
                Some(&witness),
            ),
            RestartInspection::Deny
        );
        assert_eq!(witness.0.get(), 0);
    }

    #[test]
    fn cumulative_link_budget_is_enforced_before_custody_callbacks() {
        let build_segment = |first_sequence: u64, count: usize, initial: [u8; 32]| {
            let mut links = Vec::new();
            let mut predecessor = initial;
            for index in 0..count {
                let sequence = first_sequence + u64::try_from(index).unwrap_or(0);
                let digest = audit_link_digest(sequence, &predecessor, &[7; 32]).unwrap_or([0; 32]);
                links.push(AuditLink {
                    sequence,
                    predecessor_digest: predecessor,
                    receipt_digest: [7; 32],
                    link_digest: digest,
                });
                predecessor = digest;
            }
            let expected = AuditChainExpectation {
                first_sequence,
                predecessor_digest: initial,
                last_sequence: first_sequence + u64::try_from(count).unwrap_or(0) - 1,
                final_digest: predecessor,
            };
            (links, expected)
        };
        let (previous_links, previous_expected) = build_segment(10, 128, [9; 32]);
        let (current_links, current_expected) =
            build_segment(138, 128, previous_expected.final_digest);
        let witness = CountingWitness(std::cell::Cell::new(0));
        assert_eq!(
            inspect_audit_continuity(
                &previous_links,
                Some(&previous_expected),
                &current_links,
                Some(&current_expected),
                Some(&witness),
            ),
            RestartInspection::ReviewOnly
        );
        assert_eq!(witness.0.get(), 2);

        witness.0.set(0);
        let (over_limit_links, over_limit_expected) =
            build_segment(138, 129, previous_expected.final_digest);
        assert_eq!(
            inspect_audit_continuity(
                &previous_links,
                Some(&previous_expected),
                &over_limit_links,
                Some(&over_limit_expected),
                Some(&witness),
            ),
            RestartInspection::Deny
        );
        assert_eq!(witness.0.get(), 0);
        // Individual segment inspections still accept both full chains; it
        // is specifically the combined transition budget that rejects them.
        assert_eq!(
            crate::orcheastra_audit_chain::inspect_audit_chain(
                &over_limit_links,
                Some(&over_limit_expected),
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
