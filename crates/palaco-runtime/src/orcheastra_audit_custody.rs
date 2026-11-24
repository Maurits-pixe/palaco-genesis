//! Independent-custody policy boundary for ORCHEASTRA audit chain endpoints.
//!
//! This module does not implement independent custody, authenticate a remote
//! witness, or grant execution authority. No permissive production witness is
//! provided. The witness must be separately authenticated and rollback-safe.

use sha2::{Digest, Sha256};

use crate::orcheastra_audit_chain::{
    audit_expectation_link_count, inspect_audit_chain, AuditChainExpectation, AuditLink,
};
use crate::orcheastra_restart::RestartInspection;

const CUSTODY_DOMAIN: &[u8] = b"PALACO-ORCHEASTRA-AUDIT-CUSTODY-V1\0";

/// Independent custody verdict; only an authenticated external adapter
/// may legitimately report Verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyVerdict {
    /// Independently checked and accepted.
    Verified,
    /// Evidence unavailable, unauthenticated, stale, or rejected.
    Denied,
}

/// External witness contract for a committed audit-chain expectation.
///
/// Implementations must authenticate a separate pinned source and prevent
/// rollback. A caller-provided implementation is not automatically trustworthy.
pub trait AuditCustodyWitness {
    /// Authenticate the complete expected segment against independent custody.
    fn verify_expectation(&self, expectation: &AuditChainExpectation) -> CustodyVerdict;
}

/// SHA-256 fingerprint of the canonical custody expectation.
///
/// The digest is for log correlation and cannot authenticate the expectation.
/// Only expectations spanning 1 through 256 links may be fingerprinted.
#[must_use]
pub fn custody_expectation_digest(expected: &AuditChainExpectation) -> Option<[u8; 32]> {
    if audit_expectation_link_count(expected).is_none()
        || expected.predecessor_digest == [0; 32]
        || expected.final_digest == [0; 32]
    {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(CUSTODY_DOMAIN);
    hasher.update(expected.first_sequence.to_be_bytes());
    hasher.update(expected.predecessor_digest);
    hasher.update(expected.last_sequence.to_be_bytes());
    hasher.update(expected.final_digest);
    Some(hasher.finalize().into())
}

/// Requires an external custody witness AND a complete valid audit hash chain.
///
/// Denies when the witness is missing, the witness declines, the external
/// expectation is malformed, or the chain differs. The complete local chain
/// is checked before invoking the external witness. A positive result is
/// ReviewOnly; it must not be converted into an authorization decision.
#[must_use]
pub fn inspect_custodied_audit_chain(
    links: &[AuditLink],
    expected: Option<&AuditChainExpectation>,
    witness: Option<&impl AuditCustodyWitness>,
) -> RestartInspection {
    let (Some(expected), Some(witness)) = (expected, witness) else {
        return RestartInspection::Deny;
    };
    // Reject malformed local chains before invoking an external witness.
    if custody_expectation_digest(expected).is_none()
        || inspect_audit_chain(links, Some(expected)) != RestartInspection::ReviewOnly
        || witness.verify_expectation(expected) != CustodyVerdict::Verified
    {
        return RestartInspection::Deny;
    }
    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{
        custody_expectation_digest, inspect_custodied_audit_chain, AuditCustodyWitness,
        CustodyVerdict,
    };
    use crate::orcheastra_audit_chain::{audit_link_digest, AuditChainExpectation, AuditLink};
    use crate::orcheastra_restart::RestartInspection;

    // Fake witness only tests policy plumbing, NOT trusted custody.
    struct TestWitness(AuditChainExpectation);
    impl AuditCustodyWitness for TestWitness {
        fn verify_expectation(&self, expectation: &AuditChainExpectation) -> CustodyVerdict {
            if expectation == &self.0 {
                CustodyVerdict::Verified
            } else {
                CustodyVerdict::Denied
            }
        }
    }

    // Tracks external custody invocations without locks or panics.
    struct CountingWitness(std::cell::Cell<usize>);
    impl AuditCustodyWitness for CountingWitness {
        fn verify_expectation(&self, _expectation: &AuditChainExpectation) -> CustodyVerdict {
            self.0.set(self.0.get() + 1);
            CustodyVerdict::Verified
        }
    }

    struct RejectAll;
    impl AuditCustodyWitness for RejectAll {
        fn verify_expectation(&self, _expectation: &AuditChainExpectation) -> CustodyVerdict {
            CustodyVerdict::Denied
        }
    }

    fn fixture() -> (Vec<AuditLink>, AuditChainExpectation) {
        let link_digest = audit_link_digest(9, &[8; 32], &[7; 32]).unwrap_or([0; 32]);
        let links = vec![AuditLink {
            sequence: 9,
            predecessor_digest: [8; 32],
            receipt_digest: [7; 32],
            link_digest,
        }];
        let expected = AuditChainExpectation {
            first_sequence: 9,
            predecessor_digest: [8; 32],
            last_sequence: 9,
            final_digest: link_digest,
        };
        (links, expected)
    }

    #[test]
    fn matching_test_witness_is_review_only() {
        let (links, expected) = fixture();
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&expected), Some(&TestWitness(expected))),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn invalid_local_chains_do_not_invoke_external_custody() {
        let (links, expected) = fixture();
        let witness = CountingWitness(std::cell::Cell::new(0));
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&expected), Some(&witness)),
            RestartInspection::ReviewOnly
        );
        assert_eq!(witness.0.get(), 1);

        witness.0.set(0);
        let mut changed_links = links.clone();
        changed_links[0].receipt_digest[0] ^= 1;
        assert_eq!(
            inspect_custodied_audit_chain(&changed_links, Some(&expected), Some(&witness)),
            RestartInspection::Deny
        );
        assert_eq!(witness.0.get(), 0);

        let mut changed_expected = expected;
        changed_expected.final_digest[0] ^= 1;
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&changed_expected), Some(&witness)),
            RestartInspection::Deny
        );
        assert_eq!(witness.0.get(), 0);

        assert_eq!(
            inspect_custodied_audit_chain(&[], Some(&expected), Some(&witness)),
            RestartInspection::Deny
        );
        assert_eq!(witness.0.get(), 0);
    }

    #[test]
    fn missing_or_rejecting_witness_denies() {
        let (links, expected) = fixture();
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&expected), None::<&RejectAll>),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_chain(&links, None, Some(&RejectAll)),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&expected), Some(&RejectAll)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn alternate_endpoints_and_changed_links_deny() {
        let (mut links, expected) = fixture();
        links[0].receipt_digest[0] ^= 1;
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&expected), Some(&TestWitness(expected))),
            RestartInspection::Deny
        );
        let (links, mut changed) = fixture();
        changed.final_digest[0] ^= 1;
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&changed), Some(&TestWitness(expected))),
            RestartInspection::Deny
        );
    }

    #[test]
    fn standalone_custody_digest_rejects_impossible_ranges() {
        let (_, expected) = fixture();
        assert!(custody_expectation_digest(&expected).is_some());
        let too_long = AuditChainExpectation {
            first_sequence: 1,
            last_sequence: 257,
            ..expected
        };
        assert_eq!(custody_expectation_digest(&too_long), None);
        let exactly_max = AuditChainExpectation {
            last_sequence: 256,
            ..too_long
        };
        assert!(custody_expectation_digest(&exactly_max).is_some());
        let reversed = AuditChainExpectation {
            first_sequence: 12,
            last_sequence: 11,
            ..expected
        };
        assert_eq!(custody_expectation_digest(&reversed), None);
        let near_overflow = AuditChainExpectation {
            first_sequence: 1,
            last_sequence: u64::MAX,
            ..expected
        };
        assert_eq!(custody_expectation_digest(&near_overflow), None);
    }

    #[test]
    fn custody_digest_binds_all_endpoint_fields() {
        let (_, expected) = fixture();
        let baseline = custody_expectation_digest(&expected);
        let mut changed = expected;
        changed.first_sequence = 8;
        assert_ne!(baseline, custody_expectation_digest(&changed));
        changed = expected;
        changed.last_sequence = 10;
        assert_ne!(baseline, custody_expectation_digest(&changed));
        changed = expected;
        changed.predecessor_digest[0] ^= 1;
        assert_ne!(baseline, custody_expectation_digest(&changed));
        changed = expected;
        changed.final_digest[0] ^= 1;
        assert_ne!(baseline, custody_expectation_digest(&changed));
    }

    #[test]
    fn invalid_expectations_deny() {
        let (links, mut expected) = fixture();
        expected.first_sequence = 0;
        assert_eq!(custody_expectation_digest(&expected), None);
        assert_eq!(
            inspect_custodied_audit_chain(&links, Some(&expected), Some(&TestWitness(expected))),
            RestartInspection::Deny
        );
        expected.first_sequence = 10;
        assert_eq!(custody_expectation_digest(&expected), None);
    }
}
