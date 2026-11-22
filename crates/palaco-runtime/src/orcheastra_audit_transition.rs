//! Joined custody and original-evidence review across consecutive audit segments.
//!
//! Both custody and signature verifier interfaces are caller-provided, and
//! therefore require independent trust validation beyond this crate.
//! ReviewOnly is never permission to recover or execute.

use crate::orcheastra_audit_chain::{AuditChainExpectation, AuditLink};
use crate::orcheastra_audit_continuity::inspect_audit_continuity;
use crate::orcheastra_audit_custody::AuditCustodyWitness;
use crate::orcheastra_audit_evidence::{inspect_audit_evidence, RecoveryEvidence};
use crate::orcheastra_restart::RestartInspection;
use crate::orcheastra_review_receipt::ReviewReceipt;
use crate::orcheastra_signed_anchor::Ed25519Verifier;

/// Borrowed complete input for reviewing one audit segment.
pub struct AuditSegmentEvidence<'a> {
    /// Hash-linked audit records.
    pub links: &'a [AuditLink],
    /// Corresponding review receipts, ordered as the audit records.
    pub receipts: &'a [ReviewReceipt],
    /// Original checkpoint and payload evidence for each receipt.
    pub evidence: &'a [RecoveryEvidence<'a>],
    /// Expected endpoints from an independently checked custodian.
    pub expected: &'a AuditChainExpectation,
}

/// Requires consecutive witnessed segments and complete recovery evidence.
///
/// Checks both source-evidence batches as well as the exact transition between
/// independently witnessed audit endpoints. Every rejection remains Deny.
/// No external custody implementation or Ed25519 algorithm is provided here.
#[must_use]
pub fn inspect_custodied_audit_transition(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
    witness: Option<&impl AuditCustodyWitness>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    if inspect_audit_continuity(
        previous.links,
        Some(previous.expected),
        current.links,
        Some(current.expected),
        witness,
    ) != RestartInspection::ReviewOnly
        || inspect_audit_evidence(
            previous.links,
            previous.receipts,
            previous.evidence,
            Some(previous.expected),
            verifier,
        ) != RestartInspection::ReviewOnly
        || inspect_audit_evidence(
            current.links,
            current.receipts,
            current.evidence,
            Some(current.expected),
            verifier,
        ) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{inspect_custodied_audit_transition, AuditSegmentEvidence};
    use crate::orcheastra_audit_chain::{audit_link_digest, AuditChainExpectation, AuditLink};
    use crate::orcheastra_audit_custody::{AuditCustodyWitness, CustodyVerdict};
    use crate::orcheastra_audit_evidence::RecoveryEvidence;
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_recovery::RecoveryFloor;
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint, RestartInspection};
    use crate::orcheastra_review_receipt::{review_receipt, ReviewReceipt};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor, TrustedKey,
    };

    // These adapters only test wiring. Neither is a trusted implementation.
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

    struct TestVerifier([Vec<u8>; 2]);
    impl Ed25519Verifier for TestVerifier {
        fn verify(
            &self,
            _key: &[u8; 32],
            message: &[u8],
            _signature: &[u8; 64],
        ) -> SignatureVerdict {
            if self.0.iter().any(|candidate| candidate == message) {
                SignatureVerdict::Valid
            } else {
                SignatureVerdict::Invalid
            }
        }
    }

    struct RejectVerifier;
    impl Ed25519Verifier for RejectVerifier {
        fn verify(
            &self,
            _key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> SignatureVerdict {
            SignatureVerdict::Invalid
        }
    }

    #[test]
    fn transition_revalidates_both_segments_and_denies_changed_evidence() {
        let first = digest_snapshot(7, &[6; 32], b"first").unwrap_or([0; 32]);
        let second = digest_snapshot(8, &first, b"second").unwrap_or([0; 32]);
        let checkpoints_previous = [RestartCheckpoint {
            sequence: 7,
            predecessor_digest: [6; 32],
            snapshot_digest: first,
            committed: true,
            hold: false,
            revoked: false,
        }];
        let checkpoints_current = [RestartCheckpoint {
            sequence: 8,
            predecessor_digest: first,
            snapshot_digest: second,
            committed: true,
            hold: false,
            revoked: false,
        }];
        let signed_previous = SignedAnchor {
            key_id: "audit-key",
            public_key: [4; 32],
            signature: [9; 64],
            anchor: RestartAnchor {
                sequence: 7,
                predecessor_digest: [6; 32],
                snapshot_digest: first,
                externally_verified: true,
            },
        };
        let signed_current = SignedAnchor {
            key_id: "audit-key",
            public_key: [4; 32],
            signature: [8; 64],
            anchor: RestartAnchor {
                sequence: 8,
                predecessor_digest: first,
                snapshot_digest: second,
                externally_verified: true,
            },
        };
        let key = TrustedKey {
            key_id: "audit-key",
            public_key: [4; 32],
            registry_sequence: 3,
            first_sequence: 7,
            last_sequence: 8,
            revoked: false,
        };
        let floor_previous = RecoveryFloor {
            checkpoint_sequence: 7,
            registry_sequence: 3,
        };
        let floor_current = RecoveryFloor {
            checkpoint_sequence: 8,
            registry_sequence: 3,
        };
        let verifier = TestVerifier([
            anchor_message_v2(&signed_previous.anchor, &key).unwrap_or_default(),
            anchor_message_v2(&signed_current.anchor, &key).unwrap_or_default(),
        ]);
        let payloads_previous: &[&[u8]] = &[b"first"];
        let payloads_current: &[&[u8]] = &[b"second"];
        let receipt_previous = review_receipt(
            &checkpoints_previous,
            payloads_previous,
            Some(&signed_previous),
            Some(&key),
            Some(&floor_previous),
            &verifier,
        );
        let receipt_current = review_receipt(
            &checkpoints_current,
            payloads_current,
            Some(&signed_current),
            Some(&key),
            Some(&floor_current),
            &verifier,
        );
        assert!(receipt_previous.is_some() && receipt_current.is_some());
        let receipts_previous = [receipt_previous.unwrap_or(ReviewReceipt {
            digest: [0; 32],
            checkpoint_sequence: 0,
            registry_sequence: 0,
            checkpoint_count: 0,
        })];
        let receipts_current = [receipt_current.unwrap_or(ReviewReceipt {
            digest: [0; 32],
            checkpoint_sequence: 0,
            registry_sequence: 0,
            checkpoint_count: 0,
        })];
        let digest_previous =
            audit_link_digest(10, &[5; 32], &receipts_previous[0].digest).unwrap_or([0; 32]);
        let digest_current =
            audit_link_digest(11, &digest_previous, &receipts_current[0].digest).unwrap_or([0; 32]);
        let links_previous = [AuditLink {
            sequence: 10,
            predecessor_digest: [5; 32],
            receipt_digest: receipts_previous[0].digest,
            link_digest: digest_previous,
        }];
        let links_current = [AuditLink {
            sequence: 11,
            predecessor_digest: digest_previous,
            receipt_digest: receipts_current[0].digest,
            link_digest: digest_current,
        }];
        let expected_previous = AuditChainExpectation {
            first_sequence: 10,
            predecessor_digest: [5; 32],
            last_sequence: 10,
            final_digest: digest_previous,
        };
        let expected_current = AuditChainExpectation {
            first_sequence: 11,
            predecessor_digest: digest_previous,
            last_sequence: 11,
            final_digest: digest_current,
        };
        let evidence_previous = [RecoveryEvidence {
            checkpoints: &checkpoints_previous,
            payloads: payloads_previous,
            signed: &signed_previous,
            trusted_key: &key,
            floor: &floor_previous,
        }];
        let evidence_current = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let previous = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &receipts_previous,
            evidence: &evidence_previous,
            expected: &expected_previous,
        };
        let current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        let witness = TestWitness([expected_previous, expected_current]);
        assert_eq!(
            inspect_custodied_audit_transition(&previous, &current, Some(&witness), &verifier),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &current,
                None::<&TestWitness>,
                &verifier
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &current,
                Some(&witness),
                &RejectVerifier
            ),
            RestartInspection::Deny
        );
        let changed_payloads: &[&[u8]] = &[b"SECOND"];
        let changed_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: changed_payloads,
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let changed_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &changed_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &changed_current,
                Some(&witness),
                &verifier,
            ),
            RestartInspection::Deny
        );
        let wrong_expected = AuditChainExpectation {
            first_sequence: 12,
            ..expected_current
        };
        let wrong_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &evidence_current,
            expected: &wrong_expected,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &wrong_current,
                Some(&witness),
                &verifier
            ),
            RestartInspection::Deny
        );
    }
}
