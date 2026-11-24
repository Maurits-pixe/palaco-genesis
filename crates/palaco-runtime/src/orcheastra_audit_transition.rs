//! Joined custody and original-evidence review across consecutive audit segments.
//!
//! Both custody and signature verifier interfaces are caller-provided, and
//! therefore require independent trust validation beyond this crate.
//! ReviewOnly is never permission to recover or execute.

use crate::orcheastra_audit_chain::{AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS};
use crate::orcheastra_audit_continuity::inspect_audit_continuity;
use crate::orcheastra_audit_custody::AuditCustodyWitness;
use crate::orcheastra_audit_evidence::{
    inspect_audit_evidence, inspect_audit_evidence_budget, inspect_audit_evidence_floors,
    inspect_audit_evidence_lineage, inspect_audit_evidence_signers,
    inspect_audit_receipt_source_binding, RecoveryEvidence,
};
use crate::orcheastra_audit_receipts::inspect_bound_audit_receipts;
use crate::orcheastra_payload::{
    inspect_restart_chain_payloads, MAX_CHAIN_CHECKPOINTS, MAX_SNAPSHOT_BYTES,
};
use crate::orcheastra_restart::RestartInspection;
use crate::orcheastra_review_receipt::ReviewReceipt;
use crate::orcheastra_signed_anchor::{Ed25519Verifier, MAX_KEY_ID_BYTES};

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

/// Verifies that recovery and custody counters cannot decrease at a segment boundary.
///
/// Each segment's own integrity validation is handled separately. This gate
/// compares the final verified receipt and evidence of the preceding segment
/// with the initial receipt and evidence of the next segment. No counter may
/// decrease, and a checkpoint sequence must strictly advance. Both sides must
/// also carry nonzero, feasible floors and receipt-to-registry counters.
#[must_use]
pub fn inspect_transition_monotonicity(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
) -> RestartInspection {
    let (
        Some(previous_receipt),
        Some(current_receipt),
        Some(previous_source),
        Some(current_source),
    ) = (
        previous.receipts.last(),
        current.receipts.first(),
        previous.evidence.last(),
        current.evidence.first(),
    )
    else {
        return RestartInspection::Deny;
    };

    if previous_receipt.checkpoint_sequence == 0
        || current_receipt.checkpoint_sequence <= previous_receipt.checkpoint_sequence
        || previous_receipt.registry_sequence == 0
        || current_receipt.registry_sequence == 0
        || current_receipt.registry_sequence < previous_receipt.registry_sequence
        || previous_source.floor.checkpoint_sequence == 0
        || current_source.floor.checkpoint_sequence == 0
        || current_source.floor.checkpoint_sequence < previous_source.floor.checkpoint_sequence
        || previous_source.floor.registry_sequence == 0
        || current_source.floor.registry_sequence == 0
        || current_source.floor.registry_sequence < previous_source.floor.registry_sequence
        || previous_source.trusted_key.registry_sequence == 0
        || current_source.trusted_key.registry_sequence == 0
        || current_source.trusted_key.registry_sequence
            < previous_source.trusted_key.registry_sequence
        || previous_source.floor.checkpoint_sequence > previous_receipt.checkpoint_sequence
        || current_source.floor.checkpoint_sequence > current_receipt.checkpoint_sequence
        || previous_source.floor.registry_sequence > previous_source.trusted_key.registry_sequence
        || current_source.floor.registry_sequence > current_source.trusted_key.registry_sequence
        || previous_receipt.registry_sequence != previous_source.trusted_key.registry_sequence
        || current_receipt.registry_sequence != current_source.trusted_key.registry_sequence
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

/// Requires an exact snapshot hash-chain junction between two audit segments.
///
/// Both source chains are checked separately by the composite review function.
/// This boundary additionally rejects missing checkpoint records, skipped or
/// replayed checkpoint sequences, and an incorrect snapshot predecessor.
/// Hash consistency is not independent source authentication.
#[must_use]
pub fn inspect_transition_snapshot_link(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
) -> RestartInspection {
    let (Some(previous_source), Some(current_source)) =
        (previous.evidence.last(), current.evidence.first())
    else {
        return RestartInspection::Deny;
    };
    let (Some(previous_checkpoint), Some(current_checkpoint)) = (
        previous_source.checkpoints.last(),
        current_source.checkpoints.first(),
    ) else {
        return RestartInspection::Deny;
    };
    let Some(next_sequence) = previous_checkpoint.sequence.checked_add(1) else {
        return RestartInspection::Deny;
    };
    if previous_checkpoint.snapshot_digest == [0; 32]
        || current_checkpoint.sequence != next_sequence
        || current_checkpoint.predecessor_digest != previous_checkpoint.snapshot_digest
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

/// Requires an unchanged signer identity across two audit segments.
///
/// This deliberately denies all key rotations until a separate, independently
/// authenticated rotation policy is implemented. The key validity interval
/// must also remain identical, so expanding, shrinking or shifting a key's
/// allowed checkpoint window is denied until separately authenticated.
/// Both registry revisions must be nonzero and never regress across the
/// transition, even when this guard is called without the composite review.
/// Malformed signatures, verification flags, and anchors that do not exactly
/// match their source's last checkpoint are denied.
/// Matching caller-provided keys are only a consistency check, not proof of
/// key ownership or authenticity.
#[must_use]
pub fn inspect_transition_signer_continuity(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
) -> RestartInspection {
    let (Some(previous_source), Some(current_source)) =
        (previous.evidence.last(), current.evidence.first())
    else {
        return RestartInspection::Deny;
    };
    let (Some(previous_last), Some(current_last)) = (
        previous_source.checkpoints.last(),
        current_source.checkpoints.last(),
    ) else {
        return RestartInspection::Deny;
    };
    let previous_key = previous_source.trusted_key;
    let current_key = current_source.trusted_key;
    if previous_key.revoked
        || current_key.revoked
        || previous_key.key_id.is_empty()
        || previous_key.key_id.len() > MAX_KEY_ID_BYTES
        || previous_key.key_id != current_key.key_id
        || previous_key.public_key == [0; 32]
        || previous_key.public_key != current_key.public_key
        || previous_key.registry_sequence == 0
        || current_key.registry_sequence == 0
        || current_key.registry_sequence < previous_key.registry_sequence
        || previous_source.signed.key_id != previous_key.key_id
        || current_source.signed.key_id != current_key.key_id
        || previous_source.signed.public_key != previous_key.public_key
        || current_source.signed.public_key != current_key.public_key
        || previous_source.signed.signature == [0; 64]
        || current_source.signed.signature == [0; 64]
        || !previous_source.signed.anchor.externally_verified
        || !current_source.signed.anchor.externally_verified
        || previous_source.signed.anchor.snapshot_digest == [0; 32]
        || current_source.signed.anchor.snapshot_digest == [0; 32]
        || previous_source.signed.anchor.predecessor_digest == [0; 32]
        || current_source.signed.anchor.predecessor_digest == [0; 32]
        || previous_source.signed.anchor.sequence != previous_last.sequence
        || previous_source.signed.anchor.snapshot_digest != previous_last.snapshot_digest
        || previous_source.signed.anchor.predecessor_digest != previous_last.predecessor_digest
        || current_source.signed.anchor.sequence != current_last.sequence
        || current_source.signed.anchor.snapshot_digest != current_last.snapshot_digest
        || current_source.signed.anchor.predecessor_digest != current_last.predecessor_digest
        || previous_key.first_sequence == 0
        || previous_key.first_sequence > previous_key.last_sequence
        || previous_key.first_sequence != current_key.first_sequence
        || previous_key.last_sequence != current_key.last_sequence
        || previous_source.signed.anchor.sequence < previous_key.first_sequence
        || previous_source.signed.anchor.sequence > previous_key.last_sequence
        || current_source.signed.anchor.sequence < current_key.first_sequence
        || current_source.signed.anchor.sequence > current_key.last_sequence
    {
        return RestartInspection::Deny;
    }
    RestartInspection::ReviewOnly
}

/// Denies unannounced signer changes anywhere inside a review segment.
///
/// Each receipt must have exactly one source evidence bundle. Every bundle
/// must use the same key identity and validity window as the first, and each
/// signed anchor must be bound to that key. Registry revisions may advance,
/// but never roll back. Every anchor must match its final checkpoint exactly.
/// This is not key or signature authentication.
#[must_use]
pub fn inspect_segment_signer_consistency(segment: &AuditSegmentEvidence<'_>) -> RestartInspection {
    let Some(first) = segment.evidence.first() else {
        return RestartInspection::Deny;
    };
    if segment.evidence.len() != segment.receipts.len() {
        return RestartInspection::Deny;
    }
    let baseline = first.trusted_key;
    if baseline.key_id.is_empty()
        || baseline.key_id.len() > MAX_KEY_ID_BYTES
        || baseline.public_key == [0; 32]
        || baseline.first_sequence == 0
        || baseline.first_sequence > baseline.last_sequence
    {
        return RestartInspection::Deny;
    }

    let mut prior_registry_sequence = 0;
    for source in segment.evidence {
        let Some(last_checkpoint) = source.checkpoints.last() else {
            return RestartInspection::Deny;
        };
        let key = source.trusted_key;
        if key.revoked
            || key.key_id != baseline.key_id
            || key.public_key != baseline.public_key
            || key.first_sequence != baseline.first_sequence
            || key.last_sequence != baseline.last_sequence
            || key.registry_sequence == 0
            || key.registry_sequence < prior_registry_sequence
            || source.signed.key_id != key.key_id
            || source.signed.public_key != key.public_key
            || source.signed.signature == [0; 64]
            || !source.signed.anchor.externally_verified
            || source.signed.anchor.snapshot_digest == [0; 32]
            || source.signed.anchor.predecessor_digest == [0; 32]
            || source.signed.anchor.sequence != last_checkpoint.sequence
            || source.signed.anchor.snapshot_digest != last_checkpoint.snapshot_digest
            || source.signed.anchor.predecessor_digest != last_checkpoint.predecessor_digest
            || source.signed.anchor.sequence < key.first_sequence
            || source.signed.anchor.sequence > key.last_sequence
        {
            return RestartInspection::Deny;
        }
        prior_registry_sequence = key.registry_sequence;
    }

    RestartInspection::ReviewOnly
}

/// Enforces exact checkpoint lineage between recovery receipts in one segment.
///
/// Separate source revalidation checks the checkpoints inside each receipt.
/// This gate closes the gap between consecutive receipts: no missing bundles,
/// replay, sequence skips, or mismatching snapshot predecessor are accepted.
/// Hash consistency is not a substitute for independent authentication.
#[must_use]
pub fn inspect_segment_snapshot_continuity(
    segment: &AuditSegmentEvidence<'_>,
) -> RestartInspection {
    if segment.evidence.is_empty() || segment.evidence.len() != segment.receipts.len() {
        return RestartInspection::Deny;
    }
    let mut prior_sequence: Option<u64> = None;
    let mut prior_digest = [0; 32];
    for source in segment.evidence {
        let (Some(first), Some(last)) = (source.checkpoints.first(), source.checkpoints.last())
        else {
            return RestartInspection::Deny;
        };
        if first.sequence == 0 || last.snapshot_digest == [0; 32] {
            return RestartInspection::Deny;
        }
        if let Some(previous) = prior_sequence {
            let Some(next) = previous.checked_add(1) else {
                return RestartInspection::Deny;
            };
            if first.sequence != next || first.predecessor_digest != prior_digest {
                return RestartInspection::Deny;
            }
        }
        prior_sequence = Some(last.sequence);
        prior_digest = last.snapshot_digest;
    }
    RestartInspection::ReviewOnly
}

/// Upper bound on cumulative snapshot bytes for one two-segment review.
pub const MAX_TRANSITION_PAYLOAD_BYTES: usize = 8 * MAX_SNAPSHOT_BYTES;
/// Upper bound on cumulative checkpoints for one two-segment review.
pub const MAX_TRANSITION_CHECKPOINTS: usize = 1024;
/// Upper bound on cumulative audit links across both transition segments.
pub const MAX_TRANSITION_AUDIT_LINKS: usize = MAX_AUDIT_LINKS;

/// Rejects oversized audit evidence before signature or snapshot hashing.
///
/// Counts every occurrence, including repeated borrowed payload buffers, since
/// each occurrence would otherwise be hashed again. The combined number of
/// audit links is bounded and each link must have one receipt and source.
/// All additions are checked.
/// These are per-call limits, not global concurrency or API rate limits.
#[must_use]
pub fn inspect_transition_evidence_budget(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
) -> RestartInspection {
    let mut total_bytes = 0usize;
    let mut total_checkpoints = 0usize;
    let mut total_links = 0usize;
    for segment in [previous, current] {
        if segment.evidence.is_empty()
            || segment.evidence.len() != segment.receipts.len()
            || segment.links.len() != segment.receipts.len()
        {
            return RestartInspection::Deny;
        }
        let Some(links) = total_links.checked_add(segment.links.len()) else {
            return RestartInspection::Deny;
        };
        if links > MAX_TRANSITION_AUDIT_LINKS {
            return RestartInspection::Deny;
        }
        total_links = links;
        for source in segment.evidence {
            if source.checkpoints.is_empty()
                || source.checkpoints.len() > MAX_CHAIN_CHECKPOINTS
                || source.checkpoints.len() != source.payloads.len()
            {
                return RestartInspection::Deny;
            }
            let Some(count) = total_checkpoints.checked_add(source.checkpoints.len()) else {
                return RestartInspection::Deny;
            };
            if count > MAX_TRANSITION_CHECKPOINTS {
                return RestartInspection::Deny;
            }
            total_checkpoints = count;
            for payload in source.payloads {
                if payload.len() > MAX_SNAPSHOT_BYTES {
                    return RestartInspection::Deny;
                }
                let Some(bytes) = total_bytes.checked_add(payload.len()) else {
                    return RestartInspection::Deny;
                };
                if bytes > MAX_TRANSITION_PAYLOAD_BYTES {
                    return RestartInspection::Deny;
                }
                total_bytes = bytes;
            }
        }
    }
    RestartInspection::ReviewOnly
}

/// Recomputes both segments' snapshot chains before external verifier calls.
///
/// The aggregate budget must be checked before this function to bound hashing
/// across the two segments. Each original checkpoint and payload is checked
/// against its supplied signed anchor; these anchors still need authentic
/// signatures and independently trusted custody.
#[must_use]
pub fn inspect_transition_payload_integrity(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
) -> RestartInspection {
    if inspect_transition_evidence_budget(previous, current) != RestartInspection::ReviewOnly {
        return RestartInspection::Deny;
    }
    for segment in [previous, current] {
        for source in segment.evidence {
            if inspect_restart_chain_payloads(
                source.checkpoints,
                source.payloads,
                Some(&source.signed.anchor),
            ) != RestartInspection::ReviewOnly
            {
                return RestartInspection::Deny;
            }
        }
    }
    RestartInspection::ReviewOnly
}

/// Requires consecutive witnessed segments and complete recovery evidence.
///
/// Checks both source-evidence batches as well as the exact transition between
/// independently witnessed audit endpoints. Every rejection remains Deny.
/// Complete bounded snapshot integrity on both sides precedes any external
/// signature-verifier calls; full source revalidation then precedes custody.
/// No external custody implementation or Ed25519 algorithm is provided here.
#[must_use]
pub fn inspect_custodied_audit_transition(
    previous: &AuditSegmentEvidence<'_>,
    current: &AuditSegmentEvidence<'_>,
    witness: Option<&impl AuditCustodyWitness>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    // Deterministic source preflight must precede external custody callbacks.
    if inspect_audit_evidence_budget(previous.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_budget(current.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_lineage(previous.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_lineage(current.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_signers(previous.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_signers(current.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_floors(previous.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_floors(current.evidence) != RestartInspection::ReviewOnly
        || inspect_audit_receipt_source_binding(previous.receipts, previous.evidence)
            != RestartInspection::ReviewOnly
        || inspect_audit_receipt_source_binding(current.receipts, current.evidence)
            != RestartInspection::ReviewOnly
        || inspect_bound_audit_receipts(previous.links, previous.receipts, Some(previous.expected))
            != RestartInspection::ReviewOnly
        || inspect_bound_audit_receipts(current.links, current.receipts, Some(current.expected))
            != RestartInspection::ReviewOnly
        || inspect_transition_evidence_budget(previous, current) != RestartInspection::ReviewOnly
        || inspect_segment_snapshot_continuity(previous) != RestartInspection::ReviewOnly
        || inspect_segment_snapshot_continuity(current) != RestartInspection::ReviewOnly
        || inspect_segment_signer_consistency(previous) != RestartInspection::ReviewOnly
        || inspect_segment_signer_consistency(current) != RestartInspection::ReviewOnly
        || inspect_transition_monotonicity(previous, current) != RestartInspection::ReviewOnly
        || inspect_transition_snapshot_link(previous, current) != RestartInspection::ReviewOnly
        || inspect_transition_signer_continuity(previous, current) != RestartInspection::ReviewOnly
        || inspect_transition_payload_integrity(previous, current) != RestartInspection::ReviewOnly
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
        || inspect_audit_continuity(
            previous.links,
            Some(previous.expected),
            current.links,
            Some(current.expected),
            witness,
        ) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_custodied_audit_transition, inspect_segment_signer_consistency,
        inspect_segment_snapshot_continuity, inspect_transition_evidence_budget,
        inspect_transition_monotonicity, inspect_transition_payload_integrity,
        inspect_transition_signer_continuity, inspect_transition_snapshot_link,
        AuditSegmentEvidence,
    };
    use crate::orcheastra_audit_chain::{
        audit_link_digest, AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS,
    };
    use crate::orcheastra_audit_custody::{AuditCustodyWitness, CustodyVerdict};
    use crate::orcheastra_audit_evidence::RecoveryEvidence;
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_recovery::RecoveryFloor;
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint, RestartInspection};
    use crate::orcheastra_review_receipt::{review_receipt, ReviewReceipt};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor, TrustedKey,
        MAX_KEY_ID_BYTES,
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

    struct CountingWitness(std::cell::Cell<usize>);
    impl AuditCustodyWitness for CountingWitness {
        fn verify_expectation(&self, _expected: &AuditChainExpectation) -> CustodyVerdict {
            self.0.set(self.0.get() + 1);
            CustodyVerdict::Verified
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

    struct CountingVerifier(std::cell::Cell<usize>);
    impl Ed25519Verifier for CountingVerifier {
        fn verify(
            &self,
            _key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> SignatureVerdict {
            self.0.set(self.0.get() + 1);
            SignatureVerdict::Valid
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
        assert_eq!(
            inspect_transition_monotonicity(&previous, &current),
            RestartInspection::ReviewOnly
        );
        let mut rollback_receipt = receipts_current;
        rollback_receipt[0].checkpoint_sequence = receipts_previous[0].checkpoint_sequence;
        let rollback_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &rollback_receipt,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &rollback_current),
            RestartInspection::Deny
        );
        let mut rollback_registry_receipt = receipts_current;
        rollback_registry_receipt[0].registry_sequence = 2;
        let rollback_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &rollback_registry_receipt,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &rollback_current),
            RestartInspection::Deny
        );
        let rollback_floor = RecoveryFloor {
            checkpoint_sequence: 6,
            registry_sequence: 2,
        };
        let rollback_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &rollback_floor,
        }];
        let rollback_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &rollback_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &rollback_current),
            RestartInspection::Deny
        );
        let rollback_key = TrustedKey {
            key_id: key.key_id,
            public_key: key.public_key,
            registry_sequence: 2,
            first_sequence: key.first_sequence,
            last_sequence: key.last_sequence,
            revoked: key.revoked,
        };
        let rollback_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &rollback_key,
            floor: &floor_current,
        }];
        let rollback_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &rollback_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &rollback_current),
            RestartInspection::Deny
        );
        let empty_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &[],
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &empty_current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_snapshot_link(&previous, &current),
            RestartInspection::ReviewOnly
        );
        let mut gap_checkpoints = checkpoints_current;
        gap_checkpoints[0].sequence = 9;
        let gap_evidence = [RecoveryEvidence {
            checkpoints: &gap_checkpoints,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let gap_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &gap_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_snapshot_link(&previous, &gap_current),
            RestartInspection::Deny
        );
        let mut wrong_predecessor = checkpoints_current;
        wrong_predecessor[0].predecessor_digest[0] ^= 1;
        let wrong_evidence = [RecoveryEvidence {
            checkpoints: &wrong_predecessor,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let wrong_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &wrong_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_snapshot_link(&previous, &wrong_current),
            RestartInspection::Deny
        );
        let empty_source = [RecoveryEvidence {
            checkpoints: &[],
            payloads: &[],
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let missing_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &empty_source,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_snapshot_link(&previous, &missing_current),
            RestartInspection::Deny
        );
        let missing_source = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &[],
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_snapshot_link(&previous, &missing_source),
            RestartInspection::Deny
        );
        let mut replay_checkpoint = checkpoints_current;
        replay_checkpoint[0].sequence = 7;
        let replay_evidence = [RecoveryEvidence {
            checkpoints: &replay_checkpoint,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let replay_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &replay_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_snapshot_link(&previous, &replay_current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &current),
            RestartInspection::ReviewOnly
        );
        let different_key_id = TrustedKey {
            key_id: "different-key",
            public_key: key.public_key,
            registry_sequence: key.registry_sequence,
            first_sequence: key.first_sequence,
            last_sequence: key.last_sequence,
            revoked: false,
        };
        let different_identity = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &different_key_id,
            floor: &floor_current,
        }];
        let rotated_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &different_identity,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &rotated_current),
            RestartInspection::Deny
        );
        let different_public_key = TrustedKey {
            key_id: key.key_id,
            public_key: [7; 32],
            registry_sequence: key.registry_sequence,
            first_sequence: key.first_sequence,
            last_sequence: key.last_sequence,
            revoked: false,
        };
        let different_identity = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &different_public_key,
            floor: &floor_current,
        }];
        let rotated_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &different_identity,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &rotated_current),
            RestartInspection::Deny
        );
        let revoked_key = TrustedKey {
            key_id: key.key_id,
            public_key: key.public_key,
            registry_sequence: key.registry_sequence,
            first_sequence: key.first_sequence,
            last_sequence: key.last_sequence,
            revoked: true,
        };
        let revoked_identity = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &revoked_key,
            floor: &floor_current,
        }];
        let revoked_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &revoked_identity,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &revoked_current),
            RestartInspection::Deny
        );
        let expanded_key = TrustedKey {
            key_id: key.key_id,
            public_key: key.public_key,
            registry_sequence: key.registry_sequence,
            first_sequence: key.first_sequence,
            last_sequence: 9,
            revoked: false,
        };
        let expanded_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &expanded_key,
            floor: &floor_current,
        }];
        let expanded_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &expanded_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &expanded_current),
            RestartInspection::Deny
        );
        let shifted_key = TrustedKey {
            key_id: key.key_id,
            public_key: key.public_key,
            registry_sequence: key.registry_sequence,
            first_sequence: 8,
            last_sequence: key.last_sequence,
            revoked: false,
        };
        let shifted_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &shifted_key,
            floor: &floor_current,
        }];
        let shifted_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &shifted_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &shifted_current),
            RestartInspection::Deny
        );
        let expired_key = TrustedKey {
            key_id: key.key_id,
            public_key: key.public_key,
            registry_sequence: key.registry_sequence,
            first_sequence: key.first_sequence,
            last_sequence: 7,
            revoked: false,
        };
        let expired_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &expired_key,
            floor: &floor_current,
        }];
        let expired_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &expired_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &expired_current),
            RestartInspection::Deny
        );
        let missing_identity = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &[],
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &missing_identity),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_segment_signer_consistency(&previous),
            RestartInspection::ReviewOnly
        );
        let repeated_evidence = [
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
        ];
        let repeated_receipts = [receipts_previous[0], receipts_previous[0]];
        let repeated_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &repeated_receipts,
            evidence: &repeated_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&repeated_segment),
            RestartInspection::ReviewOnly
        );
        let changed_middle_key = TrustedKey {
            key_id: "unannounced-key",
            public_key: key.public_key,
            registry_sequence: key.registry_sequence,
            first_sequence: key.first_sequence,
            last_sequence: key.last_sequence,
            revoked: false,
        };
        let changed_evidence = [
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &changed_middle_key,
                floor: &floor_previous,
            },
        ];
        let changed_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &repeated_receipts,
            evidence: &changed_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&changed_segment),
            RestartInspection::Deny
        );
        let missing_receipt_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &receipts_previous,
            evidence: &repeated_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&missing_receipt_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_segment_snapshot_continuity(&previous),
            RestartInspection::ReviewOnly
        );
        let linked_evidence = [
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
            RecoveryEvidence {
                checkpoints: &checkpoints_current,
                payloads: payloads_current,
                signed: &signed_current,
                trusted_key: &key,
                floor: &floor_current,
            },
        ];
        let linked_receipts = [receipts_previous[0], receipts_current[0]];
        let linked_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &linked_receipts,
            evidence: &linked_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_snapshot_continuity(&linked_segment),
            RestartInspection::ReviewOnly
        );
        let duplicate_evidence = [
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
        ];
        let duplicate_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &linked_receipts,
            evidence: &duplicate_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_snapshot_continuity(&duplicate_segment),
            RestartInspection::Deny
        );
        let mut gap_checkpoint = checkpoints_current;
        gap_checkpoint[0].sequence = 9;
        let gap_evidence = [
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
            RecoveryEvidence {
                checkpoints: &gap_checkpoint,
                payloads: payloads_current,
                signed: &signed_current,
                trusted_key: &key,
                floor: &floor_current,
            },
        ];
        let gap_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &linked_receipts,
            evidence: &gap_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_snapshot_continuity(&gap_segment),
            RestartInspection::Deny
        );
        let mut changed_predecessor = checkpoints_current;
        changed_predecessor[0].predecessor_digest[0] ^= 1;
        let changed_evidence = [
            RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            },
            RecoveryEvidence {
                checkpoints: &changed_predecessor,
                payloads: payloads_current,
                signed: &signed_current,
                trusted_key: &key,
                floor: &floor_current,
            },
        ];
        let changed_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &linked_receipts,
            evidence: &changed_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_snapshot_continuity(&changed_segment),
            RestartInspection::Deny
        );
        let missing_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &linked_receipts,
            evidence: &evidence_previous,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_snapshot_continuity(&missing_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_evidence_budget(&previous, &current),
            RestartInspection::ReviewOnly
        );
        let max_payload = vec![0u8; 1_048_576];
        let large_payloads: &[&[u8]] = &[max_payload.as_slice()];
        let large_evidence: Vec<RecoveryEvidence<'_>> = (0..9)
            .map(|_| RecoveryEvidence {
                checkpoints: &checkpoints_current,
                payloads: large_payloads,
                signed: &signed_current,
                trusted_key: &key,
                floor: &floor_current,
            })
            .collect();
        let large_receipts = vec![receipts_current[0]; 9];
        let oversized_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &large_receipts,
            evidence: &large_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_evidence_budget(&previous, &oversized_current),
            RestartInspection::Deny
        );
        let excessive_checkpoints = vec![checkpoints_current[0]; 256];
        let tiny_payloads: Vec<&[u8]> = vec![b"second".as_slice(); 256];
        let excess_evidence: Vec<RecoveryEvidence<'_>> = (0..5)
            .map(|_| RecoveryEvidence {
                checkpoints: &excessive_checkpoints,
                payloads: &tiny_payloads,
                signed: &signed_current,
                trusted_key: &key,
                floor: &floor_current,
            })
            .collect();
        let excess_receipts = vec![receipts_current[0]; 5];
        let excessive_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &excess_receipts,
            evidence: &excess_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_evidence_budget(&previous, &excessive_current),
            RestartInspection::Deny
        );
        // A combined two-segment review must never exceed the audit-link budget.
        let oversized_links = vec![links_previous[0]; MAX_AUDIT_LINKS];
        let oversized_receipts = vec![receipts_previous[0]; MAX_AUDIT_LINKS];
        let oversized_sources: Vec<RecoveryEvidence<'_>> = (0..MAX_AUDIT_LINKS)
            .map(|_| RecoveryEvidence {
                checkpoints: &checkpoints_previous,
                payloads: payloads_previous,
                signed: &signed_previous,
                trusted_key: &key,
                floor: &floor_previous,
            })
            .collect();
        let oversized_previous = AuditSegmentEvidence {
            links: &oversized_links,
            receipts: &oversized_receipts,
            evidence: &oversized_sources,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_transition_evidence_budget(&oversized_previous, &current),
            RestartInspection::Deny
        );
        let mismatched_links = AuditSegmentEvidence {
            links: &[],
            receipts: &receipts_previous,
            evidence: &evidence_previous,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_transition_evidence_budget(&mismatched_links, &current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_evidence_budget(&previous, &current),
            RestartInspection::ReviewOnly
        );
        let missing_payloads = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: &[],
            signed: &signed_current,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let mismatched_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &missing_payloads,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_evidence_budget(&previous, &mismatched_current),
            RestartInspection::Deny
        );
        let never_called = CountingWitness(std::cell::Cell::new(0));
        let invalid_floor = RecoveryFloor {
            checkpoint_sequence: 0,
            registry_sequence: 3,
        };
        let invalid_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &invalid_floor,
        }];
        let invalid_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &invalid_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &invalid_current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        let invalid_prior_floor = RecoveryFloor {
            checkpoint_sequence: 0,
            registry_sequence: 3,
        };
        let invalid_previous_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_previous,
            payloads: payloads_previous,
            signed: &signed_previous,
            trusted_key: &key,
            floor: &invalid_prior_floor,
        }];
        let invalid_previous = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &receipts_previous,
            evidence: &invalid_previous_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &invalid_previous,
                &current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        // Corrupted receipt linkage must reject before invoking custody.
        let bad_receipt = [ReviewReceipt {
            digest: [0; 32],
            ..receipts_current[0]
        }];
        let bad_receipt_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &bad_receipt,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &bad_receipt_segment,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        let bad_links = [AuditLink {
            receipt_digest: [1; 32],
            ..links_previous[0]
        }];
        let bad_link_segment = AuditSegmentEvidence {
            links: &bad_links,
            receipts: &receipts_previous,
            evidence: &evidence_previous,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &bad_link_segment,
                &current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        let wrong_source_count = [ReviewReceipt {
            checkpoint_count: 2,
            ..receipts_current[0]
        }];
        let mismatched_count_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &wrong_source_count,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &mismatched_count_current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        let wrong_source_registry = [ReviewReceipt {
            registry_sequence: receipts_previous[0].registry_sequence + 1,
            ..receipts_previous[0]
        }];
        let mismatched_registry_previous = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &wrong_source_registry,
            evidence: &evidence_previous,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &mismatched_registry_previous,
                &current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        // Direct signer entrypoints also fail closed on malformed anchors.
        let zero_signature = SignedAnchor {
            signature: [0; 64],
            ..signed_current.clone()
        };
        let zero_signature_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &zero_signature,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let malformed_current = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &zero_signature_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&malformed_current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &malformed_current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &malformed_current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);

        let invalid_anchor = SignedAnchor {
            anchor: RestartAnchor {
                externally_verified: false,
                ..signed_previous.anchor
            },
            ..signed_previous.clone()
        };
        let invalid_anchor_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_previous,
            payloads: payloads_previous,
            signed: &invalid_anchor,
            trusted_key: &key,
            floor: &floor_previous,
        }];
        let malformed_previous = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &receipts_previous,
            evidence: &invalid_anchor_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&malformed_previous),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&malformed_previous, &current),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);

        let long_key_id = "x".repeat(MAX_KEY_ID_BYTES + 1);
        let oversized_key = TrustedKey {
            key_id: &long_key_id,
            ..key.clone()
        };
        let oversized_signed = SignedAnchor {
            key_id: &long_key_id,
            ..signed_current.clone()
        };
        let oversized_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &oversized_signed,
            trusted_key: &oversized_key,
            floor: &floor_current,
        }];
        let oversized_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &oversized_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&oversized_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &oversized_segment),
            RestartInspection::Deny
        );
        // Independently callable signer checks must bind anchors to the final
        // source checkpoint even before full payload or signature validation.
        let wrong_current_anchor = SignedAnchor {
            anchor: RestartAnchor {
                sequence: 7,
                ..signed_current.anchor
            },
            ..signed_current.clone()
        };
        let wrong_current_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &wrong_current_anchor,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let wrong_current_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &wrong_current_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&wrong_current_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &wrong_current_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &wrong_current_segment,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);

        let wrong_previous_anchor = SignedAnchor {
            anchor: RestartAnchor {
                predecessor_digest: [3; 32],
                ..signed_previous.anchor
            },
            ..signed_previous.clone()
        };
        let wrong_previous_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_previous,
            payloads: payloads_previous,
            signed: &wrong_previous_anchor,
            trusted_key: &key,
            floor: &floor_previous,
        }];
        let wrong_previous_segment = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &receipts_previous,
            evidence: &wrong_previous_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&wrong_previous_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&wrong_previous_segment, &current),
            RestartInspection::Deny
        );
        let wrong_snapshot_anchor = SignedAnchor {
            anchor: RestartAnchor {
                snapshot_digest: [3; 32],
                ..signed_current.anchor
            },
            ..signed_current.clone()
        };
        let wrong_snapshot_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &wrong_snapshot_anchor,
            trusted_key: &key,
            floor: &floor_current,
        }];
        let wrong_snapshot_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &wrong_snapshot_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&wrong_snapshot_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &wrong_snapshot_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_segment_signer_consistency(&current),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &current),
            RestartInspection::ReviewOnly
        );
        // Standalone signer continuity must reject zero and decreasing key
        // revisions without relying on a separate monotonicity review.
        let zero_registry_key = TrustedKey {
            registry_sequence: 0,
            ..key.clone()
        };
        let zero_registry_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &zero_registry_key,
            floor: &floor_current,
        }];
        let zero_registry_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &zero_registry_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &zero_registry_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_segment_signer_consistency(&zero_registry_segment),
            RestartInspection::Deny
        );
        let older_registry_key = TrustedKey {
            registry_sequence: 2,
            ..key.clone()
        };
        let older_registry_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &older_registry_key,
            floor: &floor_current,
        }];
        let older_registry_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &older_registry_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_segment_signer_consistency(&older_registry_segment),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &older_registry_segment),
            RestartInspection::Deny
        );
        let newer_registry_key = TrustedKey {
            registry_sequence: 4,
            ..key.clone()
        };
        let newer_registry_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &newer_registry_key,
            floor: &floor_current,
        }];
        let newer_registry_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &newer_registry_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &newer_registry_segment),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_transition_signer_continuity(&previous, &current),
            RestartInspection::ReviewOnly
        );
        // Direct monotonicity review must reject impossible or zero counters.
        let missing_current_registry = [ReviewReceipt {
            registry_sequence: 0,
            ..receipts_current[0]
        }];
        let missing_registry_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &missing_current_registry,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &missing_registry_segment),
            RestartInspection::Deny
        );
        let impossible_current_floor = RecoveryFloor {
            checkpoint_sequence: 9,
            registry_sequence: 3,
        };
        let impossible_floor_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &impossible_current_floor,
        }];
        let impossible_floor_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &impossible_floor_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &impossible_floor_segment),
            RestartInspection::Deny
        );
        let future_registry_floor = RecoveryFloor {
            checkpoint_sequence: 8,
            registry_sequence: 4,
        };
        let future_registry_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_current,
            payloads: payloads_current,
            signed: &signed_current,
            trusted_key: &key,
            floor: &future_registry_floor,
        }];
        let future_registry_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &receipts_current,
            evidence: &future_registry_evidence,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &future_registry_segment),
            RestartInspection::Deny
        );
        let inconsistent_receipt = [ReviewReceipt {
            registry_sequence: 4,
            ..receipts_current[0]
        }];
        let inconsistent_registry_segment = AuditSegmentEvidence {
            links: &links_current,
            receipts: &inconsistent_receipt,
            evidence: &evidence_current,
            expected: &expected_current,
        };
        assert_eq!(
            inspect_transition_monotonicity(&previous, &inconsistent_registry_segment),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_transition_monotonicity(&previous, &current),
            RestartInspection::ReviewOnly
        );
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
        // Complete receipt and payload revalidation precedes external custody.
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &changed_current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        let changed_prior_payloads: &[&[u8]] = &[b"FIRST"];
        let changed_prior_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints_previous,
            payloads: changed_prior_payloads,
            signed: &signed_previous,
            trusted_key: &key,
            floor: &floor_previous,
        }];
        let changed_prior = AuditSegmentEvidence {
            links: &links_previous,
            receipts: &receipts_previous,
            evidence: &changed_prior_evidence,
            expected: &expected_previous,
        };
        assert_eq!(
            inspect_custodied_audit_transition(
                &changed_prior,
                &current,
                Some(&never_called),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &current,
                Some(&never_called),
                &RejectVerifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(never_called.0.get(), 0);
        // The second segment's corrupted bytes must be rejected before any
        // verifier call on the otherwise valid first segment.
        let verifier_counter = CountingVerifier(std::cell::Cell::new(0));
        assert_eq!(
            inspect_transition_payload_integrity(&previous, &changed_current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &changed_current,
                Some(&never_called),
                &verifier_counter,
            ),
            RestartInspection::Deny
        );
        assert_eq!(verifier_counter.0.get(), 0);
        assert_eq!(never_called.0.get(), 0);
        assert_eq!(
            inspect_transition_payload_integrity(&changed_prior, &current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &changed_prior,
                &current,
                Some(&never_called),
                &verifier_counter,
            ),
            RestartInspection::Deny
        );
        assert_eq!(verifier_counter.0.get(), 0);
        assert_eq!(
            inspect_transition_payload_integrity(&previous, &current),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_custodied_audit_transition(
                &previous,
                &current,
                Some(&never_called),
                &verifier_counter,
            ),
            RestartInspection::ReviewOnly
        );
        assert_eq!(verifier_counter.0.get(), 2);
        assert_eq!(never_called.0.get(), 2);
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
