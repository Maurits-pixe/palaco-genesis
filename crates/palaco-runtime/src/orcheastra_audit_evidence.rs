//! Fail-closed review of audit links against original recovery evidence.
//!
//! A successful consistency check is NOT a cryptographic attestation, does not
//! authenticate an externally supplied custody root, and cannot authorize work.

use crate::orcheastra_audit_chain::{AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS};
use crate::orcheastra_audit_custody::{inspect_custodied_audit_chain, AuditCustodyWitness};
use crate::orcheastra_audit_receipts::inspect_bound_audit_receipts;
use crate::orcheastra_payload::{
    inspect_restart_chain_payloads, MAX_CHAIN_CHECKPOINTS, MAX_SNAPSHOT_BYTES,
};
use crate::orcheastra_recovery::RecoveryFloor;
use crate::orcheastra_restart::{RestartCheckpoint, RestartInspection};
use crate::orcheastra_review_receipt::{revalidate_review_receipt, ReviewReceipt};
use crate::orcheastra_signed_anchor::{
    Ed25519Verifier, SignedAnchor, TrustedKey, MAX_KEY_ID_BYTES,
};

/// Borrowed original evidence used for one audit receipt revalidation.
///
/// The caller supplies every field. This structure does not establish
/// independent trust in the verifier, key registry or custody floor.
pub struct RecoveryEvidence<'a> {
    /// Committed checkpoint sequence and recorded digests.
    pub checkpoints: &'a [RestartCheckpoint],
    /// Exact original snapshot payloads.
    pub payloads: &'a [&'a [u8]],
    /// Proposed signed recovery anchor.
    pub signed: &'a SignedAnchor<'a>,
    /// Independently expected key record (not authenticated here).
    pub trusted_key: &'a TrustedKey<'a>,
    /// Minimum checkpoint and registry revision (not authenticated here).
    pub floor: &'a RecoveryFloor,
}

/// Maximum cumulative snapshot bytes in a single audit-evidence inspection.
pub const MAX_AUDIT_EVIDENCE_BYTES: usize = 8 * MAX_SNAPSHOT_BYTES;
/// Maximum cumulative checkpoints in a single audit-evidence inspection.
pub const MAX_AUDIT_EVIDENCE_CHECKPOINTS: usize = 1024;

/// Preflight check for cumulative work before digest or signature verification.
///
/// Every payload occurrence is counted, including repeated borrowed buffers.
/// Limits are per inspection, not a concurrency or network admission control.
/// Does not authenticate the evidence.
#[must_use]
pub fn inspect_audit_evidence_budget(evidence: &[RecoveryEvidence<'_>]) -> RestartInspection {
    if evidence.is_empty() || evidence.len() > MAX_AUDIT_LINKS {
        return RestartInspection::Deny;
    }
    let mut total_bytes = 0usize;
    let mut total_checkpoints = 0usize;
    for source in evidence {
        if source.checkpoints.is_empty()
            || source.checkpoints.len() > MAX_CHAIN_CHECKPOINTS
            || source.checkpoints.len() != source.payloads.len()
        {
            return RestartInspection::Deny;
        }
        let Some(count) = total_checkpoints.checked_add(source.checkpoints.len()) else {
            return RestartInspection::Deny;
        };
        if count > MAX_AUDIT_EVIDENCE_CHECKPOINTS {
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
            if bytes > MAX_AUDIT_EVIDENCE_BYTES {
                return RestartInspection::Deny;
            }
            total_bytes = bytes;
        }
    }
    RestartInspection::ReviewOnly
}

/// Requires contiguous original snapshot lineage across audit receipts.
///
/// Each individual receipt is revalidated by the caller. This additional
/// boundary prevents adjacent, individually valid evidence bundles from
/// representing disconnected, overlapping or replayed checkpoint chains.
/// A matching hash is only consistency, not authenticated provenance.
#[must_use]
pub fn inspect_audit_evidence_lineage(evidence: &[RecoveryEvidence<'_>]) -> RestartInspection {
    if evidence.is_empty() || evidence.len() > MAX_AUDIT_LINKS {
        return RestartInspection::Deny;
    }
    for source in evidence {
        if source.checkpoints.is_empty() {
            return RestartInspection::Deny;
        }
    }
    for pair in evidence.windows(2) {
        let (Some(previous), Some(current)) =
            (pair[0].checkpoints.last(), pair[1].checkpoints.first())
        else {
            return RestartInspection::Deny;
        };
        let Some(next) = previous.sequence.checked_add(1) else {
            return RestartInspection::Deny;
        };
        if previous.snapshot_digest == [0; 32]
            || current.sequence != next
            || current.predecessor_digest != previous.snapshot_digest
        {
            return RestartInspection::Deny;
        }
    }
    RestartInspection::ReviewOnly
}

/// Requires one stable signer identity and validity window per audit batch.
///
/// Every original evidence bundle must reference the same key ID, public key,
/// and authorized checkpoint interval. Key registry revisions may increase
/// but cannot decrease; changes to key identity or validity window are denied
/// pending an independently authenticated rotation policy. Structurally
/// invalid signatures, unverified anchors, or an anchor not matching the
/// source's final checkpoint are denied before receipt hashing. This is not proof of key provenance or genuine signatures.
#[must_use]
pub fn inspect_audit_evidence_signers(evidence: &[RecoveryEvidence<'_>]) -> RestartInspection {
    let Some(first) = evidence.first() else {
        return RestartInspection::Deny;
    };
    if evidence.len() > MAX_AUDIT_LINKS {
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
    let mut last_registry = 0;
    for source in evidence {
        let key = source.trusted_key;
        let Some(last_checkpoint) = source.checkpoints.last() else {
            return RestartInspection::Deny;
        };
        if key.revoked
            || key.key_id != baseline.key_id
            || key.public_key != baseline.public_key
            || key.first_sequence != baseline.first_sequence
            || key.last_sequence != baseline.last_sequence
            || key.registry_sequence == 0
            || key.registry_sequence < last_registry
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
        last_registry = key.registry_sequence;
    }
    RestartInspection::ReviewOnly
}

/// Enforces monotonic recovery floors throughout an audit evidence batch.
///
/// The caller-supplied minimum checkpoint and key-registry revisions cannot
/// decrease between successive evidence bundles. Each floor must be nonzero
/// and cannot exceed the bundle's final checkpoint or key registry revision.
/// This is a consistency check, not a trusted external anti-rollback store.
#[must_use]
pub fn inspect_audit_evidence_floors(evidence: &[RecoveryEvidence<'_>]) -> RestartInspection {
    if evidence.is_empty() || evidence.len() > MAX_AUDIT_LINKS {
        return RestartInspection::Deny;
    }
    let mut last_checkpoint_floor = 0;
    let mut last_registry_floor = 0;
    for source in evidence {
        let Some(last_checkpoint) = source.checkpoints.last() else {
            return RestartInspection::Deny;
        };
        let floor = source.floor;
        if floor.checkpoint_sequence == 0
            || floor.registry_sequence == 0
            || floor.checkpoint_sequence < last_checkpoint_floor
            || floor.registry_sequence < last_registry_floor
            || floor.checkpoint_sequence > last_checkpoint.sequence
            || floor.registry_sequence > source.trusted_key.registry_sequence
        {
            return RestartInspection::Deny;
        }
        last_checkpoint_floor = floor.checkpoint_sequence;
        last_registry_floor = floor.registry_sequence;
    }
    RestartInspection::ReviewOnly
}

/// Checks receipt metadata against the exact original source bundle.
///
/// Rejects untrusted receipt counts or counters that do not match the
/// checkpoint sequence, signed anchor and key registry. This cheap preflight
/// does not recompute receipt digests, verify signatures or establish custody.
#[must_use]
pub fn inspect_audit_receipt_source_binding(
    receipts: &[ReviewReceipt],
    evidence: &[RecoveryEvidence<'_>],
) -> RestartInspection {
    if evidence.is_empty() || evidence.len() > MAX_AUDIT_LINKS || evidence.len() != receipts.len() {
        return RestartInspection::Deny;
    }
    for (receipt, source) in receipts.iter().zip(evidence.iter()) {
        let Some(last) = source.checkpoints.last() else {
            return RestartInspection::Deny;
        };
        if receipt.checkpoint_count != source.checkpoints.len()
            || receipt.checkpoint_sequence != last.sequence
            || receipt.checkpoint_sequence != source.signed.anchor.sequence
            || receipt.registry_sequence != source.trusted_key.registry_sequence
        {
            return RestartInspection::Deny;
        }
    }
    RestartInspection::ReviewOnly
}

/// Recomputes all original snapshot chains before any signature callback.
///
/// Applies the combined evidence work budget first. This local integrity pass
/// cannot authenticate signed anchors or custody and never grants authority.
#[must_use]
pub fn inspect_audit_evidence_payload_integrity(
    evidence: &[RecoveryEvidence<'_>],
) -> RestartInspection {
    if inspect_audit_evidence_budget(evidence) != RestartInspection::ReviewOnly {
        return RestartInspection::Deny;
    }
    for source in evidence {
        if inspect_restart_chain_payloads(
            source.checkpoints,
            source.payloads,
            Some(&source.signed.anchor),
        ) != RestartInspection::ReviewOnly
        {
            return RestartInspection::Deny;
        }
    }
    RestartInspection::ReviewOnly
}

/// Reviews audit-chain linkage and recomputes every corresponding receipt.
///
/// Denies empty/mismatched evidence batches and any receipt that cannot be
/// independently recomputed from its supplied snapshot bytes and context.
/// Every snapshot chain is checked before the first signature-verifier call.
/// The verifier must be genuine and trusted before ReviewOnly has any evidential
/// value. This method has no execution or signing side effects.
#[must_use]
pub fn inspect_audit_evidence(
    links: &[AuditLink],
    receipts: &[ReviewReceipt],
    evidence: &[RecoveryEvidence<'_>],
    expected: Option<&AuditChainExpectation>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    if evidence.is_empty()
        || evidence.len() > MAX_AUDIT_LINKS
        || evidence.len() != receipts.len()
        || inspect_audit_evidence_budget(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_lineage(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_signers(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_floors(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_receipt_source_binding(receipts, evidence) != RestartInspection::ReviewOnly
        || inspect_bound_audit_receipts(links, receipts, expected) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_payload_integrity(evidence) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    for (receipt, source) in receipts.iter().zip(evidence.iter()) {
        if revalidate_review_receipt(
            Some(receipt),
            source.checkpoints,
            source.payloads,
            Some(source.signed),
            Some(source.trusted_key),
            Some(source.floor),
            verifier,
        ) != RestartInspection::ReviewOnly
        {
            return RestartInspection::Deny;
        }
    }

    RestartInspection::ReviewOnly
}

/// Composes independently witnessed audit endpoints with complete source review.
///
/// Rejects missing/denying custody evidence even if the caller supplied a
/// perfectly self-consistent audit chain and recovery receipts. The witness
/// implementation and signature verifier must still be independently trusted;
/// All original evidence is fully revalidated before invoking the custody
/// witness. This function grants no authority and performs no writes.
#[must_use]
pub fn inspect_custodied_audit_evidence(
    links: &[AuditLink],
    receipts: &[ReviewReceipt],
    evidence: &[RecoveryEvidence<'_>],
    expected: Option<&AuditChainExpectation>,
    witness: Option<&impl AuditCustodyWitness>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    // Preflight untrusted input before invoking an external custody witness.
    if evidence.len() != receipts.len()
        || inspect_audit_evidence_budget(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_lineage(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_signers(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence_floors(evidence) != RestartInspection::ReviewOnly
        || inspect_audit_evidence(links, receipts, evidence, expected, verifier)
            != RestartInspection::ReviewOnly
        || inspect_custodied_audit_chain(links, expected, witness) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }
    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_audit_evidence, inspect_audit_evidence_budget, inspect_audit_evidence_floors,
        inspect_audit_evidence_lineage, inspect_audit_evidence_payload_integrity,
        inspect_audit_evidence_signers,
        inspect_audit_receipt_source_binding, inspect_custodied_audit_evidence, RecoveryEvidence,
    };
    use crate::orcheastra_audit_chain::{audit_link_digest, AuditChainExpectation, AuditLink};
    use crate::orcheastra_audit_custody::{AuditCustodyWitness, CustodyVerdict};
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_recovery::RecoveryFloor;
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint, RestartInspection};
    use crate::orcheastra_review_receipt::{review_receipt, ReviewReceipt};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor, TrustedKey,
    };

    // Test-only exact-byte comparison. This is NOT Ed25519 validation.
    struct ByteMatcher(Vec<u8>);
    impl Ed25519Verifier for ByteMatcher {
        fn verify(
            &self,
            _public_key: &[u8; 32],
            message: &[u8],
            _signature: &[u8; 64],
        ) -> SignatureVerdict {
            if message == self.0 {
                SignatureVerdict::Valid
            } else {
                SignatureVerdict::Invalid
            }
        }
    }

    // Counts external signature callbacks; accepts inputs for test wiring only.
    struct CountingVerifier(std::cell::Cell<usize>);
    impl Ed25519Verifier for CountingVerifier {
        fn verify(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> SignatureVerdict {
            self.0.set(self.0.get() + 1);
            SignatureVerdict::Valid
        }
    }

    struct RejectAll;
    impl Ed25519Verifier for RejectAll {
        fn verify(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> SignatureVerdict {
            SignatureVerdict::Invalid
        }
    }

    // Test-only witness: byte equality is NOT independent custody.
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

    // Tracks external callbacks without using panic or shared locks.
    struct CountingCustody(std::cell::Cell<usize>);
    impl AuditCustodyWitness for CountingCustody {
        fn verify_expectation(&self, _expectation: &AuditChainExpectation) -> CustodyVerdict {
            self.0.set(self.0.get() + 1);
            CustodyVerdict::Verified
        }
    }

    struct RejectCustody;
    impl AuditCustodyWitness for RejectCustody {
        fn verify_expectation(&self, _expectation: &AuditChainExpectation) -> CustodyVerdict {
            CustodyVerdict::Denied
        }
    }

    #[test]
    fn all_source_payloads_precede_any_signature_callback() {
        let first_digest = digest_snapshot(7, &[6; 32], b"first").unwrap_or([0; 32]);
        let second_digest = digest_snapshot(8, &first_digest, b"second").unwrap_or([0; 32]);
        let previous_checkpoints = [RestartCheckpoint {
            sequence: 7,
            predecessor_digest: [6; 32],
            snapshot_digest: first_digest,
            committed: true,
            hold: false,
            revoked: false,
        }];
        let current_checkpoints = [RestartCheckpoint {
            sequence: 8,
            predecessor_digest: first_digest,
            snapshot_digest: second_digest,
            committed: true,
            hold: false,
            revoked: false,
        }];
        let previous_signed = SignedAnchor {
            key_id: "test-key",
            public_key: [5; 32],
            signature: [7; 64],
            anchor: RestartAnchor {
                sequence: 7,
                predecessor_digest: [6; 32],
                snapshot_digest: first_digest,
                externally_verified: true,
            },
        };
        let current_signed = SignedAnchor {
            signature: [8; 64],
            anchor: RestartAnchor {
                sequence: 8,
                predecessor_digest: first_digest,
                snapshot_digest: second_digest,
                externally_verified: true,
            },
            ..previous_signed.clone()
        };
        let key = TrustedKey {
            key_id: "test-key",
            public_key: [5; 32],
            registry_sequence: 3,
            first_sequence: 7,
            last_sequence: 8,
            revoked: false,
        };
        let previous_floor = RecoveryFloor {
            checkpoint_sequence: 7,
            registry_sequence: 3,
        };
        let current_floor = RecoveryFloor {
            checkpoint_sequence: 8,
            registry_sequence: 3,
        };
        let previous_payloads: &[&[u8]] = &[b"first"];
        let current_payloads: &[&[u8]] = &[b"second"];
        let verifier = CountingVerifier(std::cell::Cell::new(0));
        let fallback = ReviewReceipt {
            digest: [0; 32],
            checkpoint_sequence: 0,
            registry_sequence: 0,
            checkpoint_count: 0,
        };
        let previous_receipt = review_receipt(
            &previous_checkpoints,
            previous_payloads,
            Some(&previous_signed),
            Some(&key),
            Some(&previous_floor),
            &verifier,
        )
        .unwrap_or(fallback);
        let current_receipt = review_receipt(
            &current_checkpoints,
            current_payloads,
            Some(&current_signed),
            Some(&key),
            Some(&current_floor),
            &verifier,
        )
        .unwrap_or(fallback);
        assert_ne!(previous_receipt.digest, [0; 32]);
        assert_ne!(current_receipt.digest, [0; 32]);
        verifier.0.set(0);
        let receipts = [previous_receipt, current_receipt];
        let first_link = audit_link_digest(10, &[9; 32], &receipts[0].digest)
            .unwrap_or([0; 32]);
        let second_link = audit_link_digest(11, &first_link, &receipts[1].digest)
            .unwrap_or([0; 32]);
        let links = [
            AuditLink {
                sequence: 10,
                predecessor_digest: [9; 32],
                receipt_digest: receipts[0].digest,
                link_digest: first_link,
            },
            AuditLink {
                sequence: 11,
                predecessor_digest: first_link,
                receipt_digest: receipts[1].digest,
                link_digest: second_link,
            },
        ];
        let expected = AuditChainExpectation {
            first_sequence: 10,
            predecessor_digest: [9; 32],
            last_sequence: 11,
            final_digest: second_link,
        };
        let previous_source = RecoveryEvidence {
            checkpoints: &previous_checkpoints,
            payloads: previous_payloads,
            signed: &previous_signed,
            trusted_key: &key,
            floor: &previous_floor,
        };
        let current_source = RecoveryEvidence {
            checkpoints: &current_checkpoints,
            payloads: current_payloads,
            signed: &current_signed,
            trusted_key: &key,
            floor: &current_floor,
        };
        let sources = [previous_source, current_source];
        assert_eq!(
            inspect_audit_evidence_payload_integrity(&sources),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &sources, Some(&expected), &verifier),
            RestartInspection::ReviewOnly
        );
        assert_eq!(verifier.0.get(), 2);

        verifier.0.set(0);
        let corrupted_current: &[&[u8]] = &[b"SECOND"];
        let invalid_current = [
            RecoveryEvidence {
                checkpoints: &previous_checkpoints,
                payloads: previous_payloads,
                signed: &previous_signed,
                trusted_key: &key,
                floor: &previous_floor,
            },
            RecoveryEvidence {
                checkpoints: &current_checkpoints,
                payloads: corrupted_current,
                signed: &current_signed,
                trusted_key: &key,
                floor: &current_floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_payload_integrity(&invalid_current),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &invalid_current, Some(&expected), &verifier),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);

        let corrupted_previous: &[&[u8]] = &[b"FIRST"];
        let invalid_previous = [
            RecoveryEvidence {
                checkpoints: &previous_checkpoints,
                payloads: corrupted_previous,
                signed: &previous_signed,
                trusted_key: &key,
                floor: &previous_floor,
            },
            RecoveryEvidence {
                checkpoints: &current_checkpoints,
                payloads: current_payloads,
                signed: &current_signed,
                trusted_key: &key,
                floor: &current_floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &invalid_previous, Some(&expected), &verifier),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);
    }

    #[test]
    fn exact_evidence_is_review_only_but_tampering_denies() {
        let snapshot = digest_snapshot(7, &[6; 32], b"original").unwrap_or([0; 32]);
        let checkpoints = [RestartCheckpoint {
            sequence: 7,
            predecessor_digest: [6; 32],
            snapshot_digest: snapshot,
            committed: true,
            hold: false,
            revoked: false,
        }];
        let signed = SignedAnchor {
            key_id: "review-a",
            public_key: [5; 32],
            signature: [9; 64],
            anchor: RestartAnchor {
                sequence: 7,
                predecessor_digest: [6; 32],
                snapshot_digest: snapshot,
                externally_verified: true,
            },
        };
        let trusted_key = TrustedKey {
            key_id: "review-a",
            public_key: [5; 32],
            registry_sequence: 3,
            first_sequence: 1,
            last_sequence: 10,
            revoked: false,
        };
        let floor = RecoveryFloor {
            checkpoint_sequence: 7,
            registry_sequence: 3,
        };
        let verifier =
            ByteMatcher(anchor_message_v2(&signed.anchor, &trusted_key).unwrap_or_default());
        let payloads: &[&[u8]] = &[b"original"];
        let receipt = review_receipt(
            &checkpoints,
            payloads,
            Some(&signed),
            Some(&trusted_key),
            Some(&floor),
            &verifier,
        )
        .unwrap_or(ReviewReceipt {
            digest: [0; 32],
            checkpoint_sequence: 0,
            registry_sequence: 0,
            checkpoint_count: 0,
        });
        assert_ne!(receipt.digest, [0; 32]);
        let receipts: [ReviewReceipt; 1] = [receipt];
        let link_digest = audit_link_digest(10, &[8; 32], &receipt.digest).unwrap_or([0; 32]);
        let links = [AuditLink {
            sequence: 10,
            predecessor_digest: [8; 32],
            receipt_digest: receipt.digest,
            link_digest,
        }];
        let expected = AuditChainExpectation {
            first_sequence: 10,
            predecessor_digest: [8; 32],
            last_sequence: 10,
            final_digest: link_digest,
        };
        let evidence = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &signed,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &evidence, Some(&expected), &verifier),
            RestartInspection::ReviewOnly
        );
        let empty_signature = SignedAnchor {
            signature: [0; 64],
            ..signed.clone()
        };
        let invalid_signature = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &empty_signature,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&invalid_signature),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_evidence(
                &links,
                &receipts,
                &invalid_signature,
                Some(&expected),
                &verifier,
            ),
            RestartInspection::Deny
        );
        let unverified = SignedAnchor {
            anchor: RestartAnchor {
                externally_verified: false,
                ..signed.anchor
            },
            ..signed.clone()
        };
        let unverified_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &unverified,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&unverified_evidence),
            RestartInspection::Deny
        );
        let long_id = "x".repeat(crate::orcheastra_signed_anchor::MAX_KEY_ID_BYTES + 1);
        let oversized_key = TrustedKey {
            key_id: &long_id,
            ..trusted_key.clone()
        };
        let oversized_signed = SignedAnchor {
            key_id: &long_id,
            ..signed.clone()
        };
        let oversized_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &oversized_signed,
            trusted_key: &oversized_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&oversized_evidence),
            RestartInspection::Deny
        );

        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &evidence, Some(&expected), &RejectAll),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &[], Some(&expected), &verifier),
            RestartInspection::Deny
        );

        let custody_counter = CountingCustody(std::cell::Cell::new(0));
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &[],
                Some(&expected),
                Some(&custody_counter),
                &verifier,
            ),
            RestartInspection::Deny
        );
        let invalid_payloads = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads: &[],
            signed: &signed,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &invalid_payloads,
                Some(&expected),
                Some(&custody_counter),
                &verifier,
            ),
            RestartInspection::Deny
        );

        assert_eq!(custody_counter.0.get(), 0);

        // Even evidence that passes cheap preflight but fails full payload
        // hashing must not reach an external custody callback.
        let corrupted_payloads: &[&[u8]] = &[b"ORIGINAL"];
        let corrupted = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads: corrupted_payloads,
            signed: &signed,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &corrupted,
                Some(&expected),
                Some(&custody_counter),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(custody_counter.0.get(), 0);
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &evidence,
                Some(&expected),
                Some(&custody_counter),
                &RejectAll,
            ),
            RestartInspection::Deny
        );
        assert_eq!(custody_counter.0.get(), 0);
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &evidence,
                Some(&expected),
                Some(&custody_counter),
                &verifier,
            ),
            RestartInspection::ReviewOnly
        );
        assert_eq!(custody_counter.0.get(), 1);

        let tampered_payloads: &[&[u8]] = &[b"ORIGINAL"];
        let altered = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads: tampered_payloads,
            signed: &signed,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &altered, Some(&expected), &verifier),
            RestartInspection::Deny
        );

        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &evidence,
                Some(&expected),
                Some(&TestWitness(expected)),
                &verifier,
            ),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &evidence,
                Some(&expected),
                None::<&RejectCustody>,
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &evidence,
                Some(&expected),
                Some(&RejectCustody),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_custodied_audit_evidence(
                &links,
                &receipts,
                &evidence,
                Some(&expected),
                Some(&TestWitness(expected)),
                &RejectAll,
            ),
            RestartInspection::Deny
        );

        assert_eq!(
            inspect_audit_evidence_budget(&evidence),
            RestartInspection::ReviewOnly
        );
        let large = vec![0u8; 1_048_576];
        let large_payloads: &[&[u8]] = &[large.as_slice()];
        let oversized: Vec<RecoveryEvidence<'_>> = (0..9)
            .map(|_| RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads: large_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            })
            .collect();
        assert_eq!(
            inspect_audit_evidence_budget(&oversized),
            RestartInspection::Deny
        );
        let many_checkpoints = vec![checkpoints[0]; 256];
        let many_payloads: Vec<&[u8]> = vec![b"original".as_slice(); 256];
        let excessive: Vec<RecoveryEvidence<'_>> = (0..5)
            .map(|_| RecoveryEvidence {
                checkpoints: &many_checkpoints,
                payloads: &many_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            })
            .collect();
        assert_eq!(
            inspect_audit_evidence_budget(&excessive),
            RestartInspection::Deny
        );
        let wrong_count = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads: &[],
            signed: &signed,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_budget(&wrong_count),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_evidence_lineage(&evidence),
            RestartInspection::ReviewOnly
        );
        let next_snapshot = digest_snapshot(8, &snapshot, b"next").unwrap_or([0; 32]);
        let following_checkpoint = [RestartCheckpoint {
            sequence: 8,
            predecessor_digest: snapshot,
            snapshot_digest: next_snapshot,
            committed: true,
            hold: false,
            revoked: false,
        }];
        let following_payloads: &[&[u8]] = &[b"next"];
        let following_signed = SignedAnchor {
            anchor: RestartAnchor {
                sequence: 8,
                predecessor_digest: snapshot,
                snapshot_digest: next_snapshot,
                externally_verified: true,
            },
            ..signed.clone()
        };
        let following = RecoveryEvidence {
            checkpoints: &following_checkpoint,
            payloads: following_payloads,
            signed: &following_signed,
            trusted_key: &trusted_key,
            floor: &floor,
        };
        let contiguous = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            following,
        ];
        assert_eq!(
            inspect_audit_evidence_lineage(&contiguous),
            RestartInspection::ReviewOnly
        );
        assert_eq!(
            inspect_audit_evidence_signers(&contiguous),
            RestartInspection::ReviewOnly
        );
        let wrong_anchor_sequence = SignedAnchor {
            anchor: RestartAnchor {
                sequence: 9,
                ..signed.anchor
            },
            ..signed.clone()
        };
        let wrong_sequence_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &wrong_anchor_sequence,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&wrong_sequence_evidence),
            RestartInspection::Deny
        );
        let wrong_anchor_snapshot = SignedAnchor {
            anchor: RestartAnchor {
                snapshot_digest: [7; 32],
                ..signed.anchor
            },
            ..signed.clone()
        };
        let wrong_snapshot_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &wrong_anchor_snapshot,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&wrong_snapshot_evidence),
            RestartInspection::Deny
        );
        let wrong_anchor_predecessor = SignedAnchor {
            anchor: RestartAnchor {
                predecessor_digest: [7; 32],
                ..signed.anchor
            },
            ..signed.clone()
        };
        let wrong_predecessor_evidence = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &wrong_anchor_predecessor,
            trusted_key: &trusted_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&wrong_predecessor_evidence),
            RestartInspection::Deny
        );

        let swapped_key = TrustedKey {
            key_id: "swapped",
            public_key: trusted_key.public_key,
            registry_sequence: trusted_key.registry_sequence,
            first_sequence: trusted_key.first_sequence,
            last_sequence: trusted_key.last_sequence,
            revoked: false,
        };
        let switched = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &following_checkpoint,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &swapped_key,
                floor: &floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_signers(&switched),
            RestartInspection::Deny
        );
        let expanded_key = TrustedKey {
            key_id: trusted_key.key_id,
            public_key: trusted_key.public_key,
            registry_sequence: trusted_key.registry_sequence,
            first_sequence: trusted_key.first_sequence,
            last_sequence: 11,
            revoked: false,
        };
        let changed_range = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &following_checkpoint,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &expanded_key,
                floor: &floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_signers(&changed_range),
            RestartInspection::Deny
        );
        let newer_key = TrustedKey {
            key_id: trusted_key.key_id,
            public_key: trusted_key.public_key,
            registry_sequence: 4,
            first_sequence: trusted_key.first_sequence,
            last_sequence: trusted_key.last_sequence,
            revoked: false,
        };
        let decreasing_registry = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &newer_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &following_checkpoint,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_signers(&decreasing_registry),
            RestartInspection::Deny
        );
        let revoked_key = TrustedKey {
            key_id: trusted_key.key_id,
            public_key: trusted_key.public_key,
            registry_sequence: trusted_key.registry_sequence,
            first_sequence: trusted_key.first_sequence,
            last_sequence: trusted_key.last_sequence,
            revoked: true,
        };
        let revoked = [RecoveryEvidence {
            checkpoints: &checkpoints,
            payloads,
            signed: &signed,
            trusted_key: &revoked_key,
            floor: &floor,
        }];
        assert_eq!(
            inspect_audit_evidence_signers(&revoked),
            RestartInspection::Deny
        );
        assert_eq!(inspect_audit_evidence_signers(&[]), RestartInspection::Deny);
        assert_eq!(
            inspect_audit_evidence_floors(&contiguous),
            RestartInspection::ReviewOnly
        );
        let advanced_floor = RecoveryFloor {
            checkpoint_sequence: 8,
            registry_sequence: 3,
        };
        let advancing = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &following_checkpoint,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &advanced_floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_floors(&advancing),
            RestartInspection::ReviewOnly
        );
        let lowered_floor = RecoveryFloor {
            checkpoint_sequence: 6,
            registry_sequence: 2,
        };
        let regressed = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &following_checkpoint,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &lowered_floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_floors(&regressed),
            RestartInspection::Deny
        );
        let lowered_registry_floor = RecoveryFloor {
            checkpoint_sequence: 8,
            registry_sequence: 2,
        };
        let registry_regressed = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &following_checkpoint,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &lowered_registry_floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_floors(&registry_regressed),
            RestartInspection::Deny
        );
        let future_floor = RecoveryFloor {
            checkpoint_sequence: 9,
            registry_sequence: 3,
        };
        let impossible = [RecoveryEvidence {
            checkpoints: &following_checkpoint,
            payloads: following_payloads,
            signed: &signed,
            trusted_key: &trusted_key,
            floor: &future_floor,
        }];
        assert_eq!(
            inspect_audit_evidence_floors(&impossible),
            RestartInspection::Deny
        );
        assert_eq!(inspect_audit_evidence_floors(&[]), RestartInspection::Deny);
        let replay = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_lineage(&replay),
            RestartInspection::Deny
        );
        let skipped = [RestartCheckpoint {
            sequence: 9,
            ..following_checkpoint[0]
        }];
        let gap = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &skipped,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_lineage(&gap),
            RestartInspection::Deny
        );
        let altered_predecessor = [RestartCheckpoint {
            predecessor_digest: [4; 32],
            ..following_checkpoint[0]
        }];
        let disconnected = [
            RecoveryEvidence {
                checkpoints: &checkpoints,
                payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
            RecoveryEvidence {
                checkpoints: &altered_predecessor,
                payloads: following_payloads,
                signed: &signed,
                trusted_key: &trusted_key,
                floor: &floor,
            },
        ];
        assert_eq!(
            inspect_audit_evidence_lineage(&disconnected),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_receipt_source_binding(&receipts, &evidence),
            RestartInspection::ReviewOnly
        );
        let wrong_count_receipt = [ReviewReceipt {
            checkpoint_count: receipts[0].checkpoint_count + 1,
            ..receipts[0]
        }];
        assert_eq!(
            inspect_audit_receipt_source_binding(&wrong_count_receipt, &evidence),
            RestartInspection::Deny
        );
        let wrong_registry_receipt = [ReviewReceipt {
            registry_sequence: receipts[0].registry_sequence + 1,
            ..receipts[0]
        }];
        assert_eq!(
            inspect_audit_receipt_source_binding(&wrong_registry_receipt, &evidence),
            RestartInspection::Deny
        );
        let wrong_sequence_receipt = [ReviewReceipt {
            checkpoint_sequence: receipts[0].checkpoint_sequence + 1,
            ..receipts[0]
        }];
        assert_eq!(
            inspect_audit_receipt_source_binding(&wrong_sequence_receipt, &evidence),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_receipt_source_binding(&[], &evidence),
            RestartInspection::Deny
        );
        let mut altered_receipts = receipts;
        altered_receipts[0].checkpoint_sequence += 1;
        assert_eq!(
            inspect_audit_evidence(
                &links,
                &altered_receipts,
                &evidence,
                Some(&expected),
                &verifier,
            ),
            RestartInspection::Deny
        );
    }
}
