//! Fail-closed review of audit links against original recovery evidence.
//!
//! A successful consistency check is NOT a cryptographic attestation, does not
//! authenticate an externally supplied custody root, and cannot authorize work.

use crate::orcheastra_audit_chain::{
    AuditChainExpectation, AuditLink, MAX_AUDIT_LINKS,
};
use crate::orcheastra_audit_receipts::inspect_bound_audit_receipts;
use crate::orcheastra_recovery::RecoveryFloor;
use crate::orcheastra_restart::{RestartCheckpoint, RestartInspection};
use crate::orcheastra_review_receipt::{
    revalidate_review_receipt, ReviewReceipt,
};
use crate::orcheastra_signed_anchor::{
    Ed25519Verifier, SignedAnchor, TrustedKey,
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

/// Reviews audit-chain linkage and recomputes every corresponding receipt.
///
/// Denies empty/mismatched evidence batches and any receipt that cannot be
/// independently recomputed from its supplied snapshot bytes and context.
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
        || inspect_bound_audit_receipts(links, receipts, expected)
            != RestartInspection::ReviewOnly
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

#[cfg(test)]
mod tests {
    use super::{inspect_audit_evidence, RecoveryEvidence};
    use crate::orcheastra_audit_chain::{
        audit_link_digest, AuditChainExpectation, AuditLink,
    };
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_recovery::RecoveryFloor;
    use crate::orcheastra_restart::{
        RestartAnchor, RestartCheckpoint, RestartInspection,
    };
    use crate::orcheastra_review_receipt::{review_receipt, ReviewReceipt};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor,
        TrustedKey,
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
        ).unwrap_or(ReviewReceipt {
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
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &evidence, Some(&expected), &RejectAll),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_audit_evidence(&links, &receipts, &[], Some(&expected), &verifier),
            RestartInspection::Deny
        );

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
