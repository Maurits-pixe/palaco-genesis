//! Deterministic audit fingerprint for a read-only recovery assessment.
//!
//! Receipts are local, untrusted review artifacts. SHA-256 is NOT a signature.
//! Neither this module nor its receipt grants execution or publication rights.

use sha2::{Digest, Sha256};

use crate::orcheastra_recovery::{inspect_recovery, RecoveryFloor};
use crate::orcheastra_restart::{RestartCheckpoint, RestartInspection};
use crate::orcheastra_signed_anchor::{Ed25519Verifier, SignedAnchor, TrustedKey};

const RECEIPT_DOMAIN: &[u8] = b"PALACO-ORCHEASTRA-RECOVERY-REVIEW-RECEIPT-V1\0";

/// Content fingerprint of an assessment eligible for further review only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewReceipt {
    /// Domain-separated hash of the inspected evidence and review disposition.
    pub digest: [u8; 32],
    /// Last checkpoint in the reviewed chain.
    pub checkpoint_sequence: u64,
    /// Key registry revision observed during inspection.
    pub registry_sequence: u64,
    /// Number of inspected snapshots.
    pub checkpoint_count: usize,
}

/// Evaluates the full recovery evidence and fingerprints the exact input set.
///
/// Returns `None` whenever inspection denies. The fingerprint is not evidence
/// that the verifier, custody floor, or registry was genuinely trusted. The
/// caller must preserve the matching evidence separately for later inspection.
#[must_use]
pub fn review_receipt(
    checkpoints: &[RestartCheckpoint],
    payloads: &[&[u8]],
    signed: Option<&SignedAnchor<'_>>,
    trusted_key: Option<&TrustedKey<'_>>,
    floor: Option<&RecoveryFloor>,
    verifier: &impl Ed25519Verifier,
) -> Option<ReviewReceipt> {
    if inspect_recovery(checkpoints, payloads, signed, trusted_key, floor, verifier)
        != RestartInspection::ReviewOnly
    {
        return None;
    }

    let signed = signed?;
    let key = trusted_key?;
    let floor = floor?;
    let count = u64::try_from(checkpoints.len()).ok()?;
    let key_id_len = u64::try_from(key.key_id.len()).ok()?;

    let mut hash = Sha256::new();
    hash.update(RECEIPT_DOMAIN);
    hash.update(count.to_be_bytes());
    hash.update(key_id_len.to_be_bytes());
    hash.update(key.key_id.as_bytes());
    hash.update(key.public_key);
    hash.update(key.registry_sequence.to_be_bytes());
    hash.update(key.first_sequence.to_be_bytes());
    hash.update(key.last_sequence.to_be_bytes());
    hash.update([u8::from(key.revoked)]);
    hash.update(floor.checkpoint_sequence.to_be_bytes());
    hash.update(floor.registry_sequence.to_be_bytes());
    hash.update(signed.anchor.sequence.to_be_bytes());
    hash.update(signed.anchor.snapshot_digest);
    hash.update(signed.anchor.predecessor_digest);
    hash.update(signed.signature);

    for checkpoint in checkpoints {
        hash.update(checkpoint.sequence.to_be_bytes());
        hash.update(checkpoint.predecessor_digest);
        hash.update(checkpoint.snapshot_digest);
        hash.update([
            u8::from(checkpoint.committed),
            u8::from(checkpoint.hold),
            u8::from(checkpoint.revoked),
        ]);
    }

    for payload in payloads {
        hash.update(u64::try_from(payload.len()).ok()?.to_be_bytes());
        hash.update(payload);
    }

    Some(ReviewReceipt {
        digest: hash.finalize().into(),
        checkpoint_sequence: signed.anchor.sequence,
        registry_sequence: key.registry_sequence,
        checkpoint_count: checkpoints.len(),
    })
}

/// Recomputes the complete assessment and compares its receipt to an expected one.
///
/// The entire evidence set and verifier are re-evaluated: a caller cannot
/// validate a receipt merely by repeating its digest. Any mismatch or absent
/// input yields DENY. This comparison does not authenticate the expected
/// receipt or its storage, and never authorizes execution.
#[must_use]
pub fn revalidate_review_receipt(
    expected: Option<&ReviewReceipt>,
    checkpoints: &[RestartCheckpoint],
    payloads: &[&[u8]],
    signed: Option<&SignedAnchor<'_>>,
    trusted_key: Option<&TrustedKey<'_>>,
    floor: Option<&RecoveryFloor>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    let Some(expected) = expected else {
        return RestartInspection::Deny;
    };
    let Some(recomputed) = review_receipt(
        checkpoints,
        payloads,
        signed,
        trusted_key,
        floor,
        verifier,
    ) else {
        return RestartInspection::Deny;
    };
    if expected != &recomputed {
        return RestartInspection::Deny;
    }
    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{revalidate_review_receipt, review_receipt};
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_recovery::RecoveryFloor;
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor, TrustedKey,
    };

    /// Deliberately unauthenticated test-only byte equality checker.
    struct MessageMatcher(Vec<u8>);
    impl Ed25519Verifier for MessageMatcher {
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
    fn matching_evidence_produces_stable_review_fingerprint_only() {
        let snapshot = digest_snapshot(5, &[4; 32], b"payload").unwrap_or([0; 32]);
        let checkpoints = [RestartCheckpoint {
            sequence: 5,
            snapshot_digest: snapshot,
            predecessor_digest: [4; 32],
            committed: true,
            hold: false,
            revoked: false,
        }];
        let signed = SignedAnchor {
            key_id: "review-key",
            public_key: [6; 32],
            signature: [9; 64],
            anchor: RestartAnchor {
                sequence: 5,
                snapshot_digest: snapshot,
                predecessor_digest: [4; 32],
                externally_verified: true,
            },
        };
        let key = TrustedKey {
            key_id: "review-key",
            public_key: [6; 32],
            registry_sequence: 4,
            first_sequence: 1,
            last_sequence: 6,
            revoked: false,
        };
        let floor = RecoveryFloor {
            checkpoint_sequence: 5,
            registry_sequence: 4,
        };
        let matcher = MessageMatcher(anchor_message_v2(&signed.anchor, &key).unwrap_or_default());
        let first = review_receipt(
            &checkpoints,
            &[b"payload"],
            Some(&signed),
            Some(&key),
            Some(&floor),
            &matcher,
        );
        assert!(first.is_some());
        assert_eq!(
            revalidate_review_receipt(
                first.as_ref(),
                &checkpoints,
                &[b"payload"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            crate::orcheastra_restart::RestartInspection::ReviewOnly
        );
        assert_eq!(
            revalidate_review_receipt(
                None,
                &checkpoints,
                &[b"payload"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            crate::orcheastra_restart::RestartInspection::Deny
        );
        assert_eq!(
            revalidate_review_receipt(
                first.as_ref(),
                &checkpoints,
                &[b"PAYLOAD"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            crate::orcheastra_restart::RestartInspection::Deny
        );
        assert_eq!(
            revalidate_review_receipt(
                first.as_ref(),
                &checkpoints,
                &[b"payload"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &RejectAll,
            ),
            crate::orcheastra_restart::RestartInspection::Deny
        );
        if let Some(mut changed) = first {
            changed.digest[0] ^= 1;
            assert_eq!(
                revalidate_review_receipt(
                    Some(&changed),
                    &checkpoints,
                    &[b"payload"],
                    Some(&signed),
                    Some(&key),
                    Some(&floor),
                    &matcher,
                ),
                crate::orcheastra_restart::RestartInspection::Deny
            );
            changed.digest[0] ^= 1;
            changed.checkpoint_count += 1;
            assert_eq!(
                revalidate_review_receipt(
                    Some(&changed),
                    &checkpoints,
                    &[b"payload"],
                    Some(&signed),
                    Some(&key),
                    Some(&floor),
                    &matcher,
                ),
                crate::orcheastra_restart::RestartInspection::Deny
            );
        }
        assert_eq!(
            first,
            review_receipt(
                &checkpoints,
                &[b"payload"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            )
        );
        assert_eq!(
            review_receipt(
                &checkpoints,
                &[b"payload"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &RejectAll,
            ),
            None
        );
        assert_eq!(
            review_receipt(
                &checkpoints,
                &[b"PAYLOAD"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            None
        );
        assert_eq!(
            review_receipt(
                &checkpoints,
                &[b"payload"],
                Some(&signed),
                Some(&key),
                None,
                &matcher,
            ),
            None
        );
    }
}
