//! Deterministic audit fingerprint for a read-only recovery assessment.
//!
//! Receipts are local, untrusted review artifacts. SHA-256 is NOT a signature.
//! Neither this module nor its receipt grants execution or publication rights.

use sha2::{Digest, Sha256};

use crate::orcheastra_payload::inspect_chain_payload_budget;
use crate::orcheastra_recovery::{inspect_recovery, RecoveryFloor};
use crate::orcheastra_restart::{RestartCheckpoint, RestartInspection};
use crate::orcheastra_signed_anchor::{
    Ed25519Verifier, SignedAnchor, TrustedKey, MAX_KEY_ID_BYTES,
};

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
    fingerprint_review_receipt(checkpoints, payloads, signed, key, floor)
}

/// Computes a review fingerprint without trusting or verifying its input.
///
/// This function is for deterministic preflight only. Its output is NOT a
/// signature, custody record, proof of recovery, or execution authorization.
/// Inputs share the recovery verifier's checkpoint count, per-snapshot size,
/// and cumulative eight-MiB work budget. Callers must separately verify full
/// recovery evidence and cryptographic signatures before treating a matching
/// receipt as eligible for review. Key identifiers are limited to 128 bytes,
/// and signed-anchor, registry and floor fields must be structurally consistent.
#[must_use]
pub fn fingerprint_review_receipt(
    checkpoints: &[RestartCheckpoint],
    payloads: &[&[u8]],
    signed: &SignedAnchor<'_>,
    key: &TrustedKey<'_>,
    floor: &RecoveryFloor,
) -> Option<ReviewReceipt> {
    let last = checkpoints.last()?;
    if checkpoints.len() != payloads.len()
        || inspect_chain_payload_budget(payloads) != RestartInspection::ReviewOnly
        || key.key_id.is_empty()
        || key.key_id.len() > MAX_KEY_ID_BYTES
        || signed.key_id != key.key_id
        || signed.public_key != key.public_key
        || key.public_key == [0; 32]
        || signed.signature == [0; 64]
        || key.revoked
        || key.registry_sequence == 0
        || key.first_sequence == 0
        || key.first_sequence > key.last_sequence
        || signed.anchor.sequence < key.first_sequence
        || signed.anchor.sequence > key.last_sequence
        || signed.anchor.sequence != last.sequence
        || signed.anchor.snapshot_digest != last.snapshot_digest
        || signed.anchor.predecessor_digest != last.predecessor_digest
        || !signed.anchor.externally_verified
        || floor.checkpoint_sequence == 0
        || floor.registry_sequence == 0
        || floor.checkpoint_sequence > last.sequence
        || floor.registry_sequence > key.registry_sequence
    {
        return None;
    }
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
/// input yields DENY. Deterministic fingerprint mismatch is rejected before
/// invoking the external verifier; matching input still requires complete
/// recovery and signature validation. This does not authenticate the expected
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
    let (Some(expected), Some(signed), Some(key), Some(floor)) =
        (expected, signed, trusted_key, floor)
    else {
        return RestartInspection::Deny;
    };
    // A mismatching caller-provided fingerprint must not invoke the external
    // signature verifier. This comparison never replaces full recovery review.
    if fingerprint_review_receipt(checkpoints, payloads, signed, key, floor).as_ref()
        != Some(expected)
    {
        return RestartInspection::Deny;
    }
    if review_receipt(
        checkpoints,
        payloads,
        Some(signed),
        Some(key),
        Some(floor),
        verifier,
    )
    .as_ref()
        != Some(expected)
    {
        return RestartInspection::Deny;
    }
    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{revalidate_review_receipt, review_receipt, ReviewReceipt};
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_recovery::RecoveryFloor;
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor, TrustedKey,
        MAX_KEY_ID_BYTES,
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

    // Only counts calls; a Valid result here is not Ed25519 verification.
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

    #[test]
    fn fingerprint_rejects_aggregate_snapshot_over_budget() {
        let snapshot = vec![4u8; crate::orcheastra_payload::MAX_SNAPSHOT_BYTES];
        let payloads: Vec<&[u8]> = vec![snapshot.as_slice(); 9];
        let checkpoints = vec![
            RestartCheckpoint {
                sequence: 5,
                snapshot_digest: [7; 32],
                predecessor_digest: [4; 32],
                committed: true,
                hold: false,
                revoked: false,
            };
            9
        ];
        let signed = SignedAnchor {
            key_id: "review-key",
            public_key: [6; 32],
            signature: [9; 64],
            anchor: RestartAnchor {
                sequence: 5,
                snapshot_digest: [7; 32],
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
        assert_eq!(
            super::fingerprint_review_receipt(&checkpoints, &payloads, &signed, &key, &floor),
            None
        );
        let verifier = CountingVerifier(std::cell::Cell::new(0));
        assert_eq!(
            review_receipt(
                &checkpoints,
                &payloads,
                Some(&signed),
                Some(&key),
                Some(&floor),
                &verifier,
            ),
            None
        );
        assert_eq!(verifier.0.get(), 0);
    }

    #[test]
    fn altered_receipt_is_denied_before_external_verifier() {
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
        let verifier = CountingVerifier(std::cell::Cell::new(0));
        let payloads: &[&[u8]] = &[b"payload"];
        let receipt = review_receipt(
            &checkpoints,
            payloads,
            Some(&signed),
            Some(&key),
            Some(&floor),
            &verifier,
        );
        assert!(receipt.is_some());
        verifier.0.set(0);
        if let Some(receipt) = receipt {
            for corrupted in [
                ReviewReceipt {
                    digest: [3; 32],
                    ..receipt
                },
                ReviewReceipt {
                    checkpoint_count: receipt.checkpoint_count + 1,
                    ..receipt
                },
                ReviewReceipt {
                    registry_sequence: receipt.registry_sequence + 1,
                    ..receipt
                },
            ] {
                assert_eq!(
                    revalidate_review_receipt(
                        Some(&corrupted),
                        &checkpoints,
                        payloads,
                        Some(&signed),
                        Some(&key),
                        Some(&floor),
                        &verifier,
                    ),
                    crate::orcheastra_restart::RestartInspection::Deny
                );
                assert_eq!(verifier.0.get(), 0);
            }
            assert_eq!(
                revalidate_review_receipt(
                    Some(&receipt),
                    &checkpoints,
                    payloads,
                    Some(&signed),
                    Some(&key),
                    Some(&floor),
                    &verifier,
                ),
                crate::orcheastra_restart::RestartInspection::ReviewOnly
            );
            assert_eq!(verifier.0.get(), 1);
            verifier.0.set(0);
            assert_eq!(
                revalidate_review_receipt(
                    Some(&receipt),
                    &checkpoints,
                    &[b"PAYLOAD"],
                    Some(&signed),
                    Some(&key),
                    Some(&floor),
                    &verifier,
                ),
                crate::orcheastra_restart::RestartInspection::Deny
            );
            assert_eq!(verifier.0.get(), 0);

            // The unauthenticated direct fingerprint API must refuse oversized
            // key identifiers and mismatched key/anchor identity before hashing.
            let long_id = "x".repeat(MAX_KEY_ID_BYTES + 1);
            let long_key = TrustedKey {
                key_id: &long_id,
                ..key.clone()
            };
            let long_signed = SignedAnchor {
                key_id: &long_id,
                ..signed.clone()
            };
            assert_eq!(
                super::fingerprint_review_receipt(
                    &checkpoints,
                    payloads,
                    &long_signed,
                    &long_key,
                    &floor,
                ),
                None
            );
            assert_eq!(
                revalidate_review_receipt(
                    Some(&receipt),
                    &checkpoints,
                    payloads,
                    Some(&long_signed),
                    Some(&long_key),
                    Some(&floor),
                    &verifier,
                ),
                crate::orcheastra_restart::RestartInspection::Deny
            );
            assert_eq!(verifier.0.get(), 0);

            let swapped_key = TrustedKey {
                public_key: [8; 32],
                ..key.clone()
            };
            assert_eq!(
                super::fingerprint_review_receipt(
                    &checkpoints,
                    payloads,
                    &signed,
                    &swapped_key,
                    &floor,
                ),
                None
            );
            let empty_signature = SignedAnchor {
                signature: [0; 64],
                ..signed.clone()
            };
            assert_eq!(
                super::fingerprint_review_receipt(
                    &checkpoints,
                    payloads,
                    &empty_signature,
                    &key,
                    &floor,
                ),
                None
            );
            let changed_anchor = SignedAnchor {
                anchor: RestartAnchor {
                    snapshot_digest: [8; 32],
                    ..signed.anchor
                },
                ..signed.clone()
            };
            assert_eq!(
                super::fingerprint_review_receipt(
                    &checkpoints,
                    payloads,
                    &changed_anchor,
                    &key,
                    &floor,
                ),
                None
            );
            let future_floor = RecoveryFloor {
                checkpoint_sequence: 6,
                ..floor
            };
            assert_eq!(
                super::fingerprint_review_receipt(
                    &checkpoints,
                    payloads,
                    &signed,
                    &key,
                    &future_floor,
                ),
                None
            );
            assert_eq!(verifier.0.get(), 0);
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
