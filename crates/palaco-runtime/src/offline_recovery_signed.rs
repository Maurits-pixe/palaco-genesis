//! Exact receipt reconstruction and signature-byte review boundary.
//!
//! No production cryptographic verifier or execution capability is supplied.

use sha2::{Digest, Sha256};

use crate::{
    offline_orphan::OrphanState,
    offline_recovery_receipt::{RecoveryIntent, RecoveryIntentReceipt},
    offline_recovery_review::{RecoveryReview, RecoveryReviewState},
};

/// Signature evidence, opaque until checked by an approved crypto implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedReviewEvidence {
    /// Claimed public-key identifier.
    pub key_id: [u8; 32],
    /// Raw Ed25519-shaped signature bytes; no algorithm guarantee is implied.
    pub signature: [u8; 64],
}

/// Cryptographic verification boundary. Only an external audited implementation
/// can establish validity; the default supplied here is deny-all.
pub trait SignedReceiptVerifier {
    /// Check the exact statement digest, key identifier and raw signature bytes.
    fn verify(&self, digest: &[u8; 32], key_id: &[u8; 32], signature: &[u8; 64]) -> bool;
}

/// Default verifier that never accepts an untrusted signature.
pub struct DenyAllSignedReceiptVerifier;

impl SignedReceiptVerifier for DenyAllSignedReceiptVerifier {
    fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 64]) -> bool {
        false
    }
}

/// Non-authorizing signature evidence assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedReviewState {
    /// Missing, contradictory or cryptographically unverified evidence.
    Hold,
    /// External verifier accepted the exact statement; not an execution permit.
    VerifiedForSeparateReview,
}

/// Recompute ORCH-047's digest and call the external signature verifier.
///
/// Review/receipt fields are matched exactly, including the observation state.
/// This function performs no clock, revocation, replay or filesystem checks.
pub fn verify_signed_review<V: SignedReceiptVerifier>(
    review: &RecoveryReview,
    receipt: &RecoveryIntentReceipt,
    signature: &SignedReviewEvidence,
    verifier: &V,
) -> SignedReviewState {
    if receipt.execution_allowed
        || review.execution_allowed
        || review.sequence == 0
        || receipt.sequence != review.sequence
        || receipt.intent != RecoveryIntent::RequestQuarantineReview
        || review.state != RecoveryReviewState::MatchingPendingHold
        || review.observed != OrphanState::PendingOnly
        || receipt.attribution.actor_reference == [0; 32]
        || receipt.attribution.evidence_nonce == [0; 32]
        || signature.key_id == [0; 32]
        || signature.signature == [0; 64]
    {
        return SignedReviewState::Hold;
    }

    let mut hash = Sha256::new();
    hash.update(b"PALACO/ORCH-047/RECOVERY-INTENT/V1");
    hash.update(review.sequence.to_be_bytes());
    hash.update([1_u8, 1_u8, 2_u8]);
    hash.update(receipt.attribution.actor_reference);
    hash.update(receipt.attribution.evidence_nonce);
    let digest: [u8; 32] = hash.finalize().into();
    if digest != receipt.statement_sha256
        || !verifier.verify(&digest, &signature.key_id, &signature.signature)
    {
        return SignedReviewState::Hold;
    }
    SignedReviewState::VerifiedForSeparateReview
}

#[cfg(test)]
mod tests {
    use super::{
        verify_signed_review, DenyAllSignedReceiptVerifier, SignedReceiptVerifier,
        SignedReviewEvidence, SignedReviewState,
    };
    use crate::{
        offline_orphan::OrphanState,
        offline_recovery_receipt::{
            record_recovery_intent, RecoveryIntent, RecoveryIntentReceipt, ReviewAttribution,
        },
        offline_recovery_review::{RecoveryReview, RecoveryReviewState},
    };

    struct Fixture(bool);

    impl SignedReceiptVerifier for Fixture {
        fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 64]) -> bool {
            self.0
        }
    }

    fn review() -> RecoveryReview {
        RecoveryReview {
            sequence: 7,
            observed: OrphanState::PendingOnly,
            state: RecoveryReviewState::MatchingPendingHold,
            execution_allowed: false,
        }
    }

    fn receipt() -> Result<RecoveryIntentReceipt, crate::offline_recovery_receipt::ReceiptError> {
        record_recovery_intent(
            &review(),
            ReviewAttribution {
                actor_reference: [4; 32],
                evidence_nonce: [5; 32],
            },
            RecoveryIntent::RequestQuarantineReview,
        )
    }

    fn signature() -> SignedReviewEvidence {
        SignedReviewEvidence {
            key_id: [6; 32],
            signature: [7; 64],
        }
    }

    #[test]
    fn default_denies_even_matching_statement() {
        let value = receipt();
        assert!(matches!(value, Ok(value) if verify_signed_review(
            &review(), &value, &signature(), &DenyAllSignedReceiptVerifier
        ) == SignedReviewState::Hold));
    }

    #[test]
    fn mock_success_is_only_a_review_state() {
        let value = receipt();
        assert!(matches!(value, Ok(value) if verify_signed_review(
            &review(), &value, &signature(), &Fixture(true)
        ) == SignedReviewState::VerifiedForSeparateReview));
    }

    #[test]
    fn tampered_statement_is_refused_even_by_mock() {
        let value = receipt();
        assert!(matches!(value, Ok(mut value) if {
            value.statement_sha256 = [9; 32];
            verify_signed_review(&review(), &value, &signature(), &Fixture(true))
                == SignedReviewState::Hold
        }));
    }

    #[test]
    fn modified_sequence_or_execution_flag_is_refused() {
        let value = receipt();
        assert!(matches!(value, Ok(mut value) if {
            value.sequence = 8;
            verify_signed_review(&review(), &value, &signature(), &Fixture(true))
                == SignedReviewState::Hold
        }));
        let value = receipt();
        assert!(matches!(value, Ok(mut value) if {
            value.execution_allowed = true;
            verify_signed_review(&review(), &value, &signature(), &Fixture(true))
                == SignedReviewState::Hold
        }));
    }

    #[test]
    fn blank_signature_or_key_and_denied_verifier_fail_closed() {
        let value = receipt();
        assert!(matches!(value, Ok(value) if {
            let mut blank = signature();
            blank.signature = [0; 64];
            verify_signed_review(&review(), &value, &blank, &Fixture(true))
                == SignedReviewState::Hold
                && verify_signed_review(&review(), &value, &signature(), &Fixture(false))
                    == SignedReviewState::Hold
        }));
    }
}
