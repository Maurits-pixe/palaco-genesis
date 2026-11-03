//! Fail-closed authentication and anti-replay boundary for offline recovery reviews.
//!
//! A passing preflight only allows further human review, not filesystem mutation.

use crate::offline_recovery_receipt::{RecoveryIntent, RecoveryIntentReceipt};

/// Trusted verification input supplied by an independently governed caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalEvidence {
    /// Identifier of the trusted operator key; not itself proof.
    pub key_id: [u8; 32],
    /// Independently established policy epoch.
    pub policy_epoch: u64,
    /// Expiration in trusted time units as defined by the policy.
    pub expires_at: u64,
}

/// External authenticated signature verifier.
///
/// Implementations must validate the exact statement digest, key, epoch and
/// signature, and reject revoked keys. This crate supplies only a deny-all default.
pub trait ApprovalSignatureVerifier {
    /// Return true only for a genuinely authenticated and authorized reviewer.
    fn verify(&self, statement_sha256: &[u8; 32], key_id: &[u8; 32], policy_epoch: u64) -> bool;
}

/// External durable, crash-safe nonce checking boundary.
///
/// A read-only replay check is insufficient for later execution authorization.
pub trait DurableReplayVerifier {
    /// Return true only when the nonce is known to be unused by trusted storage.
    fn unused(&self, actor: &[u8; 32], nonce: &[u8; 32]) -> bool;
}

/// Safe default when no authenticated crypto implementation is installed.
pub struct DenyAllApprovalVerifier;

impl ApprovalSignatureVerifier for DenyAllApprovalVerifier {
    fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: u64) -> bool {
        false
    }
}

impl DurableReplayVerifier for DenyAllApprovalVerifier {
    fn unused(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
        false
    }
}

/// Non-executing results of review preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalPreflight {
    /// Trust evidence is incomplete, invalid, expired or not verified.
    Hold,
    /// Evidence has passed supplied interfaces; still no execution capability.
    ReadyForSeparateHumanReview,
}

/// Evaluate a requested quarantine review without changing durable state.
///
/// `trusted_now` and `minimum_policy_epoch` MUST be provided by a trusted,
/// monotone source. The result is not authorization and never consumes a nonce.
/// A future executor must atomically reserve the nonce and revalidate evidence.
pub fn verify_recovery_review<V: ApprovalSignatureVerifier, R: DurableReplayVerifier>(
    receipt: &RecoveryIntentReceipt,
    evidence: &ApprovalEvidence,
    trusted_now: Option<u64>,
    minimum_policy_epoch: u64,
    verifier: &V,
    replay: &R,
) -> ApprovalPreflight {
    if receipt.execution_allowed
        || receipt.sequence == 0
        || receipt.intent != RecoveryIntent::RequestQuarantineReview
        || receipt.attribution.actor_reference == [0; 32]
        || receipt.attribution.evidence_nonce == [0; 32]
        || receipt.statement_sha256 == [0; 32]
        || evidence.key_id == [0; 32]
        || minimum_policy_epoch == 0
        || evidence.policy_epoch < minimum_policy_epoch
    {
        return ApprovalPreflight::Hold;
    }
    let Some(now) = trusted_now else {
        return ApprovalPreflight::Hold;
    };
    if now > evidence.expires_at
        || !verifier.verify(
            &receipt.statement_sha256,
            &evidence.key_id,
            evidence.policy_epoch,
        )
        || !replay.unused(
            &receipt.attribution.actor_reference,
            &receipt.attribution.evidence_nonce,
        )
    {
        return ApprovalPreflight::Hold;
    }
    ApprovalPreflight::ReadyForSeparateHumanReview
}

#[cfg(test)]
mod tests {
    use super::{
        verify_recovery_review, ApprovalEvidence, ApprovalPreflight, ApprovalSignatureVerifier,
        DenyAllApprovalVerifier, DurableReplayVerifier,
    };
    use crate::offline_recovery_receipt::{
        RecoveryIntent, RecoveryIntentReceipt, ReviewAttribution,
    };

    struct FixtureVerifier(bool);

    impl ApprovalSignatureVerifier for FixtureVerifier {
        fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: u64) -> bool {
            self.0
        }
    }

    impl DurableReplayVerifier for FixtureVerifier {
        fn unused(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
            self.0
        }
    }

    fn receipt() -> RecoveryIntentReceipt {
        RecoveryIntentReceipt {
            sequence: 7,
            intent: RecoveryIntent::RequestQuarantineReview,
            attribution: ReviewAttribution {
                actor_reference: [1; 32],
                evidence_nonce: [2; 32],
            },
            statement_sha256: [3; 32],
            execution_allowed: false,
        }
    }

    fn evidence() -> ApprovalEvidence {
        ApprovalEvidence {
            key_id: [4; 32],
            policy_epoch: 8,
            expires_at: 100,
        }
    }

    #[test]
    fn deny_all_default_blocks_quarantine_review() {
        assert_eq!(
            verify_recovery_review(
                &receipt(),
                &evidence(),
                Some(90),
                8,
                &DenyAllApprovalVerifier,
                &DenyAllApprovalVerifier
            ),
            ApprovalPreflight::Hold
        );
    }

    #[test]
    fn missing_or_expired_trusted_time_fails_closed() {
        assert_eq!(
            verify_recovery_review(
                &receipt(),
                &evidence(),
                None,
                8,
                &FixtureVerifier(true),
                &FixtureVerifier(true)
            ),
            ApprovalPreflight::Hold
        );
        assert_eq!(
            verify_recovery_review(
                &receipt(),
                &evidence(),
                Some(101),
                8,
                &FixtureVerifier(true),
                &FixtureVerifier(true)
            ),
            ApprovalPreflight::Hold
        );
    }

    #[test]
    fn stale_epoch_and_replay_rejection_fail_closed() {
        assert_eq!(
            verify_recovery_review(
                &receipt(),
                &evidence(),
                Some(90),
                9,
                &FixtureVerifier(true),
                &FixtureVerifier(true)
            ),
            ApprovalPreflight::Hold
        );
        assert_eq!(
            verify_recovery_review(
                &receipt(),
                &evidence(),
                Some(90),
                8,
                &FixtureVerifier(true),
                &FixtureVerifier(false)
            ),
            ApprovalPreflight::Hold
        );
    }

    #[test]
    fn forged_execution_and_wrong_intent_fail_closed() {
        let mut value = receipt();
        value.execution_allowed = true;
        assert_eq!(
            verify_recovery_review(
                &value,
                &evidence(),
                Some(90),
                8,
                &FixtureVerifier(true),
                &FixtureVerifier(true)
            ),
            ApprovalPreflight::Hold
        );
        value.execution_allowed = false;
        value.intent = RecoveryIntent::Defer;
        assert_eq!(
            verify_recovery_review(
                &value,
                &evidence(),
                Some(90),
                8,
                &FixtureVerifier(true),
                &FixtureVerifier(true)
            ),
            ApprovalPreflight::Hold
        );
    }

    #[test]
    fn fixture_success_is_review_only() {
        assert_eq!(
            verify_recovery_review(
                &receipt(),
                &evidence(),
                Some(90),
                8,
                &FixtureVerifier(true),
                &FixtureVerifier(true)
            ),
            ApprovalPreflight::ReadyForSeparateHumanReview
        );
    }
}
