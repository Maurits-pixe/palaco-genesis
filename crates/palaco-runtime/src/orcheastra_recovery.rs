//! Composed, read-only recovery inspection: signed anchor plus payload chain.
//!
//! A successful result is review-only. This module cannot authenticate an
//! untrusted key registry or enforce persistent anti-rollback protection.

use crate::orcheastra_payload::inspect_restart_chain_payloads;
use crate::orcheastra_restart::{RestartCheckpoint, RestartInspection};
use crate::orcheastra_signed_anchor::{
    inspect_signed_anchor, Ed25519Verifier, SignedAnchor, TrustedKey,
};

/// Minimum accepted persisted counters supplied by an independent custodian.
///
/// The fields must be read from a trusted, rollback-resistant store.
/// Constructing this struct does NOT establish trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFloor {
    /// Minimum permitted checkpoint sequence.
    pub checkpoint_sequence: u64,
    /// Minimum permitted key registry revision.
    pub registry_sequence: u64,
}

/// Checks an entire bounded payload chain and its key-bound signed anchor.
///
/// Fails closed when the external custody floor is missing, either sequence
/// falls below its floor, the signed anchor fails the verifier, or any of the
/// supplied checkpoint payloads fail the integrity/chain checks.
/// Payload integrity and recovery floors are validated before calling the
/// external signature verifier; ReviewOnly still grants no authority.
///
/// This method has no authority to execute, commit, sign, or publish data.
#[must_use]
pub fn inspect_recovery(
    checkpoints: &[RestartCheckpoint],
    payloads: &[&[u8]],
    signed: Option<&SignedAnchor<'_>>,
    trusted_key: Option<&TrustedKey<'_>>,
    floor: Option<&RecoveryFloor>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    let (Some(signed), Some(key), Some(floor)) = (signed, trusted_key, floor) else {
        return RestartInspection::Deny;
    };

    if floor.checkpoint_sequence == 0
        || floor.registry_sequence == 0
        || signed.anchor.sequence < floor.checkpoint_sequence
        || key.registry_sequence < floor.registry_sequence
        || inspect_restart_chain_payloads(checkpoints, payloads, Some(&signed.anchor))
            != RestartInspection::ReviewOnly
        || inspect_signed_anchor(Some(signed), Some(key), verifier) != RestartInspection::ReviewOnly
    {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{inspect_recovery, RecoveryFloor};
    use crate::orcheastra_payload::digest_snapshot;
    use crate::orcheastra_restart::{RestartAnchor, RestartCheckpoint, RestartInspection};
    use crate::orcheastra_signed_anchor::{
        anchor_message_v2, Ed25519Verifier, SignatureVerdict, SignedAnchor, TrustedKey,
    };

    /// Test-only exact-byte matcher. NOT a cryptographic verifier.
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

    // A verifier may be an external adapter: count calls without panic or locks.
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

    fn fixture() -> (
        Vec<RestartCheckpoint>,
        SignedAnchor<'static>,
        TrustedKey<'static>,
        RecoveryFloor,
    ) {
        let first = digest_snapshot(9, &[8; 32], b"first").unwrap_or([0; 32]);
        let second = digest_snapshot(10, &first, b"second").unwrap_or([0; 32]);
        let checkpoints = vec![
            RestartCheckpoint {
                sequence: 9,
                predecessor_digest: [8; 32],
                snapshot_digest: first,
                committed: true,
                hold: false,
                revoked: false,
            },
            RestartCheckpoint {
                sequence: 10,
                predecessor_digest: first,
                snapshot_digest: second,
                committed: true,
                hold: false,
                revoked: false,
            },
        ];
        let signed = SignedAnchor {
            key_id: "key-a",
            public_key: [5; 32],
            signature: [7; 64],
            anchor: RestartAnchor {
                sequence: 10,
                predecessor_digest: first,
                snapshot_digest: second,
                externally_verified: true,
            },
        };
        let key = TrustedKey {
            key_id: "key-a",
            public_key: [5; 32],
            registry_sequence: 4,
            first_sequence: 9,
            last_sequence: 15,
            revoked: false,
        };
        let floor = RecoveryFloor {
            checkpoint_sequence: 10,
            registry_sequence: 4,
        };
        (checkpoints, signed, key, floor)
    }

    #[test]
    fn linked_and_signed_fixture_is_review_only_with_test_matcher() {
        let (checkpoints, signed, key, floor) = fixture();
        let matcher = ByteMatcher(anchor_message_v2(&signed.anchor, &key).unwrap_or_default());
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            RestartInspection::ReviewOnly
        );
    }

    #[test]
    fn invalid_payload_or_floor_does_not_invoke_external_verifier() {
        let (checkpoints, signed, key, floor) = fixture();
        let verifier = CountingVerifier(std::cell::Cell::new(0));
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"FIRST", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);
        let invalid_floor = RecoveryFloor {
            checkpoint_sequence: 11,
            registry_sequence: 4,
        };
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&invalid_floor),
                &verifier,
            ),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &verifier,
            ),
            RestartInspection::ReviewOnly
        );
        assert_eq!(verifier.0.get(), 1);
    }

    #[test]
    fn actual_rejecting_verifier_denies() {
        let (checkpoints, signed, key, floor) = fixture();
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &RejectAll,
            ),
            RestartInspection::Deny
        );
    }

    #[test]
    fn absent_or_rolled_back_custody_denies() {
        let (checkpoints, signed, key, mut floor) = fixture();
        let matcher = ByteMatcher(anchor_message_v2(&signed.anchor, &key).unwrap_or_default());
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                None,
                &matcher,
            ),
            RestartInspection::Deny
        );
        floor.checkpoint_sequence = 11;
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            RestartInspection::Deny
        );
        floor.checkpoint_sequence = 10;
        floor.registry_sequence = 5;
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            RestartInspection::Deny
        );
    }

    #[test]
    fn tampered_prior_payload_and_revoked_key_deny() {
        let (checkpoints, signed, mut key, floor) = fixture();
        let matcher = ByteMatcher(anchor_message_v2(&signed.anchor, &key).unwrap_or_default());
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"FIRST", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            RestartInspection::Deny
        );
        key.revoked = true;
        assert_eq!(
            inspect_recovery(
                &checkpoints,
                &[b"first", b"second"],
                Some(&signed),
                Some(&key),
                Some(&floor),
                &matcher,
            ),
            RestartInspection::Deny
        );
    }
}
