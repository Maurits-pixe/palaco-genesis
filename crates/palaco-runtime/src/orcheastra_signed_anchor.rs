//! Read-only signed-anchor review policy boundary for ORCHEASTRA.
//!
//! Cryptographic Ed25519 verification is NOT implemented here. A real,
//! independently audited verifier and trusted key registry must be wired in
//! before any external signature can count as verified.

use crate::orcheastra_restart::{RestartAnchor, RestartInspection};

/// Domain separation for signatures over restart anchor records.
pub const ANCHOR_DOMAIN: &[u8] = b"PALACO-ORCHEASTRA-RESTART-ANCHOR-V1\0";

/// New domain binds key identity and registry constraints to the signed bytes.
pub const ANCHOR_DOMAIN_V2: &[u8] = b"PALACO-ORCHEASTRA-RESTART-ANCHOR-V2\0";

/// Upper limit on key identifier length.
pub const MAX_KEY_ID_BYTES: usize = 128;

/// A proposed signature over a checkpoint anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAnchor<'a> {
    /// Exact key identifier supplied with the signature.
    pub key_id: &'a str,
    /// Raw 32-byte Ed25519 public key claimed by the registry.
    pub public_key: [u8; 32],
    /// Raw 64-byte signature supplied by the publisher.
    pub signature: [u8; 64],
    /// Immutable checkpoint anchor being reviewed.
    pub anchor: RestartAnchor,
}

/// Trusted registry record supplied by an independent registry adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey<'a> {
    /// Key identifier.
    pub key_id: &'a str,
    /// Pinned public key bytes.
    pub public_key: [u8; 32],
    /// Registry sequence for this immutable key state.
    pub registry_sequence: u64,
    /// Earliest accepted checkpoint sequence, inclusive.
    pub first_sequence: u64,
    /// Latest accepted checkpoint sequence, inclusive.
    pub last_sequence: u64,
    /// A revoked key must never pass.
    pub revoked: bool,
}

/// Verdict of an external, real cryptographic signature verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerdict {
    /// External verifier confirmed a valid Ed25519 signature.
    Valid,
    /// Invalid, malformed, unsupported, or otherwise unverified.
    Invalid,
}

/// Adapter boundary requiring an independently implemented cryptographic verifier.
///
/// Implementations must strictly verify Ed25519 over the provided exact bytes.
/// No default permissive implementation is supplied.
pub trait Ed25519Verifier {
    /// Checks a signature using the pinned key over the exact message bytes.
    fn verify(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> SignatureVerdict;
}

/// Canonical signed-anchor message, explicitly bound to checkpoint contents.
///
/// The message bytes are domain || sequence (BE) || snapshot digest ||
/// predecessor digest. The independent verifier must consume these bytes.
#[must_use]
pub fn anchor_message(anchor: &RestartAnchor) -> Vec<u8> {
    let mut message = Vec::with_capacity(ANCHOR_DOMAIN.len() + 8 + 32 + 32);
    message.extend_from_slice(ANCHOR_DOMAIN);
    message.extend_from_slice(&anchor.sequence.to_be_bytes());
    message.extend_from_slice(&anchor.snapshot_digest);
    message.extend_from_slice(&anchor.predecessor_digest);
    message
}

/// Constructs the v2 signed message, including the exact pinned key context.
///
/// Layout: domain || key-id length (u16 BE) || key-id bytes || public key ||
/// registry sequence (u64 BE) || first sequence (u64 BE) || last sequence
/// (u64 BE) || anchor sequence (u64 BE) || snapshot digest || predecessor
/// digest. Key identifiers are bounded UTF-8 bytes and cannot be empty.
///
/// This only constructs bytes: it does not authenticate the registry or key.
#[must_use]
pub fn anchor_message_v2(anchor: &RestartAnchor, key: &TrustedKey<'_>) -> Option<Vec<u8>> {
    if key.key_id.is_empty() || key.key_id.len() > MAX_KEY_ID_BYTES {
        return None;
    }
    let key_id_length = u16::try_from(key.key_id.len()).ok()?;
    let mut message =
        Vec::with_capacity(ANCHOR_DOMAIN_V2.len() + 2 + key.key_id.len() + 32 + 32 + 72);
    message.extend_from_slice(ANCHOR_DOMAIN_V2);
    message.extend_from_slice(&key_id_length.to_be_bytes());
    message.extend_from_slice(key.key_id.as_bytes());
    message.extend_from_slice(&key.public_key);
    message.extend_from_slice(&key.registry_sequence.to_be_bytes());
    message.extend_from_slice(&key.first_sequence.to_be_bytes());
    message.extend_from_slice(&key.last_sequence.to_be_bytes());
    message.extend_from_slice(&anchor.sequence.to_be_bytes());
    message.extend_from_slice(&anchor.snapshot_digest);
    message.extend_from_slice(&anchor.predecessor_digest);
    Some(message)
}

/// Enforces pinned-key policy then delegates actual cryptographic validation.
///
/// The pinned registry must come from a trusted, rollback-protected source.
/// Passing these structs from an untrusted caller provides no authentication.
/// Structurally empty signatures are denied before an external verifier call.
/// A positive outcome is still review-only, never execution authorization.
#[must_use]
pub fn inspect_signed_anchor(
    signed: Option<&SignedAnchor<'_>>,
    trusted_key: Option<&TrustedKey<'_>>,
    verifier: &impl Ed25519Verifier,
) -> RestartInspection {
    let (Some(signed), Some(key)) = (signed, trusted_key) else {
        return RestartInspection::Deny;
    };

    if signed.key_id.is_empty()
        || signed.key_id.len() > MAX_KEY_ID_BYTES
        || signed.signature == [0; 64]
        || key.key_id != signed.key_id
        || key.public_key != signed.public_key
        || key.public_key == [0; 32]
        || key.revoked
        || key.registry_sequence == 0
        || key.first_sequence == 0
        || key.first_sequence > key.last_sequence
        || signed.anchor.sequence < key.first_sequence
        || signed.anchor.sequence > key.last_sequence
        || signed.anchor.sequence == 0
        || signed.anchor.snapshot_digest == [0; 32]
        || signed.anchor.predecessor_digest == [0; 32]
        || !signed.anchor.externally_verified
    {
        return RestartInspection::Deny;
    }

    let Some(message) = anchor_message_v2(&signed.anchor, key) else {
        return RestartInspection::Deny;
    };
    if verifier.verify(&key.public_key, &message, &signed.signature) != SignatureVerdict::Valid {
        return RestartInspection::Deny;
    }

    RestartInspection::ReviewOnly
}

#[cfg(test)]
mod tests {
    use super::{
        anchor_message, anchor_message_v2, inspect_signed_anchor, Ed25519Verifier,
        SignatureVerdict, SignedAnchor, TrustedKey, ANCHOR_DOMAIN, ANCHOR_DOMAIN_V2,
        MAX_KEY_ID_BYTES,
    };
    use crate::orcheastra_restart::{RestartAnchor, RestartInspection};

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

    // Test-only callback counter. It does not perform cryptographic verification.
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

    fn fixture() -> (SignedAnchor<'static>, TrustedKey<'static>) {
        (
            SignedAnchor {
                key_id: "owner-key-a",
                public_key: [4; 32],
                signature: [8; 64],
                anchor: RestartAnchor {
                    sequence: 14,
                    snapshot_digest: [2; 32],
                    predecessor_digest: [3; 32],
                    externally_verified: true,
                },
            },
            TrustedKey {
                key_id: "owner-key-a",
                public_key: [4; 32],
                registry_sequence: 1,
                first_sequence: 10,
                last_sequence: 20,
                revoked: false,
            },
        )
    }

    #[test]
    fn malformed_signature_and_key_context_precede_verifier_call() {
        let (signed, key) = fixture();
        let verifier = CountingVerifier(std::cell::Cell::new(0));
        let zero_signature = SignedAnchor {
            signature: [0; 64],
            ..signed.clone()
        };
        assert_eq!(
            inspect_signed_anchor(Some(&zero_signature), Some(&key), &verifier),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);

        let empty_key_id = SignedAnchor {
            key_id: "",
            ..signed.clone()
        };
        assert_eq!(
            inspect_signed_anchor(Some(&empty_key_id), Some(&key), &verifier),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);

        let mut invalid_registry = key.clone();
        invalid_registry.registry_sequence = 0;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&invalid_registry), &verifier),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);

        let unverified_anchor = SignedAnchor {
            anchor: RestartAnchor {
                externally_verified: false,
                ..signed.anchor
            },
            ..signed.clone()
        };
        assert_eq!(
            inspect_signed_anchor(Some(&unverified_anchor), Some(&key), &verifier),
            RestartInspection::Deny
        );
        assert_eq!(verifier.0.get(), 0);

        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &verifier),
            RestartInspection::ReviewOnly
        );
        assert_eq!(verifier.0.get(), 1);
    }

    #[test]
    fn no_crypto_verifier_means_deny() {
        let (signed, key) = fixture();
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &RejectAll),
            RestartInspection::Deny
        );
    }

    #[test]
    fn missing_registry_or_signature_denies() {
        let (signed, key) = fixture();
        assert_eq!(
            inspect_signed_anchor(None, Some(&key), &RejectAll),
            RestartInspection::Deny
        );
        assert_eq!(
            inspect_signed_anchor(Some(&signed), None, &RejectAll),
            RestartInspection::Deny
        );
    }

    #[test]
    fn revoked_or_mismatched_key_denies() {
        let (signed, mut key) = fixture();
        key.revoked = true;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &RejectAll),
            RestartInspection::Deny
        );
        key.revoked = false;
        key.public_key[0] ^= 1;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &RejectAll),
            RestartInspection::Deny
        );
    }

    #[test]
    fn out_of_window_and_unverified_anchor_deny() {
        let (mut signed, key) = fixture();
        signed.anchor.sequence = 21;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &RejectAll),
            RestartInspection::Deny
        );
        signed.anchor.sequence = 14;
        signed.anchor.externally_verified = false;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &RejectAll),
            RestartInspection::Deny
        );
    }

    #[test]
    fn canonical_message_binds_all_anchor_fields() {
        let (signed, _) = fixture();
        let bytes = anchor_message(&signed.anchor);
        assert!(bytes.starts_with(ANCHOR_DOMAIN));
        assert_eq!(bytes.len(), ANCHOR_DOMAIN.len() + 72);
        let mut changed = signed.anchor;
        changed.snapshot_digest[0] ^= 1;
        assert_ne!(bytes, anchor_message(&changed));
        changed = signed.anchor;
        changed.sequence += 1;
        assert_ne!(bytes, anchor_message(&changed));
    }

    #[test]
    fn oversized_identifier_and_invalid_registry_version_deny() {
        let (signed, mut key) = fixture();
        key.registry_sequence = 0;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &RejectAll),
            RestartInspection::Deny
        );
        let long_id = "x".repeat(MAX_KEY_ID_BYTES + 1);
        let long_signed = SignedAnchor {
            key_id: &long_id,
            ..signed
        };
        let long_key = TrustedKey {
            key_id: &long_id,
            registry_sequence: 1,
            ..key
        };
        assert_eq!(
            inspect_signed_anchor(Some(&long_signed), Some(&long_key), &RejectAll),
            RestartInspection::Deny
        );
    }
    /// Test-only adapter that checks the message transport contract, NOT Ed25519.
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

    #[test]
    fn v2_message_binds_registry_and_key_identity() {
        let (signed, key) = fixture();
        let message = anchor_message_v2(&signed.anchor, &key).unwrap_or_default();
        assert!(!message.is_empty());
        assert!(message.starts_with(ANCHOR_DOMAIN_V2));
        assert_ne!(message, anchor_message(&signed.anchor));
        let mut modified = key.clone();
        modified.registry_sequence += 1;
        assert_ne!(
            Some(message.clone()),
            anchor_message_v2(&signed.anchor, &modified)
        );
        modified = key.clone();
        modified.first_sequence += 1;
        assert_ne!(
            Some(message.clone()),
            anchor_message_v2(&signed.anchor, &modified)
        );
        modified = key.clone();
        modified.last_sequence -= 1;
        assert_ne!(
            Some(message.clone()),
            anchor_message_v2(&signed.anchor, &modified)
        );
        modified = key.clone();
        modified.key_id = "other-key-a";
        assert_ne!(
            Some(message.clone()),
            anchor_message_v2(&signed.anchor, &modified)
        );
        modified = key.clone();
        modified.public_key[0] ^= 1;
        assert_ne!(Some(message), anchor_message_v2(&signed.anchor, &modified));
    }

    #[test]
    fn v2_review_boundary_receives_key_bound_message() {
        let (signed, key) = fixture();
        let message = anchor_message_v2(&signed.anchor, &key).unwrap_or_default();
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&key), &MessageMatcher(message.clone())),
            RestartInspection::ReviewOnly
        );
        let mut changed = key.clone();
        changed.registry_sequence += 1;
        assert_eq!(
            inspect_signed_anchor(Some(&signed), Some(&changed), &MessageMatcher(message)),
            RestartInspection::Deny
        );
    }

    #[test]
    fn v2_rejects_empty_and_oversized_key_identifiers() {
        let (signed, mut key) = fixture();
        key.key_id = "";
        assert_eq!(anchor_message_v2(&signed.anchor, &key), None);
        let long_id = "x".repeat(MAX_KEY_ID_BYTES + 1);
        key.key_id = &long_id;
        assert_eq!(anchor_message_v2(&signed.anchor, &key), None);
    }
}
