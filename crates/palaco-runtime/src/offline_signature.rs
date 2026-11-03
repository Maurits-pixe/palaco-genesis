//! Fail-closed boundary for offline manifest signature verification.
//!
//! This is an interface, not an Ed25519 implementation. The production
//! default denies all signatures until a reviewed verifier is integrated.

use crate::offline_manifest::{manifest_root, ManifestEntry, ManifestError};

/// The fixed candidate algorithm for a future reviewed implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Ed25519 candidate only; no cryptographic implementation in this module.
    Ed25519,
}

/// Signature envelope bound to one manifest root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    /// Expected root of the canonical manifest.
    pub manifest_root: [u8; 32],
    /// Identifier of a provisioned key; not a public-key trust assertion.
    pub key_id: String,
    /// Algorithm for the signature bytes.
    pub algorithm: SignatureAlgorithm,
    /// Unverified signature bytes.
    pub signature: [u8; 64],
}

/// Explicit signature boundary failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureGateError {
    /// Invalid envelope metadata.
    InvalidEnvelope,
    /// Root is not valid for the manifest.
    ManifestInvalid,
    /// Signature root and actual manifest root differ.
    RootMismatch,
    /// No approved verifier or provisioned key is available.
    UntrustedSigner,
}

/// Signature implementation interface. Implementations must enforce approved
/// key custody, algorithm policy, key revocation and cryptographic verification.
pub trait OfflineSignatureVerifier {
    /// Verify the envelope, rejecting unknown or revoked signers.
    fn verify_signature(&self, envelope: &SignedManifest) -> bool;
}

/// Default, safe verifier before real signature implementation is reviewed.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllSignatureVerifier;

impl OfflineSignatureVerifier for DenyAllSignatureVerifier {
    fn verify_signature(&self, _envelope: &SignedManifest) -> bool {
        false
    }
}

/// Verify a manifest-root binding and delegate signature validation.
///
/// A custom verifier is trusted code and must undergo independent review.
/// A returned success does not grant runtime authority or prove disk durability.
pub fn check_signed_manifest(
    entries: &[ManifestEntry],
    envelope: &SignedManifest,
    verifier: &impl OfflineSignatureVerifier,
) -> Result<(), SignatureGateError> {
    if envelope.key_id.is_empty()
        || envelope.key_id.len() > 64
        || !envelope
            .key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SignatureGateError::InvalidEnvelope);
    }

    let computed =
        manifest_root(entries).map_err(|_: ManifestError| SignatureGateError::ManifestInvalid)?;
    if computed != envelope.manifest_root {
        return Err(SignatureGateError::RootMismatch);
    }
    if !verifier.verify_signature(envelope) {
        return Err(SignatureGateError::UntrustedSigner);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        check_signed_manifest, DenyAllSignatureVerifier, OfflineSignatureVerifier,
        SignatureAlgorithm, SignatureGateError, SignedManifest,
    };
    use crate::offline_manifest::{manifest_root, ManifestEntry};

    fn fixture() -> (Vec<ManifestEntry>, SignedManifest) {
        let entries = vec![ManifestEntry {
            id: "public-fixture".to_string(),
            bytes: 12,
            sha256: [3_u8; 32],
        }];
        let root = manifest_root(&entries).unwrap_or([0_u8; 32]);
        let signed = SignedManifest {
            manifest_root: root,
            key_id: "test-key".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            signature: [7_u8; 64],
        };
        (entries, signed)
    }

    struct InsecureTestOnlyVerifier;
    impl OfflineSignatureVerifier for InsecureTestOnlyVerifier {
        fn verify_signature(&self, _envelope: &SignedManifest) -> bool {
            true
        }
    }

    #[test]
    fn default_denies_even_a_matching_root() {
        let (entries, signed) = fixture();
        assert_eq!(
            check_signed_manifest(&entries, &signed, &DenyAllSignatureVerifier),
            Err(SignatureGateError::UntrustedSigner)
        );
    }

    #[test]
    fn changed_manifest_is_rejected_before_verifier() {
        let (mut entries, signed) = fixture();
        entries[0].bytes = 13;
        assert_eq!(
            check_signed_manifest(&entries, &signed, &InsecureTestOnlyVerifier),
            Err(SignatureGateError::RootMismatch)
        );
    }

    #[test]
    fn invalid_key_identifier_is_rejected() {
        let (entries, mut signed) = fixture();
        signed.key_id = "../key".to_string();
        assert_eq!(
            check_signed_manifest(&entries, &signed, &InsecureTestOnlyVerifier),
            Err(SignatureGateError::InvalidEnvelope)
        );
    }

    #[test]
    fn invalid_manifest_is_rejected() {
        let (_, signed) = fixture();
        assert_eq!(
            check_signed_manifest(&[], &signed, &InsecureTestOnlyVerifier),
            Err(SignatureGateError::ManifestInvalid)
        );
    }

    #[test]
    fn test_stub_demonstrates_why_a_verifier_needs_review() {
        let (entries, signed) = fixture();
        // The unsafe test stub is intentionally unavailable outside #[cfg(test)].
        assert_eq!(
            check_signed_manifest(&entries, &signed, &InsecureTestOnlyVerifier),
            Ok(())
        );
    }
}
