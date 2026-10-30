//! Detached Ed25519 signature check for canonical PALACO Harbor evidence bytes.
//!
//! This checks a signature only. Key trust, key revocation, time, consent,
//! scope, and evidence-to-request binding remain independent gates. A caller
//! cannot treat a valid signature as an authorization decision.

use ed25519_dalek::{Signature, VerifyingKey};

const DOMAIN: &[u8] = b"PALACO-HARBOR-ED25519-EVIDENCE-v1\0";
const MAX_EVIDENCE_BYTES: usize = 65_536;

/// A structural or cryptographic signature-check failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheckError {
    MissingPayload,
    OversizedPayload,
    InvalidPublicKey,
    InvalidSignature,
}

/// Verify the signature of exact evidence bytes with domain separation.
///
/// The public key must be authorized and current by a distinct governed
/// trust-root service; this function does not know whether it is trusted.
pub fn verify_detached_signature(
    public_key: &[u8; 32],
    evidence_bytes: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), SignatureCheckError> {
    if evidence_bytes.is_empty() {
        return Err(SignatureCheckError::MissingPayload);
    }
    if evidence_bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(SignatureCheckError::OversizedPayload);
    }
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SignatureCheckError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature_bytes);
    let mut message = Vec::with_capacity(DOMAIN.len() + evidence_bytes.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(evidence_bytes);
    key.verify_strict(&message, &signature)
        .map_err(|_| SignatureCheckError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::{verify_detached_signature, SignatureCheckError, DOMAIN};
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(data: &[u8]) -> ([u8; 32], [u8; 64]) {
        // Fixed deterministic test key only; never configured for production.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(data);
        let signature = signing.sign(&message);
        (signing.verifying_key().to_bytes(), signature.to_bytes())
    }

    #[test]
    fn valid_detached_signature_checks_exact_bytes() {
        let payload = b"subject=person-1;scope=rio:invite";
        let (key, signature) = sign(payload);
        assert_eq!(verify_detached_signature(&key, payload, &signature), Ok(()));
    }

    #[test]
    fn changed_payload_or_signature_fails() {
        let payload = b"scope=rio:invite";
        let (key, mut signature) = sign(payload);
        assert_eq!(
            verify_detached_signature(&key, b"scope=rio:admin", &signature),
            Err(SignatureCheckError::InvalidSignature)
        );
        signature[0] ^= 1;
        assert_eq!(
            verify_detached_signature(&key, payload, &signature),
            Err(SignatureCheckError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_public_key_and_untrusted_message_fail() {
        let payload = b"evidence";
        let (_, signature) = sign(payload);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(
            verify_detached_signature(&other.verifying_key().to_bytes(), payload, &signature),
            Err(SignatureCheckError::InvalidSignature)
        );
    }

    #[test]
    fn empty_or_oversized_payload_rejected_before_crypto() {
        let (key, signature) = sign(b"valid");
        assert_eq!(
            verify_detached_signature(&key, b"", &signature),
            Err(SignatureCheckError::MissingPayload)
        );
        assert_eq!(
            verify_detached_signature(&key, &vec![0u8; 65_537], &signature),
            Err(SignatureCheckError::OversizedPayload)
        );
    }
}
