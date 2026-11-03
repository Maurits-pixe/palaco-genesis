//! SHA-256 content integrity preflight for bounded public offline chunks.
//!
//! A matching digest detects accidental corruption against a trusted expected
//! digest. It does not authenticate that digest, encrypt content or prove disk
//! durability.

use sha2::{Digest, Sha256};

/// Maximum number of bytes accepted by the in-memory verifier (16 MiB).
pub const MAX_VERIFIED_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// A manifest-provided integrity expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedChunk {
    /// Expected digest from a separately trusted manifest.
    pub sha256: [u8; 32],
    /// Exact expected byte count.
    pub bytes: usize,
}

/// Errors when a chunk is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    /// Empty or oversized chunk declaration.
    InvalidSize,
    /// Actual size differs from the trusted manifest.
    SizeMismatch,
    /// Actual content digest differs from the trusted manifest.
    DigestMismatch,
}

/// Verify a public/synthetic chunk fully in memory, with no network access.
///
/// Caller must independently authenticate the manifest. This function does
/// not write, accept, stage, or promote any file.
pub fn verify_chunk(expected: ExpectedChunk, content: &[u8]) -> Result<(), IntegrityError> {
    if expected.bytes == 0 || expected.bytes > MAX_VERIFIED_CHUNK_BYTES {
        return Err(IntegrityError::InvalidSize);
    }
    if content.len() != expected.bytes {
        return Err(IntegrityError::SizeMismatch);
    }

    let actual = Sha256::digest(content);
    if actual.as_slice() != expected.sha256 {
        return Err(IntegrityError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{verify_chunk, ExpectedChunk, IntegrityError, MAX_VERIFIED_CHUNK_BYTES};
    use sha2::{Digest, Sha256};

    fn expected(bytes: &[u8]) -> ExpectedChunk {
        let digest = Sha256::digest(bytes);
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(&digest);
        ExpectedChunk {
            sha256,
            bytes: bytes.len(),
        }
    }

    #[test]
    fn intact_chunk_passes() {
        let content = b"public PALACO offline fixture";
        assert_eq!(verify_chunk(expected(content), content), Ok(()));
    }

    #[test]
    fn corruption_is_detected() {
        let original = b"public PALACO offline fixture";
        let altered = b"public PALACO offline fixturE";
        assert_eq!(
            verify_chunk(expected(original), altered),
            Err(IntegrityError::DigestMismatch)
        );
    }

    #[test]
    fn truncated_content_is_detected() {
        let original = b"public PALACO offline fixture";
        assert_eq!(
            verify_chunk(expected(original), b"public"),
            Err(IntegrityError::SizeMismatch)
        );
    }

    #[test]
    fn empty_chunks_are_denied() {
        assert_eq!(
            verify_chunk(expected(b""), b""),
            Err(IntegrityError::InvalidSize)
        );
    }

    #[test]
    fn declared_oversize_chunk_is_denied() {
        assert_eq!(
            verify_chunk(
                ExpectedChunk {
                    sha256: [0_u8; 32],
                    bytes: MAX_VERIFIED_CHUNK_BYTES + 1,
                },
                b"sample"
            ),
            Err(IntegrityError::InvalidSize)
        );
    }

    #[test]
    fn unauthenticated_digest_is_not_an_authority_claim() {
        // This proves only that the supplied bytes and supplied digest agree.
        let adversarial = b"attacker-controlled bytes";
        assert_eq!(verify_chunk(expected(adversarial), adversarial), Ok(()));
    }
}
