//! Non-personal, create-only disk staging for bounded offline chunks.
//!
//! Staging is NOT content promotion, encrypted storage, authenticated
//! provenance or crash-durability proof. Never use for private user data.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::offline_integrity::{verify_chunk, ExpectedChunk, MAX_VERIFIED_CHUNK_BYTES};

/// Staging errors; no implicit retry or overwrite.
#[derive(Debug)]
pub enum StagingError {
    /// Invalid identifier or untrusted directory.
    InvalidTarget,
    /// Content digest or declared size is invalid.
    IntegrityFailed,
    /// A pending file already exists.
    AlreadyExists,
    /// Filesystem failure; caller must inspect any incomplete staging file.
    Io(std::io::Error),
}

/// A pathname for an unpromoted public/synthetic chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPublicChunk {
    /// Full path to the still-untrusted pending file.
    pub path: PathBuf,
}

/// Write a verified public/synthetic fixture into a new pending file.
///
/// The caller must supply a private-to-the-process, access-controlled root
/// directory. This method cannot safely handle concurrent hostile writers,
/// symlink swaps, power-loss guarantees or private data.
pub fn stage_public_chunk(
    root: &Path,
    id: &str,
    expected: ExpectedChunk,
    content: &[u8],
) -> Result<PendingPublicChunk, StagingError> {
    let path = pending_path(root, id)?;
    verify_chunk(expected, content).map_err(|_| StagingError::IntegrityFailed)?;

    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(StagingError::AlreadyExists);
        }
        Err(error) => return Err(StagingError::Io(error)),
    };
    file.write_all(content).map_err(StagingError::Io)?;
    file.sync_all().map_err(StagingError::Io)?;
    Ok(PendingPublicChunk { path })
}

/// Re-read a pending chunk and verify it before a separate promotion decision.
///
/// Read-only verification does not mark a generation active or delete files.
pub fn verify_staged_public_chunk(
    root: &Path,
    id: &str,
    expected: ExpectedChunk,
) -> Result<(), StagingError> {
    let path = pending_path(root, id)?;
    if expected.bytes == 0 || expected.bytes > MAX_VERIFIED_CHUNK_BYTES {
        return Err(StagingError::IntegrityFailed);
    }
    let metadata = fs::symlink_metadata(&path).map_err(StagingError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() != expected.bytes as u64 {
        return Err(StagingError::IntegrityFailed);
    }
    let file = File::open(&path).map_err(StagingError::Io)?;
    let mut content = Vec::new();
    file.take((MAX_VERIFIED_CHUNK_BYTES + 1) as u64)
        .read_to_end(&mut content)
        .map_err(StagingError::Io)?;
    verify_chunk(expected, &content).map_err(|_| StagingError::IntegrityFailed)
}

fn pending_path(root: &Path, id: &str) -> Result<PathBuf, StagingError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(StagingError::InvalidTarget);
    }
    let metadata = fs::symlink_metadata(root).map_err(StagingError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(StagingError::InvalidTarget);
    }
    Ok(root.join(format!("pending_{id}.bin")))
}

#[cfg(test)]
mod tests {
    use super::{stage_public_chunk, verify_staged_public_chunk, StagingError};
    use crate::offline_integrity::ExpectedChunk;
    use sha2::{Digest, Sha256};
    use std::fs;

    fn expected(content: &[u8]) -> ExpectedChunk {
        ExpectedChunk {
            sha256: Sha256::digest(content).into(),
            bytes: content.len(),
        }
    }

    #[test]
    fn persisted_fixture_can_be_reverified_without_network() -> Result<(), std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch039-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        let bytes = b"public fixture offline";
        let outcome = stage_public_chunk(&path, "fixture", expected(bytes), bytes);
        assert!(outcome.is_ok());
        assert!(verify_staged_public_chunk(&path, "fixture", expected(bytes)).is_ok());
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn existing_pending_file_is_never_overwritten() -> Result<(), std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch039-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        let bytes = b"original";
        assert!(stage_public_chunk(&path, "same", expected(bytes), bytes).is_ok());
        assert!(matches!(
            stage_public_chunk(&path, "same", expected(bytes), bytes),
            Err(StagingError::AlreadyExists)
        ));
        assert!(verify_staged_public_chunk(&path, "same", expected(bytes)).is_ok());
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn malformed_id_fails_before_write() -> Result<(), std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch039-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        assert!(matches!(
            stage_public_chunk(&path, "../escape", expected(b"x"), b"x"),
            Err(StagingError::InvalidTarget)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn mismatched_payload_is_not_written() -> Result<(), std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch039-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        assert!(matches!(
            stage_public_chunk(&path, "fixture", expected(b"good"), b"evil"),
            Err(StagingError::IntegrityFailed)
        ));
        assert!(!path.join("pending_fixture.bin").exists());
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn tampering_after_write_is_detected() -> Result<(), std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch039-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        let bytes = b"original";
        assert!(stage_public_chunk(&path, "fixture", expected(bytes), bytes).is_ok());
        fs::write(path.join("pending_fixture.bin"), b"modified")?;
        assert!(matches!(
            verify_staged_public_chunk(&path, "fixture", expected(bytes)),
            Err(StagingError::IntegrityFailed)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }
}
