//! Local-file staging for a serialized ORCHEASTRA snapshot payload.
//!
//! This layer stores *opaque bytes* and checks file integrity. It does not
//! serialize or authenticate a `JournalSnapshot`, nor does it implement the
//! multi-writer `SnapshotStore` transaction contract. No task is executed.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::chain::Digest256;

const MAGIC: &[u8; 16] = b"ORCHEASTRA-FILE1";
const MAX_PAYLOAD: u64 = 64 * 1024 * 1024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

/// Reasons a local staging or verification step fails closed.
#[derive(Debug)]
pub enum FileStoreError {
    /// Filesystem operation failed.
    Io(std::io::Error),
    /// File header or length is malformed.
    InvalidFormat,
    /// Payload exceeds the configured bound.
    TooLarge,
    /// The staged bytes do not match the digest.
    IntegrityMismatch,
    /// Stored generation does not match the independently trusted one.
    GenerationMismatch,
    /// A file already exists at the requested immutable path.
    AlreadyExists,
}

/// A locally stored opaque payload, not an authenticated audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlob {
    /// Number provided by the caller, not proven by local storage.
    pub generation: u64,
    /// Complete serialized payload supplied to the staging adapter.
    pub bytes: Vec<u8>,
    /// SHA-256 digest computed over the payload.
    pub payload_hash: Digest256,
}

fn payload_hash(bytes: &[u8]) -> Digest256 {
    Sha256::digest(bytes).into()
}

/// Write a self-checking payload to a new file in a local directory.
///
/// Creates a unique temporary file, calls `sync_all`, then publishes using an exclusive hard link at
/// `snapshot-{generation:020}.bin` and attempts to sync the directory.
/// Never reuse a generation in a directory. The local filesystem rename is
/// not a trusted multi-process compare-and-swap, and a crash before a trusted
/// external checkpoint is committed MUST be handled by the caller.
pub fn stage_blob(
    directory: &Path,
    generation: u64,
    bytes: &[u8],
) -> Result<PathBuf, FileStoreError> {
    let payload_len = u64::try_from(bytes.len()).map_err(|_| FileStoreError::TooLarge)?;
    if payload_len > MAX_PAYLOAD {
        return Err(FileStoreError::TooLarge);
    }
    fs::create_dir_all(directory).map_err(FileStoreError::Io)?;
    let target = directory.join(format!("snapshot-{generation:020}.bin"));
    if target.exists() {
        return Err(FileStoreError::AlreadyExists);
    }
    let unique = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
    let staged = directory.join(format!(
        ".snapshot-{generation:020}-{}-{unique}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(FileStoreError::Io)?;
    let write_result = (|| {
        file.write_all(MAGIC).map_err(FileStoreError::Io)?;
        file.write_all(&generation.to_be_bytes())
            .map_err(FileStoreError::Io)?;
        file.write_all(&payload_len.to_be_bytes())
            .map_err(FileStoreError::Io)?;
        file.write_all(&payload_hash(bytes))
            .map_err(FileStoreError::Io)?;
        file.write_all(bytes).map_err(FileStoreError::Io)?;
        file.sync_all().map_err(FileStoreError::Io)
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    // An exclusive hard-link publishes the completed inode only if no file
    // already owns this generation. Unlike rename, it never replaces a
    // concurrent writer's file. Filesystems without hard links fail closed.
    if let Err(error) = fs::hard_link(&staged, &target) {
        let _ = fs::remove_file(&staged);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(FileStoreError::AlreadyExists)
        } else {
            Err(FileStoreError::Io(error))
        };
    }
    fs::remove_file(&staged).map_err(FileStoreError::Io)?;
    // Directory durability varies by platform: error rather than claiming a
    // committed trusted checkpoint when sync cannot be completed.
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(FileStoreError::Io)?;
    Ok(target)
}

/// Read a complete file and check the payload digest and trusted generation.
///
/// `trusted_generation` MUST be obtained independently. This function
/// detects corruption but cannot authenticate a maliciously replaced blob.
pub fn read_blob(path: &Path, trusted_generation: u64) -> Result<StoredBlob, FileStoreError> {
    let mut file = File::open(path).map_err(FileStoreError::Io)?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header).map_err(FileStoreError::Io)?;
    if &header[..16] != MAGIC {
        return Err(FileStoreError::InvalidFormat);
    }
    let generation = u64::from_be_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| FileStoreError::InvalidFormat)?,
    );
    if generation != trusted_generation {
        return Err(FileStoreError::GenerationMismatch);
    }
    let length = u64::from_be_bytes(
        header[24..32]
            .try_into()
            .map_err(|_| FileStoreError::InvalidFormat)?,
    );
    if length > MAX_PAYLOAD {
        return Err(FileStoreError::TooLarge);
    }
    let expected_hash: Digest256 = header[32..64]
        .try_into()
        .map_err(|_| FileStoreError::InvalidFormat)?;
    let size = usize::try_from(length).map_err(|_| FileStoreError::TooLarge)?;
    let mut bytes = vec![0u8; size];
    file.read_exact(&mut bytes).map_err(FileStoreError::Io)?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing).map_err(FileStoreError::Io)? != 0 {
        return Err(FileStoreError::InvalidFormat);
    }
    if payload_hash(&bytes) != expected_hash {
        return Err(FileStoreError::IntegrityMismatch);
    }
    Ok(StoredBlob {
        generation,
        bytes,
        payload_hash: expected_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> PathBuf {
        let next = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "palaco-orcheastra-test-{}-{next}",
            std::process::id()
        ))
    }

    #[test]
    fn staged_blob_survives_close_and_reopen() -> Result<(), String> {
        let dir = sandbox();
        let path =
            stage_blob(&dir, 3, b"offline audit sample").map_err(|error| format!("{error:?}"))?;
        let restored = read_blob(&path, 3).map_err(|error| format!("{error:?}"))?;
        assert_eq!(restored.bytes, b"offline audit sample");
        assert_eq!(restored.generation, 3);
        assert!(matches!(
            read_blob(&path, 2),
            Err(FileStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            stage_blob(&dir, 3, b"replace"),
            Err(FileStoreError::AlreadyExists)
        ));
        fs::remove_dir_all(dir).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn modified_payload_is_rejected() -> Result<(), String> {
        let dir = sandbox();
        let path = stage_blob(&dir, 1, b"known").map_err(|error| format!("{error:?}"))?;
        let mut raw = fs::read(&path).map_err(|error| format!("{error:?}"))?;
        let last = raw.len().checked_sub(1).ok_or("empty file")?;
        raw[last] ^= 1;
        fs::write(&path, raw).map_err(|error| format!("{error:?}"))?;
        assert!(matches!(
            read_blob(&path, 1),
            Err(FileStoreError::IntegrityMismatch)
        ));
        fs::remove_dir_all(dir).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn trailing_payload_data_is_rejected() -> Result<(), String> {
        let dir = sandbox();
        let path = stage_blob(&dir, 1, b"known").map_err(|error| format!("{error:?}"))?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|error| format!("{error:?}"))?;
        file.write_all(b"extra")
            .map_err(|error| format!("{error:?}"))?;
        drop(file);
        assert!(matches!(
            read_blob(&path, 1),
            Err(FileStoreError::InvalidFormat)
        ));
        fs::remove_dir_all(dir).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }
}
