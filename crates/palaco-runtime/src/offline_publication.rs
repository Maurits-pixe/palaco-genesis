//! No-clobber publication marker for non-personal offline test generations.
//!
//! This publishes an observational marker only, not trusted content,
//! generation authority, or a VACATION MODE READY decision.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 6] = b"PLPUB1";
const FRAME_BYTES: usize = 6 + 8 + 32 + 32;

/// Marker describing a candidate generation; not an authorization receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicCandidateMarker {
    /// Generation sequence from a separately checked plan.
    pub sequence: u64,
    /// Digest of a separately validated manifest.
    pub manifest_root: [u8; 32],
}

/// File operation failures are never silently retried.
#[derive(Debug)]
pub enum MarkerError {
    /// Malformed generation, root or frame.
    InvalidMarker,
    /// Generation marker already exists and must not be replaced.
    AlreadyExists,
    /// Filesystem failure; uncertain write outcome must be inspected.
    Io(std::io::Error),
}

/// Publish one marker with no-replace hard-link creation in a trusted directory.
///
/// The caller must provide an exclusively owned directory on a filesystem
/// supporting hard links and directory sync. No hostile writer protection,
/// cryptographic source trust or power-fail guarantee is implied.
pub fn publish_test_marker(
    root: &Path,
    marker: PublicCandidateMarker,
) -> Result<PathBuf, MarkerError> {
    if marker.sequence == 0 {
        return Err(MarkerError::InvalidMarker);
    }
    validate_root(root)?;
    let final_path = final_path(root, marker.sequence);
    let stage_path = root.join(format!("marker_{}.pending", marker.sequence));
    let frame = encode(marker);

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage_path)
    {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(MarkerError::AlreadyExists);
        }
        Err(error) => return Err(MarkerError::Io(error)),
    };
    file.write_all(&frame).map_err(MarkerError::Io)?;
    file.sync_all().map_err(MarkerError::Io)?;
    drop(file);

    match fs::hard_link(&stage_path, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(MarkerError::AlreadyExists);
        }
        Err(error) => return Err(MarkerError::Io(error)),
    }
    sync_directory(root)?;
    fs::remove_file(&stage_path).map_err(MarkerError::Io)?;
    sync_directory(root)?;
    Ok(final_path)
}

/// Reopen and validate the marker frame after restart.
///
/// Does not establish that the external manifest or content is authentic.
pub fn read_test_marker(root: &Path, sequence: u64) -> Result<PublicCandidateMarker, MarkerError> {
    if sequence == 0 {
        return Err(MarkerError::InvalidMarker);
    }
    validate_root(root)?;
    let path = final_path(root, sequence);
    let metadata = fs::symlink_metadata(&path).map_err(MarkerError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() != FRAME_BYTES as u64 {
        return Err(MarkerError::InvalidMarker);
    }
    let file = File::open(path).map_err(MarkerError::Io)?;
    let mut bytes = Vec::new();
    file.take((FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(MarkerError::Io)?;
    let parsed = decode(&bytes)?;
    if parsed.sequence != sequence {
        return Err(MarkerError::InvalidMarker);
    }
    Ok(parsed)
}

fn validate_root(root: &Path) -> Result<(), MarkerError> {
    let metadata = fs::symlink_metadata(root).map_err(MarkerError::Io)?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(MarkerError::InvalidMarker)
    }
}

fn final_path(root: &Path, sequence: u64) -> PathBuf {
    root.join(format!("marker_{sequence}.bin"))
}

fn sync_directory(root: &Path) -> Result<(), MarkerError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(MarkerError::Io)
}

fn encode(marker: PublicCandidateMarker) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&marker.sequence.to_le_bytes());
    frame.extend_from_slice(&marker.manifest_root);
    let digest = Sha256::digest(&frame);
    frame.extend_from_slice(&digest);
    frame
}

fn decode(frame: &[u8]) -> Result<PublicCandidateMarker, MarkerError> {
    if frame.len() != FRAME_BYTES || !frame.starts_with(MAGIC) {
        return Err(MarkerError::InvalidMarker);
    }
    let payload_end = FRAME_BYTES - 32;
    if Sha256::digest(&frame[..payload_end]).as_slice() != &frame[payload_end..] {
        return Err(MarkerError::InvalidMarker);
    }
    let sequence_bytes: [u8; 8] = frame[MAGIC.len()..(MAGIC.len() + 8)]
        .try_into()
        .map_err(|_| MarkerError::InvalidMarker)?;
    let manifest_root: [u8; 32] = frame[(MAGIC.len() + 8)..payload_end]
        .try_into()
        .map_err(|_| MarkerError::InvalidMarker)?;
    Ok(PublicCandidateMarker {
        sequence: u64::from_le_bytes(sequence_bytes),
        manifest_root,
    })
}

#[cfg(test)]
mod tests {
    use super::{publish_test_marker, read_test_marker, MarkerError, PublicCandidateMarker};
    use std::fs;

    fn root() -> Result<std::path::PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch043-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    fn marker() -> PublicCandidateMarker {
        PublicCandidateMarker {
            sequence: 7,
            manifest_root: [8_u8; 32],
        }
    }

    #[test]
    fn can_reopen_a_synced_marker() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(publish_test_marker(&path, marker()).is_ok());
        assert!(matches!(read_test_marker(&path, 7), Ok(value) if value == marker()));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn duplicate_publication_cannot_replace_existing() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(publish_test_marker(&path, marker()).is_ok());
        assert!(matches!(
            publish_test_marker(&path, marker()),
            Err(MarkerError::AlreadyExists)
        ));
        assert!(matches!(read_test_marker(&path, 7), Ok(value) if value == marker()));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn tampered_published_marker_is_rejected() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(publish_test_marker(&path, marker()).is_ok());
        let file = path.join("marker_7.bin");
        let mut bytes = fs::read(&file)?;
        bytes[16] ^= 1;
        fs::write(file, bytes)?;
        assert!(matches!(
            read_test_marker(&path, 7),
            Err(MarkerError::InvalidMarker)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn zero_generation_is_rejected() -> Result<(), std::io::Error> {
        let path = root()?;
        let invalid = PublicCandidateMarker {
            sequence: 0,
            manifest_root: [0_u8; 32],
        };
        assert!(matches!(
            publish_test_marker(&path, invalid),
            Err(MarkerError::InvalidMarker)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }
    #[test]
    fn abandoned_pending_marker_blocks_replacement() -> Result<(), std::io::Error> {
        let path = root()?;
        let pending = path.join("marker_7.pending");
        fs::write(&pending, b"interrupted write")?;
        assert!(matches!(
            publish_test_marker(&path, marker()),
            Err(MarkerError::AlreadyExists)
        ));
        assert_eq!(fs::read(&pending)?, b"interrupted write");
        assert!(!path.join("marker_7.bin").exists());
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn concurrent_writers_never_replace_a_final_marker() -> Result<(), std::io::Error> {
        let path = root()?;
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| publish_test_marker(&path, marker())))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(Ok(_))))
                .count(),
            1
        );
        assert!(outcomes
            .iter()
            .all(|outcome| matches!(outcome, Ok(Ok(_)) | Ok(Err(MarkerError::AlreadyExists)))));
        assert!(matches!(read_test_marker(&path, 7), Ok(value) if value == marker()));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_root_is_rejected() -> Result<(), std::io::Error> {
        let path = root()?;
        let linked = path.with_extension("symlink");
        std::os::unix::fs::symlink(&path, &linked)?;
        assert!(matches!(
            publish_test_marker(&linked, marker()),
            Err(MarkerError::InvalidMarker)
        ));
        fs::remove_file(&linked)?;
        fs::remove_dir_all(&path)?;
        Ok(())
    }
}
