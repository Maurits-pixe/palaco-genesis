//! Read-only inspection of abandoned candidate publication files.
//!
//! Orphan detection never deletes, repairs, renames, or authorizes data.

use std::{
    fs::{self, File},
    io::{Read, ErrorKind},
    path::Path,
};

use sha2::{Digest, Sha256};

/// Maximum pending marker bytes accepted for diagnostic hashing.
pub const MAX_ORPHAN_BYTES: u64 = 1_024;

/// Result of a local candidate marker inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanState {
    /// No pending marker exists.
    NoPending,
    /// Pending data exists but no published name exists.
    PendingOnly,
    /// Both pending and published names exist.
    PendingAndPublished,
}

/// Diagnostic receipt; not trusted provenance or recovery authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrphanInspection {
    /// Candidate sequence.
    pub sequence: u64,
    /// Observed pending state.
    pub state: OrphanState,
    /// Byte length of pending data, when present.
    pub pending_bytes: Option<u64>,
    /// SHA-256 of pending bytes, when present.
    pub pending_sha256: Option<[u8; 32]>,
}

/// Fail-closed diagnostic failures.
#[derive(Debug)]
pub enum OrphanError {
    /// Invalid identifier or untrusted object type.
    InvalidTarget,
    /// Pending data is too large to inspect safely.
    Oversized,
    /// Read or metadata operation failed.
    Io(std::io::Error),
}

/// Inspect one possible abandoned marker without making filesystem changes.
///
/// The root must be owned exclusively by the calling application. Hostile
/// concurrent mutations are out of scope until descriptor-based I/O exists.
pub fn inspect_marker_orphan(
    root: &Path,
    sequence: u64,
) -> Result<OrphanInspection, OrphanError> {
    if sequence == 0 {
        return Err(OrphanError::InvalidTarget);
    }
    let root_metadata = fs::symlink_metadata(root).map_err(OrphanError::Io)?;
    if !root_metadata.file_type().is_dir() {
        return Err(OrphanError::InvalidTarget);
    }

    let pending = root.join(format!("marker_{sequence}.pending"));
    let published = root.join(format!("marker_{sequence}.bin"));
    let pending_metadata = match fs::symlink_metadata(&pending) {
        Ok(value) => Some(value),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(OrphanError::Io(error)),
    };
    let Some(metadata) = pending_metadata else {
        return Ok(OrphanInspection {
            sequence,
            state: OrphanState::NoPending,
            pending_bytes: None,
            pending_sha256: None,
        });
    };
    if !metadata.file_type().is_file() {
        return Err(OrphanError::InvalidTarget);
    }
    if metadata.len() > MAX_ORPHAN_BYTES {
        return Err(OrphanError::Oversized);
    }

    let published_exists = match fs::symlink_metadata(published) {
        Ok(value) if value.file_type().is_file() => true,
        Ok(_) => return Err(OrphanError::InvalidTarget),
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => return Err(OrphanError::Io(error)),
    };
    let file = File::open(pending).map_err(OrphanError::Io)?;
    let mut data = Vec::new();
    file.take(MAX_ORPHAN_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(OrphanError::Io)?;
    if data.len() as u64 > MAX_ORPHAN_BYTES {
        return Err(OrphanError::Oversized);
    }

    Ok(OrphanInspection {
        sequence,
        state: if published_exists {
            OrphanState::PendingAndPublished
        } else {
            OrphanState::PendingOnly
        },
        pending_bytes: Some(data.len() as u64),
        pending_sha256: Some(Sha256::digest(&data).into()),
    })
}

#[cfg(test)]
mod tests {
    use super::{inspect_marker_orphan, OrphanError, OrphanState};
    use std::fs;

    fn root() -> Result<std::path::PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch045-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    #[test]
    fn missing_pending_is_observed_without_mutation() -> Result<(), std::io::Error> {
        let path = root()?;
        let inspection = inspect_marker_orphan(&path, 7);
        assert!(matches!(inspection, Ok(value) if value.state == OrphanState::NoPending));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn abandoned_pending_is_observed_and_preserved() -> Result<(), std::io::Error> {
        let path = root()?;
        let pending = path.join("marker_7.pending");
        fs::write(&pending, b"partial marker")?;
        let inspection = inspect_marker_orphan(&path, 7);
        assert!(matches!(inspection, Ok(value) if value.state == OrphanState::PendingOnly));
        assert_eq!(fs::read(&pending)?, b"partial marker");
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn completed_link_with_pending_is_classified() -> Result<(), std::io::Error> {
        let path = root()?;
        let pending = path.join("marker_7.pending");
        fs::write(&pending, b"fixture")?;
        fs::hard_link(&pending, path.join("marker_7.bin"))?;
        let inspection = inspect_marker_orphan(&path, 7);
        assert!(matches!(
            inspection,
            Ok(value) if value.state == OrphanState::PendingAndPublished
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn oversized_marker_is_rejected_without_deletion() -> Result<(), std::io::Error> {
        let path = root()?;
        let pending = path.join("marker_7.pending");
        fs::write(&pending, vec![0_u8; 1_025])?;
        assert!(matches!(
            inspect_marker_orphan(&path, 7),
            Err(OrphanError::Oversized)
        ));
        assert!(pending.exists());
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pending_is_rejected() -> Result<(), std::io::Error> {
        let path = root()?;
        let target = path.join("untrusted");
        fs::write(&target, b"fixture")?;
        std::os::unix::fs::symlink(&target, path.join("marker_7.pending"))?;
        assert!(matches!(
            inspect_marker_orphan(&path, 7),
            Err(OrphanError::InvalidTarget)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }
}
