//! Create-only public checkpoint files; never trusted anchor provenance.
//!
//! Requires an exclusively controlled directory. Whole-directory rollback and
//! hostile concurrent writers are outside this fixture storage contract.

use crate::offline_revocation_checkpoint::RevocationCheckpoint;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"PLANCH01";
const FRAME_BYTES: usize = 88;

/// Storage error; failed writes can leave evidence requiring inspection.
#[derive(Debug)]
pub enum CheckpointStoreError {
    /// Invalid root, checkpoint or stored frame.
    Invalid,
    /// Revision already exists, possibly as an interrupted write.
    AlreadyExists,
    /// Filesystem failure with an uncertain write outcome.
    Io(std::io::Error),
}

/// Write one public checkpoint without replacement, then sync file and directory.
///
/// No cleanup, automatic retry, trust promotion, or power-loss guarantee.
/// Caller must prevent hostile mutation of the directory and its ancestors.
pub fn persist_checkpoint(
    root: &Path,
    checkpoint: &RevocationCheckpoint,
) -> Result<PathBuf, CheckpointStoreError> {
    validate_root(root)?;
    if checkpoint.revision == 0 || !checkpoint.is_well_formed() {
        return Err(CheckpointStoreError::Invalid);
    }
    let path = checkpoint_path(root, checkpoint.revision);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                CheckpointStoreError::AlreadyExists
            } else {
                CheckpointStoreError::Io(error)
            }
        })?;
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&checkpoint.revision.to_be_bytes());
    frame.extend_from_slice(&checkpoint.policy_epoch.to_be_bytes());
    frame.extend_from_slice(&checkpoint.registry_digest);
    frame.extend_from_slice(&checkpoint.commitment);
    file.write_all(&frame).map_err(CheckpointStoreError::Io)?;
    file.sync_all().map_err(CheckpointStoreError::Io)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(CheckpointStoreError::Io)?;
    Ok(path)
}

/// Reopen an explicit revision as untrusted evidence, never as ExternalAnchor.
///
/// Rejects partial, oversized, corrupt and mismatched revision frames.
/// Does not select a latest revision or prove authenticity or rollback safety.
pub fn read_checkpoint(
    root: &Path,
    revision: u64,
) -> Result<RevocationCheckpoint, CheckpointStoreError> {
    validate_root(root)?;
    if revision == 0 {
        return Err(CheckpointStoreError::Invalid);
    }
    let path = checkpoint_path(root, revision);
    let metadata = fs::symlink_metadata(&path).map_err(CheckpointStoreError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() != FRAME_BYTES as u64 {
        return Err(CheckpointStoreError::Invalid);
    }
    let mut frame = Vec::new();
    File::open(path)
        .map_err(CheckpointStoreError::Io)?
        .take((FRAME_BYTES + 1) as u64)
        .read_to_end(&mut frame)
        .map_err(CheckpointStoreError::Io)?;
    if frame.len() != FRAME_BYTES || &frame[..8] != MAGIC {
        return Err(CheckpointStoreError::Invalid);
    }
    let invalid = |_| CheckpointStoreError::Invalid;
    let checkpoint = RevocationCheckpoint {
        revision: u64::from_be_bytes(frame[8..16].try_into().map_err(invalid)?),
        policy_epoch: u64::from_be_bytes(frame[16..24].try_into().map_err(invalid)?),
        registry_digest: frame[24..56].try_into().map_err(invalid)?,
        commitment: frame[56..88].try_into().map_err(invalid)?,
    };
    if checkpoint.revision != revision || !checkpoint.is_well_formed() {
        return Err(CheckpointStoreError::Invalid);
    }
    Ok(checkpoint)
}

fn checkpoint_path(root: &Path, revision: u64) -> PathBuf {
    root.join(format!("checkpoint_{revision}.bin"))
}

fn validate_root(root: &Path) -> Result<(), CheckpointStoreError> {
    if !fs::symlink_metadata(root)
        .map_err(CheckpointStoreError::Io)?
        .file_type()
        .is_dir()
    {
        return Err(CheckpointStoreError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_revocation_checkpoint::{
        assess_checkpoint, propose_anchor, CheckpointAssessment,
    };

    fn root() -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch054-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    #[test]
    fn synced_checkpoint_reopens_without_replacement() -> Result<(), std::io::Error> {
        let root = root()?;
        let checkpoint = RevocationCheckpoint::new(1, 2, [3; 32]);
        assert!(persist_checkpoint(&root, &checkpoint).is_ok());
        assert!(matches!(read_checkpoint(&root, 1), Ok(value) if value == checkpoint));
        assert!(matches!(
            persist_checkpoint(&root, &checkpoint),
            Err(CheckpointStoreError::AlreadyExists)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn interrupted_write_is_preserved_and_denied() -> Result<(), std::io::Error> {
        let root = root()?;
        let path = checkpoint_path(&root, 1);
        fs::write(&path, b"interrupted")?;
        assert!(matches!(
            read_checkpoint(&root, 1),
            Err(CheckpointStoreError::Invalid)
        ));
        assert!(matches!(
            persist_checkpoint(&root, &RevocationCheckpoint::new(1, 2, [3; 32])),
            Err(CheckpointStoreError::AlreadyExists)
        ));
        assert_eq!(fs::read(path)?, b"interrupted");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupt_wrong_revision_and_oversized_frames_are_denied() -> Result<(), std::io::Error> {
        let root = root()?;
        let checkpoint = RevocationCheckpoint::new(1, 2, [3; 32]);
        assert!(persist_checkpoint(&root, &checkpoint).is_ok());
        fs::copy(checkpoint_path(&root, 1), checkpoint_path(&root, 2))?;
        assert!(matches!(
            read_checkpoint(&root, 2),
            Err(CheckpointStoreError::Invalid)
        ));
        let mut bytes = fs::read(checkpoint_path(&root, 1))?;
        bytes[24] ^= 1;
        fs::write(checkpoint_path(&root, 1), &bytes)?;
        assert!(matches!(
            read_checkpoint(&root, 1),
            Err(CheckpointStoreError::Invalid)
        ));
        bytes.push(0);
        fs::write(checkpoint_path(&root, 1), bytes)?;
        assert!(matches!(
            read_checkpoint(&root, 1),
            Err(CheckpointStoreError::Invalid)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn reopened_old_state_requires_separate_anchor() -> Result<(), std::io::Error> {
        let root = root()?;
        let old = RevocationCheckpoint::new(1, 2, [3; 32]);
        let current = RevocationCheckpoint::new(2, 2, [4; 32]);
        assert!(persist_checkpoint(&root, &old).is_ok());
        let loaded = read_checkpoint(&root, 1).map_err(|_| std::io::Error::other("read failed"))?;
        let anchor = propose_anchor(&current);
        assert_eq!(
            assess_checkpoint(&loaded, anchor.as_ref()),
            CheckpointAssessment::RollbackDetected
        );
        assert_eq!(
            assess_checkpoint(&loaded, None),
            CheckpointAssessment::MissingAnchor
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn concurrent_creation_has_exactly_one_winner() -> Result<(), std::io::Error> {
        let root = root()?;
        let checkpoint = RevocationCheckpoint::new(1, 2, [3; 32]);
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| persist_checkpoint(&root, &checkpoint)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| matches!(value, Ok(Ok(_))))
                .count(),
            1
        );
        assert!(outcomes
            .iter()
            .all(|value| matches!(value, Ok(Ok(_)) | Ok(Err(CheckpointStoreError::AlreadyExists)))));
        assert!(matches!(read_checkpoint(&root, 1), Ok(value) if value == checkpoint));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_file_is_denied() -> Result<(), std::io::Error> {
        let root = root()?;
        let target = root.join("target");
        fs::write(&target, [0; FRAME_BYTES])?;
        std::os::unix::fs::symlink(target, checkpoint_path(&root, 1))?;
        assert!(matches!(
            read_checkpoint(&root, 1),
            Err(CheckpointStoreError::Invalid)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
