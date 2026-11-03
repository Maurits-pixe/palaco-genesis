//! Bounded, create-only offline journal snapshot for public test chunks.
//!
//! A journal is observational metadata, NOT a power-loss guarantee,
//! authenticated evidence, or permission to activate offline content.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 5] = b"PLJ01";
const MAX_JOURNAL_BYTES: u64 = 64;

/// Three non-authoritative preparation milestones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalStep {
    /// Preparation started.
    Started,
    /// Caller says its pending data was synchronized.
    DataSynced,
    /// Caller says its pending digest was inspected.
    HashInspected,
}

/// A journal snapshot describes at most three ordered observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSnapshot {
    /// Ordered observations of preparation, never runtime authorization.
    pub steps: Vec<JournalStep>,
}

/// Journal errors.
#[derive(Debug)]
pub enum JournalError {
    /// Identifier or snapshot is invalid.
    InvalidInput,
    /// On-disk frame is truncated, corrupt, or has unexpected content.
    CorruptFrame,
    /// A new journal would replace an existing one.
    AlreadyExists,
    /// Filesystem operation failed.
    Io(std::io::Error),
}

/// Create one immutable journal snapshot, requesting a file sync.
///
/// The root directory must be trusted and exclusive to this process.
/// No automatic cleanup or overwrite is attempted after failures.
pub fn create_journal(
    root: &Path,
    id: &str,
    snapshot: &JournalSnapshot,
) -> Result<(), JournalError> {
    if !valid_sequence(&snapshot.steps) {
        return Err(JournalError::InvalidInput);
    }
    let path = journal_path(root, id)?;
    let frame = encode(&snapshot.steps);
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(JournalError::AlreadyExists);
        }
        Err(error) => return Err(JournalError::Io(error)),
    };
    file.write_all(&frame).map_err(JournalError::Io)?;
    file.sync_all().map_err(JournalError::Io)
}

/// Reopen a journal from disk and verify its bounded frame and digest.
///
/// A matching digest does not prove authentic history; the expected trust
/// anchor and durable generation state are not implemented here.
pub fn read_journal(root: &Path, id: &str) -> Result<JournalSnapshot, JournalError> {
    let path = journal_path(root, id)?;
    let metadata = fs::symlink_metadata(&path).map_err(JournalError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::CorruptFrame);
    }
    let file = fs::File::open(path).map_err(JournalError::Io)?;
    let mut frame = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut frame)
        .map_err(JournalError::Io)?;
    decode(&frame)
}

fn journal_path(root: &Path, id: &str) -> Result<std::path::PathBuf, JournalError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(JournalError::InvalidInput);
    }
    let metadata = fs::symlink_metadata(root).map_err(JournalError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(JournalError::InvalidInput);
    }
    Ok(root.join(format!("journal_{id}.bin")))
}

fn valid_sequence(steps: &[JournalStep]) -> bool {
    !steps.is_empty()
        && steps.len() <= 3
        && steps.iter().enumerate().all(|(i, step)| match (i, step) {
            (0, JournalStep::Started)
            | (1, JournalStep::DataSynced)
            | (2, JournalStep::HashInspected) => true,
            _ => false,
        })
}

fn encode(steps: &[JournalStep]) -> Vec<u8> {
    let mut data = Vec::with_capacity(MAGIC.len() + 1 + steps.len() + 32);
    data.extend_from_slice(MAGIC);
    data.push(steps.len() as u8);
    for step in steps {
        data.push(match step {
            JournalStep::Started => 1,
            JournalStep::DataSynced => 2,
            JournalStep::HashInspected => 3,
        });
    }
    let digest = Sha256::digest(&data);
    data.extend_from_slice(&digest);
    data
}

fn decode(frame: &[u8]) -> Result<JournalSnapshot, JournalError> {
    if frame.len() < MAGIC.len() + 1 + 1 + 32 || !frame.starts_with(MAGIC) {
        return Err(JournalError::CorruptFrame);
    }
    let count = usize::from(frame[MAGIC.len()]);
    if count == 0 || count > 3 || frame.len() != MAGIC.len() + 1 + count + 32 {
        return Err(JournalError::CorruptFrame);
    }
    let split = frame.len() - 32;
    if Sha256::digest(&frame[..split]).as_slice() != &frame[split..] {
        return Err(JournalError::CorruptFrame);
    }
    let steps = frame[(MAGIC.len() + 1)..split]
        .iter()
        .map(|byte| match byte {
            1 => Ok(JournalStep::Started),
            2 => Ok(JournalStep::DataSynced),
            3 => Ok(JournalStep::HashInspected),
            _ => Err(JournalError::CorruptFrame),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !valid_sequence(&steps) {
        return Err(JournalError::CorruptFrame);
    }
    Ok(JournalSnapshot { steps })
}

#[cfg(test)]
mod tests {
    use super::{create_journal, read_journal, JournalError, JournalSnapshot, JournalStep};
    use std::fs;

    fn root() -> Result<std::path::PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch041-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    fn full() -> JournalSnapshot {
        JournalSnapshot {
            steps: vec![
                JournalStep::Started,
                JournalStep::DataSynced,
                JournalStep::HashInspected,
            ],
        }
    }

    #[test]
    fn reopen_complete_snapshot() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(create_journal(&path, "fixture", &full()).is_ok());
        assert!(matches!(
            read_journal(&path, "fixture"),
            Ok(value) if value.steps == full().steps
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn truncated_frame_is_rejected() -> Result<(), std::io::Error> {
        let path = root()?;
        fs::write(path.join("journal_fixture.bin"), b"PLJ01\x03\x01")?;
        assert!(matches!(
            read_journal(&path, "fixture"),
            Err(JournalError::CorruptFrame)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn tampering_is_rejected() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(create_journal(&path, "fixture", &full()).is_ok());
        let file = path.join("journal_fixture.bin");
        let mut bytes = fs::read(&file)?;
        bytes[6] = 3;
        fs::write(file, bytes)?;
        assert!(matches!(
            read_journal(&path, "fixture"),
            Err(JournalError::CorruptFrame)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn duplicate_snapshot_is_never_overwritten() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(create_journal(&path, "fixture", &full()).is_ok());
        assert!(matches!(
            create_journal(&path, "fixture", &full()),
            Err(JournalError::AlreadyExists)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn skipped_milestones_are_invalid() -> Result<(), std::io::Error> {
        let path = root()?;
        let invalid = JournalSnapshot {
            steps: vec![JournalStep::Started, JournalStep::HashInspected],
        };
        assert!(matches!(
            create_journal(&path, "fixture", &invalid),
            Err(JournalError::InvalidInput)
        ));
        fs::remove_dir_all(&path)?;
        Ok(())
    }
}
