//! Read-only offline staging recovery inspection after restart.
//!
//! This module does not delete, repair, promote, or authorize any content.

use std::{io::ErrorKind, path::Path};

use crate::{
    offline_integrity::ExpectedChunk,
    offline_staging::{verify_staged_public_chunk, StagingError},
};

/// Upper bound for recovery inspection of a single batch.
pub const MAX_RECOVERY_ITEMS: usize = 4_096;

/// Expected public/synthetic pending content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPending {
    /// Safe identifier in a trusted staging root.
    pub id: String,
    /// Expected size and digest from a separate manifest.
    pub chunk: ExpectedChunk,
}

/// Read-only inspection result per pending artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingState {
    /// File was present and its SHA-256 matched.
    MatchesExpected,
    /// File is not present in the staging root.
    Missing,
    /// File exists but content/size differs.
    Corrupt,
    /// Access is unsafe or a filesystem error prevents verification.
    Inaccessible,
}

/// Inspection report. This is not a trusted recovery receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Stable, input-order states and identifiers.
    pub items: Vec<(String, PendingState)>,
}

impl RecoveryReport {
    /// Whether all nonempty inspected items passed digest verification.
    #[must_use]
    pub fn all_match(&self) -> bool {
        !self.items.is_empty()
            && self
                .items
                .iter()
                .all(|(_, state)| *state == PendingState::MatchesExpected)
    }
}

/// Batch-level errors before filesystem inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    /// Batch contains no items or exceeds the safety cap.
    InvalidBatch,
    /// Duplicated or malformed identifiers.
    InvalidIdentifier,
}

/// Inspect a trusted-root staging batch after cold start.
///
/// Never turns a matching file into active content; actual promotion requires
/// authenticated manifest, provenance and crash-durable generation semantics.
pub fn inspect_pending(
    root: &Path,
    expected: &[ExpectedPending],
) -> Result<RecoveryReport, RecoveryError> {
    if expected.is_empty() || expected.len() > MAX_RECOVERY_ITEMS {
        return Err(RecoveryError::InvalidBatch);
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in expected {
        if item.id.is_empty()
            || item.id.len() > 64
            || !item
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            || !seen.insert(&item.id)
        {
            return Err(RecoveryError::InvalidIdentifier);
        }
    }

    let items = expected
        .iter()
        .map(|item| {
            let state = match verify_staged_public_chunk(root, &item.id, item.chunk) {
                Ok(()) => PendingState::MatchesExpected,
                Err(StagingError::Io(error)) if error.kind() == ErrorKind::NotFound => {
                    PendingState::Missing
                }
                Err(StagingError::IntegrityFailed) => PendingState::Corrupt,
                Err(StagingError::InvalidTarget)
                | Err(StagingError::AlreadyExists)
                | Err(StagingError::Io(_)) => PendingState::Inaccessible,
            };
            (item.id.clone(), state)
        })
        .collect();
    Ok(RecoveryReport { items })
}

#[cfg(test)]
mod tests {
    use super::{inspect_pending, ExpectedPending, PendingState, RecoveryError};
    use crate::{
        offline_integrity::ExpectedChunk,
        offline_staging::stage_public_chunk,
    };
    use sha2::{Digest, Sha256};
    use std::fs;

    fn entry(id: &str, bytes: &[u8]) -> ExpectedPending {
        ExpectedPending {
            id: id.to_string(),
            chunk: ExpectedChunk {
                sha256: Sha256::digest(bytes).into(),
                bytes: bytes.len(),
            },
        }
    }

    fn isolated_root() -> Result<std::path::PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch040-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    #[test]
    fn cold_restart_inspection_detects_valid_file() -> Result<(), std::io::Error> {
        let root = isolated_root()?;
        let pending = entry("a", b"public fixture");
        assert!(stage_public_chunk(&root, &pending.id, pending.chunk, b"public fixture").is_ok());
        let report = inspect_pending(&root, &[pending]);
        assert!(report.is_ok());
        assert!(report.is_ok_and(|value| value.all_match()));
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn absent_file_is_not_ready() -> Result<(), std::io::Error> {
        let root = isolated_root()?;
        let report = inspect_pending(&root, &[entry("absent", b"expected")]);
        assert_eq!(
            report.map(|value| value.items[0].1),
            Ok(PendingState::Missing)
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn interrupted_partial_write_is_not_ready() -> Result<(), std::io::Error> {
        let root = isolated_root()?;
        fs::write(root.join("pending_a.bin"), b"part")?;
        let report = inspect_pending(&root, &[entry("a", b"complete")]);
        assert_eq!(
            report.map(|value| value.items[0].1),
            Ok(PendingState::Corrupt)
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn duplicate_expected_ids_fail_closed() {
        let item = entry("a", b"fixture");
        assert_eq!(
            inspect_pending(std::path::Path::new("."), &[item.clone(), item]),
            Err(RecoveryError::InvalidIdentifier)
        );
    }

    #[test]
    fn empty_batch_is_not_success() {
        assert_eq!(
            inspect_pending(std::path::Path::new("."), &[]),
            Err(RecoveryError::InvalidBatch)
        );
    }
}
