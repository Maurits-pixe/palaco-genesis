//! Read-only preflight joining staged chunks, recovery and journal evidence.
//!
//! An inspected candidate is not an authenticated, durable or active generation.

use std::path::Path;

use crate::{
    offline_generation::Generation,
    offline_journal::{read_journal, JournalStep},
    offline_recovery::{inspect_pending, ExpectedPending},
};

/// Result of local non-private candidate inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectedCandidate {
    /// Candidate generation identifier; not promoted.
    pub generation: Generation,
    /// Number of checked non-private chunks.
    pub verified_chunks: u32,
}

/// Reasons candidate inspection remains blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionPreflightError {
    /// Empty, excessive or mismatched generation declaration.
    InvalidGeneration,
    /// The journal does not exist, is damaged, or lacks required milestones.
    JournalNotComplete,
    /// Some expected content is missing, unreadable or corrupted.
    ContentNotVerified,
}

/// Inspect a candidate on disk without activating, modifying or deleting it.
///
/// The supplied expected chunk digests are not yet authenticated; returning
/// Ok is not a signed receipt, no authorization or a durable commit decision.
pub fn inspect_transaction_candidate(
    root: &Path,
    journal_id: &str,
    generation: Generation,
    expected: &[ExpectedPending],
) -> Result<InspectedCandidate, TransactionPreflightError> {
    let expected_count =
        u32::try_from(expected.len()).map_err(|_| TransactionPreflightError::InvalidGeneration)?;
    if generation.sequence == 0
        || generation.artifacts == 0
        || expected_count != generation.artifacts
    {
        return Err(TransactionPreflightError::InvalidGeneration);
    }

    let journal =
        read_journal(root, journal_id).map_err(|_| TransactionPreflightError::JournalNotComplete)?;
    if journal.steps
        != [
            JournalStep::Started,
            JournalStep::DataSynced,
            JournalStep::HashInspected,
        ]
    {
        return Err(TransactionPreflightError::JournalNotComplete);
    }

    let report = inspect_pending(root, expected)
        .map_err(|_| TransactionPreflightError::ContentNotVerified)?;
    if !report.all_match() {
        return Err(TransactionPreflightError::ContentNotVerified);
    }

    Ok(InspectedCandidate {
        generation,
        verified_chunks: expected_count,
    })
}

#[cfg(test)]
mod tests {
    use super::{inspect_transaction_candidate, TransactionPreflightError};
    use crate::{
        offline_generation::Generation,
        offline_integrity::ExpectedChunk,
        offline_journal::{create_journal, JournalSnapshot, JournalStep},
        offline_recovery::ExpectedPending,
        offline_staging::stage_public_chunk,
    };
    use sha2::{Digest, Sha256};
    use std::fs;

    fn root() -> Result<std::path::PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("palaco-orch042-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    fn expected(bytes: &[u8]) -> ExpectedPending {
        ExpectedPending {
            id: "chunk".to_string(),
            chunk: ExpectedChunk {
                sha256: Sha256::digest(bytes).into(),
                bytes: bytes.len(),
            },
        }
    }

    fn generation() -> Generation {
        Generation {
            sequence: 1,
            artifacts: 1,
        }
    }

    fn full_journal() -> JournalSnapshot {
        JournalSnapshot {
            steps: vec![
                JournalStep::Started,
                JournalStep::DataSynced,
                JournalStep::HashInspected,
            ],
        }
    }

    #[test]
    fn complete_candidate_is_only_inspected() -> Result<(), std::io::Error> {
        let path = root()?;
        let chunk = expected(b"public fixture");
        assert!(stage_public_chunk(&path, &chunk.id, chunk.chunk, b"public fixture").is_ok());
        assert!(create_journal(&path, "candidate", &full_journal()).is_ok());
        let result = inspect_transaction_candidate(&path, "candidate", generation(), &[chunk]);
        assert!(result.is_ok());
        assert_eq!(result.map(|value| value.verified_chunks), Ok(1));
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn missing_chunk_is_blocked() -> Result<(), std::io::Error> {
        let path = root()?;
        assert!(create_journal(&path, "candidate", &full_journal()).is_ok());
        assert_eq!(
            inspect_transaction_candidate(
                &path,
                "candidate",
                generation(),
                &[expected(b"missing")]
            ),
            Err(TransactionPreflightError::ContentNotVerified)
        );
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn incomplete_journal_is_blocked() -> Result<(), std::io::Error> {
        let path = root()?;
        let chunk = expected(b"public fixture");
        assert!(stage_public_chunk(&path, &chunk.id, chunk.chunk, b"public fixture").is_ok());
        assert!(create_journal(
            &path,
            "candidate",
            &JournalSnapshot {
                steps: vec![JournalStep::Started]
            }
        )
        .is_ok());
        assert_eq!(
            inspect_transaction_candidate(&path, "candidate", generation(), &[chunk]),
            Err(TransactionPreflightError::JournalNotComplete)
        );
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn wrong_declared_count_is_blocked() -> Result<(), std::io::Error> {
        let path = root()?;
        let generation = Generation {
            sequence: 1,
            artifacts: 2,
        };
        assert_eq!(
            inspect_transaction_candidate(&path, "candidate", generation, &[expected(b"x")]),
            Err(TransactionPreflightError::InvalidGeneration)
        );
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    #[test]
    fn corrupted_chunk_is_blocked() -> Result<(), std::io::Error> {
        let path = root()?;
        let chunk = expected(b"public fixture");
        assert!(stage_public_chunk(&path, &chunk.id, chunk.chunk, b"public fixture").is_ok());
        assert!(create_journal(&path, "candidate", &full_journal()).is_ok());
        fs::write(path.join("pending_chunk.bin"), b"broken fixture")?;
        assert_eq!(
            inspect_transaction_candidate(&path, "candidate", generation(), &[chunk]),
            Err(TransactionPreflightError::ContentNotVerified)
        );
        fs::remove_dir_all(&path)?;
        Ok(())
    }
}
