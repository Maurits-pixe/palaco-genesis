//! Versioned JSON transfer between verified ORCHEASTRA snapshots and local files.
//!
//! A caller supplies an independently authenticated recovery anchor.
//! Deserializing and replaying a journal does not authorize any operation.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::chain::ChainedDecision;
use super::file_store::{read_blob, stage_blob, FileStoreError};
use super::persistence::{
    recover_at_anchor, verify_snapshot, JournalSnapshot, StoreError, TrustedRecoveryAnchor,
};
use super::recovery::RecoveryCheckpoint;
use super::tasks::{PlanError, TaskCoordinator, TaskPlan, TaskSpec};

/// The only supported snapshot transfer protocol version.
pub const FORMAT_VERSION: u32 = 1;

/// Errors that prevent local snapshot transfer.
#[derive(Debug)]
pub enum SnapshotFileError {
    /// Local file stage, open or integrity verification failed.
    File(FileStoreError),
    /// JSON encoding or decoding failed.
    Codec(serde_json::Error),
    /// Unsupported snapshot version was supplied.
    WrongVersion,
    /// The task plan did not pass structural validation.
    Plan(PlanError),
    /// The journal did not match the trusted checkpoint.
    Verification(StoreError),
}

/// Canonical wire representation. The plan is reconstructed and validated
/// rather than trusting serialized private graph indexes or cached readiness.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    format_version: u32,
    tasks: Vec<TaskSpec>,
    records: Vec<ChainedDecision>,
    checkpoint: RecoveryCheckpoint,
}

fn to_wire(snapshot: &JournalSnapshot) -> WireSnapshot {
    let tasks = snapshot
        .plan
        .ordered_ids()
        .iter()
        .filter_map(|id| snapshot.plan.task(id).cloned())
        .collect();
    WireSnapshot {
        format_version: FORMAT_VERSION,
        tasks,
        records: snapshot.records.clone(),
        checkpoint: snapshot.checkpoint,
    }
}

/// Convert a verified structured snapshot to versioned JSON bytes.
///
/// The trusted checkpoint must come from an independent source. JSON is an
/// interchange format, not a cryptographic signature or an authority token.
pub fn encode_snapshot(
    snapshot: &JournalSnapshot,
    trusted: &RecoveryCheckpoint,
) -> Result<Vec<u8>, SnapshotFileError> {
    verify_snapshot(snapshot, trusted).map_err(SnapshotFileError::Verification)?;
    serde_json::to_vec(&to_wire(snapshot)).map_err(SnapshotFileError::Codec)
}

/// Decode untrusted JSON and reconstruct its task graph without execution.
///
/// The checkpoint is not trusted because it appears in JSON. A separate,
/// authenticated checkpoint must match it before recovery is possible.
pub fn decode_snapshot(
    bytes: &[u8],
    trusted: &RecoveryCheckpoint,
) -> Result<JournalSnapshot, SnapshotFileError> {
    let wire: WireSnapshot = serde_json::from_slice(bytes).map_err(SnapshotFileError::Codec)?;
    if wire.format_version != FORMAT_VERSION {
        return Err(SnapshotFileError::WrongVersion);
    }
    let plan = TaskPlan::build(wire.tasks).map_err(SnapshotFileError::Plan)?;
    let snapshot = JournalSnapshot {
        plan,
        records: wire.records,
        checkpoint: wire.checkpoint,
    };
    verify_snapshot(&snapshot, trusted).map_err(SnapshotFileError::Verification)?;
    Ok(snapshot)
}

/// Persist an encoded snapshot in an immutable generation-named local file.
///
/// It does not implement distributed CAS. The caller must atomically publish
/// the authenticated checkpoint *separately*, or discard this uncommitted file
/// on restart. This function does not publish a trusted anchor.
pub fn stage_snapshot(
    directory: &Path,
    generation: u64,
    snapshot: &JournalSnapshot,
    trusted: &RecoveryCheckpoint,
) -> Result<PathBuf, SnapshotFileError> {
    let bytes = encode_snapshot(snapshot, trusted)?;
    stage_blob(directory, generation, &bytes).map_err(SnapshotFileError::File)
}

/// Load and verify a local file against an independent trusted generation
/// and checkpoint, returning only an inert, reconstructed coordinator.
///
/// A valid historical `Proposed` decision must never be executed or renewed
/// based on this return value. Recheck all current gates before new proposals.
pub fn load_verified_snapshot(
    path: &Path,
    trusted: &TrustedRecoveryAnchor,
) -> Result<TaskCoordinator, SnapshotFileError> {
    let stored = read_blob(path, trusted.generation).map_err(SnapshotFileError::File)?;
    let snapshot = decode_snapshot(&stored.bytes, &trusted.checkpoint)?;
    recover_at_anchor(&snapshot, stored.generation, trusted)
        .map_err(SnapshotFileError::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::recovery::export_checkpoint;
    use crate::orcheastra::{AdmissionDecision, AdmissionReason};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CASE: AtomicU64 = AtomicU64::new(0);

    fn sample() -> Result<JournalSnapshot, String> {
        let plan = TaskPlan::build([
            TaskSpec {
                id: "identity".to_owned(),
                module: "PALACO One".to_owned(),
                dependencies: vec![],
                evidence_ref: "proof:identity".to_owned(),
            },
            TaskSpec {
                id: "rio".to_owned(),
                module: "RIO".to_owned(),
                dependencies: vec!["identity".to_owned()],
                evidence_ref: "proof:rio".to_owned(),
            },
        ])
        .map_err(|error| format!("{error:?}"))?;
        let mut coordinator = TaskCoordinator::new(plan.clone());
        coordinator
            .record("identity", AdmissionDecision::Proposed, "proof:identity")
            .map_err(|error| format!("{error:?}"))?;
        coordinator
            .record(
                "rio",
                AdmissionDecision::Blocked(AdmissionReason::Hold),
                "proof:rio",
            )
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        Ok(JournalSnapshot {
            plan,
            records,
            checkpoint,
        })
    }

    #[test]
    fn structured_snapshot_survives_file_reopen() -> Result<(), String> {
        let snapshot = sample()?;
        let serial = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "palaco-orcheastra-wire-{}-{serial}",
            std::process::id()
        ));
        let path = stage_snapshot(&dir, 9, &snapshot, &snapshot.checkpoint)
            .map_err(|error| format!("{error:?}"))?;
        let anchor = TrustedRecoveryAnchor {
            generation: 9,
            checkpoint: snapshot.checkpoint,
        };
        let restored =
            load_verified_snapshot(&path, &anchor).map_err(|error| format!("{error:?}"))?;
        assert_eq!(restored.entries().len(), 2);
        assert_eq!(
            restored.entries()[1].decision,
            AdmissionDecision::Blocked(AdmissionReason::Hold)
        );
        fs::remove_dir_all(dir).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn manipulated_checkpoint_is_rejected() -> Result<(), String> {
        let snapshot = sample()?;
        let bytes = encode_snapshot(&snapshot, &snapshot.checkpoint)
            .map_err(|error| format!("{error:?}"))?;
        let mut trusted = snapshot.checkpoint;
        trusted.head = [42u8; 32];
        assert!(matches!(
            decode_snapshot(&bytes, &trusted),
            Err(SnapshotFileError::Verification(_))
        ));
        Ok(())
    }

    #[test]
    fn unsupported_wire_version_is_rejected() -> Result<(), String> {
        let snapshot = sample()?;
        let bytes = encode_snapshot(&snapshot, &snapshot.checkpoint)
            .map_err(|error| format!("{error:?}"))?;
        let mut decoded: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| format!("{error:?}"))?;
        decoded["format_version"] = serde_json::json!(99);
        let future_bytes = serde_json::to_vec(&decoded).map_err(|error| format!("{error:?}"))?;
        assert!(matches!(
            decode_snapshot(&future_bytes, &snapshot.checkpoint),
            Err(SnapshotFileError::WrongVersion)
        ));
        Ok(())
    }
}
