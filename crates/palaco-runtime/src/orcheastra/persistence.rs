//! Persistence boundary for ORCHEASTRA: atomic snapshots, no implicit authority.
//!
//! A production implementation must provide transactional durability and an
//! independently authenticated monotonic checkpoint. This contract itself
//! performs no filesystem or network IO.

use super::chain::{ChainedDecision, Digest256};
use super::recovery::{recover_coordinator, RecoveryCheckpoint, RecoveryError};
use super::tasks::{TaskCoordinator, TaskPlan};

/// A complete snapshot that must be written atomically by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSnapshot {
    /// Validated task plan stored with the journal.
    pub plan: TaskPlan,
    /// Recorded decisions and their integrity chain.
    pub records: Vec<ChainedDecision>,
    /// Checkpoint verified against an independently trusted anchor.
    pub checkpoint: RecoveryCheckpoint,
}

/// Versioned write result used to prevent lost updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedVersion {
    /// Monotonic, externally authenticated generation of a stored snapshot.
    pub generation: u64,
    /// SHA-256 head that was committed at that generation.
    pub head: Digest256,
}

/// Storage contract failures, never treated as authorization to continue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No independently trusted head was available.
    MissingTrustedAnchor,
    /// The trusted checkpoint does not match the submitted journal.
    InvalidSnapshot(RecoveryError),
    /// Another writer changed the authoritative generation.
    ConcurrentModification,
    /// A durable transaction could not be completed.
    TransactionFailed,
}

/// Atomic snapshot persistence boundary.
///
/// Implementations MUST commit the plan, records, checkpoint and generation
/// in one durable transaction, and MUST enforce an independently anchored
/// compare-and-swap generation. Successful persistence is not permission
/// to perform any task.
pub trait SnapshotStore {
    /// Transactionally persist a verified snapshot if the expected generation
    /// is still current, returning the independently anchored new generation.
    fn compare_and_swap(
        &mut self,
        expected: CommittedVersion,
        snapshot: &JournalSnapshot,
    ) -> Result<CommittedVersion, StoreError>;
}

/// Verify an immutable snapshot before invoking any storage backend.
///
/// The `trusted` argument must come from an independent authenticated
/// service and must not be copied from the untrusted snapshot.
pub fn verify_snapshot(
    snapshot: &JournalSnapshot,
    trusted: &RecoveryCheckpoint,
) -> Result<TaskCoordinator, StoreError> {
    if &snapshot.checkpoint != trusted {
        return Err(StoreError::MissingTrustedAnchor);
    }
    recover_coordinator(snapshot.plan.clone(), &snapshot.records, trusted)
        .map_err(StoreError::InvalidSnapshot)
}

/// Persist a verified snapshot using backend-provided transactional semantics.
///
/// The caller must obtain both `trusted` and `expected` from authenticated,
/// rollback-resistant channels. This function never executes the proposals.
pub fn commit_verified<S: SnapshotStore>(
    store: &mut S,
    snapshot: &JournalSnapshot,
    trusted: &RecoveryCheckpoint,
    expected: CommittedVersion,
) -> Result<CommittedVersion, StoreError> {
    verify_snapshot(snapshot, trusted)?;
    store.compare_and_swap(expected, snapshot)
}

/// Verified recovery anchor with an externally trusted monotonic generation.
///
/// The generation MUST be obtained from a separate, authenticated and
/// rollback-resistant source. This record is not a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedRecoveryAnchor {
    /// Generation known to have been committed.
    pub generation: u64,
    /// Checkpoint bound to that generation.
    pub checkpoint: RecoveryCheckpoint,
}

/// Recover a journal only when its generation equals the independent anchor.
///
/// A snapshot with a correct hash but from an older generation cannot silently
/// replace the latest trusted state. The function is read-only and never
/// resumes execution, renews authority, or bypasses revocation.
pub fn recover_at_anchor(
    snapshot: &JournalSnapshot,
    observed_generation: u64,
    trusted: &TrustedRecoveryAnchor,
) -> Result<TaskCoordinator, StoreError> {
    if observed_generation != trusted.generation {
        return Err(StoreError::ConcurrentModification);
    }
    verify_snapshot(snapshot, &trusted.checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::recovery::export_checkpoint;
    use crate::orcheastra::tasks::TaskSpec;

    struct RejectingStore;

    impl SnapshotStore for RejectingStore {
        fn compare_and_swap(
            &mut self,
            _: CommittedVersion,
            _: &JournalSnapshot,
        ) -> Result<CommittedVersion, StoreError> {
            Err(StoreError::ConcurrentModification)
        }
    }

    #[derive(Default)]
    struct SimulatedStore {
        generation: u64,
        committed: Option<JournalSnapshot>,
        interrupt_next: bool,
    }

    impl SnapshotStore for SimulatedStore {
        fn compare_and_swap(
            &mut self,
            expected: CommittedVersion,
            snapshot: &JournalSnapshot,
        ) -> Result<CommittedVersion, StoreError> {
            let head = self
                .committed
                .as_ref()
                .map_or([0u8; 32], |current| current.checkpoint.head);
            if expected.generation != self.generation || expected.head != head {
                return Err(StoreError::ConcurrentModification);
            }
            if self.interrupt_next {
                self.interrupt_next = false;
                return Err(StoreError::TransactionFailed);
            }
            let next = self
                .generation
                .checked_add(1)
                .ok_or(StoreError::TransactionFailed)?;
            self.committed = Some(snapshot.clone());
            self.generation = next;
            Ok(CommittedVersion {
                generation: next,
                head: snapshot.checkpoint.head,
            })
        }
    }

    #[test]
    fn interrupted_write_does_not_publish_partial_snapshot() -> Result<(), String> {
        let snapshot = snapshot()?;
        let mut store = SimulatedStore {
            interrupt_next: true,
            ..SimulatedStore::default()
        };
        let before = CommittedVersion {
            generation: 0,
            head: [0u8; 32],
        };
        assert_eq!(
            commit_verified(&mut store, &snapshot, &snapshot.checkpoint, before),
            Err(StoreError::TransactionFailed)
        );
        assert!(store.committed.is_none());
        assert_eq!(store.generation, 0);
        let after = commit_verified(&mut store, &snapshot, &snapshot.checkpoint, before)
            .map_err(|err| format!("{err:?}"))?;
        assert_eq!(after.generation, 1);
        assert_eq!(after.head, snapshot.checkpoint.head);
        assert_eq!(
            commit_verified(&mut store, &snapshot, &snapshot.checkpoint, before),
            Err(StoreError::ConcurrentModification)
        );
        Ok(())
    }

    fn snapshot() -> Result<JournalSnapshot, String> {
        let plan = TaskPlan::build([TaskSpec {
            id: "one".to_owned(),
            module: "PALACO One".to_owned(),
            dependencies: vec![],
            evidence_ref: "proof:one".to_owned(),
        }])
        .map_err(|err| format!("{err:?}"))?;
        let coordinator = TaskCoordinator::new(plan.clone());
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|err| format!("{err:?}"))?;
        Ok(JournalSnapshot {
            plan,
            records,
            checkpoint,
        })
    }

    #[test]
    fn old_generation_is_rejected_even_with_valid_chain() -> Result<(), String> {
        let snapshot = snapshot()?;
        let anchor = TrustedRecoveryAnchor {
            generation: 7,
            checkpoint: snapshot.checkpoint,
        };
        assert!(matches!(
            recover_at_anchor(&snapshot, 6, &anchor),
            Err(StoreError::ConcurrentModification)
        ));
        let restored = recover_at_anchor(&snapshot, 7, &anchor)
            .map_err(|err| format!("{err:?}"))?;
        assert!(restored.entries().is_empty());
        Ok(())
    }

    #[test]
    fn authenticated_snapshot_can_be_replayed_without_executing() -> Result<(), String> {
        let snapshot = snapshot()?;
        let recovered =
            verify_snapshot(&snapshot, &snapshot.checkpoint).map_err(|err| format!("{err:?}"))?;
        assert!(recovered.entries().is_empty());
        Ok(())
    }

    #[test]
    fn checkpoint_mismatch_fails_before_storage_call() -> Result<(), String> {
        let snapshot = snapshot()?;
        let mut trusted = snapshot.checkpoint;
        trusted.head = [42u8; 32];
        let version = CommittedVersion {
            generation: 0,
            head: [0u8; 32],
        };
        let result = commit_verified(&mut RejectingStore, &snapshot, &trusted, version);
        assert_eq!(result, Err(StoreError::MissingTrustedAnchor));
        Ok(())
    }

    #[test]
    fn backend_conflict_remains_fail_closed() -> Result<(), String> {
        let snapshot = snapshot()?;
        let version = CommittedVersion {
            generation: 0,
            head: [0u8; 32],
        };
        let result = commit_verified(
            &mut RejectingStore,
            &snapshot,
            &snapshot.checkpoint,
            version,
        );
        assert_eq!(result, Err(StoreError::ConcurrentModification));
        Ok(())
    }
}
