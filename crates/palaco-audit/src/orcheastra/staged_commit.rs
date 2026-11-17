//! Stage a validated ORCHEASTRA snapshot before requesting audit publication.
//!
//! The local snapshot is intentionally not authoritative: only a separately
//! authenticated audit checkpoint can make it eligible for recovery. This
//! module never performs actions recorded in the recovered task journal.

use std::path::{Path, PathBuf};

use palaco_runtime::orcheastra::{
    persistence::{JournalSnapshot, TrustedRecoveryAnchor},
    snapshot_file::{load_verified_snapshot, stage_snapshot, SnapshotFileError},
};

use super::{
    publish::{prepare_publication, CheckpointPublisher, PublishError},
    AnchorError, AuditAnchorVerifier,
};

/// Safe publication outcome. This does not convey authority to execute tasks.
#[derive(Debug)]
pub struct StagedPublication {
    /// The immutable local snapshot file, already synced to the extent the
    /// filesystem supports, and referenced by its generation.
    pub path: PathBuf,
    /// Candidate audit anchor accepted by the publisher.
    pub anchor: TrustedRecoveryAnchor,
}

/// Fail-closed staging or audit publication error.
#[derive(Debug)]
pub enum StagePublishError {
    /// No authorized latest anchor was available.
    Anchor(AnchorError),
    /// The candidate is not a strict extension of committed history.
    Proposal(PublishError),
    /// File staging or verification failed.
    File(SnapshotFileError),
    /// Audit publisher did not accept the candidate.
    Commit(AnchorError),
}

/// Stage and verify an immutable local file before audit CAS publication.
///
/// The independent audit source must attest to the latest anchor. On a
/// publisher error, an *unanchored orphan file may remain*: callers MUST
/// ignore it during restart and must not infer a successful commit from its
/// presence. The adapter never retries a conflicted generation automatically.
///
/// Even after CAS success the publisher must separately guarantee durable,
/// authenticated storage and monotonicity; this API is not a transaction
/// spanning local files and an independent audit service.
pub fn stage_then_publish<V: AuditAnchorVerifier, P: CheckpointPublisher>(
    verifier: &V,
    publisher: &mut P,
    journal_id: &str,
    directory: &Path,
    snapshot: &JournalSnapshot,
) -> Result<StagedPublication, StagePublishError> {
    if journal_id.trim().is_empty() {
        return Err(StagePublishError::Anchor(AnchorError::UnauthorizedJournal));
    }
    let previous = verifier
        .latest_anchor(journal_id)
        .map_err(StagePublishError::Anchor)?;
    let proposal = prepare_publication(&previous, snapshot).map_err(StagePublishError::Proposal)?;
    let path = stage_snapshot(
        directory,
        proposal.next.generation,
        snapshot,
        &proposal.next.checkpoint,
    )
    .map_err(StagePublishError::File)?;

    // Validate the exact bytes staged on disk before any publisher is called.
    // This is an integrity check, not independent authentication.
    load_verified_snapshot(&path, &proposal.next).map_err(StagePublishError::File)?;

    publisher
        .compare_and_swap(journal_id, &proposal.expected_previous, &proposal.next)
        .map_err(StagePublishError::Commit)?;
    Ok(StagedPublication {
        path,
        anchor: proposal.next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::recover_from_audit;
    use palaco_runtime::orcheastra::{
        persistence::JournalSnapshot,
        recovery::{export_checkpoint, plan_fingerprint, RecoveryCheckpoint},
        tasks::{TaskCoordinator, TaskPlan, TaskSpec},
        AdmissionDecision,
    };
    use std::{
        cell::RefCell,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_CASE: AtomicU64 = AtomicU64::new(0);

    fn sandbox() -> PathBuf {
        let next = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "palaco-orcheastra-stage-publish-{}-{next}",
            std::process::id()
        ))
    }

    fn fixture() -> Result<(TrustedRecoveryAnchor, JournalSnapshot), String> {
        let plan = TaskPlan::build([TaskSpec {
            id: "identity".to_owned(),
            module: "PALACO One".to_owned(),
            dependencies: vec![],
            evidence_ref: "proof:identity".to_owned(),
        }])
        .map_err(|error| format!("{error:?}"))?;
        let previous = TrustedRecoveryAnchor {
            generation: 0,
            checkpoint: RecoveryCheckpoint {
                plan_hash: plan_fingerprint(&plan),
                sequence: 0,
                head: [0u8; 32],
            },
        };
        let mut coordinator = TaskCoordinator::new(plan.clone());
        coordinator
            .record("identity", AdmissionDecision::Proposed, "proof:identity")
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        Ok((
            previous,
            JournalSnapshot {
                plan,
                records,
                checkpoint,
            },
        ))
    }

    struct SharedAudit {
        current: RefCell<TrustedRecoveryAnchor>,
        refuse_writes: bool,
    }

    impl AuditAnchorVerifier for SharedAudit {
        fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            Ok(*self.current.borrow())
        }
    }

    // The mock publisher shares the verifier's state for a realistic CAS
    // sequence, but this is not a durable or cryptographic trust authority.
    struct Publisher<'a>(&'a SharedAudit);

    impl CheckpointPublisher for Publisher<'_> {
        fn compare_and_swap(
            &mut self,
            journal_id: &str,
            expected: &TrustedRecoveryAnchor,
            next: &TrustedRecoveryAnchor,
        ) -> Result<(), AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            if self.0.refuse_writes {
                return Err(AnchorError::Unavailable);
            }
            let mut current = self.0.current.borrow_mut();
            if *current != *expected {
                return Err(AnchorError::Stale);
            }
            *current = *next;
            Ok(())
        }
    }

    #[test]
    fn committed_snapshot_recovers_after_reopen() -> Result<(), String> {
        let (initial, snapshot) = fixture()?;
        let directory = sandbox();
        let audit = SharedAudit {
            current: RefCell::new(initial),
            refuse_writes: false,
        };
        let published = stage_then_publish(
            &audit,
            &mut Publisher(&audit),
            "orcheastra:test",
            &directory,
            &snapshot,
        )
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(published.anchor.generation, 1);
        // Reopen the file through the independent verifier entrypoint. No
        // recovered historical proposal is ever executed.
        let restored = recover_from_audit(&audit, "orcheastra:test", &published.path)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(restored.coordinator().entries().len(), 1);
        fs::remove_dir_all(directory).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn rejected_cas_leaves_only_an_untrusted_orphan() -> Result<(), String> {
        let (initial, snapshot) = fixture()?;
        let directory = sandbox();
        let audit = SharedAudit {
            current: RefCell::new(initial),
            refuse_writes: true,
        };
        assert!(matches!(
            stage_then_publish(
                &audit,
                &mut Publisher(&audit),
                "orcheastra:test",
                &directory,
                &snapshot,
            ),
            Err(StagePublishError::Commit(AnchorError::Unavailable))
        ));
        assert_eq!(*audit.current.borrow(), initial);
        let orphan = directory.join("snapshot-00000000000000000001.bin");
        assert!(orphan.exists());
        assert!(recover_from_audit(&audit, "orcheastra:test", &orphan).is_err());
        fs::remove_dir_all(directory).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn invalid_candidate_is_refused_before_creating_any_file() -> Result<(), String> {
        let (initial, snapshot) = fixture()?;
        let directory = sandbox();
        let audit = SharedAudit {
            current: RefCell::new(initial),
            refuse_writes: false,
        };
        let mut invalid = snapshot;
        invalid.checkpoint.head = [37u8; 32];
        assert!(matches!(
            stage_then_publish(
                &audit,
                &mut Publisher(&audit),
                "orcheastra:test",
                &directory,
                &invalid,
            ),
            Err(StagePublishError::Proposal(_))
        ));
        assert!(!directory.exists());
        Ok(())
    }
}
