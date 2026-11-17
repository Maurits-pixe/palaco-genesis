//! Read-only reconciliation after an interrupted or ambiguous audit publication.
//!
//! Recovery never trusts a staged file as the authority. A successful
//! publication can only be identified using the independent audit verifier.

use std::path::Path;

use super::{
    publish::PublicationProposal, recover_from_audit, AnchorError, AuditAnchorVerifier,
    AuditRecovery, AuditRecoveryError,
};

/// Reconciliation result; neither branch conveys execution authority.
#[derive(Debug)]
pub enum ReconcileOutcome {
    /// The published anchor is independently confirmed and the exact staged
    /// file was verified and replayed. Historical proposals remain inert.
    Committed(AuditRecovery),
    /// The independently trusted anchor is still the previous generation.
    /// The newer local file is not authorized for recovery.
    Unanchored,
    /// A different anchor was published, so the candidate cannot be trusted.
    Conflict,
}

/// Reconciliation fails closed when the audit authority or data is unavailable.
#[derive(Debug)]
pub enum ReconcileError {
    /// The journal scope was not supplied.
    EmptyJournalId,
    /// No authoritative, independently authenticated latest anchor.
    Anchor(AnchorError),
    /// The selected committed snapshot failed independent replay verification.
    Recovery(AuditRecoveryError),
}

/// Reconcile an uncertain result, e.g. when the publisher's response was lost.
///
/// The expected candidate is a hint, not a proof. This operation retrieves
/// the latest verified anchor, requires an exact match, reads the local
/// generation-named file through the existing authenticated recovery entry,
/// and rereads the latest anchor to detect concurrent advances. It never
/// republishs, retries CAS, deletes orphan files or executes recovered tasks.
///
/// A trusted verifier must itself implement authenticated, rollback-resistant
/// reads. For a production deployment, the verifier must additionally offer
/// suitable consistency semantics; this function alone cannot make two
/// separate remote reads linearizable.
pub fn reconcile_publication<V: AuditAnchorVerifier>(
    verifier: &V,
    journal_id: &str,
    directory: &Path,
    proposal: &PublicationProposal,
) -> Result<ReconcileOutcome, ReconcileError> {
    if journal_id.trim().is_empty() {
        return Err(ReconcileError::EmptyJournalId);
    }
    let current = verifier
        .latest_anchor(journal_id)
        .map_err(ReconcileError::Anchor)?;
    if current == proposal.expected_previous {
        return Ok(ReconcileOutcome::Unanchored);
    }
    if current != proposal.next {
        return Ok(ReconcileOutcome::Conflict);
    }

    let path = directory.join(format!(
        "snapshot-{:020}.bin",
        proposal.next.generation
    ));
    let recovery = recover_from_audit(verifier, journal_id, &path)
        .map_err(ReconcileError::Recovery)?;

    // A monotonic authority may have advanced while we read the local file.
    let confirmed = verifier
        .latest_anchor(journal_id)
        .map_err(ReconcileError::Anchor)?;
    if confirmed != proposal.next {
        return Ok(ReconcileOutcome::Conflict);
    }
    Ok(ReconcileOutcome::Committed(recovery))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::publish::prepare_publication;
    use palaco_runtime::orcheastra::{
        persistence::{JournalSnapshot, TrustedRecoveryAnchor},
        recovery::{export_checkpoint, plan_fingerprint, RecoveryCheckpoint},
        snapshot_file::stage_snapshot,
        tasks::{TaskCoordinator, TaskPlan, TaskSpec},
        AdmissionDecision,
    };
    use std::{
        cell::{Cell, RefCell},
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "palaco-orcheastra-reconcile-{}-{id}",
            std::process::id()
        ))
    }

    fn fixture() -> Result<(PublicationProposal, JournalSnapshot), String> {
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
        let snapshot = JournalSnapshot {
            plan,
            records,
            checkpoint,
        };
        let proposal =
            prepare_publication(&previous, &snapshot).map_err(|error| format!("{error:?}"))?;
        Ok((proposal, snapshot))
    }

    struct Verifier {
        anchor: RefCell<TrustedRecoveryAnchor>,
        // Changing between reads simulates a concurrent remote publication.
        advance_on_read: Cell<Option<usize>>,
        reads: Cell<usize>,
    }

    impl Verifier {
        fn new(anchor: TrustedRecoveryAnchor) -> Self {
            Self {
                anchor: RefCell::new(anchor),
                advance_on_read: Cell::new(None),
                reads: Cell::new(0),
            }
        }
    }

    impl AuditAnchorVerifier for Verifier {
        fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            let count = self.reads.get() + 1;
            self.reads.set(count);
            if self.advance_on_read.get() == Some(count) {
                self.anchor.borrow_mut().generation += 1;
            }
            Ok(*self.anchor.borrow())
        }
    }

    #[test]
    fn lost_acknowledgment_can_confirm_committed_history() -> Result<(), String> {
        let (proposal, snapshot) = fixture()?;
        let directory = test_dir();
        stage_snapshot(
            &directory,
            proposal.next.generation,
            &snapshot,
            &proposal.next.checkpoint,
        )
        .map_err(|error| format!("{error:?}"))?;
        // The writer never saw an ACK, but the independent authority did
        // commit the exact next checkpoint.
        let audit = Verifier::new(proposal.next);
        let outcome = reconcile_publication(&audit, "orcheastra:test", &directory, &proposal)
            .map_err(|error| format!("{error:?}"))?;
        match outcome {
            ReconcileOutcome::Committed(recovery) => {
                assert_eq!(recovery.coordinator().entries().len(), 1);
            }
            other => return Err(format!("unexpected {other:?}")),
        }
        fs::remove_dir_all(directory).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn orphan_after_rejected_cas_never_recovers() -> Result<(), String> {
        let (proposal, snapshot) = fixture()?;
        let directory = test_dir();
        stage_snapshot(
            &directory,
            proposal.next.generation,
            &snapshot,
            &proposal.next.checkpoint,
        )
        .map_err(|error| format!("{error:?}"))?;
        let audit = Verifier::new(proposal.expected_previous);
        assert!(matches!(
            reconcile_publication(&audit, "orcheastra:test", &directory, &proposal),
            Ok(ReconcileOutcome::Unanchored)
        ));
        fs::remove_dir_all(directory).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn competing_commit_and_missing_snapshot_fail_closed() -> Result<(), String> {
        let (proposal, _) = fixture()?;
        let directory = test_dir();
        let mut competing = proposal.next;
        competing.checkpoint.head = [99u8; 32];
        let audit = Verifier::new(competing);
        assert!(matches!(
            reconcile_publication(&audit, "orcheastra:test", &directory, &proposal),
            Ok(ReconcileOutcome::Conflict)
        ));
        let audit = Verifier::new(proposal.next);
        assert!(matches!(
            reconcile_publication(&audit, "orcheastra:test", &directory, &proposal),
            Err(ReconcileError::Recovery(_))
        ));
        Ok(())
    }

    #[test]
    fn concurrent_advance_during_reopen_returns_conflict() -> Result<(), String> {
        let (proposal, snapshot) = fixture()?;
        let directory = test_dir();
        stage_snapshot(
            &directory,
            proposal.next.generation,
            &snapshot,
            &proposal.next.checkpoint,
        )
        .map_err(|error| format!("{error:?}"))?;
        let audit = Verifier::new(proposal.next);
        audit.advance_on_read.set(Some(3));
        assert!(matches!(
            reconcile_publication(&audit, "orcheastra:test", &directory, &proposal),
            Ok(ReconcileOutcome::Conflict)
        ));
        fs::remove_dir_all(directory).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }
}
