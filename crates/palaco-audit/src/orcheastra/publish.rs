//! Fail-closed publication contract for new ORCHEASTRA audit checkpoints.
//!
//! A trusted publisher must authenticate the writer and atomically update
//! the independent checkpoint authority. Preparing a proposal grants no
//! ability to issue credentials, execute tasks, or override HOLD.

use palaco_runtime::orcheastra::{
    chain::Digest256,
    persistence::{verify_snapshot, JournalSnapshot, StoreError, TrustedRecoveryAnchor},
};

use super::{AnchorError, AuditAnchorVerifier};

/// Reasons an audit checkpoint cannot be published.
#[derive(Debug)]
pub enum PublishError {
    /// The prior authoritative checkpoint could not be established.
    PriorAnchor(AnchorError),
    /// Supplied snapshot fails integrity, graph or dependency validation.
    InvalidSnapshot(StoreError),
    /// A new checkpoint changes the previously committed task plan.
    PlanChanged,
    /// New journal does not extend the previous committed sequence.
    NotExtended,
    /// Previously committed history was modified or removed.
    PrefixMismatch,
    /// Monotonic generation cannot be incremented safely.
    GenerationExhausted,
    /// Durable compare-and-swap publication rejected or failed.
    Commit(AnchorError),
}

/// A prepared, strictly extending checkpoint awaiting publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationProposal {
    /// Exact journal scope; carried separately to avoid accidental reuse.
    pub expected_previous: TrustedRecoveryAnchor,
    /// Candidate next-generation checkpoint.
    pub next: TrustedRecoveryAnchor,
}

/// Trusted backend implementing an atomic authenticated compare-and-swap.
///
/// A production implementation MUST authenticate the writer, persist the
/// signed or MACed checkpoint and high-water generation atomically, and
/// verify that `expected_previous` is still authoritative. Implementations
/// MUST NOT treat this trait as a local file-store API or a permission token.
pub trait CheckpointPublisher {
    /// Publish only if the independent latest anchor is still `expected_previous`.
    fn compare_and_swap(
        &mut self,
        journal_id: &str,
        expected_previous: &TrustedRecoveryAnchor,
        next: &TrustedRecoveryAnchor,
    ) -> Result<(), AnchorError>;
}

/// Verify complete candidate history and strict extension of a trusted anchor.
///
/// A checkpoint can be prepared for *proposal* but is never considered
/// authentic until a trusted publisher commits it and an independent
/// verifier confirms its latest generation.
pub fn prepare_publication(
    previous: &TrustedRecoveryAnchor,
    candidate: &JournalSnapshot,
) -> Result<PublicationProposal, PublishError> {
    verify_snapshot(candidate, &candidate.checkpoint).map_err(PublishError::InvalidSnapshot)?;
    if candidate.checkpoint.plan_hash != previous.checkpoint.plan_hash {
        return Err(PublishError::PlanChanged);
    }
    if candidate.checkpoint.sequence <= previous.checkpoint.sequence {
        return Err(PublishError::NotExtended);
    }
    let previous_count =
        usize::try_from(previous.checkpoint.sequence).map_err(|_| PublishError::PrefixMismatch)?;
    let prefix_head: Digest256 = if previous_count == 0 {
        [0u8; 32]
    } else {
        candidate
            .records
            .get(previous_count - 1)
            .ok_or(PublishError::PrefixMismatch)?
            .hash
    };
    if prefix_head != previous.checkpoint.head {
        return Err(PublishError::PrefixMismatch);
    }
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or(PublishError::GenerationExhausted)?;
    Ok(PublicationProposal {
        expected_previous: *previous,
        next: TrustedRecoveryAnchor {
            generation,
            checkpoint: candidate.checkpoint,
        },
    })
}

/// Request atomic publication after obtaining a verified previous checkpoint.
///
/// This function never signs data, stores secrets or issues task authority.
/// The publisher must independently enforce journal scope, writer permission,
/// CAS ordering and durability. A successful CAS is only audit publication.
pub fn publish_checkpoint<V: AuditAnchorVerifier, P: CheckpointPublisher>(
    verifier: &V,
    publisher: &mut P,
    journal_id: &str,
    candidate: &JournalSnapshot,
) -> Result<TrustedRecoveryAnchor, PublishError> {
    if journal_id.trim().is_empty() {
        return Err(PublishError::PriorAnchor(AnchorError::UnauthorizedJournal));
    }
    let previous = verifier
        .latest_anchor(journal_id)
        .map_err(PublishError::PriorAnchor)?;
    let proposal = prepare_publication(&previous, candidate)?;
    publisher
        .compare_and_swap(journal_id, &proposal.expected_previous, &proposal.next)
        .map_err(PublishError::Commit)?;
    Ok(proposal.next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_runtime::orcheastra::{
        recovery::{export_checkpoint, plan_fingerprint},
        tasks::{TaskCoordinator, TaskPlan, TaskSpec},
        AdmissionDecision,
    };

    fn plan() -> Result<TaskPlan, String> {
        TaskPlan::build([
            TaskSpec {
                id: "one".to_owned(),
                module: "PALACO One".to_owned(),
                dependencies: vec![],
                evidence_ref: "proof:one".to_owned(),
            },
            TaskSpec {
                id: "rio".to_owned(),
                module: "RIO".to_owned(),
                dependencies: vec!["one".to_owned()],
                evidence_ref: "proof:rio".to_owned(),
            },
        ])
        .map_err(|error| format!("{error:?}"))
    }

    fn state() -> Result<(TrustedRecoveryAnchor, JournalSnapshot), String> {
        let plan = plan()?;
        let genesis = TrustedRecoveryAnchor {
            generation: 0,
            checkpoint: palaco_runtime::orcheastra::recovery::RecoveryCheckpoint {
                plan_hash: plan_fingerprint(&plan),
                sequence: 0,
                head: [0u8; 32],
            },
        };
        let mut coordinator = TaskCoordinator::new(plan.clone());
        coordinator
            .record("one", AdmissionDecision::Proposed, "proof:one")
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        Ok((
            genesis,
            JournalSnapshot {
                plan,
                records,
                checkpoint,
            },
        ))
    }

    struct Verifier(TrustedRecoveryAnchor);
    impl AuditAnchorVerifier for Verifier {
        fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
            if journal_id == "orcheastra:test" {
                Ok(self.0)
            } else {
                Err(AnchorError::UnauthorizedJournal)
            }
        }
    }

    struct Publisher {
        current: TrustedRecoveryAnchor,
        rejected: bool,
    }

    impl CheckpointPublisher for Publisher {
        fn compare_and_swap(
            &mut self,
            journal_id: &str,
            previous: &TrustedRecoveryAnchor,
            next: &TrustedRecoveryAnchor,
        ) -> Result<(), AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            if self.rejected || self.current != *previous {
                return Err(AnchorError::Stale);
            }
            self.current = *next;
            Ok(())
        }
    }

    #[test]
    fn genesis_to_first_checkpoint_is_published_once() -> Result<(), String> {
        let (genesis, snapshot) = state()?;
        let verifier = Verifier(genesis);
        let mut publisher = Publisher {
            current: genesis,
            rejected: false,
        };
        let committed = publish_checkpoint(&verifier, &mut publisher, "orcheastra:test", &snapshot)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(committed.generation, 1);
        assert_eq!(committed.checkpoint.sequence, 1);
        assert_eq!(publisher.current, committed);
        assert!(matches!(
            publish_checkpoint(&verifier, &mut publisher, "orcheastra:test", &snapshot,),
            Err(PublishError::Commit(AnchorError::Stale))
        ));
        Ok(())
    }

    #[test]
    fn committed_history_must_be_a_prefix() -> Result<(), String> {
        let (genesis, snapshot) = state()?;
        let earlier = prepare_publication(&genesis, &snapshot)
            .map_err(|error| format!("{error:?}"))?
            .next;
        assert!(matches!(
            prepare_publication(&earlier, &snapshot),
            Err(PublishError::NotExtended)
        ));
        let mut coordinator = TaskCoordinator::new(snapshot.plan.clone());
        coordinator
            .record("one", AdmissionDecision::ObserveOnly, "proof:one")
            .map_err(|error| format!("{error:?}"))?;
        coordinator
            .record("rio", AdmissionDecision::Proposed, "proof:rio")
            .err()
            .ok_or("dependency rule must reject observation")?;
        // A structurally valid alternative journal must still be refused
        // because the first committed decision has changed.
        coordinator
            .record("rio", AdmissionDecision::ObserveOnly, "proof:rio")
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        let alternative = JournalSnapshot {
            plan: snapshot.plan,
            records,
            checkpoint,
        };
        assert!(matches!(
            prepare_publication(&earlier, &alternative),
            Err(PublishError::PrefixMismatch)
        ));
        Ok(())
    }

    #[test]
    fn missing_anchor_and_commit_conflict_fail_closed() -> Result<(), String> {
        let (genesis, snapshot) = state()?;
        let verifier = Verifier(genesis);
        let mut publisher = Publisher {
            current: genesis,
            rejected: true,
        };
        assert!(matches!(
            publish_checkpoint(&verifier, &mut publisher, "", &snapshot),
            Err(PublishError::PriorAnchor(AnchorError::UnauthorizedJournal))
        ));
        assert!(matches!(
            publish_checkpoint(&verifier, &mut publisher, "orcheastra:test", &snapshot,),
            Err(PublishError::Commit(AnchorError::Stale))
        ));
        assert_eq!(publisher.current, genesis);
        Ok(())
    }
}
