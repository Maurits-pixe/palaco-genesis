//! Fail-closed recovery of an ORCHEASTRA decision journal.
//!
//! This module does not persist, authenticate, sign or execute records.
//! The checkpoint MUST be independently authenticated by a trusted caller.

use sha2::{Digest, Sha256};

use super::chain::{
    chain_entries, chain_head, verify_chain, ChainError, ChainedDecision, Digest256,
};
use super::tasks::{JournalError, TaskCoordinator, TaskPlan};

/// A checkpoint to be independently stored and authenticated outside the journal.
///
/// The pair of plan digest and record count prevents silently substituting
/// a different task graph or a shorter history when the checkpoint is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryCheckpoint {
    /// Domain-separated digest of the exact task plan.
    pub plan_hash: Digest256,
    /// Number of decisions contained in the committed journal.
    pub sequence: u64,
    /// Chain head for that committed sequence.
    pub head: Digest256,
}

/// Reason recovery refuses to reconstruct any coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// The supplied graph does not match the independent checkpoint.
    PlanMismatch,
    /// Record count does not match the independent checkpoint.
    SequenceMismatch,
    /// Hash chain or checkpoint head is inconsistent.
    Integrity(ChainError),
    /// An integrity-valid entry violates the plan's admission rules.
    InvalidJournal(JournalError),
    /// A journal entry does not reconstruct at its original sequence.
    ReplayMismatch,
    /// Journal is too large to express as a u64 sequence.
    SequenceOverflow,
}

fn encode_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

/// Canonical SHA-256 fingerprint of the task graph and evidence references.
///
/// Dependencies are sorted and deduplicated because ordering and duplicates
/// are semantically irrelevant to dependency resolution.
#[must_use]
pub fn plan_fingerprint(plan: &TaskPlan) -> Digest256 {
    let mut hash = Sha256::new();
    hash.update(b"PALACO-ORCHEASTRA-TASK-PLAN-V1");
    hash.update((plan.ordered_ids().len() as u64).to_be_bytes());
    let mut identifiers = plan.ordered_ids().to_vec();
    identifiers.sort();
    for id in identifiers {
        if let Some(task) = plan.task(&id) {
            encode_bytes(&mut hash, task.id.as_bytes());
            encode_bytes(&mut hash, task.module.as_bytes());
            encode_bytes(&mut hash, task.evidence_ref.as_bytes());
            let unique: std::collections::BTreeSet<_> = task.dependencies.iter().collect();
            hash.update((unique.len() as u64).to_be_bytes());
            for dependency in unique {
                encode_bytes(&mut hash, dependency.as_bytes());
            }
        }
    }
    hash.finalize().into()
}

/// Construct a checkpoint and its records for transfer to an external store.
///
/// The returned checkpoint must be authenticated independently before it
/// can serve as a recovery anchor. Neither return value is persisted here.
pub fn export_checkpoint(
    coordinator: &TaskCoordinator,
) -> Result<(RecoveryCheckpoint, Vec<ChainedDecision>), RecoveryError> {
    let records = chain_entries(coordinator.entries()).map_err(RecoveryError::Integrity)?;
    let sequence = u64::try_from(records.len()).map_err(|_| RecoveryError::SequenceOverflow)?;
    Ok((
        RecoveryCheckpoint {
            plan_hash: plan_fingerprint(coordinator.plan()),
            sequence,
            head: chain_head(&records),
        },
        records,
    ))
}

/// Verify an independently authenticated checkpoint and replay its decisions.
///
/// Replay uses the same admission and dependency constraints as a live
/// coordinator. `Proposed` remains only a proposal, never execution.
/// On any error no partially reconstructed coordinator is returned.
pub fn recover_coordinator(
    plan: TaskPlan,
    records: &[ChainedDecision],
    trusted: &RecoveryCheckpoint,
) -> Result<TaskCoordinator, RecoveryError> {
    if plan_fingerprint(&plan) != trusted.plan_hash {
        return Err(RecoveryError::PlanMismatch);
    }
    let count = u64::try_from(records.len()).map_err(|_| RecoveryError::SequenceOverflow)?;
    if count != trusted.sequence {
        return Err(RecoveryError::SequenceMismatch);
    }
    verify_chain(records, &trusted.head).map_err(RecoveryError::Integrity)?;

    let mut coordinator = TaskCoordinator::new(plan);
    for record in records {
        let entry = &record.entry;
        let sequence = coordinator
            .record(&entry.task_id, entry.decision, &entry.evidence_ref)
            .map_err(RecoveryError::InvalidJournal)?;
        if sequence != entry.sequence {
            return Err(RecoveryError::ReplayMismatch);
        }
    }
    Ok(coordinator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::tasks::{TaskReadiness, TaskSpec};
    use crate::orcheastra::{AdmissionDecision, AdmissionReason};

    fn plan() -> Result<TaskPlan, super::super::tasks::PlanError> {
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
    }

    #[test]
    fn authentic_checkpoint_restores_decisions() -> Result<(), String> {
        let tasks = plan().map_err(|e| format!("{e:?}"))?;
        let mut coordinator = TaskCoordinator::new(tasks.clone());
        coordinator
            .record("one", AdmissionDecision::Proposed, "proof:one")
            .map_err(|e| format!("{e:?}"))?;
        coordinator
            .record(
                "rio",
                AdmissionDecision::Blocked(AdmissionReason::Hold),
                "proof:rio",
            )
            .map_err(|e| format!("{e:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|e| format!("{e:?}"))?;
        let restored =
            recover_coordinator(tasks, &records, &checkpoint).map_err(|e| format!("{e:?}"))?;
        assert_eq!(restored.entries(), coordinator.entries());
        assert_eq!(
            restored.readiness("rio"),
            Some(TaskReadiness::Blocked(AdmissionReason::Hold))
        );
        Ok(())
    }

    #[test]
    fn truncation_and_plan_substitution_are_rejected() -> Result<(), String> {
        let tasks = plan().map_err(|e| format!("{e:?}"))?;
        let mut coordinator = TaskCoordinator::new(tasks.clone());
        coordinator
            .record("one", AdmissionDecision::Proposed, "proof:one")
            .map_err(|e| format!("{e:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|e| format!("{e:?}"))?;
        assert!(matches!(
            recover_coordinator(tasks.clone(), &[], &checkpoint),
            Err(RecoveryError::SequenceMismatch)
        ));
        let altered = TaskPlan::build([
            TaskSpec {
                id: "one".to_owned(),
                module: "FALSIFIED".to_owned(),
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
        .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            recover_coordinator(altered, &records, &checkpoint).err(),
            Some(RecoveryError::PlanMismatch)
        );
        Ok(())
    }

    #[test]
    fn integrity_valid_but_impossible_history_is_rejected() -> Result<(), String> {
        let tasks = plan().map_err(|e| format!("{e:?}"))?;
        let forged = [super::super::tasks::DecisionEntry {
            sequence: 1,
            task_id: "rio".to_owned(),
            decision: AdmissionDecision::Proposed,
            evidence_ref: "proof:rio".to_owned(),
        }];
        let records = chain_entries(&forged).map_err(|e| format!("{e:?}"))?;
        let checkpoint = RecoveryCheckpoint {
            plan_hash: plan_fingerprint(&tasks),
            sequence: 1,
            head: chain_head(&records),
        };
        assert_eq!(
            recover_coordinator(tasks, &records, &checkpoint).err(),
            Some(RecoveryError::InvalidJournal(
                JournalError::DependencyNotProposed
            ))
        );
        Ok(())
    }

    #[test]
    fn altered_record_is_rejected_even_with_correct_checkpoint() -> Result<(), String> {
        let tasks = plan().map_err(|e| format!("{e:?}"))?;
        let mut coordinator = TaskCoordinator::new(tasks.clone());
        coordinator
            .record("one", AdmissionDecision::Proposed, "proof:one")
            .map_err(|e| format!("{e:?}"))?;
        let (checkpoint, mut records) =
            export_checkpoint(&coordinator).map_err(|e| format!("{e:?}"))?;
        records[0].entry.decision = AdmissionDecision::ObserveOnly;
        assert_eq!(
            recover_coordinator(tasks, &records, &checkpoint).err(),
            Some(RecoveryError::Integrity(ChainError::DigestMismatch))
        );
        Ok(())
    }
}
