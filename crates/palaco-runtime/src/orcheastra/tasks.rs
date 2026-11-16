//! Offline-only, deterministic ORCHEASTRA task planning and decision journal.
//!
//! Planning is intentionally separate from execution and authorization.
//! No task, including one marked ready, can execute through this module.

use std::collections::{BTreeMap, BTreeSet};

use super::{AdmissionDecision, AdmissionReason};

/// A proposed PALACO task with explicit predecessor identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    /// Unique, nonempty task identifier.
    pub id: String,
    /// PALACO module expected to handle the task.
    pub module: String,
    /// Required preceding tasks.
    pub dependencies: Vec<String>,
    /// Reference to evidence stored outside this coordinator.
    pub evidence_ref: String,
}

/// Deterministic rejection of an invalid task plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// At least one task identifier, module, or evidence reference is missing.
    EmptyField,
    /// Two tasks use the same identifier.
    DuplicateTask(String),
    /// The referenced predecessor is not part of the same plan.
    UnknownDependency(String),
    /// A task may not depend on itself.
    SelfDependency(String),
    /// A cycle makes dependency ordering impossible.
    Cycle,
}

/// An immutable, validated collection of tasks in topological order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPlan {
    tasks: BTreeMap<String, TaskSpec>,
    order: Vec<String>,
}

impl TaskPlan {
    /// Validate the graph and produce a stable topological ordering.
    pub fn build(tasks: impl IntoIterator<Item = TaskSpec>) -> Result<Self, PlanError> {
        let mut indexed = BTreeMap::new();
        for task in tasks {
            if task.id.trim().is_empty()
                || task.module.trim().is_empty()
                || task.evidence_ref.trim().is_empty()
            {
                return Err(PlanError::EmptyField);
            }
            if indexed.insert(task.id.clone(), task.clone()).is_some() {
                return Err(PlanError::DuplicateTask(task.id));
            }
        }

        let mut indegree = BTreeMap::new();
        let mut descendants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (id, task) in &indexed {
            let unique: BTreeSet<_> = task.dependencies.iter().cloned().collect();
            for dependency in &unique {
                if dependency == id {
                    return Err(PlanError::SelfDependency(id.clone()));
                }
                if !indexed.contains_key(dependency) {
                    return Err(PlanError::UnknownDependency(dependency.clone()));
                }
                descendants
                    .entry(dependency.clone())
                    .or_default()
                    .insert(id.clone());
            }
            indegree.insert(id.clone(), unique.len());
        }

        let mut available: BTreeSet<String> = indegree
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(id, _)| id.clone())
            .collect();
        let mut order = Vec::with_capacity(indexed.len());

        while let Some(id) = available.pop_first() {
            order.push(id.clone());
            if let Some(children) = descendants.get(&id) {
                for child in children {
                    if let Some(count) = indegree.get_mut(child) {
                        *count -= 1;
                        if *count == 0 {
                            available.insert(child.clone());
                        }
                    }
                }
            }
        }

        if order.len() != indexed.len() {
            return Err(PlanError::Cycle);
        }
        Ok(Self {
            tasks: indexed,
            order,
        })
    }

    /// Returns task identifiers in deterministic dependency-first order.
    #[must_use]
    pub fn ordered_ids(&self) -> &[String] {
        &self.order
    }

    /// Returns a task by its identifier.
    #[must_use]
    pub fn task(&self, id: &str) -> Option<&TaskSpec> {
        self.tasks.get(id)
    }
}

/// Non-executing status derived from the plan and recorded decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskReadiness {
    /// At least one predecessor has not been admitted.
    Waiting,
    /// A decision forbids this task.
    Blocked(AdmissionReason),
    /// The task is eligible for a proposal, not execution.
    ReadyForProposal,
    /// The proposal was recorded, not executed.
    Proposed,
}

/// One append-only, process-local decision record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEntry {
    /// One-based, monotonic journal sequence.
    pub sequence: u64,
    /// Task to which the decision applies.
    pub task_id: String,
    /// Decision obtained from the admission gate.
    pub decision: AdmissionDecision,
    /// External audit evidence locator (not an artifact verification).
    pub evidence_ref: String,
}

/// Journaling error; no change is made when an append is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// The task does not belong to this plan.
    UnknownTask,
    /// This task already has an immutable decision.
    AlreadyDecided,
    /// A predecessor is not marked proposed.
    DependencyNotProposed,
    /// Sequence space is exhausted.
    SequenceExhausted,
    /// A supplied evidence locator is missing or disagrees with the plan.
    EvidenceMismatch,
}

/// In-memory journal and read-only task coordinator.
///
/// Decisions and references are not durable or independently verified.
/// Callers must persist their own authenticated audit trail.
#[derive(Debug, Clone)]
pub struct TaskCoordinator {
    plan: TaskPlan,
    entries: Vec<DecisionEntry>,
    decisions: BTreeMap<String, AdmissionDecision>,
    next_sequence: Option<u64>,
}

impl TaskCoordinator {
    /// Creates an empty decision journal for a validated immutable plan.
    #[must_use]
    pub fn new(plan: TaskPlan) -> Self {
        Self {
            plan,
            entries: Vec::new(),
            decisions: BTreeMap::new(),
            next_sequence: Some(1),
        }
    }

    /// Derives readiness without modifying the journal.
    #[must_use]
    pub fn readiness(&self, task_id: &str) -> Option<TaskReadiness> {
        let task = self.plan.task(task_id)?;
        if let Some(decision) = self.decisions.get(task_id) {
            return Some(match decision {
                AdmissionDecision::Blocked(reason) => TaskReadiness::Blocked(*reason),
                AdmissionDecision::Proposed => TaskReadiness::Proposed,
                AdmissionDecision::ObserveOnly => TaskReadiness::ReadyForProposal,
            });
        }
        if task
            .dependencies
            .iter()
            .any(|dep| self.decisions.get(dep) != Some(&AdmissionDecision::Proposed))
        {
            return Some(TaskReadiness::Waiting);
        }
        Some(TaskReadiness::ReadyForProposal)
    }

    /// Append a supplied gate decision after checking task and dependencies.
    ///
    /// This never performs a task, nor does it interpret `Proposed` as approval.
    pub fn record(
        &mut self,
        task_id: &str,
        decision: AdmissionDecision,
        evidence_ref: &str,
    ) -> Result<u64, JournalError> {
        let task = self.plan.task(task_id).ok_or(JournalError::UnknownTask)?;
        if self.decisions.contains_key(task_id) {
            return Err(JournalError::AlreadyDecided);
        }
        if evidence_ref.trim().is_empty() || evidence_ref != task.evidence_ref {
            return Err(JournalError::EvidenceMismatch);
        }
        if decision == AdmissionDecision::Proposed
            && self.readiness(task_id) != Some(TaskReadiness::ReadyForProposal)
        {
            return Err(JournalError::DependencyNotProposed);
        }
        let sequence = self.next_sequence.ok_or(JournalError::SequenceExhausted)?;
        self.next_sequence = sequence.checked_add(1);
        self.entries.push(DecisionEntry {
            sequence,
            task_id: task_id.to_owned(),
            decision,
            evidence_ref: evidence_ref.to_owned(),
        });
        self.decisions.insert(task_id.to_owned(), decision);
        Ok(sequence)
    }

    /// Returns immutable decision records in append order.
    #[must_use]
    pub fn entries(&self) -> &[DecisionEntry] {
        &self.entries
    }

    /// Returns the validated task plan.
    #[must_use]
    pub fn plan(&self) -> &TaskPlan {
        &self.plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, deps: &[&str]) -> TaskSpec {
        TaskSpec {
            id: id.to_owned(),
            module: "RIO".to_owned(),
            dependencies: deps.iter().map(|dep| (*dep).to_owned()).collect(),
            evidence_ref: format!("evidence:{id}"),
        }
    }

    #[test]
    fn sorting_is_deterministic_and_dependency_first() {
        let plan = TaskPlan::build([task("c", &["b"]), task("a", &[]), task("b", &["a"])]);
        assert_eq!(
            plan.map(|plan| plan.order),
            Ok(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()])
        );
    }

    #[test]
    fn rejects_missing_predecessor_and_cycles() {
        assert_eq!(
            TaskPlan::build([task("a", &["missing"])]),
            Err(PlanError::UnknownDependency("missing".to_owned()))
        );
        assert_eq!(
            TaskPlan::build([task("a", &["b"]), task("b", &["a"])]),
            Err(PlanError::Cycle)
        );
        assert_eq!(
            TaskPlan::build([task("a", &["a"])]),
            Err(PlanError::SelfDependency("a".to_owned()))
        );
        assert_eq!(
            TaskPlan::build([task("a", &[]), task("a", &[])]),
            Err(PlanError::DuplicateTask("a".to_owned()))
        );
    }

    #[test]
    fn cannot_propose_before_dependencies() -> Result<(), PlanError> {
        let plan = TaskPlan::build([task("rio", &["identity"]), task("identity", &[])])?;
        let mut coordinator = TaskCoordinator::new(plan);
        assert_eq!(coordinator.readiness("rio"), Some(TaskReadiness::Waiting));
        assert_eq!(
            coordinator.record("rio", AdmissionDecision::Proposed, "evidence:rio"),
            Err(JournalError::DependencyNotProposed)
        );
        assert_eq!(coordinator.entries().len(), 0);
        assert_eq!(
            coordinator.record("identity", AdmissionDecision::Proposed, "evidence:identity"),
            Ok(1)
        );
        assert_eq!(
            coordinator.readiness("rio"),
            Some(TaskReadiness::ReadyForProposal)
        );
        assert_eq!(
            coordinator.record("rio", AdmissionDecision::Proposed, "evidence:rio"),
            Ok(2)
        );
        assert_eq!(coordinator.entries().len(), 2);
        Ok(())
    }

    #[test]
    fn denied_dependency_never_unblocks_downstream() -> Result<(), PlanError> {
        let plan = TaskPlan::build([task("rio", &["identity"]), task("identity", &[])])?;
        let mut coordinator = TaskCoordinator::new(plan);
        assert_eq!(
            coordinator.record(
                "identity",
                AdmissionDecision::Blocked(AdmissionReason::Hold),
                "evidence:identity",
            ),
            Ok(1)
        );
        assert_eq!(coordinator.readiness("rio"), Some(TaskReadiness::Waiting));
        assert_eq!(
            coordinator.record("rio", AdmissionDecision::Proposed, "evidence:rio"),
            Err(JournalError::DependencyNotProposed)
        );
        Ok(())
    }

    #[test]
    fn journal_rejects_duplicate_and_false_evidence() -> Result<(), PlanError> {
        let plan = TaskPlan::build([task("a", &[])])?;
        let mut coordinator = TaskCoordinator::new(plan);
        assert_eq!(
            coordinator.record("a", AdmissionDecision::Proposed, "wrong"),
            Err(JournalError::EvidenceMismatch)
        );
        assert_eq!(
            coordinator.record("a", AdmissionDecision::Proposed, "evidence:a"),
            Ok(1)
        );
        assert_eq!(
            coordinator.record("a", AdmissionDecision::Proposed, "evidence:a"),
            Err(JournalError::AlreadyDecided)
        );
        assert_eq!(coordinator.entries().len(), 1);
        Ok(())
    }
}
