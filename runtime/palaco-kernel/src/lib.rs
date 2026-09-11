//! Kernel orchestration contracts for PALACO.
//!
//! The kernel is the final runtime-facing layer that consumes a validated
//! runtime plan and carries its fail-closed disposition into execution cycles.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

use palaco_foundation::{
    errors::RevalidationError,
    traits::{CurrentlyAssessable, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, RevalidationOutcome, Timestamp},
};
use palaco_runtime::{RuntimeDisposition, RuntimePlan};

/// Current disposition enforced by the PALACO kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KernelDisposition {
    /// The kernel may proceed with execution.
    Execute,
    /// The kernel must escalate for more review.
    Escalate,
    /// The kernel must remain in a safe state.
    #[default]
    SafeState,
}

/// Kernel cycle derived from a runtime plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCycle {
    /// Runtime plan entering the kernel.
    pub runtime_plan: RuntimePlan,
    /// Disposition enforced by the kernel.
    pub disposition: KernelDisposition,
}

impl KernelCycle {
    /// Creates a kernel cycle from a runtime plan.
    #[must_use]
    pub fn new(runtime_plan: RuntimePlan) -> Self {
        let disposition = match runtime_plan.disposition {
            RuntimeDisposition::Execute => KernelDisposition::Execute,
            RuntimeDisposition::Escalate => KernelDisposition::Escalate,
            RuntimeDisposition::SafeState => KernelDisposition::SafeState,
        };

        Self {
            runtime_plan,
            disposition,
        }
    }
}

impl Validatable for KernelCycle {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.runtime_plan.validate()
    }
}

impl CurrentlyAssessable for KernelCycle {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        match self.disposition {
            KernelDisposition::Execute => self.runtime_plan.current_validity(at),
            KernelDisposition::Escalate => CurrentValidity::InsufficientEvidence,
            KernelDisposition::SafeState => CurrentValidity::SafeStateRequired,
        }
    }
}

impl Revalidatable for KernelCycle {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        match self.disposition {
            KernelDisposition::Execute => self.runtime_plan.revalidate(context),
            KernelDisposition::Escalate => Ok(RevalidationOutcome::Escalated),
            KernelDisposition::SafeState => Ok(RevalidationOutcome::SafeState),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{LocalResult, TimeZone, Utc};
    use palaco_events::EventEnvelope;
    use palaco_foundation::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        traits::{CurrentlyAssessable, Revalidatable},
        types::{
            CurrentValidity, DecisionContext, RevalidationOutcome, TrustLevel, ValidityWindow,
        },
    };
    use palaco_oracle::PlausibleState;
    use palaco_runtime::RuntimePlan;
    use palaco_trias::{AuthorizationScope, GovernanceDecision};
    use palaco_types::DomainMarker;

    use crate::{KernelCycle, KernelDisposition};

    fn timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Result<chrono::DateTime<Utc>, &'static str> {
        match Utc.with_ymd_and_hms(year, month, day, hour, minute, second) {
            LocalResult::Single(value) => Ok(value),
            LocalResult::Ambiguous(_, _) | LocalResult::None => Err("invalid UTC timestamp"),
        }
    }

    fn context(observed_at: chrono::DateTime<Utc>) -> DecisionContext {
        DecisionContext {
            state: StateSnapshotId::new(),
            policy_version: PolicyVersionId::new(),
            observed_at,
        }
    }

    fn kernel_cycle(scope: AuthorizationScope) -> Result<KernelCycle, &'static str> {
        let context = context(timestamp(2026, 1, 15, 12, 0, 0)?);
        let decision = GovernanceDecision::new(
            palaco_oracle::OracleReport::new(
                palaco_evidence::EvidenceBundle::new(
                    EventEnvelope {
                        marker: DomainMarker,
                    },
                    Evidence::new(
                        uuid::Uuid::new_v4(),
                        timestamp(2026, 1, 10, 12, 0, 0)?,
                        NodeId::new(),
                        TrustLevel::High,
                        ValidityWindow::new(
                            timestamp(2026, 1, 1, 0, 0, 0)?,
                            timestamp(2026, 1, 31, 23, 59, 59)?,
                        ),
                    ),
                    palaco_evidence::EvidenceCompleteness::Complete,
                ),
                context,
                PlausibleState::Stable,
            ),
            context,
            scope,
            timestamp(2026, 1, 15, 12, 0, 0)?,
            ValidityWindow::new(
                timestamp(2026, 1, 1, 0, 0, 0)?,
                timestamp(2026, 1, 31, 23, 59, 59)?,
            ),
        );

        Ok(KernelCycle::new(RuntimePlan::new(
            palaco_citadel::ExecutionBoundary::new(decision),
        )))
    }

    #[test]
    fn kernel_cycle_confirms_execution_path() -> Result<(), &'static str> {
        let cycle = kernel_cycle(AuthorizationScope::Execute)?;

        assert_eq!(
            cycle.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::Valid
        );
        assert_eq!(
            cycle.revalidate(&cycle.runtime_plan.boundary.decision.context),
            Ok(RevalidationOutcome::Confirmed)
        );

        Ok(())
    }

    #[test]
    fn kernel_cycle_escalates_non_executable_scope() -> Result<(), &'static str> {
        let cycle = kernel_cycle(AuthorizationScope::Observe)?;

        assert_eq!(cycle.disposition, KernelDisposition::Escalate);
        assert_eq!(
            cycle.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::InsufficientEvidence
        );

        Ok(())
    }
}
