//! Runtime orchestration contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_citadel::{BoundaryDisposition, ExecutionBoundary};
use palaco_foundation::{
    errors::RevalidationError,
    traits::{CurrentlyAssessable, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, RevalidationOutcome, Timestamp},
};

/// Runtime action selected after boundary revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeDisposition {
    /// Continue with execution.
    Execute,
    /// Pause and escalate for further review.
    Escalate,
    /// Remain in safe state.
    #[default]
    SafeState,
}

/// Runtime plan derived from an execution boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlan {
    /// Boundary request consumed by the runtime.
    pub boundary: ExecutionBoundary,
    /// Current runtime disposition.
    pub disposition: RuntimeDisposition,
}

impl RuntimePlan {
    /// Creates a runtime plan from an execution boundary.
    #[must_use]
    pub fn new(boundary: ExecutionBoundary) -> Self {
        let disposition = match boundary.disposition {
            BoundaryDisposition::Execute => RuntimeDisposition::Execute,
            BoundaryDisposition::Escalate => RuntimeDisposition::Escalate,
            BoundaryDisposition::SafeState => RuntimeDisposition::SafeState,
        };

        Self {
            boundary,
            disposition,
        }
    }
}

impl Validatable for RuntimePlan {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.boundary.validate()
    }
}

impl CurrentlyAssessable for RuntimePlan {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        match self.disposition {
            RuntimeDisposition::Execute => self.boundary.current_validity(at),
            RuntimeDisposition::Escalate => CurrentValidity::InsufficientEvidence,
            RuntimeDisposition::SafeState => CurrentValidity::SafeStateRequired,
        }
    }
}

impl Revalidatable for RuntimePlan {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        match self.disposition {
            RuntimeDisposition::Execute => self.boundary.revalidate(context),
            RuntimeDisposition::Escalate => Ok(RevalidationOutcome::Escalated),
            RuntimeDisposition::SafeState => Ok(RevalidationOutcome::SafeState),
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
    use palaco_trias::{AuthorizationScope, GovernanceDecision};
    use palaco_types::DomainMarker;

    use crate::{RuntimeDisposition, RuntimePlan};

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

    fn plan(scope: AuthorizationScope) -> Result<RuntimePlan, &'static str> {
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

        Ok(RuntimePlan::new(palaco_citadel::ExecutionBoundary::new(
            decision,
        )))
    }

    #[test]
    fn runtime_plan_confirms_execution_path() -> Result<(), &'static str> {
        let plan = plan(AuthorizationScope::Execute)?;

        assert_eq!(
            plan.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::Valid
        );
        assert_eq!(
            plan.revalidate(&plan.boundary.decision.context),
            Ok(RevalidationOutcome::Confirmed)
        );

        Ok(())
    }

    #[test]
    fn runtime_plan_escalates_non_executable_scope() -> Result<(), &'static str> {
        let plan = plan(AuthorizationScope::Observe)?;

        assert_eq!(plan.disposition, RuntimeDisposition::Escalate);
        assert_eq!(
            plan.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::InsufficientEvidence
        );

        Ok(())
    }
}
