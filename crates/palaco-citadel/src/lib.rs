//! Execution boundary contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_constitution::{AuthorizationGrant, IdentityHandle};
use palaco_foundation::{
    errors::RevalidationError,
    traits::{CurrentlyAssessable, FailClosed, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, RevalidationOutcome, Timestamp},
};
use palaco_trias::{AuthorizationScope, GovernanceDecision};

/// Resulting enforcement mode at the execution boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BoundaryDisposition {
    /// Execution is allowed to proceed.
    Execute,
    /// Execution must escalate for additional review.
    Escalate,
    /// Execution must remain in a safe closed state.
    #[default]
    SafeState,
}

/// Execution boundary request carried into the runtime layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBoundary {
    /// Governance decision authorizing the boundary crossing.
    pub decision: GovernanceDecision,
    /// Explicit authorization grant derived from the governance decision.
    pub authorization: AuthorizationGrant,
    /// Current disposition enforced at the boundary.
    pub disposition: BoundaryDisposition,
}

impl ExecutionBoundary {
    /// Creates an execution boundary from a governance decision.
    #[must_use]
    pub fn new(decision: GovernanceDecision) -> Self {
        let disposition = match decision.scope {
            AuthorizationScope::Execute => BoundaryDisposition::Execute,
            AuthorizationScope::Observe | AuthorizationScope::Advise => {
                BoundaryDisposition::Escalate
            }
        };
        let authorization = AuthorizationGrant {
            authorization_id: decision.id.0.to_string(),
            scope: decision.authority.clone(),
            granted_to: IdentityHandle::default(),
            provenance: decision.provenance.clone(),
        };

        Self {
            decision,
            authorization,
            disposition,
        }
    }
}

impl Validatable for ExecutionBoundary {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.decision.validate()
    }
}

impl CurrentlyAssessable for ExecutionBoundary {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        match self.disposition {
            BoundaryDisposition::Execute => self.decision.current_validity(at),
            BoundaryDisposition::Escalate => CurrentValidity::InsufficientEvidence,
            BoundaryDisposition::SafeState => CurrentValidity::SafeStateRequired,
        }
    }
}

impl Revalidatable for ExecutionBoundary {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        match self.disposition {
            BoundaryDisposition::Execute => self.decision.revalidate(context),
            BoundaryDisposition::Escalate => Ok(RevalidationOutcome::Escalated),
            BoundaryDisposition::SafeState => Ok(RevalidationOutcome::SafeState),
        }
    }
}

impl FailClosed for ExecutionBoundary {
    type Output = BoundaryDisposition;

    fn fail_closed(&self) -> Self::Output {
        BoundaryDisposition::SafeState
    }
}

#[cfg(test)]
mod tests {
    use chrono::{LocalResult, TimeZone, Utc};
    use palaco_events::EventEnvelope;
    use palaco_foundation::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        traits::{CurrentlyAssessable, FailClosed, Revalidatable},
        types::{
            CurrentValidity, DecisionContext, RevalidationOutcome, TrustLevel, ValidityWindow,
        },
    };
    use palaco_oracle::PlausibleState;
    use palaco_trias::{AuthorizationScope, GovernanceDecision};
    use palaco_types::DomainMarker;

    use crate::{BoundaryDisposition, ExecutionBoundary};

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

    fn decision(scope: AuthorizationScope) -> Result<GovernanceDecision, &'static str> {
        let context = context(timestamp(2026, 1, 15, 12, 0, 0)?);

        Ok(GovernanceDecision::new(
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
        ))
    }

    #[test]
    fn execution_boundary_confirms_executable_decision() -> Result<(), &'static str> {
        let boundary = ExecutionBoundary::new(decision(AuthorizationScope::Execute)?);

        assert_eq!(
            boundary.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::Valid
        );
        assert_eq!(
            boundary.revalidate(&boundary.decision.context),
            Ok(RevalidationOutcome::Confirmed)
        );

        Ok(())
    }

    #[test]
    fn execution_boundary_fails_closed_when_requested() -> Result<(), &'static str> {
        let boundary = ExecutionBoundary::new(decision(AuthorizationScope::Observe)?);

        assert_eq!(boundary.fail_closed(), BoundaryDisposition::SafeState);
        assert_eq!(
            boundary.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::InsufficientEvidence
        );

        Ok(())
    }
}
