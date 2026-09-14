//! Governance and authority contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_constitution::{AuthorityScope, ProvenanceRecord};
use palaco_foundation::{
    errors::{RevalidationError, RevocationReason, ValidationError},
    identity::DecisionId,
    traits::{CurrentlyAssessable, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, RevalidationOutcome, Timestamp, ValidityWindow},
};
use palaco_oracle::{OracleReport, PlausibleState};

/// Scope of authority granted by a governance decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorizationScope {
    /// Observation may continue but no action is authorized.
    Observe,
    /// Advisory recommendations may be issued.
    #[default]
    Advise,
    /// Execution may proceed while current validity holds.
    Execute,
}

impl AuthorizationScope {
    #[must_use]
    fn authority(self) -> AuthorityScope {
        let capability = match self {
            Self::Observe => "palaco.observe",
            Self::Advise => "palaco.advise",
            Self::Execute => "palaco.execute",
        };

        AuthorityScope {
            capability: capability.to_string(),
        }
    }
}

/// Governance decision produced from an oracle report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceDecision {
    /// Unique identifier for the decision.
    pub id: DecisionId,
    /// Report evaluated by the governance layer.
    pub report: OracleReport,
    /// Context to which the decision remains bound.
    pub context: DecisionContext,
    /// Authorized scope under this decision.
    pub scope: AuthorizationScope,
    /// Time at which the decision was issued.
    pub issued_at: Timestamp,
    /// Window during which the decision may remain current.
    pub validity_window: ValidityWindow,
    /// Authority scope approved by governance.
    pub authority: AuthorityScope,
    /// Provenance of the governance outcome.
    pub provenance: ProvenanceRecord,
}

impl GovernanceDecision {
    /// Creates a governance decision tied to a specific context and validity window.
    #[must_use]
    pub fn new(
        report: OracleReport,
        context: DecisionContext,
        scope: AuthorizationScope,
        issued_at: Timestamp,
        validity_window: ValidityWindow,
    ) -> Self {
        let id = DecisionId::new();

        Self {
            authority: scope.authority(),
            provenance: ProvenanceRecord {
                source: "palaco-trias".to_string(),
                record_locator: format!("decision:{}", id.0),
            },
            id,
            report,
            context,
            scope,
            issued_at,
            validity_window,
        }
    }
}

impl Validatable for GovernanceDecision {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.validity_window.not_after < self.validity_window.not_before {
            return Err(ValidationError::InvalidValidityWindow);
        }

        self.report.validate()
    }
}

impl CurrentlyAssessable for GovernanceDecision {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        if !self.validity_window.contains(at) {
            return if at < self.validity_window.not_before {
                CurrentValidity::Pending
            } else {
                CurrentValidity::Expired
            };
        }

        self.report.current_validity(at)
    }
}

impl Revalidatable for GovernanceDecision {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        if context.observed_at > self.validity_window.not_after {
            return Err(RevalidationError::RevocationRequired {
                reason: RevocationReason::EvidenceExpired,
            });
        }

        let report_outcome = self.report.revalidate(context)?;

        match (self.scope, self.report.plausible_state, report_outcome) {
            (_, PlausibleState::Ambiguous, _) => Ok(RevalidationOutcome::SafeState),
            (AuthorizationScope::Observe, _, _) => Ok(RevalidationOutcome::Escalated),
            (_, _, outcome) => Ok(outcome),
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
    use palaco_types::DomainMarker;

    use crate::{AuthorizationScope, GovernanceDecision};

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
                palaco_oracle::PlausibleState::Stable,
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
    fn execute_scope_confirms_current_decision() -> Result<(), &'static str> {
        let decision = decision(AuthorizationScope::Execute)?;

        assert_eq!(
            decision.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::Valid
        );
        assert_eq!(
            decision.revalidate(&decision.context),
            Ok(RevalidationOutcome::Confirmed)
        );

        Ok(())
    }

    #[test]
    fn decision_expires_after_its_validity_window() -> Result<(), &'static str> {
        let decision = decision(AuthorizationScope::Execute)?;

        assert_eq!(
            decision.current_validity(timestamp(2026, 2, 1, 0, 0, 0)?),
            CurrentValidity::Expired
        );
        assert!(decision
            .revalidate(&context(timestamp(2026, 2, 1, 0, 0, 0)?))
            .is_err());

        Ok(())
    }
}
