//! Analysis and advisory contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_evidence::EvidenceBundle;
use palaco_foundation::{
    errors::{EscalationReason, RevalidationError},
    traits::{CurrentlyAssessable, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, RevalidationOutcome, Timestamp},
};

/// Plausible system state derived from current evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlausibleState {
    /// Evidence supports normal operation.
    #[default]
    Stable,
    /// Evidence suggests current conditions are changing.
    Drifting,
    /// Evidence is too incomplete to select a single stable state.
    Ambiguous,
}

/// Advisory report derived from evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleReport {
    /// Evidence used to derive the report.
    pub evidence: EvidenceBundle,
    /// Decision context used to interpret the evidence.
    pub context: DecisionContext,
    /// Current plausible state inferred from the evidence.
    pub plausible_state: PlausibleState,
}

impl OracleReport {
    /// Creates a new oracle report for a specific decision context.
    #[must_use]
    pub fn new(
        evidence: EvidenceBundle,
        context: DecisionContext,
        plausible_state: PlausibleState,
    ) -> Self {
        Self {
            evidence,
            context,
            plausible_state,
        }
    }
}

impl Validatable for OracleReport {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.evidence.validate()
    }
}

impl CurrentlyAssessable for OracleReport {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        let evidence_validity = self.evidence.current_validity(at);

        match self.plausible_state {
            PlausibleState::Stable | PlausibleState::Drifting => evidence_validity,
            PlausibleState::Ambiguous => CurrentValidity::SafeStateRequired,
        }
    }
}

impl Revalidatable for OracleReport {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;
        self.evidence.revalidate(context)?;

        match self.plausible_state {
            PlausibleState::Stable => Ok(RevalidationOutcome::Confirmed),
            PlausibleState::Drifting => Ok(RevalidationOutcome::Escalated),
            PlausibleState::Ambiguous => Err(RevalidationError::EscalationRequired {
                reason: EscalationReason::IncompleteEvidence,
            }),
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

    use crate::{OracleReport, PlausibleState};

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

    fn report(plausible_state: PlausibleState) -> Result<OracleReport, &'static str> {
        Ok(OracleReport::new(
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
            context(timestamp(2026, 1, 15, 12, 0, 0)?),
            plausible_state,
        ))
    }

    #[test]
    fn stable_report_confirms_current_evidence() -> Result<(), &'static str> {
        let report = report(PlausibleState::Stable)?;

        assert_eq!(
            report.current_validity(timestamp(2026, 1, 15, 12, 0, 0)?),
            CurrentValidity::Valid
        );
        assert_eq!(
            report.revalidate(&report.context),
            Ok(RevalidationOutcome::Confirmed)
        );

        Ok(())
    }

    #[test]
    fn ambiguous_report_forces_safe_state() -> Result<(), &'static str> {
        let report = report(PlausibleState::Ambiguous)?;

        assert_eq!(
            report.current_validity(timestamp(2026, 1, 15, 12, 0, 0)?),
            CurrentValidity::SafeStateRequired
        );
        assert!(report.revalidate(&report.context).is_err());

        Ok(())
    }
}
