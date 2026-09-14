//! Audit contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_foundation::{
    traits::{CurrentlyAssessable, Validatable},
    types::{CurrentValidity, Timestamp},
};
use palaco_runtime::RuntimePlan;

/// Current audit posture for a runtime record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditDisposition {
    /// The record confirms a valid executable path.
    Current,
    /// The record indicates the runtime must be reviewed.
    Escalated,
    /// The record captures a safe-state or revoked path.
    #[default]
    ArchivedSafeState,
}

/// Audit record emitted from runtime activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Runtime plan captured by the audit layer.
    pub runtime_plan: RuntimePlan,
    /// Validity recorded at audit time.
    pub recorded_validity: CurrentValidity,
    /// Final audit disposition.
    pub disposition: AuditDisposition,
    /// Timestamp when the audit record was captured.
    pub recorded_at: Timestamp,
}

impl AuditRecord {
    /// Creates an audit record from a runtime plan at a specific timestamp.
    #[must_use]
    pub fn new(runtime_plan: RuntimePlan, recorded_at: Timestamp) -> Self {
        let recorded_validity = runtime_plan.current_validity(recorded_at);
        let disposition = match recorded_validity {
            CurrentValidity::Valid => AuditDisposition::Current,
            CurrentValidity::Pending | CurrentValidity::InsufficientEvidence => {
                AuditDisposition::Escalated
            }
            CurrentValidity::Expired
            | CurrentValidity::Revoked
            | CurrentValidity::SafeStateRequired => AuditDisposition::ArchivedSafeState,
        };

        Self {
            runtime_plan,
            recorded_validity,
            disposition,
            recorded_at,
        }
    }
}

impl Validatable for AuditRecord {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.runtime_plan.validate()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{LocalResult, TimeZone, Utc};
    use palaco_events::EventEnvelope;
    use palaco_foundation::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        types::{CurrentValidity, DecisionContext, TrustLevel, ValidityWindow},
    };
    use palaco_oracle::PlausibleState;
    use palaco_runtime::RuntimePlan;
    use palaco_trias::{AuthorizationScope, GovernanceDecision};
    use palaco_types::DomainMarker;

    use crate::{AuditDisposition, AuditRecord};

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

    fn runtime_plan(scope: AuthorizationScope) -> Result<RuntimePlan, &'static str> {
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
    fn audit_record_marks_current_execution_as_current() -> Result<(), &'static str> {
        let record = AuditRecord::new(
            runtime_plan(AuthorizationScope::Execute)?,
            timestamp(2026, 1, 20, 0, 0, 0)?,
        );

        assert_eq!(record.recorded_validity, CurrentValidity::Valid);
        assert_eq!(record.disposition, AuditDisposition::Current);

        Ok(())
    }

    #[test]
    fn audit_record_marks_observe_scope_as_escalated() -> Result<(), &'static str> {
        let record = AuditRecord::new(
            runtime_plan(AuthorizationScope::Observe)?,
            timestamp(2026, 1, 20, 0, 0, 0)?,
        );

        assert_eq!(
            record.recorded_validity,
            CurrentValidity::InsufficientEvidence
        );
        assert_eq!(record.disposition, AuditDisposition::Escalated);

        Ok(())
    }
}
