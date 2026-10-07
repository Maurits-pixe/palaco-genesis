//! Observability contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_audit::AuditRecord;
use palaco_foundation::{
    identity::NodeId,
    traits::{CurrentlyAssessable, Validatable},
    types::{CurrentValidity, Timestamp, TrustLevel},
};

/// Current observability posture for a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObservatoryDisposition {
    /// The snapshot reflects a current executable state.
    Current,
    /// The snapshot reflects degraded or incomplete certainty.
    Degraded,
    /// The snapshot records a safe-state path.
    #[default]
    SafeState,
}

/// Coverage observed for a sensor at a specific observation instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObservationCoverage {
    /// The sensor delivered the expected observation set.
    #[default]
    Complete,
    /// The sensor delivered only part of the expected observation set.
    Partial,
    /// The sensor delivered no usable observation set.
    Missing,
}

/// Sensor trust assertion captured by the observability layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorObservation {
    /// Sensor node that produced the reading.
    pub sensor: NodeId,
    /// Trust level currently assigned to the sensor.
    pub trust: TrustLevel,
    /// Coverage observed for this sensor.
    pub coverage: ObservationCoverage,
    /// Time at which the sensor observation was captured.
    pub observed_at: Timestamp,
}

impl SensorObservation {
    /// Creates a sensor observation for the observability layer.
    #[must_use]
    pub fn new(
        sensor: NodeId,
        trust: TrustLevel,
        coverage: ObservationCoverage,
        observed_at: Timestamp,
    ) -> Self {
        Self {
            sensor,
            trust,
            coverage,
            observed_at,
        }
    }
}

/// Observatory snapshot built from audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatorySnapshot {
    /// Audit record exposed through the observability layer.
    pub audit_record: AuditRecord,
    /// Sensor observations known at snapshot time.
    pub sensor_observations: Vec<SensorObservation>,
    /// Validity seen at observation time.
    pub observed_validity: CurrentValidity,
    /// Resulting observability disposition.
    pub disposition: ObservatoryDisposition,
    /// Timestamp when the snapshot was taken.
    pub observed_at: Timestamp,
}

impl ObservatorySnapshot {
    /// Creates an observatory snapshot from an audit record.
    #[must_use]
    pub fn new(
        audit_record: AuditRecord,
        observed_at: Timestamp,
        sensor_observations: Vec<SensorObservation>,
    ) -> Self {
        let observed_validity = audit_record.runtime_plan.current_validity(observed_at);
        let disposition = Self::disposition_for(observed_validity, &sensor_observations);

        Self {
            audit_record,
            sensor_observations,
            observed_validity,
            disposition,
            observed_at,
        }
    }

    fn disposition_for(
        observed_validity: CurrentValidity,
        sensor_observations: &[SensorObservation],
    ) -> ObservatoryDisposition {
        if sensor_observations
            .iter()
            .any(|sensor| sensor.coverage == ObservationCoverage::Missing)
        {
            return ObservatoryDisposition::SafeState;
        }

        if sensor_observations.iter().any(|sensor| {
            sensor.coverage == ObservationCoverage::Partial
                || matches!(sensor.trust, TrustLevel::Unknown | TrustLevel::Low)
        }) {
            return ObservatoryDisposition::Degraded;
        }

        match observed_validity {
            CurrentValidity::Valid => ObservatoryDisposition::Current,
            CurrentValidity::Pending | CurrentValidity::InsufficientEvidence => {
                ObservatoryDisposition::Degraded
            }
            CurrentValidity::Expired
            | CurrentValidity::Revoked
            | CurrentValidity::SafeStateRequired => ObservatoryDisposition::SafeState,
        }
    }
}

impl Validatable for ObservatorySnapshot {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.audit_record.validate()
    }
}

impl CurrentlyAssessable for ObservatorySnapshot {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        if at < self.observed_at {
            return CurrentValidity::Pending;
        }

        let runtime_validity = self.audit_record.runtime_plan.current_validity(at);

        if self
            .sensor_observations
            .iter()
            .any(|sensor| sensor.coverage == ObservationCoverage::Missing)
        {
            return CurrentValidity::SafeStateRequired;
        }

        if self.sensor_observations.iter().any(|sensor| {
            sensor.coverage == ObservationCoverage::Partial
                || matches!(sensor.trust, TrustLevel::Unknown | TrustLevel::Low)
        }) {
            return CurrentValidity::InsufficientEvidence;
        }

        runtime_validity
    }
}

#[cfg(test)]
mod tests {
    use chrono::{LocalResult, TimeZone, Utc};
    use palaco_events::EventEnvelope;
    use palaco_foundation::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        traits::CurrentlyAssessable,
        types::{CurrentValidity, DecisionContext, Timestamp, TrustLevel, ValidityWindow},
    };
    use palaco_oracle::PlausibleState;
    use palaco_runtime::RuntimePlan;
    use palaco_trias::{AuthorizationScope, GovernanceDecision};
    use palaco_types::DomainMarker;

    use crate::{
        ObservationCoverage, ObservatoryDisposition, ObservatorySnapshot, SensorObservation,
    };

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

    fn audit_record(scope: AuthorizationScope) -> Result<palaco_audit::AuditRecord, &'static str> {
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

        Ok(palaco_audit::AuditRecord::new(
            RuntimePlan::new(palaco_citadel::ExecutionBoundary::new(decision)),
            timestamp(2026, 1, 20, 0, 0, 0)?,
        ))
    }

    fn sensor_observation(
        trust: TrustLevel,
        coverage: ObservationCoverage,
        observed_at: Timestamp,
    ) -> SensorObservation {
        SensorObservation::new(NodeId::new(), trust, coverage, observed_at)
    }

    #[test]
    fn observatory_snapshot_marks_current_execution_as_current() -> Result<(), &'static str> {
        let snapshot = ObservatorySnapshot::new(
            audit_record(AuthorizationScope::Execute)?,
            timestamp(2026, 1, 20, 0, 0, 0)?,
            vec![sensor_observation(
                TrustLevel::High,
                ObservationCoverage::Complete,
                timestamp(2026, 1, 20, 0, 0, 0)?,
            )],
        );

        assert_eq!(snapshot.observed_validity, CurrentValidity::Valid);
        assert_eq!(snapshot.disposition, ObservatoryDisposition::Current);

        Ok(())
    }

    #[test]
    fn observatory_snapshot_marks_observe_scope_as_degraded() -> Result<(), &'static str> {
        let snapshot = ObservatorySnapshot::new(
            audit_record(AuthorizationScope::Observe)?,
            timestamp(2026, 1, 20, 0, 0, 0)?,
            vec![sensor_observation(
                TrustLevel::Low,
                ObservationCoverage::Partial,
                timestamp(2026, 1, 20, 0, 0, 0)?,
            )],
        );

        assert_eq!(
            snapshot.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::InsufficientEvidence
        );
        assert_eq!(snapshot.disposition, ObservatoryDisposition::Degraded);

        Ok(())
    }

    #[test]
    fn observatory_snapshot_marks_missing_sensor_coverage_as_safe_state() -> Result<(), &'static str>
    {
        let snapshot = ObservatorySnapshot::new(
            audit_record(AuthorizationScope::Execute)?,
            timestamp(2026, 1, 20, 0, 0, 0)?,
            vec![sensor_observation(
                TrustLevel::Medium,
                ObservationCoverage::Missing,
                timestamp(2026, 1, 20, 0, 0, 0)?,
            )],
        );

        assert_eq!(
            snapshot.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::SafeStateRequired
        );
        assert_eq!(snapshot.disposition, ObservatoryDisposition::SafeState);

        Ok(())
    }

    #[test]
    fn observatory_snapshot_preserves_runtime_expiry_after_observation() -> Result<(), &'static str>
    {
        let snapshot = ObservatorySnapshot::new(
            audit_record(AuthorizationScope::Execute)?,
            timestamp(2026, 1, 20, 0, 0, 0)?,
            vec![sensor_observation(
                TrustLevel::High,
                ObservationCoverage::Complete,
                timestamp(2026, 1, 20, 0, 0, 0)?,
            )],
        );

        assert_eq!(
            snapshot.current_validity(timestamp(2026, 2, 1, 0, 0, 0)?),
            CurrentValidity::Expired
        );

        Ok(())
    }
}
