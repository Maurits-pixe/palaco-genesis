//! Evidence chain contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_events::EventEnvelope;
use palaco_foundation::{
    errors::{EscalationReason, RevalidationError},
    evidence::Evidence,
    traits::{CurrentlyAssessable, Identifiable, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, EvidenceId, RevalidationOutcome, Timestamp},
};

/// Completeness of an evidence bundle in the current decision context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvidenceCompleteness {
    /// The bundle contains the necessary context for current assessment.
    #[default]
    Complete,
    /// The bundle is structurally valid but context is incomplete.
    Partial,
}

/// Evidence bundle produced from domain events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    /// Source event captured in the evidence chain.
    pub source_event: EventEnvelope,
    /// Canonical evidence object bound to temporal validity.
    pub evidence: Evidence,
    /// Completeness of the bundle for current evaluation.
    pub completeness: EvidenceCompleteness,
}

impl EvidenceBundle {
    /// Creates a new evidence bundle from an event and evidence object.
    #[must_use]
    pub fn new(
        source_event: EventEnvelope,
        evidence: Evidence,
        completeness: EvidenceCompleteness,
    ) -> Self {
        Self {
            source_event,
            evidence,
            completeness,
        }
    }
}

impl Identifiable for EvidenceBundle {
    type Id = EvidenceId;

    fn id(&self) -> Self::Id {
        self.evidence.id()
    }
}

impl Validatable for EvidenceBundle {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.evidence.validate()
    }
}

impl CurrentlyAssessable for EvidenceBundle {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        match self.completeness {
            EvidenceCompleteness::Complete => self.evidence.current_validity(at),
            EvidenceCompleteness::Partial => CurrentValidity::InsufficientEvidence,
        }
    }
}

impl Revalidatable for EvidenceBundle {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        match self.completeness {
            EvidenceCompleteness::Complete => self.evidence.revalidate(context),
            EvidenceCompleteness::Partial => Err(RevalidationError::EscalationRequired {
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
        types::{CurrentValidity, DecisionContext, TrustLevel, ValidityWindow},
    };
    use palaco_types::DomainMarker;

    use crate::{EvidenceBundle, EvidenceCompleteness};

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

    #[test]
    fn evidence_bundle_delegates_current_validity_when_complete() -> Result<(), &'static str> {
        let bundle = EvidenceBundle::new(
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
            EvidenceCompleteness::Complete,
        );

        assert_eq!(
            bundle.current_validity(timestamp(2026, 1, 15, 12, 0, 0)?),
            CurrentValidity::Valid
        );

        Ok(())
    }

    #[test]
    fn evidence_bundle_escalates_when_context_is_partial() -> Result<(), &'static str> {
        let bundle = EvidenceBundle::new(
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
            EvidenceCompleteness::Partial,
        );

        assert!(bundle
            .revalidate(&context(timestamp(2026, 1, 15, 12, 0, 0)?))
            .is_err());

        Ok(())
    }
}
