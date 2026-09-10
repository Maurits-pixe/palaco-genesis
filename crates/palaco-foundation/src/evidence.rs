use serde::{Deserialize, Serialize};

use crate::{
    errors::{EscalationReason, RevalidationError, RevocationReason, ValidationError},
    identity::NodeId,
    traits::{CurrentlyAssessable, FailClosed, Identifiable, Revalidatable, Validatable},
    types::{
        CurrentValidity, DecisionContext, EvidenceId, RevalidationOutcome, Timestamp, TrustLevel,
        ValidityWindow,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub timestamp: Timestamp,
    pub source: NodeId,
    pub trust: TrustLevel,
    pub validity_window: ValidityWindow,
}

impl Evidence {
    #[must_use]
    pub fn new(
        id: EvidenceId,
        timestamp: Timestamp,
        source: NodeId,
        trust: TrustLevel,
        validity_window: ValidityWindow,
    ) -> Self {
        Self {
            id,
            timestamp,
            source,
            trust,
            validity_window,
        }
    }
}

impl Identifiable for Evidence {
    type Id = EvidenceId;

    fn id(&self) -> Self::Id {
        self.id
    }
}

impl Validatable for Evidence {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.validity_window.not_after < self.validity_window.not_before {
            return Err(ValidationError::InvalidValidityWindow);
        }

        Ok(())
    }
}

impl CurrentlyAssessable for Evidence {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        if at < self.validity_window.not_before {
            return CurrentValidity::Pending;
        }

        if at > self.validity_window.not_after {
            return CurrentValidity::Expired;
        }

        match self.trust {
            TrustLevel::Unknown | TrustLevel::Low => CurrentValidity::InsufficientEvidence,
            TrustLevel::Medium | TrustLevel::High => CurrentValidity::Valid,
        }
    }
}

impl Revalidatable for Evidence {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        match self.current_validity(context.observed_at) {
            CurrentValidity::Pending | CurrentValidity::SafeStateRequired => {
                Ok(RevalidationOutcome::SafeState)
            }
            CurrentValidity::Valid => Ok(RevalidationOutcome::Confirmed),
            CurrentValidity::Expired => Err(RevalidationError::RevocationRequired {
                reason: RevocationReason::EvidenceExpired,
            }),
            CurrentValidity::Revoked => Ok(RevalidationOutcome::Revoked),
            CurrentValidity::InsufficientEvidence => Err(RevalidationError::EscalationRequired {
                reason: EscalationReason::LowTrust,
            }),
        }
    }
}

impl FailClosed for Evidence {
    type Output = CurrentValidity;

    fn fail_closed(&self) -> Self::Output {
        CurrentValidity::SafeStateRequired
    }
}
