use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("validity window must not end before it starts")]
    InvalidValidityWindow,
    #[error("decision context is required for revalidation")]
    MissingDecisionContext,
    #[error("validation failed: {message}")]
    Message { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RevocationReason {
    #[error("evidence expired")]
    EvidenceExpired,
    #[error("policy was withdrawn")]
    PolicyWithdrawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EscalationReason {
    #[error("evidence trust is too low")]
    LowTrust,
    #[error("evidence is incomplete for the current decision context")]
    IncompleteEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RevalidationError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("revocation required: {reason}")]
    RevocationRequired { reason: RevocationReason },
    #[error("escalation required: {reason}")]
    EscalationRequired { reason: EscalationReason },
}
