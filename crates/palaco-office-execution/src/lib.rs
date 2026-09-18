#![forbid(unsafe_code)]

use palaco_office_event_contract::{
    Authorization, AuthorizationState, EventEnvelope, ExecutionState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDecision {
    Authorized,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    InvalidEvent(String),
    MissingAuthorizationReference,
    AuthorizationNotGranted,
    ExecutionAlreadyStarted,
    ExecutionAlreadyCompleted,
    ExecutionBlocked,
}

impl CommitError {
    pub fn reason(&self) -> &str {
        match self {
            Self::InvalidEvent(v) => v.as_str(),
            Self::MissingAuthorizationReference => "authorization reference is required",
            Self::AuthorizationNotGranted => "authorization is not granted",
            Self::ExecutionAlreadyStarted => "execution has already started",
            Self::ExecutionAlreadyCompleted => "execution has already completed",
            Self::ExecutionBlocked => "execution is blocked",
        }
    }
}

/// The final constitutional boundary before an external side effect.
///
/// A GRANTED authorization is necessary but is not itself execution.
/// The commit gate atomically records the transition to EXECUTING in the
/// event envelope only after validation and authorization checks succeed.
pub fn execution_commit_gate(event: &EventEnvelope) -> Result<CommitDecision, CommitError> {
    event.validate().map_err(CommitError::InvalidEvent)?;

    if !matches!(event.authorization, AuthorizationState::Granted) {
        return Err(CommitError::AuthorizationNotGranted);
    }
    if event.authorization.reference.as_deref().map(str::trim).filter(|v| !v.is_empty()).is_none() {
        return Err(CommitError::MissingAuthorizationReference);
    }

    match event.execution {
        ExecutionState::NotStarted => Ok(CommitDecision::Authorized),
        ExecutionState::Started => Err(CommitError::ExecutionAlreadyStarted),
        ExecutionState::Completed => Err(CommitError::ExecutionAlreadyCompleted),
        ExecutionState::Failed => Err(CommitError::ExecutionBlocked),
        ExecutionState::Blocked => Err(CommitError::ExecutionBlocked),
    }
}

/// Applies the commit transition after the caller has passed the gate.
///
/// The transition deliberately does not perform an external action.
pub fn commit_execution(event: &mut EventEnvelope) -> Result<(), CommitError> {
    execution_commit_gate(event)?;
    event.execution = ExecutionState::Started;
    Ok(())
}

/// Explicit authorization constructor used by integration layers.
pub fn granted_authorization(reference: impl Into<String>) -> Result<Authorization, CommitError> {
    let reference = reference.into();
    if reference.trim().is_empty() {
        return Err(CommitError::MissingAuthorizationReference);
    }
    Ok(Authorization {
        state: AuthorizationState::Granted,
        reference: Some(reference),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{
        EventType, IdempotencyKey, Provenance, TraceId,
    };

    fn event() -> EventEnvelope {
        EventEnvelope::new(
            "event-1".to_owned(),
            EventType::EmailReceived,
            "1.0.0".to_owned(),
            "microsoft-graph".to_owned(),
            "outlook-mail".to_owned(),
            "message".to_owned(),
            "message-1".to_owned(),
            "2026-09-18T10:00:00Z".to_owned(),
            "2026-09-18T10:00:01Z".to_owned(),
            AuthorizationState::Granted,
            ExecutionState::NotStarted,
            TraceId("trace-1".to_owned()),
            IdempotencyKey::from_parts("graph", "message-1", "EMAIL_RECEIVED", "palaco"),
            Provenance::new("graph:message/1".to_owned()),
        )
    }

    #[test]
    fn granted_without_reference_is_blocked() {
        let mut e = event();
        e.authorization.reference = None;
        assert_eq!(
            execution_commit_gate(&e),
            Err(CommitError::MissingAuthorizationReference)
        );
    }

    #[test]
    fn none_is_blocked() {
        let mut e = event();
        e.authorization = AuthorizationState::None;
        assert_eq!(
            execution_commit_gate(&e),
            Err(CommitError::AuthorizationNotGranted)
        );
    }

    #[test]
    fn granted_can_commit_but_does_not_execute_external_action() {
        let mut e = event();
        assert_eq!(execution_commit_gate(&e), Ok(CommitDecision::Authorized));
        assert_eq!(e.execution, ExecutionState::NotStarted);
        assert!(commit_execution(&mut e).is_ok());
        assert_eq!(e.execution, ExecutionState::Started);
    }

    #[test]
    fn second_commit_is_blocked() {
        let mut e = event();
        assert!(commit_execution(&mut e).is_ok());
        assert_eq!(
            commit_execution(&mut e),
            Err(CommitError::ExecutionAlreadyStarted)
        );
    }

    #[test]
    fn revoked_cannot_commit() {
        let mut e = event();
        e.authorization = AuthorizationState::Revoked;
        assert_eq!(
            execution_commit_gate(&e),
            Err(CommitError::AuthorizationNotGranted)
        );
    }
}
