#![forbid(unsafe_code)]

use palaco_office_event_contract::{
    Authorization, AuthorizationState, EventEnvelope, EventType, ExecutionState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidEvent(String),
    InvalidTransition(&'static str),
    MissingReference,
}

impl AuthorizationError {
    pub fn reason(&self) -> String {
        match self {
            Self::InvalidEvent(v) => v.clone(),
            Self::InvalidTransition(v) => (*v).to_owned(),
            Self::MissingReference => "authorization reference is required".to_owned(),
        }
    }
}

/// Creates an authorization request without granting authority.
pub fn request(event: &EventEnvelope) -> Result<EventEnvelope, AuthorizationError> {
    event.validate().map_err(AuthorizationError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::None) {
        return Err(AuthorizationError::InvalidTransition(
            "authorization request requires NONE state",
        ));
    }
    if !matches!(event.execution, ExecutionState::NotStarted) {
        return Err(AuthorizationError::InvalidTransition(
            "authorization request requires NOT_STARTED execution",
        ));
    }

    let mut requested = event.clone();
    requested.event_type = EventType::AuthorizationRequested;
    requested.authorization = Authorization {
        state: AuthorizationState::Requested,
        reference: None,
    };
    Ok(requested)
}

/// Grants a previously requested authorization with a non-empty reference.
/// This function records authorization state only; it does not execute.
pub fn grant(
    event: &EventEnvelope,
    reference: impl Into<String>,
) -> Result<EventEnvelope, AuthorizationError> {
    event.validate().map_err(AuthorizationError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::Requested) {
        return Err(AuthorizationError::InvalidTransition(
            "only REQUESTED authorization can be granted",
        ));
    }
    let reference = reference.into();
    if reference.trim().is_empty() {
        return Err(AuthorizationError::MissingReference);
    }

    let mut granted = event.clone();
    granted.event_type = EventType::AuthorizationGranted;
    granted.authorization = Authorization {
        state: AuthorizationState::Granted,
        reference: Some(reference),
    };
    Ok(granted)
}

/// Rejects a requested authorization without permitting execution.
pub fn reject(event: &EventEnvelope) -> Result<EventEnvelope, AuthorizationError> {
    event.validate().map_err(AuthorizationError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::Requested) {
        return Err(AuthorizationError::InvalidTransition(
            "only REQUESTED authorization can be rejected",
        ));
    }

    let mut rejected = event.clone();
    rejected.event_type = EventType::AuthorizationRejected;
    rejected.authorization.state = AuthorizationState::Rejected;
    rejected.authorization.reference = None;
    Ok(rejected)
}

/// Revokes an existing authorization. Execution is blocked and the reference is preserved.
pub fn revoke(event: &EventEnvelope) -> Result<EventEnvelope, AuthorizationError> {
    event.validate().map_err(AuthorizationError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::Granted) {
        return Err(AuthorizationError::InvalidTransition(
            "only GRANTED authorization can be revoked",
        ));
    }

    let mut revoked = event.clone();
    revoked.event_type = EventType::Revoked;
    revoked.authorization.state = AuthorizationState::Revoked;
    revoked.execution = ExecutionState::Blocked;
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{
        EventType, IdempotencyKey, Provenance, TraceId,
    };

    fn event() -> EventEnvelope {
        EventEnvelope::new(
            "event-auth-1".to_owned(),
            EventType::EmailReceived,
            "1.0.0".to_owned(),
            "test".to_owned(),
            "test".to_owned(),
            "message".to_owned(),
            "message-1".to_owned(),
            "2026-09-18T10:00:00Z".to_owned(),
            "2026-09-18T10:00:01Z".to_owned(),
            AuthorizationState::None,
            ExecutionState::NotStarted,
            TraceId("trace-auth".to_owned()),
            IdempotencyKey::from_parts("test", "message-1", "EMAIL_RECEIVED", "palaco"),
            Provenance::new("test:message/1".to_owned()),
        )
    }

    #[test]
    fn request_does_not_grant() -> Result<(), AuthorizationError> {
        let requested = request(&event())?;
        assert_eq!(requested.authorization.state, AuthorizationState::Requested);
        assert_eq!(requested.execution, ExecutionState::NotStarted);
        Ok(())
    }

    #[test]
    fn grant_requires_request_and_reference() -> Result<(), AuthorizationError> {
        let requested = request(&event())?;
        assert_eq!(
            grant(&requested, " "),
            Err(AuthorizationError::MissingReference)
        );
        let granted = grant(&requested, "auth:1")?;
        assert_eq!(granted.authorization.state, AuthorizationState::Granted);
        assert_eq!(granted.authorization.reference.as_deref(), Some("auth:1"));
        assert_eq!(granted.execution, ExecutionState::NotStarted);
        Ok(())
    }

    #[test]
    fn reject_is_terminal_for_this_authorization_instance() -> Result<(), AuthorizationError> {
        let requested = request(&event())?;
        let rejected = reject(&requested)?;
        assert_eq!(rejected.authorization.state, AuthorizationState::Rejected);
        assert_eq!(rejected.execution, ExecutionState::NotStarted);
        Ok(())
    }

    #[test]
    fn revoke_preserves_reference_and_blocks_execution() -> Result<(), AuthorizationError> {
        let requested = request(&event())?;
        let granted = grant(&requested, "auth:1")?;
        let revoked = revoke(&granted)?;
        assert_eq!(revoked.authorization.state, AuthorizationState::Revoked);
        assert_eq!(revoked.authorization.reference.as_deref(), Some("auth:1"));
        assert_eq!(revoked.execution, ExecutionState::Blocked);
        Ok(())
    }
}
