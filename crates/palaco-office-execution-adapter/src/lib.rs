#![forbid(unsafe_code)]

use palaco_office_event_contract::{EventEnvelope, ExecutionState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    InvalidEvent(String),
    AuthorizationNotGranted,
    AuthorizationReferenceMissing,
    ExecutionNotCommitted,
    UnsupportedAction(String),
}

/// A side-effect adapter is deliberately separate from authorization and commit.
/// Implementations must perform no external operation unless the envelope is
/// already in STARTED state and carries an authorization reference.
pub trait ExecutionAdapter {
    fn execute(&self, event: &EventEnvelope) -> Result<ExecutionResult, AdapterError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub event_id: String,
    pub destination: String,
    pub external_reference: Option<String>,
}

/// Validates the constitutional preconditions required at the adapter boundary.
/// This function performs no external side effect.
pub fn authorize_adapter_entry(event: &EventEnvelope) -> Result<(), AdapterError> {
    event.validate().map_err(AdapterError::InvalidEvent)?;

    if !event.authorization.permits_execution() {
        return Err(AdapterError::AuthorizationNotGranted);
    }

    if event
        .authorization
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Err(AdapterError::AuthorizationReferenceMissing);
    }

    if !matches!(event.execution, ExecutionState::Started) {
        return Err(AdapterError::ExecutionNotCommitted);
    }

    Ok(())
}

/// Deterministic preflight for a proposed action. No external operation occurs.
pub fn preflight(event: &EventEnvelope) -> Result<&str, AdapterError> {
    authorize_adapter_entry(event)?;
    let action = event
        .proposed_action
        .as_ref()
        .ok_or_else(|| AdapterError::UnsupportedAction("no proposed action".to_owned()))?;

    if action.action_type.trim().is_empty() || action.destination.trim().is_empty() {
        return Err(AdapterError::UnsupportedAction(
            "action type and destination are required".to_owned(),
        ));
    }

    Ok(action.destination.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{
        AuthorizationState, EventEnvelope, EventType, ExecutionState, IdempotencyKey,
        ProposedAction, Provenance, TraceId,
    };

    fn event() -> EventEnvelope {
        let mut e = EventEnvelope::new(
            "event-adapter-1".to_owned(),
            EventType::EmailReceived,
            "1.0.0".to_owned(),
            "test".to_owned(),
            "test".to_owned(),
            "message".to_owned(),
            "message-1".to_owned(),
            "2026-09-18T10:00:00Z".to_owned(),
            "2026-09-18T10:00:01Z".to_owned(),
            AuthorizationState::Granted,
            ExecutionState::Started,
            TraceId("trace-adapter".to_owned()),
            IdempotencyKey::from_parts("test", "message-1", "EMAIL_RECEIVED", "palaco"),
            Provenance::new("test:message/1".to_owned()),
        );
        e.authorization.reference = Some("auth:adapter-1".to_owned());
        e.proposed_action = Some(ProposedAction {
            action_type: "create_task".to_owned(),
            destination: "todo".to_owned(),
            description: "Follow up".to_owned(),
        });
        e
    }

    #[test]
    fn adapter_entry_requires_committed_execution() {
        let mut e = event();
        e.execution = ExecutionState::NotStarted;
        assert_eq!(
            authorize_adapter_entry(&e),
            Err(AdapterError::ExecutionNotCommitted)
        );
    }

    #[test]
    fn adapter_entry_requires_authorization_reference() {
        let mut e = event();
        e.authorization.reference = None;
        assert_eq!(
            authorize_adapter_entry(&e),
            Err(AdapterError::AuthorizationReferenceMissing)
        );
    }

    #[test]
    fn revoked_authorization_cannot_reach_adapter() {
        let mut e = event();
        e.authorization.state = AuthorizationState::Revoked;
        assert_eq!(
            authorize_adapter_entry(&e),
            Err(AdapterError::AuthorizationNotGranted)
        );
    }

    #[test]
    fn preflight_is_side_effect_free() -> Result<(), AdapterError> {
        let e = event();
        assert_eq!(preflight(&e)?, "todo");
        assert_eq!(e.execution, ExecutionState::Started);
        Ok(())
    }
}
