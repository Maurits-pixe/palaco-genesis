#![forbid(unsafe_code)]

use std::collections::HashSet;
use palaco_office_event_contract::{AuthorizationState, EventEnvelope, ExecutionState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyError {
    InvalidEvent(String),
    AuthorizationNotExecutable,
    AuthorizationReferenceMissing,
    ExecutionNotStarted,
    ExecutionTerminal,
    DuplicateIdempotencyKey,
    EmptyIdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimDecision {
    Claimed,
    Duplicate,
}

#[derive(Debug, Default)]
pub struct IdempotencyRegistry {
    claimed: HashSet<String>,
}

impl IdempotencyRegistry {
    /// Claims an idempotency key exactly once. A duplicate claim never executes work.
    pub fn claim(&mut self, key: &str) -> Result<ClaimDecision, SafetyError> {
        let key = key.trim();
        if key.is_empty() {
            return Err(SafetyError::EmptyIdempotencyKey);
        }
        if self.claimed.insert(key.to_owned()) {
            Ok(ClaimDecision::Claimed)
        } else {
            Ok(ClaimDecision::Duplicate)
        }
    }
}

/// Checks all safety conditions immediately before an adapter is allowed to perform
/// an external side effect. This deliberately re-checks authorization after commit.
pub fn pre_side_effect_check(
    event: &EventEnvelope,
    registry: &mut IdempotencyRegistry,
) -> Result<ClaimDecision, SafetyError> {
    event.validate().map_err(SafetyError::InvalidEvent)?;

    if !matches!(event.execution, ExecutionState::Started) {
        return Err(match event.execution {
            ExecutionState::Completed | ExecutionState::Failed | ExecutionState::Blocked =>
                SafetyError::ExecutionTerminal,
            ExecutionState::NotStarted => SafetyError::ExecutionNotStarted,
            ExecutionState::Started => unreachable!(),
        });
    }

    if !matches!(event.authorization.state, AuthorizationState::Granted) {
        return Err(SafetyError::AuthorizationNotExecutable);
    }

    if event
        .authorization
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Err(SafetyError::AuthorizationReferenceMissing);
    }

    registry.claim(&event.idempotency_key.0)
}

/// Immutable execution outcome metadata. It does not itself perform an external side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub event_id: String,
    pub authorization_reference: String,
    pub trace_id: String,
    pub idempotency_key: String,
    pub external_reference: Option<String>,
}

pub fn completed_receipt(
    event: &EventEnvelope,
    external_reference: Option<String>,
) -> Result<ExecutionReceipt, SafetyError> {
    event.validate().map_err(SafetyError::InvalidEvent)?;
    if !matches!(event.execution, ExecutionState::Completed) {
        return Err(SafetyError::ExecutionNotStarted);
    }
    let authorization_reference = event.authorization.reference.clone()
        .ok_or(SafetyError::AuthorizationReferenceMissing)?;
    Ok(ExecutionReceipt {
        event_id: event.event_id.clone(),
        authorization_reference,
        trace_id: event.trace_id.0.clone(),
        idempotency_key: event.idempotency_key.0.clone(),
        external_reference,
    })
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
            "event-safety-1".to_owned(), EventType::EmailReceived, "1.0.0".to_owned(),
            "test".to_owned(), "test".to_owned(), "message".to_owned(), "message-1".to_owned(),
            "2026-09-18T10:00:00Z".to_owned(), "2026-09-18T10:00:01Z".to_owned(),
            AuthorizationState::Granted, ExecutionState::Started,
            TraceId("trace-safety".to_owned()),
            IdempotencyKey::from_parts("test", "message-1", "EMAIL_RECEIVED", "todo"),
            Provenance::new("test:message/1".to_owned()),
        );
        e.authorization.reference = Some("auth:safety-1".to_owned());
        e.proposed_action = Some(ProposedAction {
            action_type: "create_task".to_owned(),
            destination: "todo".to_owned(),
            description: "Follow up".to_owned(),
        });
        e
    }

    #[test]
    fn duplicate_claim_is_blocked_without_second_execution() -> Result<(), SafetyError> {
        let e = event();
        let mut registry = IdempotencyRegistry::default();
        assert_eq!(pre_side_effect_check(&e, &mut registry)?, ClaimDecision::Claimed);
        assert_eq!(pre_side_effect_check(&e, &mut registry)?, ClaimDecision::Duplicate);
        Ok(())
    }

    #[test]
    fn revocation_is_rechecked_before_side_effect() {
        let mut e = event();
        e.authorization.state = AuthorizationState::Revoked;
        let mut registry = IdempotencyRegistry::default();
        assert_eq!(
            pre_side_effect_check(&e, &mut registry),
            Err(SafetyError::AuthorizationNotExecutable)
        );
    }

    #[test]
    fn expiration_is_not_treated_as_grant() {
        let mut e = event();
        e.authorization.state = AuthorizationState::Expired;
        let mut registry = IdempotencyRegistry::default();
        assert_eq!(
            pre_side_effect_check(&e, &mut registry),
            Err(SafetyError::AuthorizationNotExecutable)
        );
    }

    #[test]
    fn completed_receipt_retains_constitutional_trace() -> Result<(), SafetyError> {
        let mut e = event();
        e.execution = ExecutionState::Completed;
        let receipt = completed_receipt(&e, Some("graph:task-123".to_owned()))?;
        assert_eq!(receipt.event_id, "event-safety-1");
        assert_eq!(receipt.authorization_reference, "auth:safety-1");
        assert_eq!(receipt.trace_id, "trace-safety");
        assert!(!receipt.idempotency_key.is_empty());
        assert_eq!(receipt.external_reference.as_deref(), Some("graph:task-123"));
        Ok(())
    }

    #[test]
    fn empty_idempotency_key_fails_closed() {
        let mut registry = IdempotencyRegistry::default();
        assert_eq!(
            registry.claim(" "),
            Err(SafetyError::EmptyIdempotencyKey)
        );
    }
}
