#![forbid(unsafe_code)]

use palaco_office_event_contract::{
    EventEnvelope, EventType, ProposedAction,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioDisposition {
    Observe,
    Summarize,
    Propose,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioResponse {
    pub disposition: RioDisposition,
    pub event_id: String,
    pub message: String,
}

pub fn interpret(event: &EventEnvelope) -> RioResponse {
    let (disposition, message) = match event.event_type {
        EventType::AuthorizationRequested => (
            RioDisposition::Observe,
            "Authorization request observed; no authorization is granted by RIO.".to_owned(),
        ),
        EventType::AuthorizationGranted => (
            RioDisposition::Observe,
            "Authorization grant observed; RIO does not execute external actions.".to_owned(),
        ),
        EventType::Revoked | EventType::RevokeRequested => (
            RioDisposition::Block,
            "Revocation state observed; pending execution must remain blocked.".to_owned(),
        ),
        EventType::ExecutionStarted
        | EventType::ExecutionCompleted
        | EventType::ExecutionFailed => (
            RioDisposition::Observe,
            "Execution lifecycle observed; RIO does not become the execution authority.".to_owned(),
        ),
        _ if event.proposed_action.is_some() => (
            RioDisposition::Propose,
            "Proposed action available for authorized downstream handling.".to_owned(),
        ),
        _ => (
            RioDisposition::Summarize,
            "Office event accepted for interpretation and summary.".to_owned(),
        ),
    };

    RioResponse {
        disposition,
        event_id: event.event_id.clone(),
        message,
    }
}

pub fn propose_action(
    event: &EventEnvelope,
    action: ProposedAction,
) -> Result<EventEnvelope, &'static str> {
    if event.event_id.trim().is_empty() {
        return Err("cannot propose for an event without an id");
    }
    if action.action_type.trim().is_empty() {
        return Err("action type must not be empty");
    }
    if action.destination.trim().is_empty() {
        return Err("action destination must not be empty");
    }

    let mut proposed = event.clone();
    proposed.proposed_action = Some(action);
    Ok(proposed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{
        AuthorizationState, EventType, ExecutionState,
    };

    fn event(event_type: EventType) -> EventEnvelope {
        EventEnvelope {
            event_id: "evt-rio-1".to_owned(),
            event_type,
            event_version: "1.0.0".to_owned(),
            source: palaco_office_event_contract::SourceRef {
                system: "test".to_owned(),
                connector: "test".to_owned(),
                object_type: "message".to_owned(),
                object_id: "object-1".to_owned(),
            },
            occurred_at: "2026-09-18T10:00:00Z".to_owned(),
            received_at: "2026-09-18T10:00:01Z".to_owned(),
            actor: None,
            classification: palaco_office_event_contract::Classification {
                domain: "office".to_owned(),
                category: "test".to_owned(),
                confidence: 1.0,
                priority: "normal".to_owned(),
            },
            evidence: vec![palaco_office_event_contract::Evidence {
                reference: "evidence:test".to_owned(),
                sha256: None,
                kind: Some("source".to_owned()),
            }],
            context_refs: vec![],
            proposed_action: None,
            authorization: palaco_office_event_contract::Authorization {
                state: AuthorizationState::None,
                reference: None,
            },
            execution: ExecutionState::NotStarted,
            provenance: palaco_office_event_contract::Provenance::new("source:test".to_owned()),
            trace_id: palaco_office_event_contract::TraceId("trace-rio".to_owned()),
            idempotency_key: "key-rio".to_owned(),
        }
    }

    #[test]
    fn rio_does_not_grant_authorization() {
        let response = interpret(&event(EventType::AuthorizationRequested));
        assert_eq!(response.disposition, RioDisposition::Observe);
    }

    #[test]
    fn rio_blocks_revocation_state() {
        let response = interpret(&event(EventType::Revoked));
        assert_eq!(response.disposition, RioDisposition::Block);
    }

    #[test]
    fn rio_can_propose_without_executing() {
        let proposed = propose_action(
            &event(EventType::EmailReceived),
            ProposedAction {
                action_type: "create_task".to_owned(),
                destination: "todo".to_owned(),
                description: "Follow up".to_owned(),
            },
        );
        assert!(proposed.is_ok());
        let result = proposed.unwrap_or_else(|_| event(EventType::EmailReceived));
        assert!(result.proposed_action.is_some());
        assert_eq!(result.execution, ExecutionState::NotStarted);
    }
}
