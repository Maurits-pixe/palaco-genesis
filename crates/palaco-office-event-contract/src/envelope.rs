use crate::{
    authorization::{Authorization, AuthorizationState},
    event_type::EventType,
    provenance::Provenance,
    trace::TraceId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    pub system: String,
    pub connector: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    pub domain: String,
    pub category: String,
    pub confidence: f64,
    pub priority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub reference: String,
    pub sha256: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedAction {
    pub action_type: String,
    pub destination: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub event_type: EventType,
    pub event_version: String,
    pub source: SourceRef,
    pub occurred_at: String,
    pub received_at: String,
    pub actor: Option<String>,
    pub classification: Classification,
    pub evidence: Vec<Evidence>,
    pub context_refs: Vec<String>,
    pub proposed_action: Option<ProposedAction>,
    pub authorization: Authorization,
    pub execution: ExecutionState,
    pub provenance: Provenance,
    pub trace_id: TraceId,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState { NotStarted, Started, Completed, Failed, Blocked }

impl EventEnvelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.event_version != "1.0.0" { return Err("unsupported event contract version"); }
        if self.event_id.trim().is_empty() { return Err("missing event id"); }
        if self.source.object_id.trim().is_empty() { return Err("missing source object id"); }
        if !(0.0..=1.0).contains(&self.classification.confidence) { return Err("invalid confidence"); }
        if self.evidence.is_empty() { return Err("missing evidence"); }
        self.provenance.validate()
    }

    pub fn execution_gate(&self) -> Result<(), &'static str> {
        self.validate()?;
        if !self.authorization.permits_execution() {
            return Err("execution blocked: authorization is not GRANTED");
        }
        if self.execution != ExecutionState::NotStarted {
            return Err("execution blocked: state is not NotStarted");
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.authorization.state = AuthorizationState::Revoked;
        self.execution = ExecutionState::Blocked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            event_id: "evt-1".into(),
            event_type: EventType::EmailReceived,
            event_version: "1.0.0".into(),
            source: SourceRef {
                system: "microsoft-graph".into(),
                connector: "outlook-mail".into(),
                object_type: "message".into(),
                object_id: "msg-1".into(),
            },
            occurred_at: "2026-09-18T10:00:00Z".into(),
            received_at: "2026-09-18T10:00:01Z".into(),
            actor: None,
            classification: Classification {
                domain: "office".into(),
                category: "email".into(),
                confidence: 1.0,
                priority: "normal".into(),
            },
            evidence: vec![Evidence {
                reference: "outlook://message/msg-1".into(),
                sha256: None,
                kind: Some("source".into()),
            }],
            context_refs: vec![],
            proposed_action: None,
            authorization: Authorization { state: AuthorizationState::None, reference: None },
            execution: ExecutionState::NotStarted,
            provenance: Provenance {
                source_ref: "graph:outlook:message:msg-1".into(),
                parent_event_id: None,
                source_hash: None,
            },
            trace_id: TraceId::new("trace-1").expect("test fixture"),
            idempotency_key: "key-1".into(),
        }
    }

    #[test]
    fn execution_requires_explicit_grant() {
        let event = envelope();
        assert_eq!(
            event.execution_gate(),
            Err("execution blocked: authorization is not GRANTED")
        );
    }

    #[test]
    fn revoke_blocks_execution() {
        let mut event = envelope();
        event.authorization.state = AuthorizationState::Granted;
        assert!(event.execution_gate().is_ok());
        event.revoke();
        assert_eq!(event.execution, ExecutionState::Blocked);
        assert!(!event.authorization.permits_execution());
    }
}
