use std::collections::HashMap;

use palaco_office_event_contract::{
    Classification, EventEnvelope, EventType, Evidence, ProposedAction, Provenance, SourceRef,
    TraceId, Authorization, AuthorizationState, ExecutionState,
};

/// Normalized immutable snapshot received from an Outlook/Graph connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlookMessageSnapshot {
    pub object_id: String,
    pub occurred_at: String,
    pub received_at: String,
    pub source_ref: String,
    pub evidence_ref: String,
    pub evidence_sha256: Option<String>,
}

/// Intake validation outcome. Invalid input is quarantined and never executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntakeOutcome {
    Accepted(EventEnvelope),
    Quarantined { reason: String },
}

/// In-memory idempotency registry for the intake boundary.
#[derive(Debug, Default)]
pub struct IntakeRegistry {
    seen: HashMap<String, String>,
}

impl IntakeRegistry {
    /// Accept a new canonical idempotency key, or reject a duplicate.
    pub fn register(&mut self, key: String, event_id: String) -> Result<(), &'static str> {
        if key.trim().is_empty() || event_id.trim().is_empty() {
            return Err("idempotency registration requires non-empty values");
        }
        if self.seen.contains_key(&key) {
            return Err("duplicate idempotency key");
        }
        self.seen.insert(key, event_id);
        Ok(())
    }
}

/// Converts a validated Outlook message snapshot into PALACO_EVENT_V1.
pub fn normalize_outlook_message(
    snapshot: OutlookMessageSnapshot,
    event_id: String,
    trace_id: TraceId,
    idempotency_key: String,
) -> IntakeOutcome {
    if snapshot.object_id.trim().is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing Outlook object id".into() };
    }
    if snapshot.source_ref.trim().is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing source provenance".into() };
    }
    if snapshot.evidence_ref.trim().is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing evidence reference".into() };
    }
    if event_id.trim().is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing event id".into() };
    }
    if idempotency_key.trim().is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing idempotency key".into() };
    }

    IntakeOutcome::Accepted(EventEnvelope {
        event_id,
        event_type: EventType::EmailReceived,
        event_version: "1.0.0".into(),
        source: SourceRef {
            system: "microsoft-graph".into(),
            connector: "outlook-mail".into(),
            object_type: "message".into(),
            object_id: snapshot.object_id,
        },
        occurred_at: snapshot.occurred_at,
        received_at: snapshot.received_at,
        actor: None,
        classification: Classification {
            domain: "office".into(),
            category: "email".into(),
            confidence: 1.0,
            priority: "normal".into(),
        },
        evidence: vec![Evidence {
            reference: snapshot.evidence_ref,
            sha256: snapshot.evidence_sha256,
            kind: Some("outlook-message-snapshot".into()),
        }],
        context_refs: Vec::new(),
        proposed_action: None::<ProposedAction>,
        authorization: Authorization {
            state: AuthorizationState::None,
            reference: None,
        },
        execution: ExecutionState::NotStarted,
        provenance: Provenance {
            source_ref: snapshot.source_ref,
            parent_event_id: None,
            source_hash: None,
        },
        trace_id,
        idempotency_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> OutlookMessageSnapshot {
        OutlookMessageSnapshot {
            object_id: "message-1".into(),
            occurred_at: "2026-09-18T10:00:00Z".into(),
            received_at: "2026-09-18T10:00:01Z".into(),
            source_ref: "graph:outlook:message:message-1".into(),
            evidence_ref: "outlook://message/message-1".into(),
            evidence_sha256: None,
        }
    }

    #[test]
    fn normalized_mail_is_not_authorized_for_execution() -> Result<(), &'static str> {
        let trace = TraceId::new("trace-1")?;
        let outcome = normalize_outlook_message(snapshot(), "evt-1".into(), trace, "key-1".into());
        let IntakeOutcome::Accepted(event) = outcome else {
            return Err("expected accepted event");
        };
        assert_eq!(event.authorization.state, AuthorizationState::None);
        assert_eq!(
            event.execution_gate(),
            Err("execution blocked: authorization is not GRANTED")
        );
        Ok(())
    }

    #[test]
    fn missing_provenance_is_quarantined() -> Result<(), &'static str> {
        let mut input = snapshot();
        input.source_ref.clear();
        let trace = TraceId::new("trace-2")?;
        match normalize_outlook_message(input, "evt-2".into(), trace, "key-2".into()) {
            IntakeOutcome::Quarantined { reason } => assert_eq!(reason, "missing source provenance"),
            IntakeOutcome::Accepted(_) => return Err("missing provenance was accepted"),
        }
        Ok(())
    }

    #[test]
    fn duplicate_idempotency_is_rejected() -> Result<(), &'static str> {
        let mut registry = IntakeRegistry::default();
        registry.register("same-key".into(), "evt-1".into())?;
        assert_eq!(registry.register("same-key".into(), "evt-2".into()), Err("duplicate idempotency key"));
        Ok(())
    }
}
