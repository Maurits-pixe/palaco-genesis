#![forbid(unsafe_code)]

use palaco_office_event_contract::{
    AuthorizationState, EventEnvelope, EventType, ExecutionState, IdempotencyKey, Provenance,
    TraceId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlookCalendarSnapshot {
    pub object_id: String,
    pub change_kind: CalendarChangeKind,
    pub occurred_at: String,
    pub received_at: String,
    pub source_ref: String,
    pub evidence_ref: String,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarChangeKind {
    Created,
    Updated,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntakeOutcome {
    Accepted(EventEnvelope),
    Quarantined { reason: String },
}

#[derive(Debug, Default)]
pub struct IntakeRegistry {
    keys: std::collections::HashSet<String>,
}

impl IntakeRegistry {
    pub fn register(&mut self, key: &IdempotencyKey) -> Result<(), String> {
        if key.as_str().is_empty() {
            return Err("idempotency key must not be empty".to_owned());
        }
        if !self.keys.insert(key.as_str().to_owned()) {
            return Err("duplicate idempotency key".to_owned());
        }
        Ok(())
    }
}

pub fn normalize_outlook_calendar_event(
    snapshot: &OutlookCalendarSnapshot,
    event_id: &str,
    trace_id: &TraceId,
    idempotency_key: IdempotencyKey,
) -> IntakeOutcome {
    if snapshot.object_id.is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing calendar object id".to_owned() };
    }
    if snapshot.source_ref.is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing source provenance".to_owned() };
    }
    if snapshot.evidence_ref.is_empty() || snapshot.evidence_sha256.is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing evidence reference or hash".to_owned() };
    }
    if event_id.is_empty() {
        return IntakeOutcome::Quarantined { reason: "missing event id".to_owned() };
    }

    let event_type = match snapshot.change_kind {
        CalendarChangeKind::Created => EventType::MeetingCreated,
        CalendarChangeKind::Updated => EventType::MeetingUpdated,
        CalendarChangeKind::Cancelled => EventType::MeetingCancelled,
    };

    let provenance = Provenance::new(snapshot.source_ref.clone());
    let mut event = EventEnvelope::new(
        event_id.to_owned(),
        event_type,
        "1.0.0".to_owned(),
        "microsoft-graph".to_owned(),
        "outlook-calendar".to_owned(),
        "event".to_owned(),
        snapshot.object_id.clone(),
        snapshot.occurred_at.clone(),
        snapshot.received_at.clone(),
        AuthorizationState::None,
        ExecutionState::NotStarted,
        trace_id.clone(),
        idempotency_key,
        provenance,
    );

    event.evidence.push(snapshot.evidence_ref.clone());
    IntakeOutcome::Accepted(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> OutlookCalendarSnapshot {
        OutlookCalendarSnapshot {
            object_id: "calendar-event-1".to_owned(),
            change_kind: CalendarChangeKind::Created,
            occurred_at: "2026-09-18T10:00:00Z".to_owned(),
            received_at: "2026-09-18T10:00:01Z".to_owned(),
            source_ref: "graph:calendar/event/1".to_owned(),
            evidence_ref: "evidence:calendar/event/1".to_owned(),
            evidence_sha256: "abc".to_owned(),
        }
    }

    fn key() -> IdempotencyKey {
        IdempotencyKey::from_parts("microsoft-graph", "calendar-event-1", "MEETING_CREATED", "palaco")
    }

    #[test]
    fn created_event_starts_without_authorization() {
        let trace = TraceId::new("trace-1".to_owned()).unwrap_or_else(|_| TraceId::new("fallback".to_owned()).expect("trace construction"));
        let result = normalize_outlook_calendar_event(&snapshot(), "event-1", &trace, key());
        match result {
            IntakeOutcome::Accepted(event) => {
                assert_eq!(event.authorization, AuthorizationState::None);
                assert_eq!(event.execution, ExecutionState::NotStarted);
                assert_eq!(event.event_type, EventType::MeetingCreated);
            }
            IntakeOutcome::Quarantined { reason } => panic!("unexpected quarantine: {reason}"),
        }
    }

    #[test]
    fn missing_provenance_is_quarantined() {
        let mut value = snapshot();
        value.source_ref.clear();
        let trace = TraceId::new("trace-2".to_owned()).unwrap_or_else(|_| TraceId::new("fallback".to_owned()).expect("trace construction"));
        let result = normalize_outlook_calendar_event(&value, "event-2", &trace, key());
        assert!(matches!(result, IntakeOutcome::Quarantined { .. }));
    }

    #[test]
    fn registry_rejects_duplicate_keys() {
        let mut registry = IntakeRegistry::default();
        let first = registry.register(&key());
        assert!(first.is_ok());
        let second = registry.register(&key());
        assert!(second.is_err());
    }
}
