#![forbid(unsafe_code)]

pub mod authorization;
pub mod envelope;
pub mod event_type;
pub mod idempotency;
pub mod provenance;
pub mod trace;

pub use authorization::{Authorization, AuthorizationState};
pub use envelope::{Classification, Evidence, EventEnvelope, ExecutionState, ProposedAction, SourceRef};
pub use event_type::EventType;
pub use idempotency::idempotency_key;
pub use provenance::Provenance;
pub use trace::TraceId;
