//! Evidence chain contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_events::EventEnvelope;

/// Evidence bundle produced from domain events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvidenceBundle {
    /// Source event captured in the evidence chain.
    pub source_event: EventEnvelope,
}
