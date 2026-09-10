//! Domain event contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_types::DomainMarker;

/// Event envelope shared across PALACO layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventEnvelope {
    /// Marker tying the contract back to foundational shared types.
    pub marker: DomainMarker,
}
