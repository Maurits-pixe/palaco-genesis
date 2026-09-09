//! Foundational PALACO shared types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Shared foundational marker type for the PALACO workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DomainMarker;
