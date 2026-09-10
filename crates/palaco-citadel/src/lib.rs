//! Execution boundary contracts for PALACO.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

/// Execution boundary request carried into the runtime layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecutionBoundary;
