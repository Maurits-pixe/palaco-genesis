//! Runtime orchestration contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_citadel::ExecutionBoundary;

/// Runtime plan derived from an execution boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlan {
    /// Boundary request consumed by the runtime.
    pub boundary: ExecutionBoundary,
}
