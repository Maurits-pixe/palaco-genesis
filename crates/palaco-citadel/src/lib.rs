//! Execution boundary contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_trias::GovernanceDecision;

/// Execution boundary request validated by governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBoundary {
    /// Governance decision authorizing the boundary crossing.
    pub decision: GovernanceDecision,
}
