//! Governance and authority contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_oracle::OracleReport;

/// Governance decision produced from an oracle report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceDecision {
    /// Report evaluated by the governance layer.
    pub report: OracleReport,
}
