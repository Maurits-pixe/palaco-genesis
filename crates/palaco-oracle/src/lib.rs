//! Analysis and advisory contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_evidence::EvidenceBundle;

/// Advisory report derived from evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OracleReport {
    /// Evidence used to derive the report.
    pub evidence: EvidenceBundle,
}
