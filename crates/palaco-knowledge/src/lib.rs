//! Versioned knowledge contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_evidence::EvidenceBundle;

/// Advisory knowledge record linked to the evidence chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KnowledgeRecord {
    /// Evidence from which this knowledge record was derived.
    pub evidence: EvidenceBundle,
}
