//! Versioned knowledge contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_evidence::EvidenceBundle;

/// Advisory knowledge record linked to the evidence chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeRecord {
    /// Evidence from which this knowledge record was derived.
    pub evidence: EvidenceBundle,
}

impl KnowledgeRecord {
    /// Creates a knowledge record from an evidence bundle.
    #[must_use]
    pub fn new(evidence: EvidenceBundle) -> Self {
        Self { evidence }
    }
}
