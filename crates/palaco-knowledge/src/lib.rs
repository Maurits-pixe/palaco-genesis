//! Versioned knowledge contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_constitution::{HistoricalClassification, ProvenanceRecord};
use palaco_evidence::EvidenceBundle;

/// Advisory knowledge record linked to the evidence chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KnowledgeRecord {
    /// Evidence from which this knowledge record was derived.
    pub evidence: EvidenceBundle,
    /// Historical status assigned during constitutional classification.
    pub classification: HistoricalClassification,
    /// Provenance supporting this knowledge record.
    pub provenance: ProvenanceRecord,
}
