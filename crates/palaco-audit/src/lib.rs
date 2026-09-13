//! Audit contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_runtime::RuntimePlan;

/// Audit record emitted from runtime activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Runtime plan captured by the audit layer.
    pub runtime_plan: RuntimePlan,
}
