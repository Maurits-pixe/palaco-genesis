//! Observability contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_audit::AuditRecord;

/// Observatory snapshot built from audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatorySnapshot {
    /// Audit record exposed through the observability layer.
    pub audit_record: AuditRecord,
}
