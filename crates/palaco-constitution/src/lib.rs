//! Constitutional core contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Identity handle for a person, agent, service, or surface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityHandle {
    /// Stable subject identifier.
    pub subject: String,
    /// Surface or domain where the identity is acting.
    pub surface: String,
}

/// Source record that explains where data or authority originated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProvenanceRecord {
    /// Human-readable source system or document family.
    pub source: String,
    /// Stable locator for the originating record.
    pub record_locator: String,
}

/// Named authority scope guarded by constitutional checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorityScope {
    /// Scope or capability name.
    pub capability: String,
}

/// Authorization grant for a scoped action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorizationGrant {
    /// Unique authorization identifier.
    pub authorization_id: String,
    /// Scope covered by the grant.
    pub scope: AuthorityScope,
    /// Subject allowed to act.
    pub granted_to: IdentityHandle,
    /// Provenance supporting the grant.
    pub provenance: ProvenanceRecord,
}

/// Revocation record for a previously granted authorization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevocationRecord {
    /// Authorization identifier that is no longer valid.
    pub authorization_id: String,
    /// Reason for revocation.
    pub reason: String,
    /// Provenance of the revocation decision.
    pub provenance: ProvenanceRecord,
}

/// Trace lifecycle state for a request or action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceStatus {
    /// The flow has been prepared but not completed.
    #[default]
    Pending,
    /// The flow completed normally.
    Completed,
    /// The flow was stopped because a revocation took effect.
    Revoked,
}

/// Trace record attached to every constitutional flow.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraceRecord {
    /// Stable trace identifier.
    pub trace_id: String,
    /// Subject associated with the trace.
    pub subject: IdentityHandle,
    /// Provenance carried through the flow.
    pub provenance: ProvenanceRecord,
    /// Current lifecycle state.
    pub status: TraceStatus,
}

/// Constitutional rules that must hold across PALACO flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstitutionalRule {
    /// Requests must establish context before any action can proceed.
    NoActionBeforeContext,
    /// Authority claims must cite provenance.
    NoAuthorityWithoutProvenance,
    /// Governance decisions require evidence.
    NoDecisionWithoutEvidence,
    /// Execution requires valid authorization.
    NoExecutionWithoutAuthorization,
}

/// Historical classification for ingested material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoricalClassification {
    /// Normative canonical material.
    Canon,
    /// A formal specification.
    Specification,
    /// A recorded decision.
    Decision,
    /// Design material that informs implementation.
    Design,
    /// Experimental or exploratory material.
    Experiment,
    /// A draft that is not yet ratified.
    #[default]
    Draft,
    /// Material explicitly rejected.
    Rejected,
    /// Material replaced by newer canonical content.
    Superseded,
}

/// Constitutional validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstitutionalError {
    /// Context was required but missing.
    MissingContext,
    /// Provenance was required but missing.
    MissingProvenance,
    /// Evidence was required but missing.
    MissingEvidence,
    /// Requested authority did not match the governing decision.
    AuthorityMismatch,
    /// Authorization was required but missing or invalid.
    MissingAuthorization,
    /// A revocation invalidated the attempted action.
    AuthorizationRevoked,
}

impl AuthorizationGrant {
    /// Returns `true` when this grant covers the requested scope.
    pub fn authorizes(&self, scope: &AuthorityScope) -> bool {
        self.scope == *scope && !self.authorization_id.is_empty()
    }
}

impl RevocationRecord {
    /// Returns `true` when this record revokes the provided authorization.
    pub fn revokes(&self, grant: &AuthorizationGrant) -> bool {
        self.authorization_id == grant.authorization_id && !self.authorization_id.is_empty()
    }
}

/// Enforces the rule that actions require context.
pub fn ensure_context_before_action(context_ready: bool) -> Result<(), ConstitutionalError> {
    if context_ready {
        Ok(())
    } else {
        Err(ConstitutionalError::MissingContext)
    }
}

/// Enforces the rule that authority claims require provenance.
pub fn ensure_authority_has_provenance(
    scope: &AuthorityScope,
    provenance: &ProvenanceRecord,
) -> Result<(), ConstitutionalError> {
    if scope.capability.is_empty() || provenance.record_locator.is_empty() {
        Err(ConstitutionalError::MissingProvenance)
    } else {
        Ok(())
    }
}

/// Enforces the rule that decisions require evidence.
pub fn ensure_decision_has_evidence(has_evidence: bool) -> Result<(), ConstitutionalError> {
    if has_evidence {
        Ok(())
    } else {
        Err(ConstitutionalError::MissingEvidence)
    }
}

/// Enforces the rule that execution requires a live authorization.
pub fn ensure_execution_is_authorized(
    scope: &AuthorityScope,
    authorization: Option<&AuthorizationGrant>,
    revocation: Option<&RevocationRecord>,
) -> Result<(), ConstitutionalError> {
    let grant = authorization.ok_or(ConstitutionalError::MissingAuthorization)?;

    if !grant.authorizes(scope) {
        return Err(ConstitutionalError::MissingAuthorization);
    }

    if revocation.is_some_and(|record| record.revokes(grant)) {
        return Err(ConstitutionalError::AuthorizationRevoked);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scope() -> AuthorityScope {
        AuthorityScope {
            capability: "rio.execute".to_string(),
        }
    }

    fn sample_identity() -> IdentityHandle {
        IdentityHandle {
            subject: "rio-user".to_string(),
            surface: "rio-web".to_string(),
        }
    }

    fn sample_provenance() -> ProvenanceRecord {
        ProvenanceRecord {
            source: "specs/PVB-011".to_string(),
            record_locator: "PVB-011#authorization".to_string(),
        }
    }

    #[test]
    fn rejects_actions_without_context() {
        assert_eq!(
            ensure_context_before_action(false),
            Err(ConstitutionalError::MissingContext)
        );
    }

    #[test]
    fn rejects_authority_without_provenance() {
        assert_eq!(
            ensure_authority_has_provenance(&sample_scope(), &ProvenanceRecord::default()),
            Err(ConstitutionalError::MissingProvenance)
        );
    }

    #[test]
    fn rejects_execution_without_authorization() {
        assert_eq!(
            ensure_execution_is_authorized(&sample_scope(), None, None),
            Err(ConstitutionalError::MissingAuthorization)
        );
    }

    #[test]
    fn rejects_revoked_authorization() {
        let grant = AuthorizationGrant {
            authorization_id: "grant-1".to_string(),
            scope: sample_scope(),
            granted_to: sample_identity(),
            provenance: sample_provenance(),
        };
        let revocation = RevocationRecord {
            authorization_id: "grant-1".to_string(),
            reason: "revoked".to_string(),
            provenance: sample_provenance(),
        };

        assert_eq!(
            ensure_execution_is_authorized(&sample_scope(), Some(&grant), Some(&revocation)),
            Err(ConstitutionalError::AuthorizationRevoked)
        );
    }
}
