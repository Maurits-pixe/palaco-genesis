//! ORCHEASTRA deterministic, offline-first admission gate.
//!
//! This module evaluates an execution *proposal*. It never performs an action,
//! grants credentials, or overrides the Citadel runtime boundary.

/// Requested operation in the PALACO ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrcheastraOperation {
    /// Read-only inspection of an existing module.
    Observe,
    /// Request a state-changing operation.
    Mutate,
}

/// Evidence available to the orchestration admission gate.
///
/// Each field is explicitly supplied by a trusted caller. A flag is not
/// cryptographic verification; the upstream identity, evidence, and Citadel
/// components must validate the underlying signed artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdmissionEvidence {
    /// Trusted identity and accountable actor have been verified.
    pub identity_verified: bool,
    /// A valid, scoped authority decision has been verified.
    pub authority_verified: bool,
    /// The evidence bundle has been verified.
    pub evidence_verified: bool,
    /// The requested action is within the granted scope.
    pub scope_matches: bool,
    /// Policy and state versions were revalidated at the decision time.
    pub context_current: bool,
    /// A revocation or explicit denial applies.
    pub revoked: bool,
    /// A global or project-level hold applies.
    pub hold_active: bool,
    /// The underlying Citadel boundary explicitly allows execution.
    pub citadel_execute: bool,
}

/// An auditable refusal or escalation reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionReason {
    /// Admission is permitted, but no action has been executed.
    Admitted,
    /// Only read-only inspection is permitted.
    ReadOnly,
    /// Identity has not been verified.
    IdentityMissing,
    /// Authority has not been verified.
    AuthorityMissing,
    /// Evidence has not been verified.
    EvidenceMissing,
    /// Authority does not cover the requested scope.
    ScopeMismatch,
    /// The policy/state snapshot is stale.
    StaleContext,
    /// Explicit revocation overrides all positive signals.
    Revoked,
    /// An active hold overrides all positive signals.
    Hold,
    /// The Citadel boundary does not allow execution.
    CitadelDenied,
}

/// Fail-closed result returned to a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Inspection may proceed without mutation.
    ObserveOnly,
    /// Proposed mutation passed the admission checks; runtime must revalidate.
    Proposed,
    /// Mutation must not proceed.
    Blocked(AdmissionReason),
}

/// Evaluate a proposed ORCHEASTRA operation.
///
/// This is a pure decision function. Mutation is never executed here.
/// The Citadel and runtime must independently revalidate immediately
/// before any real-world action.
#[must_use]
pub fn evaluate_admission(
    operation: OrcheastraOperation,
    evidence: &AdmissionEvidence,
) -> AdmissionDecision {
    if evidence.revoked {
        return AdmissionDecision::Blocked(AdmissionReason::Revoked);
    }
    if evidence.hold_active {
        return AdmissionDecision::Blocked(AdmissionReason::Hold);
    }
    if !evidence.identity_verified {
        return AdmissionDecision::Blocked(AdmissionReason::IdentityMissing);
    }
    if operation == OrcheastraOperation::Observe {
        return AdmissionDecision::ObserveOnly;
    }
    if !evidence.authority_verified {
        return AdmissionDecision::Blocked(AdmissionReason::AuthorityMissing);
    }
    if !evidence.evidence_verified {
        return AdmissionDecision::Blocked(AdmissionReason::EvidenceMissing);
    }
    if !evidence.scope_matches {
        return AdmissionDecision::Blocked(AdmissionReason::ScopeMismatch);
    }
    if !evidence.context_current {
        return AdmissionDecision::Blocked(AdmissionReason::StaleContext);
    }
    if !evidence.citadel_execute {
        return AdmissionDecision::Blocked(AdmissionReason::CitadelDenied);
    }

    AdmissionDecision::Proposed
}

/// Evaluate a mutation proposal against an actual PALACO runtime plan.
///
/// The caller-provided flags are untrusted until verified by their respective
/// authority services. Citadel disposition, policy/state context and runtime
/// revalidation are derived independently here; callers cannot force those
/// checks to `true` by setting the matching booleans.
///
/// This is an assessment only: it never commits or executes an action.
#[must_use]
pub fn evaluate_runtime_proposal(
    plan: &crate::RuntimePlan,
    context: &palaco_foundation::types::DecisionContext,
    claims: &AdmissionEvidence,
) -> AdmissionDecision {
    use palaco_foundation::{
        traits::{CurrentlyAssessable, Revalidatable},
        types::{CurrentValidity, RevalidationOutcome},
    };

    // A negative authority signal cannot be overridden by runtime success.
    if claims.revoked {
        return AdmissionDecision::Blocked(AdmissionReason::Revoked);
    }
    if claims.hold_active {
        return AdmissionDecision::Blocked(AdmissionReason::Hold);
    }
    if !claims.identity_verified {
        return AdmissionDecision::Blocked(AdmissionReason::IdentityMissing);
    }
    if !claims.authority_verified {
        return AdmissionDecision::Blocked(AdmissionReason::AuthorityMissing);
    }
    if !claims.evidence_verified {
        return AdmissionDecision::Blocked(AdmissionReason::EvidenceMissing);
    }
    if !claims.scope_matches {
        return AdmissionDecision::Blocked(AdmissionReason::ScopeMismatch);
    }

    let original = &plan.boundary.decision.context;
    let same_snapshot = context.state == original.state
        && context.policy_version == original.policy_version
        && context.observed_at >= original.observed_at;
    if !same_snapshot
        || !claims.context_current
        || plan.current_validity(context.observed_at) != CurrentValidity::Valid
        || plan.revalidate(context) != Ok(RevalidationOutcome::Confirmed)
    {
        return AdmissionDecision::Blocked(AdmissionReason::StaleContext);
    }

    if !claims.citadel_execute
        || plan.disposition != crate::RuntimeDisposition::Execute
        || plan.boundary.disposition != palaco_citadel::BoundaryDisposition::Execute
    {
        return AdmissionDecision::Blocked(AdmissionReason::CitadelDenied);
    }

    AdmissionDecision::Proposed
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_admission, AdmissionDecision, AdmissionEvidence, AdmissionReason,
        OrcheastraOperation,
    };

    fn valid_evidence() -> AdmissionEvidence {
        AdmissionEvidence {
            identity_verified: true,
            authority_verified: true,
            evidence_verified: true,
            scope_matches: true,
            context_current: true,
            revoked: false,
            hold_active: false,
            citadel_execute: true,
        }
    }

    #[test]
    fn default_fails_closed() {
        assert_eq!(
            evaluate_admission(OrcheastraOperation::Mutate, &AdmissionEvidence::default()),
            AdmissionDecision::Blocked(AdmissionReason::IdentityMissing)
        );
    }

    #[test]
    fn complete_proposal_is_not_execution() {
        assert_eq!(
            evaluate_admission(OrcheastraOperation::Mutate, &valid_evidence()),
            AdmissionDecision::Proposed
        );
    }

    #[test]
    fn revocation_and_hold_take_precedence() {
        let mut evidence = valid_evidence();
        evidence.revoked = true;
        evidence.hold_active = true;
        assert_eq!(
            evaluate_admission(OrcheastraOperation::Mutate, &evidence),
            AdmissionDecision::Blocked(AdmissionReason::Revoked)
        );
        evidence.revoked = false;
        assert_eq!(
            evaluate_admission(OrcheastraOperation::Mutate, &evidence),
            AdmissionDecision::Blocked(AdmissionReason::Hold)
        );
        assert_eq!(
            evaluate_admission(OrcheastraOperation::Observe, &evidence),
            AdmissionDecision::Blocked(AdmissionReason::Hold)
        );
    }

    #[test]
    fn every_required_mutation_gate_blocks() {
        let cases: &[(fn(&mut AdmissionEvidence), AdmissionReason)] = &[
            (|e| e.identity_verified = false, AdmissionReason::IdentityMissing),
            (|e| e.authority_verified = false, AdmissionReason::AuthorityMissing),
            (|e| e.evidence_verified = false, AdmissionReason::EvidenceMissing),
            (|e| e.scope_matches = false, AdmissionReason::ScopeMismatch),
            (|e| e.context_current = false, AdmissionReason::StaleContext),
            (|e| e.citadel_execute = false, AdmissionReason::CitadelDenied),
        ];
        for (invalidate, reason) in cases {
            let mut evidence = valid_evidence();
            invalidate(&mut evidence);
            assert_eq!(
                evaluate_admission(OrcheastraOperation::Mutate, &evidence),
                AdmissionDecision::Blocked(*reason)
            );
        }
    }

    #[test]
    fn observation_does_not_require_mutation_authority() {
        let evidence = AdmissionEvidence {
            identity_verified: true,
            ..AdmissionEvidence::default()
        };
        assert_eq!(
            evaluate_admission(OrcheastraOperation::Observe, &evidence),
            AdmissionDecision::ObserveOnly
        );
    }
}
