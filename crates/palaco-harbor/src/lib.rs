//! Fail-closed admission and quarantine reference contracts for Harbor.
//!
//! Admission is a routing assessment, not an authorization to execute.
//! This in-process reference model performs no persistence or network access.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

use std::collections::HashSet;

pub mod evidence_digest;
#[cfg(unix)]
pub mod local_file_replay;
pub mod replay_contract;
pub mod verifier_boundary;

/// Information asserted by the caller, not independently verified by Harbor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionEvidence {
    /// Identity binding has been verified by an upstream authority.
    pub identity_verified: bool,
    /// Provenance is present and verified by an upstream verifier.
    pub provenance_verified: bool,
    /// Consent is explicit, current, and bound to the requested purpose.
    pub consent_verified: bool,
    /// Scope is explicitly bounded and verified.
    pub scope_verified: bool,
    /// An upstream revocation check was performed and was current.
    pub revocation_checked: bool,
    /// The upstream verifier found the grant revoked.
    pub revoked: bool,
    /// A trusted time source established temporal validity.
    pub temporal_validity_verified: bool,
}

/// The exact request identifiers to which upstream evidence must be bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionRequest<'a> {
    /// Non-empty subject identifier.
    pub subject_id: &'a str,
    /// Non-empty, purpose-specific identifier.
    pub purpose: &'a str,
    /// Non-empty requested authorization scope identifier.
    pub scope: &'a str,
}

/// Identifiers that an upstream verifier asserts were checked.
///
/// This type does not authenticate the assertions or establish freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceBinding<'a> {
    /// Subject named in the verified evidence.
    pub subject_id: &'a str,
    /// Purpose named in the verified consent evidence.
    pub purpose: &'a str,
    /// Scope named in the verified evidence.
    pub scope: &'a str,
}

/// A routing choice that never grants execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDisposition {
    /// Forward to a separate authorization gate; execution is not permitted here.
    ForwardForAuthorization,
    /// Insufficient or uncertain evidence: isolate the request for review.
    Quarantine(QuarantineReason),
    /// Definitively disallowed condition: reject without forwarding.
    Reject(RejectionReason),
}

/// Missing or uncertain evidence that requires quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// Identity has not been verified.
    IdentityUnknown,
    /// Provenance has not been verified.
    ProvenanceUnknown,
    /// Consent has not been verified for this purpose.
    ConsentUnknown,
    /// Requested scope has not been verified.
    ScopeUnknown,
    /// Revocation status is not known to be current.
    RevocationUnknown,
    /// Trusted temporal validity has not been established.
    TemporalUnknown,
    /// A required request/evidence identifier was empty.
    MissingBinding,
    /// Evidence references a different subject, purpose, or scope.
    BindingMismatch,
    /// A receipt identifier was not supplied.
    MissingReceiptId,
    /// This process has already forwarded the receipt identifier.
    ReplayDetected,
    /// Durable reservation did not return a trustworthy completion outcome.
    ReservationUncertain,
}

/// A condition that is independently sufficient for rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// A verified revocation was reported.
    Revoked,
}

/// Stateless, deterministic Harbor routing policy.
///
/// All checks must be supplied by trusted upstream components. Passing booleans
/// does not constitute evidence or a cryptographic verification in itself.
#[must_use]
pub fn assess_admission(evidence: &AdmissionEvidence) -> AdmissionDisposition {
    // A verified revocation always wins, regardless of other missing fields.
    if evidence.revocation_checked && evidence.revoked {
        return AdmissionDisposition::Reject(RejectionReason::Revoked);
    }

    if !evidence.identity_verified {
        return AdmissionDisposition::Quarantine(QuarantineReason::IdentityUnknown);
    }
    if !evidence.provenance_verified {
        return AdmissionDisposition::Quarantine(QuarantineReason::ProvenanceUnknown);
    }
    if !evidence.consent_verified {
        return AdmissionDisposition::Quarantine(QuarantineReason::ConsentUnknown);
    }
    if !evidence.scope_verified {
        return AdmissionDisposition::Quarantine(QuarantineReason::ScopeUnknown);
    }
    if !evidence.revocation_checked {
        return AdmissionDisposition::Quarantine(QuarantineReason::RevocationUnknown);
    }
    if !evidence.temporal_validity_verified {
        return AdmissionDisposition::Quarantine(QuarantineReason::TemporalUnknown);
    }

    AdmissionDisposition::ForwardForAuthorization
}

/// Checks exact evidence/request binding before ordinary Harbor routing.
///
/// Equality here is necessary but not sufficient: callers must independently
/// authenticate, time-bind, and replay-protect the supplied evidence.
#[must_use]
pub fn assess_bound_admission(
    request: &AdmissionRequest<'_>,
    binding: &EvidenceBinding<'_>,
    evidence: &AdmissionEvidence,
) -> AdmissionDisposition {
    if request.subject_id.is_empty()
        || request.purpose.is_empty()
        || request.scope.is_empty()
        || binding.subject_id.is_empty()
        || binding.purpose.is_empty()
        || binding.scope.is_empty()
    {
        return AdmissionDisposition::Quarantine(QuarantineReason::MissingBinding);
    }

    // A verified revocation always takes precedence over mismatched metadata.
    if evidence.revocation_checked && evidence.revoked {
        return AdmissionDisposition::Reject(RejectionReason::Revoked);
    }

    if request.subject_id != binding.subject_id
        || request.purpose != binding.purpose
        || request.scope != binding.scope
    {
        return AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch);
    }

    assess_admission(evidence)
}

/// Process-local ledger of receipt identifiers forwarded for authorization.
///
/// This is not durable, distributed, or cryptographic replay protection. A
/// restart, parallel instance, or forged identifier can bypass this ledger.
/// An external durable uniqueness authority is required for production.
#[derive(Debug, Default)]
pub struct InMemoryReplayLedger {
    forwarded_receipts: HashSet<String>,
}

impl InMemoryReplayLedger {
    /// Creates an empty process-local ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Assesses an exactly bound request and reserves a non-empty receipt ID.
    ///
    /// The exclusive mutable borrow serializes attempts that share this ledger.
    /// Only requests eligible for an independent authorization gate consume an
    /// ID. This method does not itself authorize or execute anything.
    pub fn assess_once(
        &mut self,
        receipt_id: &str,
        request: &AdmissionRequest<'_>,
        binding: &EvidenceBinding<'_>,
        evidence: &AdmissionEvidence,
    ) -> AdmissionDisposition {
        let disposition = assess_bound_admission(request, binding, evidence);
        if disposition != AdmissionDisposition::ForwardForAuthorization {
            return disposition;
        }
        if receipt_id.is_empty() {
            return AdmissionDisposition::Quarantine(QuarantineReason::MissingReceiptId);
        }
        if !self.forwarded_receipts.insert(receipt_id.to_owned()) {
            return AdmissionDisposition::Quarantine(QuarantineReason::ReplayDetected);
        }
        AdmissionDisposition::ForwardForAuthorization
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assess_admission, assess_bound_admission, AdmissionDisposition, AdmissionEvidence,
        AdmissionRequest, EvidenceBinding, InMemoryReplayLedger, QuarantineReason, RejectionReason,
    };

    fn complete() -> AdmissionEvidence {
        AdmissionEvidence {
            identity_verified: true,
            provenance_verified: true,
            consent_verified: true,
            scope_verified: true,
            revocation_checked: true,
            revoked: false,
            temporal_validity_verified: true,
        }
    }

    #[test]
    fn complete_evidence_only_forwards_to_authorization() {
        assert_eq!(
            assess_admission(&complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
    }

    #[test]
    fn unknown_identity_quarantines() {
        let mut e = complete();
        e.identity_verified = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::IdentityUnknown)
        );
    }

    #[test]
    fn missing_provenance_quarantines() {
        let mut e = complete();
        e.provenance_verified = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::ProvenanceUnknown)
        );
    }

    #[test]
    fn missing_consent_quarantines() {
        let mut e = complete();
        e.consent_verified = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::ConsentUnknown)
        );
    }

    #[test]
    fn scope_drift_quarantines() {
        let mut e = complete();
        e.scope_verified = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::ScopeUnknown)
        );
    }

    #[test]
    fn unknown_revocation_state_quarantines() {
        let mut e = complete();
        e.revocation_checked = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::RevocationUnknown)
        );
    }

    #[test]
    fn unknown_trusted_time_quarantines() {
        let mut e = complete();
        e.temporal_validity_verified = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::TemporalUnknown)
        );
    }

    #[test]
    fn verified_revocation_wins_over_other_missing_evidence() {
        let mut e = complete();
        e.revoked = true;
        e.consent_verified = false;
        e.temporal_validity_verified = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Reject(RejectionReason::Revoked)
        );
    }

    #[test]
    fn unverified_revocation_cannot_be_treated_as_authority() {
        let mut e = complete();
        e.revoked = true;
        e.revocation_checked = false;
        assert_eq!(
            assess_admission(&e),
            AdmissionDisposition::Quarantine(QuarantineReason::RevocationUnknown)
        );
    }
    #[test]
    fn receipt_is_forwarded_only_once_in_same_ledger() {
        let mut ledger = InMemoryReplayLedger::new();
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &binding(), &complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &binding(), &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::ReplayDetected)
        );
    }

    #[test]
    fn distinct_receipts_are_independent() {
        let mut ledger = InMemoryReplayLedger::new();
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &binding(), &complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
        assert_eq!(
            ledger.assess_once("receipt-2", &request(), &binding(), &complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
    }

    #[test]
    fn missing_receipt_id_quarantines() {
        let mut ledger = InMemoryReplayLedger::new();
        assert_eq!(
            ledger.assess_once("", &request(), &binding(), &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::MissingReceiptId)
        );
    }

    #[test]
    fn rejected_or_quarantined_requests_do_not_consume_receipt() {
        let mut ledger = InMemoryReplayLedger::new();
        let mut bad_binding = binding();
        bad_binding.scope = "wrong";
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &bad_binding, &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &binding(), &complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
    }

    #[test]
    fn verified_revocation_wins_over_replay_detection() {
        let mut ledger = InMemoryReplayLedger::new();
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &binding(), &complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
        let mut evidence = complete();
        evidence.revoked = true;
        assert_eq!(
            ledger.assess_once("receipt-1", &request(), &binding(), &evidence),
            AdmissionDisposition::Reject(RejectionReason::Revoked)
        );
    }

    fn request() -> AdmissionRequest<'static> {
        AdmissionRequest {
            subject_id: "person-1",
            purpose: "contact",
            scope: "rio:invite",
        }
    }

    fn binding() -> EvidenceBinding<'static> {
        EvidenceBinding {
            subject_id: "person-1",
            purpose: "contact",
            scope: "rio:invite",
        }
    }

    #[test]
    fn exact_binding_only_forwards_to_authorization() {
        assert_eq!(
            assess_bound_admission(&request(), &binding(), &complete()),
            AdmissionDisposition::ForwardForAuthorization
        );
    }

    #[test]
    fn subject_mismatch_quarantines() {
        let mut b = binding();
        b.subject_id = "person-2";
        assert_eq!(
            assess_bound_admission(&request(), &b, &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
    }

    #[test]
    fn purpose_mismatch_quarantines() {
        let mut b = binding();
        b.purpose = "marketing";
        assert_eq!(
            assess_bound_admission(&request(), &b, &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
    }

    #[test]
    fn scope_mismatch_quarantines() {
        let mut b = binding();
        b.scope = "citadel:admin";
        assert_eq!(
            assess_bound_admission(&request(), &b, &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
    }

    #[test]
    fn empty_binding_quarantines() {
        let mut b = binding();
        b.subject_id = "";
        assert_eq!(
            assess_bound_admission(&request(), &b, &complete()),
            AdmissionDisposition::Quarantine(QuarantineReason::MissingBinding)
        );
    }

    #[test]
    fn verified_revocation_wins_even_with_binding_mismatch() {
        let mut b = binding();
        b.scope = "citadel:admin";
        let mut e = complete();
        e.revoked = true;
        assert_eq!(
            assess_bound_admission(&request(), &b, &e),
            AdmissionDisposition::Reject(RejectionReason::Revoked)
        );
    }
}
