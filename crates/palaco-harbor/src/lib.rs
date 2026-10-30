//! Fail-closed admission and quarantine reference contracts for Harbor.
//!
//! Admission is a routing assessment, not an authorization to execute.
//! This in-process reference model performs no persistence or network access.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

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

#[cfg(test)]
mod tests {
    use super::{
        assess_admission, AdmissionDisposition, AdmissionEvidence, QuarantineReason, RejectionReason,
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
}
