//! Independently implemented evidence-verifier boundary for Harbor.
//!
//! This module supplies no signature algorithm, trusted key registry, clock,
//! revocation authority or verifier implementation. An untrusted implementation
//! of this trait can lie. Never connect a test double to a production gate.

use crate::evidence_digest::{assess_with_derived_reservation, EvidenceIdentity};
use crate::replay_contract::ReplayReservationStore;
use crate::{
    AdmissionDisposition, AdmissionEvidence, AdmissionRequest, EvidenceBinding, QuarantineReason,
    RejectionReason,
};

/// A decisive failure reported by an independently trusted evidence verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationFailure {
    InvalidSignature,
    UntrustedVerifier,
    Expired,
    ScopeMismatch,
    Revoked,
    RevocationUnknown,
    TemporalUnknown,
    Unavailable,
}

/// Owned claims supplied after independent upstream verification.
///
/// The verifier must authenticate exact payload bytes and bind all fields to
/// the request; this structure does not itself establish any such fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    pub subject_id: String,
    pub purpose: String,
    pub scope: String,
    pub verifier_id: String,
    pub evidence_ref: String,
    pub payload_sha256: String,
    pub trust_epoch: u64,
}

/// Adapter boundary. Production implementations must have separately governed
/// trust roots, authenticating keys, revocation sources and trusted time.
pub trait EvidenceVerifier {
    fn verify(
        &self,
        request: &AdmissionRequest<'_>,
        signed_envelope: &[u8],
    ) -> Result<VerifiedClaims, VerificationFailure>;
}

/// Verify first; reserve only when the verifier accepts and bindings match.
///
/// Forwarding is only a routing result for an independent authorization gate.
#[must_use]
pub fn assess_verified_envelope<S: ReplayReservationStore, V: EvidenceVerifier>(
    store: &mut S,
    verifier: &V,
    receipt_id: &str,
    request: &AdmissionRequest<'_>,
    signed_envelope: &[u8],
) -> AdmissionDisposition {
    let claims = match verifier.verify(request, signed_envelope) {
        Ok(claims) => claims,
        Err(VerificationFailure::Revoked) => {
            return AdmissionDisposition::Reject(RejectionReason::Revoked);
        }
        Err(VerificationFailure::ScopeMismatch) => {
            return AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch);
        }
        Err(VerificationFailure::Expired | VerificationFailure::TemporalUnknown) => {
            return AdmissionDisposition::Quarantine(QuarantineReason::TemporalUnknown);
        }
        Err(VerificationFailure::RevocationUnknown) => {
            return AdmissionDisposition::Quarantine(QuarantineReason::RevocationUnknown);
        }
        Err(
            VerificationFailure::InvalidSignature
            | VerificationFailure::UntrustedVerifier
            | VerificationFailure::Unavailable,
        ) => {
            return AdmissionDisposition::Quarantine(QuarantineReason::ProvenanceUnknown);
        }
    };
    let binding = EvidenceBinding {
        subject_id: &claims.subject_id,
        purpose: &claims.purpose,
        scope: &claims.scope,
    };
    let identity = EvidenceIdentity {
        verifier_id: &claims.verifier_id,
        evidence_ref: &claims.evidence_ref,
        payload_sha256: &claims.payload_sha256,
        trust_epoch: claims.trust_epoch,
    };
    // These flags record the accepted *verifier result*, not local proof.
    let admission = AdmissionEvidence {
        identity_verified: true,
        provenance_verified: true,
        consent_verified: true,
        scope_verified: true,
        revocation_checked: true,
        revoked: false,
        temporal_validity_verified: true,
    };
    assess_with_derived_reservation(store, receipt_id, request, &binding, &admission, &identity)
}

#[cfg(test)]
mod tests {
    use super::{assess_verified_envelope, EvidenceVerifier, VerificationFailure, VerifiedClaims};
    use crate::replay_contract::{ReplayReservationStore, ReservationError, ReservationOutcome};
    use crate::{AdmissionDisposition, AdmissionRequest, QuarantineReason, RejectionReason};
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeStore {
        writes: usize,
        values: HashMap<String, String>,
    }

    impl ReplayReservationStore for FakeStore {
        fn reserve(
            &mut self,
            receipt: &str,
            key: &str,
        ) -> Result<ReservationOutcome, ReservationError> {
            self.writes += 1;
            match self.values.get(receipt) {
                None => {
                    self.values.insert(receipt.to_owned(), key.to_owned());
                    Ok(ReservationOutcome::Reserved)
                }
                Some(old) if old == key => Ok(ReservationOutcome::AlreadyReserved),
                Some(_) => Ok(ReservationOutcome::BindingConflict),
            }
        }
    }

    // A scripted *test double*, NOT an actual cryptographic verifier.
    struct ScriptedVerifier {
        result: Result<VerifiedClaims, VerificationFailure>,
    }

    impl EvidenceVerifier for ScriptedVerifier {
        fn verify(
            &self,
            _request: &AdmissionRequest<'_>,
            _signed_envelope: &[u8],
        ) -> Result<VerifiedClaims, VerificationFailure> {
            self.result.clone()
        }
    }

    fn accepted() -> VerifiedClaims {
        VerifiedClaims {
            subject_id: "person-1".to_owned(),
            purpose: "contact".to_owned(),
            scope: "rio:invite".to_owned(),
            verifier_id: "trusted-v1".to_owned(),
            evidence_ref: "receipt-v1".to_owned(),
            payload_sha256: "a".repeat(64),
            trust_epoch: 7,
        }
    }

    fn request() -> AdmissionRequest<'static> {
        AdmissionRequest {
            subject_id: "person-1",
            purpose: "contact",
            scope: "rio:invite",
        }
    }

    #[test]
    fn negative_verification_never_reserves() {
        for (failure, expected) in [
            (
                VerificationFailure::InvalidSignature,
                AdmissionDisposition::Quarantine(QuarantineReason::ProvenanceUnknown),
            ),
            (
                VerificationFailure::UntrustedVerifier,
                AdmissionDisposition::Quarantine(QuarantineReason::ProvenanceUnknown),
            ),
            (
                VerificationFailure::Expired,
                AdmissionDisposition::Quarantine(QuarantineReason::TemporalUnknown),
            ),
            (
                VerificationFailure::ScopeMismatch,
                AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch),
            ),
            (
                VerificationFailure::Revoked,
                AdmissionDisposition::Reject(RejectionReason::Revoked),
            ),
            (
                VerificationFailure::RevocationUnknown,
                AdmissionDisposition::Quarantine(QuarantineReason::RevocationUnknown),
            ),
            (
                VerificationFailure::TemporalUnknown,
                AdmissionDisposition::Quarantine(QuarantineReason::TemporalUnknown),
            ),
            (
                VerificationFailure::Unavailable,
                AdmissionDisposition::Quarantine(QuarantineReason::ProvenanceUnknown),
            ),
        ] {
            let verifier = ScriptedVerifier {
                result: Err(failure),
            };
            let mut store = FakeStore::default();
            assert_eq!(
                assess_verified_envelope(&mut store, &verifier, "r-1", &request(), b"envelope"),
                expected
            );
            assert_eq!(store.writes, 0);
        }
    }

    #[test]
    fn accepted_claims_forward_once_and_replay_quarantines() {
        let verifier = ScriptedVerifier {
            result: Ok(accepted()),
        };
        let mut store = FakeStore::default();
        assert_eq!(
            assess_verified_envelope(&mut store, &verifier, "r-1", &request(), b"envelope"),
            AdmissionDisposition::ForwardForAuthorization
        );
        assert_eq!(
            assess_verified_envelope(&mut store, &verifier, "r-1", &request(), b"envelope"),
            AdmissionDisposition::Quarantine(QuarantineReason::ReplayDetected)
        );
        assert_eq!(store.writes, 2);
    }

    #[test]
    fn verifier_binding_mismatch_cannot_reserve() {
        let mut claims = accepted();
        claims.scope = "rio:admin".to_owned();
        let verifier = ScriptedVerifier { result: Ok(claims) };
        let mut store = FakeStore::default();
        assert_eq!(
            assess_verified_envelope(&mut store, &verifier, "r-1", &request(), b"envelope"),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
        assert_eq!(store.writes, 0);
    }

    #[test]
    fn same_receipt_different_verified_payload_quarantines() {
        let mut store = FakeStore::default();
        let first = ScriptedVerifier {
            result: Ok(accepted()),
        };
        let mut changed = accepted();
        changed.payload_sha256 = "b".repeat(64);
        let second = ScriptedVerifier {
            result: Ok(changed),
        };
        assert_eq!(
            assess_verified_envelope(&mut store, &first, "r-1", &request(), b"envelope"),
            AdmissionDisposition::ForwardForAuthorization
        );
        assert_eq!(
            assess_verified_envelope(&mut store, &second, "r-1", &request(), b"other"),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
    }
}
