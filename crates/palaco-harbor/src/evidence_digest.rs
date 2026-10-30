//! Canonical, domain-separated content binding for Harbor replay reservations.
//!
//! A digest binds bytes; it cannot authenticate their origin or grant authority.
//! The caller must validate verifier identity, signed evidence, scope, consent,
//! revocation, freshness and the payload before providing this context.

use crate::replay_contract::{assess_with_reservation, ReplayReservationStore, ReservationError};
use crate::{assess_bound_admission, AdmissionDisposition, AdmissionEvidence, AdmissionRequest, EvidenceBinding, QuarantineReason};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const DOMAIN: &[u8] = b"PALACO-HARBOR-REPLAY-BINDING-v1\0";
const MAX_FIELD: usize = 4096;

/// Claims about evidence already validated outside Harbor.
///
/// The type itself does not validate signatures, time, consent or revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceIdentity<'a> {
    /// Stable identity of the independent upstream verifier.
    pub verifier_id: &'a str,
    /// Identifier of the exact verified evidence/receipt version.
    pub evidence_ref: &'a str,
    /// SHA-256 hex digest of the exact authenticated payload bytes.
    pub payload_sha256: &'a str,
    /// Monotone trusted epoch asserted by an upstream authority.
    pub trust_epoch: u64,
}

fn append_field(hasher: &mut Sha256, value: &str) -> Result<(), ReservationError> {
    if value.is_empty() || value.len() > MAX_FIELD {
        return Err(ReservationError::Unavailable);
    }
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

/// Derive a stable reservation key from the complete request/evidence identity.
///
/// A content digest must never be interpreted as proof of truth or authorization.
pub fn derive_binding_key(
    request: &AdmissionRequest<'_>,
    evidence: &EvidenceIdentity<'_>,
) -> Result<String, ReservationError> {
    if evidence.payload_sha256.len() != 64
        || !evidence.payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || evidence.trust_epoch == 0
    {
        return Err(ReservationError::Unavailable);
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    append_field(&mut hasher, request.subject_id)?;
    append_field(&mut hasher, request.purpose)?;
    append_field(&mut hasher, request.scope)?;
    append_field(&mut hasher, evidence.verifier_id)?;
    append_field(&mut hasher, evidence.evidence_ref)?;
    append_field(&mut hasher, &evidence.payload_sha256.to_ascii_lowercase())?;
    hasher.update(evidence.trust_epoch.to_be_bytes());
    let digest = hasher.finalize();
    let mut key = String::with_capacity(64);
    for byte in digest {
        write!(&mut key, "{byte:02x}").map_err(|_| ReservationError::Unavailable)?;
    }
    Ok(key)
}

/// Fail closed on invalid binding inputs, then apply independent Harbor routing.
///
/// This accepts upstream assertions, not cryptographic proof. Routing forward is
/// never permission to execute.
#[must_use]
pub fn assess_with_derived_reservation<S: ReplayReservationStore>(
    store: &mut S,
    receipt_id: &str,
    request: &AdmissionRequest<'_>,
    binding: &EvidenceBinding<'_>,
    admission: &AdmissionEvidence,
    evidence: &EvidenceIdentity<'_>,
) -> AdmissionDisposition {
    let admission_decision = assess_bound_admission(request, binding, admission);
    if admission_decision != AdmissionDisposition::ForwardForAuthorization {
        return admission_decision;
    }
    let key = match derive_binding_key(request, evidence) {
        Ok(key) => key,
        Err(_) => return AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch),
    };
    assess_with_reservation(store, receipt_id, &key, request, binding, admission)
}

#[cfg(test)]
mod tests {
    use super::{assess_with_derived_reservation, derive_binding_key, EvidenceIdentity};
    use crate::replay_contract::{ReplayReservationStore, ReservationError, ReservationOutcome};
    use crate::{AdmissionDisposition, AdmissionEvidence, AdmissionRequest, EvidenceBinding, QuarantineReason};
    use std::collections::HashMap;

    fn request<'a>(subject: &'a str, purpose: &'a str) -> AdmissionRequest<'a> {
        AdmissionRequest { subject_id: subject, purpose, scope: "rio:invite" }
    }

    fn evidence<'a>(digest: &'a str) -> EvidenceIdentity<'a> {
        EvidenceIdentity {
            verifier_id: "verifier-1",
            evidence_ref: "proof-v1",
            payload_sha256: digest,
            trust_epoch: 2,
        }
    }

    #[derive(Default)]
    struct Store(HashMap<String, String>);

    impl ReplayReservationStore for Store {
        fn reserve(&mut self, id: &str, key: &str) -> Result<ReservationOutcome, ReservationError> {
            match self.0.get(id) {
                None => {
                    self.0.insert(id.to_owned(), key.to_owned());
                    Ok(ReservationOutcome::Reserved)
                }
                Some(old) if old == key => Ok(ReservationOutcome::AlreadyReserved),
                Some(_) => Ok(ReservationOutcome::BindingConflict),
            }
        }
    }

    #[test]
    fn stable_digest_and_field_boundaries() {
        let payload = "a".repeat(64);
        let a = derive_binding_key(&request("ab", "c"), &evidence(&payload));
        let b = derive_binding_key(&request("ab", "c"), &evidence(&payload));
        let crossed = derive_binding_key(&request("a", "bc"), &evidence(&payload));
        assert_eq!(a, b);
        assert_ne!(a, crossed);
    }

    #[test]
    fn changes_in_evidence_or_epoch_change_binding() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let baseline = derive_binding_key(&request("person", "contact"), &evidence(&a));
        let changed = derive_binding_key(&request("person", "contact"), &evidence(&b));
        let mut epoch = evidence(&a);
        epoch.trust_epoch = 3;
        assert_ne!(baseline, changed);
        assert_ne!(baseline, derive_binding_key(&request("person", "contact"), &epoch));
    }

    #[test]
    fn invalid_digest_or_epoch_fails_closed() {
        let mut identity = evidence("not-a-sha256");
        assert_eq!(derive_binding_key(&request("person", "contact"), &identity), Err(ReservationError::Unavailable));
        identity.payload_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        identity.trust_epoch = 0;
        assert_eq!(derive_binding_key(&request("person", "contact"), &identity), Err(ReservationError::Unavailable));
    }

    #[test]
    fn same_receipt_with_changed_payload_quarantines() {
        let mut store = Store::default();
        let req = request("person", "contact");
        let bind = EvidenceBinding { subject_id: "person", purpose: "contact", scope: "rio:invite" };
        let admission = AdmissionEvidence {
            identity_verified: true, provenance_verified: true, consent_verified: true,
            scope_verified: true, revocation_checked: true, revoked: false,
            temporal_validity_verified: true,
        };
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert_eq!(
            assess_with_derived_reservation(&mut store, "r-1", &req, &bind, &admission, &evidence(&a)),
            AdmissionDisposition::ForwardForAuthorization
        );
        assert_eq!(
            assess_with_derived_reservation(&mut store, "r-1", &req, &bind, &admission, &evidence(&b)),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
    }
}
