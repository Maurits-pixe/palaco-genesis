//! Storage contract for Harbor replay reservations.
//!
//! This module does not implement durable storage. The adapter must provide
//! transactionally atomic uniqueness across processes and restarts.

use crate::{
    assess_bound_admission, AdmissionDisposition, AdmissionEvidence, AdmissionRequest,
    EvidenceBinding, QuarantineReason,
};

/// Result of a reservation operation committed by the storage authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationOutcome {
    /// A new receipt was atomically reserved and durably committed.
    Reserved,
    /// The same receipt and binding had previously been reserved.
    AlreadyReserved,
    /// The receipt ID was previously bound to different immutable content.
    BindingConflict,
}

/// Storage uncertainty must never permit forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError {
    /// The storage service was unavailable before a reliable result.
    Unavailable,
    /// The write may have committed but its result is unknown.
    UncertainCompletion,
}

/// Interface to a durable, transactionally unique reservation authority.
///
/// Implementations MUST serialize reservation by receipt ID, durably bind the
/// ID to immutable request content, and make recovery/retry return the same
/// committed result. A content digest alone is not proof of truth or authority.
pub trait ReplayReservationStore {
    /// Atomically reserve a receipt identifier for the supplied binding key.
    ///
    /// This must be a single durable decision across every participating
    /// instance; a process-local set is not a conforming implementation.
    fn reserve(
        &mut self,
        receipt_id: &str,
        binding_key: &str,
    ) -> Result<ReservationOutcome, ReservationError>;
}

/// Fail-closed result after Harbor routing and storage reservation.
///
/// A successful result still only forwards to an independent authorization
/// gate; it never creates execution authority.
#[must_use]
pub fn assess_with_reservation<S: ReplayReservationStore>(
    store: &mut S,
    receipt_id: &str,
    binding_key: &str,
    request: &AdmissionRequest<'_>,
    binding: &EvidenceBinding<'_>,
    evidence: &AdmissionEvidence,
) -> AdmissionDisposition {
    let decision = assess_bound_admission(request, binding, evidence);
    if decision != AdmissionDisposition::ForwardForAuthorization {
        return decision;
    }
    if receipt_id.is_empty() || binding_key.is_empty() {
        return AdmissionDisposition::Quarantine(QuarantineReason::MissingReceiptId);
    }

    match store.reserve(receipt_id, binding_key) {
        Ok(ReservationOutcome::Reserved) => AdmissionDisposition::ForwardForAuthorization,
        Ok(ReservationOutcome::AlreadyReserved) => {
            AdmissionDisposition::Quarantine(QuarantineReason::ReplayDetected)
        }
        Ok(ReservationOutcome::BindingConflict) => {
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        }
        Err(ReservationError::Unavailable | ReservationError::UncertainCompletion) => {
            AdmissionDisposition::Quarantine(QuarantineReason::ReservationUncertain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assess_with_reservation, ReplayReservationStore, ReservationError, ReservationOutcome,
    };
    use crate::{
        AdmissionDisposition, AdmissionEvidence, AdmissionRequest, EvidenceBinding,
        QuarantineReason, RejectionReason,
    };
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeStore {
        records: HashMap<String, String>,
        failure: Option<ReservationError>,
        calls: usize,
    }

    impl ReplayReservationStore for FakeStore {
        fn reserve(
            &mut self,
            receipt_id: &str,
            binding_key: &str,
        ) -> Result<ReservationOutcome, ReservationError> {
            self.calls += 1;
            if let Some(error) = self.failure {
                return Err(error);
            }
            match self.records.get(receipt_id) {
                Some(existing) if existing == binding_key => {
                    Ok(ReservationOutcome::AlreadyReserved)
                }
                Some(_) => Ok(ReservationOutcome::BindingConflict),
                None => {
                    self.records
                        .insert(receipt_id.to_owned(), binding_key.to_owned());
                    Ok(ReservationOutcome::Reserved)
                }
            }
        }
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

    fn evidence() -> AdmissionEvidence {
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
    fn reserved_once_then_replay_quarantines() {
        let mut store = FakeStore::default();
        assert_eq!(
            assess_with_reservation(
                &mut store, "r-1", "binding-1", &request(), &binding(), &evidence(),
            ),
            AdmissionDisposition::ForwardForAuthorization
        );
        assert_eq!(
            assess_with_reservation(
                &mut store, "r-1", "binding-1", &request(), &binding(), &evidence(),
            ),
            AdmissionDisposition::Quarantine(QuarantineReason::ReplayDetected)
        );
    }

    #[test]
    fn same_id_different_content_quarantines() {
        let mut store = FakeStore::default();
        store.records.insert("r-1".into(), "binding-1".into());
        assert_eq!(
            assess_with_reservation(
                &mut store, "r-1", "binding-2", &request(), &binding(), &evidence(),
            ),
            AdmissionDisposition::Quarantine(QuarantineReason::BindingMismatch)
        );
    }

    #[test]
    fn unavailable_and_uncertain_storage_fail_closed() {
        for failure in [
            ReservationError::Unavailable,
            ReservationError::UncertainCompletion,
        ] {
            let mut store = FakeStore {
                failure: Some(failure),
                ..FakeStore::default()
            };
            assert_eq!(
                assess_with_reservation(
                    &mut store, "r-1", "binding-1", &request(), &binding(), &evidence(),
                ),
                AdmissionDisposition::Quarantine(QuarantineReason::ReservationUncertain)
            );
        }
    }

    #[test]
    fn rejected_request_never_touches_storage() {
        let mut store = FakeStore::default();
        let mut e = evidence();
        e.revoked = true;
        assert_eq!(
            assess_with_reservation(
                &mut store, "r-1", "binding-1", &request(), &binding(), &e,
            ),
            AdmissionDisposition::Reject(RejectionReason::Revoked)
        );
        assert_eq!(store.calls, 0);
    }

    #[test]
    fn missing_receipt_or_binding_key_never_touches_storage() {
        let mut store = FakeStore::default();
        for (receipt, key) in [("", "binding-1"), ("r-1", "")] {
            assert_eq!(
                assess_with_reservation(
                    &mut store, receipt, key, &request(), &binding(), &evidence(),
                ),
                AdmissionDisposition::Quarantine(QuarantineReason::MissingReceiptId)
            );
        }
        assert_eq!(store.calls, 0);
    }
}
