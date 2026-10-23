use palaco_record::{
    AppendOutcome, CompletionState, EvidenceState, ExecutionState, FailureState, Record,
    RecordError, RecordLedger, VerificationState,
};

fn prepared_record() -> Record {
    Record::new(
        "record-001",
        "run-002",
        "auth-ref-001",
        "scope-digest-001",
        "idempotency-001",
        1_000,
        1,
    )
}

#[test]
fn crash_before_first_effect_preserves_no_effect_boundary() {
    let mut record = prepared_record();

    assert_eq!(record.record_crash(false), Ok(()));
    assert_eq!(record.execution_state(), ExecutionState::CrashAmbiguous);
    assert_eq!(record.completion_state(), CompletionState::Unknown);
    assert_eq!(record.verification_state(), VerificationState::NotAttempted);
    assert_eq!(
        record.failure_state(),
        Some(FailureState::CrashBeforeFirstEffect)
    );
    assert!(!record.has_first_effect());
}

#[test]
fn crash_after_first_effect_preserves_uncertain_outcome() {
    let mut record = prepared_record();

    assert_eq!(record.accept_handoff(), Ok(()));
    assert_eq!(record.release_execution(), Ok(()));
    assert_eq!(record.observe_first_effect(1_100), Ok(()));
    assert_eq!(record.record_crash(true), Ok(()));
    assert_eq!(record.execution_state(), ExecutionState::CrashAmbiguous);
    assert_eq!(record.completion_state(), CompletionState::Unknown);
    assert_eq!(record.verification_state(), VerificationState::Pending);
    assert_eq!(
        record.failure_state(),
        Some(FailureState::CrashAfterFirstEffect)
    );
    assert!(record.has_first_effect());
}

#[test]
fn replay_is_idempotent_and_does_not_append_a_second_record() {
    let mut ledger = RecordLedger::default();
    let record = prepared_record();

    assert_eq!(ledger.append(record.clone()), AppendOutcome::Appended);
    assert_eq!(ledger.append(record), AppendOutcome::Replay);
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.is_empty());
}

#[test]
fn scope_drift_is_rejected_without_mutating_bound_scope() {
    let record = prepared_record();

    assert_eq!(record.check_scope("scope-digest-001"), Ok(()));
    assert_eq!(
        record.check_scope("scope-digest-expanded"),
        Err(RecordError::ScopeDrift)
    );
    assert_eq!(record.provenance().scope_digest(), "scope-digest-001");
}

#[test]
fn record_handoff_preserves_parent_and_previous_lineage_without_authority() {
    let parent = prepared_record();
    let child = parent.child_record("record-002", "idempotency-002", 1_001, 2);

    assert_eq!(child.provenance().parent_record_id(), Some("record-001"));
    assert_eq!(
        child.provenance().previous_record_id(),
        Some("record-001")
    );
    assert_eq!(child.provenance().authorization_ref(), "auth-ref-001");
    assert!(!child.grants_authority());
}

#[test]
fn missing_evidence_cannot_become_verified() {
    let mut record = prepared_record();

    assert_eq!(record.accept_handoff(), Ok(()));
    assert_eq!(record.release_execution(), Ok(()));
    assert_eq!(record.observe_first_effect(1_100), Ok(()));
    assert_eq!(record.complete(), Ok(()));
    record.set_evidence(EvidenceState::Missing);

    assert_eq!(record.verification_state(), VerificationState::Unverified);
    assert_eq!(record.verify(), Err(RecordError::EvidenceMissing));
    assert_ne!(record.verification_state(), VerificationState::Verified);
}

#[test]
fn conflicting_evidence_cannot_become_verified() {
    let mut record = prepared_record();

    assert_eq!(record.accept_handoff(), Ok(()));
    assert_eq!(record.release_execution(), Ok(()));
    assert_eq!(record.observe_first_effect(1_100), Ok(()));
    assert_eq!(record.complete(), Ok(()));
    record.set_evidence(EvidenceState::Conflicting);

    assert_eq!(record.verification_state(), VerificationState::Conflicted);
    assert_eq!(record.verify(), Err(RecordError::EvidenceConflict));
    assert_ne!(record.verification_state(), VerificationState::Verified);
}

#[test]
fn uncertain_completion_blocks_verification_even_with_complete_evidence() {
    let mut record = prepared_record();

    assert_eq!(record.accept_handoff(), Ok(()));
    assert_eq!(record.release_execution(), Ok(()));
    assert_eq!(record.observe_first_effect(1_100), Ok(()));
    assert_eq!(record.record_crash(true), Ok(()));
    record.set_evidence(EvidenceState::Complete);

    assert_eq!(record.completion_state(), CompletionState::Unknown);
    assert_eq!(
        record.verify(),
        Err(RecordError::VerificationNotReady)
    );
    assert_eq!(
        record.failure_state(),
        Some(FailureState::UnknownCompletion)
    );
    assert_ne!(record.verification_state(), VerificationState::Verified);
}
