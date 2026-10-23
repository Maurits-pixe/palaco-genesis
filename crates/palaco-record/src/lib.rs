//! Append-only execution record contracts for PAD-RECORD-001.
//!
//! This crate is deliberately control-plane and in-memory. It models record
//! identity, lifecycle state, evidence state, handoff lineage, and replay
//! behaviour without launching processes or touching external systems.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The record contract version implemented by this crate.
pub const CONTRACT_VERSION: &str = "PAD-RECORD-001/v1";

/// Execution lifecycle state captured by a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    /// The operation is assembled but has not crossed a handoff boundary.
    Prepared,
    /// The exact first-effect handoff was accepted.
    HandoffAccepted,
    /// The execution gate released the exact declared operation.
    ExecutionReleased,
    /// A first effect was observed.
    FirstEffectObserved,
    /// The declared operation is active.
    Running,
    /// The lifecycle ended with an observed completion boundary.
    Completed,
    /// The declared operation ended in failure.
    Failed,
    /// The declared operation was cancelled.
    Cancelled,
    /// The declared operation crossed its time boundary.
    TimedOut,
    /// The record cannot yet distinguish release, effect, or outcome.
    CrashAmbiguous,
}

/// Completion state, deliberately separate from execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionState {
    /// No completion boundary has been observed.
    NotStarted,
    /// The operation is active or its terminal state is not yet known.
    InProgress,
    /// A completion boundary was observed.
    Complete,
    /// The operation completed with a failure result.
    Failed,
    /// Completion cannot be reconstructed yet.
    Unknown,
}

/// Verification state, deliberately separate from completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationState {
    /// No verification has been attempted.
    NotAttempted,
    /// Verification is waiting for sufficient evidence.
    Pending,
    /// The declared verification contract was independently satisfied.
    Verified,
    /// Verification cannot be established from the available evidence.
    Unverified,
    /// Evidence or authoritative inputs conflict.
    Conflicted,
}

/// Evidence state attached to the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState {
    /// No sufficient evidence is available.
    Missing,
    /// Evidence is complete for the declared record contract.
    Complete,
    /// Evidence sources disagree.
    Conflicting,
}

/// Failure or uncertainty reason preserved in the append-only record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureState {
    /// A crash occurred before a first effect was observed.
    CrashBeforeFirstEffect,
    /// A crash occurred after a first effect was observed.
    CrashAfterFirstEffect,
    /// Scope changed after the record was bound.
    ScopeDrift,
    /// Required evidence is absent.
    MissingEvidence,
    /// Evidence sources conflict.
    ConflictingEvidence,
    /// Completion could not be reconstructed.
    UnknownCompletion,
    /// Verification could not be established.
    UnknownVerification,
    /// A replay was detected for an existing idempotency identity.
    Replay,
}

/// Record identity and contract binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordIdentity {
    record_id: String,
    run_id: String,
    contract_version: String,
    sequence: u64,
}

impl RecordIdentity {
    /// Creates a new record identity.
    #[must_use]
    pub fn new(record_id: impl Into<String>, run_id: impl Into<String>, sequence: u64) -> Self {
        Self {
            record_id: record_id.into(),
            run_id: run_id.into(),
            contract_version: CONTRACT_VERSION.to_owned(),
            sequence,
        }
    }

    /// Returns the stable record identifier.
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// Returns the run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the bound record contract version.
    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    /// Returns the append sequence assigned to the record.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Provenance and lineage references for a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordProvenance {
    parent_record_id: Option<String>,
    previous_record_id: Option<String>,
    authorization_ref: String,
    scope_digest: String,
    idempotency_key: String,
    created_at: u64,
    observed_at: Option<u64>,
    append_only: bool,
}

impl RecordProvenance {
    /// Returns the immediate parent record, if this is a handoff child.
    #[must_use]
    pub fn parent_record_id(&self) -> Option<&str> {
        self.parent_record_id.as_deref()
    }

    /// Returns the previous record in the append-only chain, if present.
    #[must_use]
    pub fn previous_record_id(&self) -> Option<&str> {
        self.previous_record_id.as_deref()
    }

    /// Returns the authorization reference without granting authority.
    #[must_use]
    pub fn authorization_ref(&self) -> &str {
        &self.authorization_ref
    }

    /// Returns the exact scope digest bound to the record.
    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    /// Returns the replay/idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Returns the record creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the observed transition timestamp, if one exists.
    #[must_use]
    pub fn observed_at(&self) -> Option<u64> {
        self.observed_at
    }

    /// Returns whether this record is append-only.
    #[must_use]
    pub fn append_only(&self) -> bool {
        self.append_only
    }
}

/// Errors produced when a record transition would violate the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// A requested lifecycle transition is not valid from the current state.
    InvalidTransition,
    /// The observed scope differs from the bound scope.
    ScopeDrift,
    /// Evidence is insufficient for independent verification.
    EvidenceMissing,
    /// Evidence conflicts with another authoritative source.
    EvidenceConflict,
    /// Verification was requested before its prerequisites were satisfied.
    VerificationNotReady,
}

/// A single append-only record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    identity: RecordIdentity,
    provenance: RecordProvenance,
    execution_state: ExecutionState,
    completion_state: CompletionState,
    verification_state: VerificationState,
    evidence_state: EvidenceState,
    failure_state: Option<FailureState>,
}

impl Record {
    /// Creates a new prepared record without authority or external effects.
    #[must_use]
    pub fn new(
        record_id: impl Into<String>,
        run_id: impl Into<String>,
        authorization_ref: impl Into<String>,
        scope_digest: impl Into<String>,
        idempotency_key: impl Into<String>,
        created_at: u64,
        sequence: u64,
    ) -> Self {
        Self {
            identity: RecordIdentity::new(record_id, run_id, sequence),
            provenance: RecordProvenance {
                parent_record_id: None,
                previous_record_id: None,
                authorization_ref: authorization_ref.into(),
                scope_digest: scope_digest.into(),
                idempotency_key: idempotency_key.into(),
                created_at,
                observed_at: None,
                append_only: true,
            },
            execution_state: ExecutionState::Prepared,
            completion_state: CompletionState::NotStarted,
            verification_state: VerificationState::NotAttempted,
            evidence_state: EvidenceState::Missing,
            failure_state: None,
        }
    }

    /// Creates a new child record while preserving parent and previous lineage.
    #[must_use]
    pub fn child_record(
        &self,
        record_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        created_at: u64,
        sequence: u64,
    ) -> Self {
        let parent_id = self.identity.record_id.clone();
        let mut child = Self::new(
            record_id,
            self.identity.run_id.clone(),
            self.provenance.authorization_ref.clone(),
            self.provenance.scope_digest.clone(),
            idempotency_key,
            created_at,
            sequence,
        );
        child.provenance.parent_record_id = Some(parent_id.clone());
        child.provenance.previous_record_id = Some(parent_id);
        child
    }

    /// Returns the record identity.
    #[must_use]
    pub fn identity(&self) -> &RecordIdentity {
        &self.identity
    }

    /// Returns the provenance binding.
    #[must_use]
    pub fn provenance(&self) -> &RecordProvenance {
        &self.provenance
    }

    /// Returns the execution state.
    #[must_use]
    pub fn execution_state(&self) -> ExecutionState {
        self.execution_state
    }

    /// Returns the completion state.
    #[must_use]
    pub fn completion_state(&self) -> CompletionState {
        self.completion_state
    }

    /// Returns the verification state.
    #[must_use]
    pub fn verification_state(&self) -> VerificationState {
        self.verification_state
    }

    /// Returns the evidence state.
    #[must_use]
    pub fn evidence_state(&self) -> EvidenceState {
        self.evidence_state
    }

    /// Returns the recorded failure or uncertainty reason.
    #[must_use]
    pub fn failure_state(&self) -> Option<FailureState> {
        self.failure_state
    }

    /// Returns true after a first effect has been observed.
    #[must_use]
    pub fn has_first_effect(&self) -> bool {
        matches!(
            self.execution_state,
            ExecutionState::FirstEffectObserved
                | ExecutionState::Running
                | ExecutionState::Completed
                | ExecutionState::Failed
                | ExecutionState::Cancelled
                | ExecutionState::TimedOut
                | ExecutionState::CrashAmbiguous
        ) && matches!(
            self.failure_state,
            Some(FailureState::CrashAfterFirstEffect) | None
        )
    }

    /// Records a matching scope observation without changing the record.
    pub fn check_scope(&self, observed_scope_digest: &str) -> Result<(), RecordError> {
        if observed_scope_digest == self.provenance.scope_digest {
            Ok(())
        } else {
            Err(RecordError::ScopeDrift)
        }
    }

    /// Records acceptance of the exact first-effect handoff.
    pub fn accept_handoff(&mut self) -> Result<(), RecordError> {
        match self.execution_state {
            ExecutionState::Prepared => {
                self.execution_state = ExecutionState::HandoffAccepted;
                Ok(())
            }
            _ => Err(RecordError::InvalidTransition),
        }
    }

    /// Records that the exact first effect was observed.
    pub fn observe_first_effect(&mut self, observed_at: u64) -> Result<(), RecordError> {
        match self.execution_state {
            ExecutionState::ExecutionReleased => {
                self.execution_state = ExecutionState::FirstEffectObserved;
                self.completion_state = CompletionState::InProgress;
                self.verification_state = VerificationState::Pending;
                self.provenance.observed_at = Some(observed_at);
                Ok(())
            }
            _ => Err(RecordError::InvalidTransition),
        }
    }

    /// Marks the execution release without claiming a first effect.
    pub fn release_execution(&mut self) -> Result<(), RecordError> {
        match self.execution_state {
            ExecutionState::HandoffAccepted => {
                self.execution_state = ExecutionState::ExecutionReleased;
                Ok(())
            }
            _ => Err(RecordError::InvalidTransition),
        }
    }

    /// Records an observed successful completion boundary.
    pub fn complete(&mut self) -> Result<(), RecordError> {
        if self.has_first_effect()
            && matches!(
                self.execution_state,
                ExecutionState::FirstEffectObserved | ExecutionState::Running
            )
        {
            self.execution_state = ExecutionState::Completed;
            self.completion_state = CompletionState::Complete;
            self.verification_state = VerificationState::Pending;
            Ok(())
        } else {
            Err(RecordError::InvalidTransition)
        }
    }

    /// Records a crash and preserves whether a first effect had occurred.
    pub fn record_crash(&mut self, after_first_effect: bool) -> Result<(), RecordError> {
        if after_first_effect && !self.has_first_effect() {
            return Err(RecordError::InvalidTransition);
        }

        if !after_first_effect
            && matches!(
                self.execution_state,
                ExecutionState::FirstEffectObserved
                    | ExecutionState::Running
                    | ExecutionState::Completed
                    | ExecutionState::Failed
                    | ExecutionState::Cancelled
                    | ExecutionState::TimedOut
            )
        {
            return Err(RecordError::InvalidTransition);
        }

        self.execution_state = ExecutionState::CrashAmbiguous;
        self.completion_state = CompletionState::Unknown;
        self.verification_state = if after_first_effect {
            VerificationState::Pending
        } else {
            VerificationState::NotAttempted
        };
        self.failure_state = Some(if after_first_effect {
            FailureState::CrashAfterFirstEffect
        } else {
            FailureState::CrashBeforeFirstEffect
        });
        Ok(())
    }

    /// Applies evidence state without turning evidence into authorization.
    pub fn set_evidence(&mut self, evidence_state: EvidenceState) {
        self.evidence_state = evidence_state;
        self.verification_state = match evidence_state {
            EvidenceState::Missing => {
                if self.failure_state.is_none() {
                    self.failure_state = Some(FailureState::MissingEvidence);
                }
                VerificationState::Unverified
            }
            EvidenceState::Complete => VerificationState::Pending,
            EvidenceState::Conflicting => {
                if self.failure_state.is_none() {
                    self.failure_state = Some(FailureState::ConflictingEvidence);
                }
                VerificationState::Conflicted
            }
        };
    }

    /// Independently verifies a completed record with complete evidence.
    pub fn verify(&mut self) -> Result<(), RecordError> {
        if self.completion_state != CompletionState::Complete {
            self.failure_state = Some(FailureState::UnknownCompletion);
            return Err(RecordError::VerificationNotReady);
        }

        match self.evidence_state {
            EvidenceState::Missing => {
                self.failure_state = Some(FailureState::MissingEvidence);
                self.verification_state = VerificationState::Unverified;
                Err(RecordError::EvidenceMissing)
            }
            EvidenceState::Conflicting => {
                self.failure_state = Some(FailureState::ConflictingEvidence);
                self.verification_state = VerificationState::Conflicted;
                Err(RecordError::EvidenceConflict)
            }
            EvidenceState::Complete => {
                self.verification_state = VerificationState::Verified;
                Ok(())
            }
        }
    }

    /// Returns false permanently: a record is not an authority grant.
    #[must_use]
    pub fn grants_authority(&self) -> bool {
        false
    }
}

/// Result of appending a record to an in-memory append-only ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// A new record was appended.
    Appended,
    /// An exact record or idempotency identity already existed.
    Replay,
}

/// Minimal append-only ledger used by the PAD-RECORD-001 harness tests.
#[derive(Debug, Default)]
pub struct RecordLedger {
    records: Vec<Record>,
}

impl RecordLedger {
    /// Appends a record once and reports duplicate identity or idempotency keys.
    pub fn append(&mut self, record: Record) -> AppendOutcome {
        let duplicate = self.records.iter().any(|existing| {
            existing.identity.record_id == record.identity.record_id
                || existing.provenance.idempotency_key == record.provenance.idempotency_key
        });

        if duplicate {
            AppendOutcome::Replay
        } else {
            self.records.push(record);
            AppendOutcome::Appended
        }
    }

    /// Returns the number of durable records in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether the ledger contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the newest record, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&Record> {
        self.records.last()
    }
}
