//! Execution boundary contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_constitution::{AuthorizationGrant, IdentityHandle};
use palaco_foundation::{
    errors::RevalidationError,
    traits::{CurrentlyAssessable, FailClosed, Revalidatable, Validatable},
    types::{CurrentValidity, DecisionContext, RevalidationOutcome, Timestamp},
};
use palaco_trias::{AuthorizationScope, GovernanceDecision};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

/// Outcome of one execution attempt at the in-memory commit gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The attempt was ordered and accepted.
    Committed { sequence: u64 },
    /// The attempt was ordered and denied.
    Denied {
        sequence: u64,
        reason: CommitDenialReason,
    },
}

/// Reason an execution attempt was denied by the commit gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDenialReason {
    /// The grant did not identify an authorization.
    InvalidAuthorization,
    /// The grant did not cover the requested scope.
    ScopeMismatch,
    /// The grant did not include provenance.
    MissingProvenance,
    /// The authorization had already been revoked in registry order.
    AuthorizationRevoked,
}

/// Failure to safely process an operation in the in-memory commit gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitGateError {
    /// The registry lock was poisoned; the operation failed closed.
    LockPoisoned,
    /// The sequence number space was exhausted.
    SequenceExhausted,
    /// An attempt identifier was empty.
    EmptyAttemptId,
    /// An idempotency key was reused for a different request.
    IdempotencyConflict,
}

/// One append-only event in the process-local commit-gate registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRegistryRecord {
    /// Monotone order assigned while holding the registry lock.
    pub sequence: u64,
    /// Recorded event.
    pub event: CommitRegistryEvent,
}

/// Event recorded by the process-local commit-gate registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRegistryEvent {
    /// Execution attempt and its immutable outcome.
    Attempt {
        /// Caller-provided idempotency key.
        attempt_id: String,
        /// Authorization considered by the gate.
        authorization_id: String,
        /// Scope requested by the attempt.
        requested_scope: String,
        /// Outcome assigned at this registry position.
        outcome: CommitOutcome,
    },
    /// Revocation observed by the gate.
    Revocation {
        /// Authorization targeted by the revocation.
        authorization_id: String,
        /// Recorded reason.
        reason: String,
        /// Provenance locator supplied with the revocation.
        record_locator: String,
    },
}

#[derive(Debug)]
struct CommitRegistryState {
    next_sequence: Option<u64>,
    records: Vec<CommitRegistryRecord>,
    attempts: HashMap<String, (String, String, CommitOutcome)>,
    revoked_authorizations: HashSet<String>,
}

impl CommitRegistryState {
    fn append(
        &mut self,
        event: impl FnOnce(u64) -> CommitRegistryEvent,
    ) -> Result<u64, CommitGateError> {
        let sequence = self
            .next_sequence
            .ok_or(CommitGateError::SequenceExhausted)?;
        self.next_sequence = sequence.checked_add(1);
        self.records.push(CommitRegistryRecord {
            sequence,
            event: event(sequence),
        });
        Ok(sequence)
    }
}

/// Process-local reference model for serializing commit and revocation events.
///
/// This gate provides in-process ordering only. It is neither durable nor
/// replicated, and therefore is not an exchange-grade registry or proof
/// authority. Callers must verify revocation authority before recording one.
#[derive(Debug)]
pub struct InMemoryCommitGate {
    state: Mutex<CommitRegistryState>,
}

impl Default for InMemoryCommitGate {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCommitGate {
    /// Creates an empty process-local registry with sequence numbers starting at one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CommitRegistryState {
                next_sequence: Some(1),
                records: Vec::new(),
                attempts: HashMap::new(),
                revoked_authorizations: HashSet::new(),
            }),
        }
    }

    /// Records a revocation in sequence order.
    ///
    /// The caller is responsible for verifying the authority and provenance of
    /// the revocation. This method only serializes the supplied event.
    pub fn record_revocation(
        &self,
        revocation: &palaco_constitution::RevocationRecord,
    ) -> Result<u64, CommitGateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CommitGateError::LockPoisoned)?;
        let sequence = state.append(|_| CommitRegistryEvent::Revocation {
            authorization_id: revocation.authorization_id.clone(),
            reason: revocation.reason.clone(),
            record_locator: revocation.provenance.record_locator.clone(),
        })?;
        if !revocation.authorization_id.is_empty() {
            state
                .revoked_authorizations
                .insert(revocation.authorization_id.clone());
        }
        Ok(sequence)
    }

    /// Resolves and appends an execution attempt at one in-process ordering point.
    ///
    /// Replaying an identical attempt identifier returns its original outcome
    /// without appending another event. Reusing that identifier for a different
    /// authorization or scope fails with `IdempotencyConflict`.
    pub fn try_commit(
        &self,
        attempt_id: impl Into<String>,
        grant: &AuthorizationGrant,
        requested_scope: &palaco_constitution::AuthorityScope,
    ) -> Result<CommitOutcome, CommitGateError> {
        let attempt_id = attempt_id.into();
        if attempt_id.is_empty() {
            return Err(CommitGateError::EmptyAttemptId);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| CommitGateError::LockPoisoned)?;
        let request_identity = (
            grant.authorization_id.clone(),
            requested_scope.capability.clone(),
        );
        if let Some((authorization_id, scope, outcome)) = state.attempts.get(&attempt_id) {
            if (authorization_id, scope) == (&request_identity.0, &request_identity.1) {
                return Ok(*outcome);
            }
            return Err(CommitGateError::IdempotencyConflict);
        }

        let reason = if grant.authorization_id.is_empty() {
            Some(CommitDenialReason::InvalidAuthorization)
        } else if grant.scope != *requested_scope {
            Some(CommitDenialReason::ScopeMismatch)
        } else if grant.scope.capability.is_empty() || grant.provenance.record_locator.is_empty() {
            Some(CommitDenialReason::MissingProvenance)
        } else if state
            .revoked_authorizations
            .contains(&grant.authorization_id)
        {
            Some(CommitDenialReason::AuthorizationRevoked)
        } else {
            None
        };

        let authorization_id = grant.authorization_id.clone();
        let requested_scope_name = requested_scope.capability.clone();
        let sequence = state.next_sequence.ok_or(CommitGateError::SequenceExhausted)?;
        let outcome = match reason {
            Some(reason) => CommitOutcome::Denied { sequence, reason },
            None => CommitOutcome::Committed { sequence },
        };
        state.append(|_| CommitRegistryEvent::Attempt {
            attempt_id: attempt_id.clone(),
            authorization_id: authorization_id.clone(),
            requested_scope: requested_scope_name.clone(),
            outcome,
        })?;
        state.attempts.insert(
            attempt_id,
            (authorization_id, requested_scope_name, outcome),
        );
        Ok(outcome)
    }

    /// Returns an ordered snapshot of events recorded so far.
    pub fn records(&self) -> Result<Vec<CommitRegistryRecord>, CommitGateError> {
        self.state
            .lock()
            .map(|state| state.records.clone())
            .map_err(|_| CommitGateError::LockPoisoned)
    }
}

/// Resulting enforcement mode at the execution boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BoundaryDisposition {
    /// Execution is allowed to proceed.
    Execute,
    /// Execution must escalate for additional review.
    Escalate,
    /// Execution must remain in a safe closed state.
    #[default]
    SafeState,
}

/// Execution boundary request carried into the runtime layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBoundary {
    /// Governance decision authorizing the boundary crossing.
    pub decision: GovernanceDecision,
    /// Explicit authorization grant derived from the governance decision.
    pub authorization: AuthorizationGrant,
    /// Current disposition enforced at the boundary.
    pub disposition: BoundaryDisposition,
}

impl ExecutionBoundary {
    /// Creates an execution boundary from a governance decision.
    #[must_use]
    pub fn new(decision: GovernanceDecision) -> Self {
        let disposition = match decision.scope {
            AuthorizationScope::Execute => BoundaryDisposition::Execute,
            AuthorizationScope::Observe | AuthorizationScope::Advise => {
                BoundaryDisposition::Escalate
            }
        };
        let authorization = AuthorizationGrant {
            authorization_id: decision.id.0.to_string(),
            scope: decision.authority.clone(),
            granted_to: IdentityHandle::default(),
            provenance: decision.provenance.clone(),
        };

        Self {
            decision,
            authorization,
            disposition,
        }
    }
}

impl Validatable for ExecutionBoundary {
    fn validate(&self) -> Result<(), palaco_foundation::errors::ValidationError> {
        self.decision.validate()
    }
}

impl CurrentlyAssessable for ExecutionBoundary {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity {
        match self.disposition {
            BoundaryDisposition::Execute => self.decision.current_validity(at),
            BoundaryDisposition::Escalate => CurrentValidity::InsufficientEvidence,
            BoundaryDisposition::SafeState => CurrentValidity::SafeStateRequired,
        }
    }
}

impl Revalidatable for ExecutionBoundary {
    type Context = DecisionContext;

    fn revalidate(
        &self,
        context: &Self::Context,
    ) -> Result<RevalidationOutcome, RevalidationError> {
        self.validate()?;

        match self.disposition {
            BoundaryDisposition::Execute => self.decision.revalidate(context),
            BoundaryDisposition::Escalate => Ok(RevalidationOutcome::Escalated),
            BoundaryDisposition::SafeState => Ok(RevalidationOutcome::SafeState),
        }
    }
}

impl FailClosed for ExecutionBoundary {
    type Output = BoundaryDisposition;

    fn fail_closed(&self) -> Self::Output {
        BoundaryDisposition::SafeState
    }
}

#[cfg(test)]
mod tests {
    use chrono::{LocalResult, TimeZone, Utc};
    use palaco_constitution::{AuthorityScope, AuthorizationGrant, IdentityHandle, ProvenanceRecord};
    use palaco_events::EventEnvelope;
    use palaco_foundation::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        traits::{CurrentlyAssessable, FailClosed, Revalidatable},
        types::{
            CurrentValidity, DecisionContext, RevalidationOutcome, TrustLevel, ValidityWindow,
        },
    };
    use palaco_oracle::PlausibleState;
    use palaco_trias::{AuthorizationScope, GovernanceDecision};
    use palaco_types::DomainMarker;

    use crate::{
        BoundaryDisposition, CommitDenialReason, CommitOutcome, ExecutionBoundary,
        InMemoryCommitGate,
    };

    fn grant() -> AuthorizationGrant {
        AuthorizationGrant {
            authorization_id: "authorization-1".to_string(),
            scope: AuthorityScope {
                capability: "palaco.execute".to_string(),
            },
            granted_to: IdentityHandle::default(),
            provenance: ProvenanceRecord {
                source: "test".to_string(),
                record_locator: "grant-1".to_string(),
            },
        }
    }

    fn timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Result<chrono::DateTime<Utc>, &'static str> {
        match Utc.with_ymd_and_hms(year, month, day, hour, minute, second) {
            LocalResult::Single(value) => Ok(value),
            LocalResult::Ambiguous(_, _) | LocalResult::None => Err("invalid UTC timestamp"),
        }
    }

    fn context(observed_at: chrono::DateTime<Utc>) -> DecisionContext {
        DecisionContext {
            state: StateSnapshotId::new(),
            policy_version: PolicyVersionId::new(),
            observed_at,
        }
    }

    fn decision(scope: AuthorizationScope) -> Result<GovernanceDecision, &'static str> {
        let context = context(timestamp(2026, 1, 15, 12, 0, 0)?);

        Ok(GovernanceDecision::new(
            palaco_oracle::OracleReport::new(
                palaco_evidence::EvidenceBundle::new(
                    EventEnvelope {
                        marker: DomainMarker,
                    },
                    Evidence::new(
                        uuid::Uuid::new_v4(),
                        timestamp(2026, 1, 10, 12, 0, 0)?,
                        NodeId::new(),
                        TrustLevel::High,
                        ValidityWindow::new(
                            timestamp(2026, 1, 1, 0, 0, 0)?,
                            timestamp(2026, 1, 31, 23, 59, 59)?,
                        ),
                    ),
                    palaco_evidence::EvidenceCompleteness::Complete,
                ),
                context,
                PlausibleState::Stable,
            ),
            context,
            scope,
            timestamp(2026, 1, 15, 12, 0, 0)?,
            ValidityWindow::new(
                timestamp(2026, 1, 1, 0, 0, 0)?,
                timestamp(2026, 1, 31, 23, 59, 59)?,
            ),
        ))
    }

    #[test]
    fn execution_boundary_confirms_executable_decision() -> Result<(), &'static str> {
        let boundary = ExecutionBoundary::new(decision(AuthorizationScope::Execute)?);

        assert_eq!(
            boundary.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::Valid
        );
        assert_eq!(
            boundary.revalidate(&boundary.decision.context),
            Ok(RevalidationOutcome::Confirmed)
        );

        Ok(())
    }

    #[test]
    fn execution_boundary_fails_closed_when_requested() -> Result<(), &'static str> {
        let boundary = ExecutionBoundary::new(decision(AuthorizationScope::Observe)?);

        assert_eq!(boundary.fail_closed(), BoundaryDisposition::SafeState);
        assert_eq!(
            boundary.current_validity(timestamp(2026, 1, 20, 0, 0, 0)?),
            CurrentValidity::InsufficientEvidence
        );

        Ok(())
    }

    #[test]
    fn commit_gate_denies_attempt_ordered_after_revocation() {
        let gate = InMemoryCommitGate::new();
        let grant = grant();
        let scope = grant.scope.clone();
        let revocation = palaco_constitution::RevocationRecord {
            authorization_id: grant.authorization_id.clone(),
            reason: "withdrawn".to_string(),
            provenance: ProvenanceRecord {
                source: "governance".to_string(),
                record_locator: "revocation-1".to_string(),
            },
        };

        assert_eq!(gate.record_revocation(&revocation), Ok(1));
        assert_eq!(
            gate.try_commit("attempt-1", &grant, &scope),
            Ok(CommitOutcome::Denied {
                sequence: 2,
                reason: CommitDenialReason::AuthorizationRevoked,
            })
        );
    }

    #[test]
    fn commit_gate_preserves_commit_ordered_before_revocation() {
        let gate = InMemoryCommitGate::new();
        let grant = grant();
        let scope = grant.scope.clone();
        let revocation = palaco_constitution::RevocationRecord {
            authorization_id: grant.authorization_id.clone(),
            reason: "withdrawn".to_string(),
            provenance: ProvenanceRecord {
                source: "governance".to_string(),
                record_locator: "revocation-1".to_string(),
            },
        };

        assert_eq!(
            gate.try_commit("attempt-1", &grant, &scope),
            Ok(CommitOutcome::Committed { sequence: 1 })
        );
        assert_eq!(gate.record_revocation(&revocation), Ok(2));
        assert_eq!(
            gate.try_commit("attempt-2", &grant, &scope),
            Ok(CommitOutcome::Denied {
                sequence: 3,
                reason: CommitDenialReason::AuthorizationRevoked,
            })
        );
    }

    #[test]
    fn commit_gate_replay_is_idempotent_and_rejects_payload_changes() {
        let gate = InMemoryCommitGate::new();
        let grant = grant();
        let scope = grant.scope.clone();
        let outcome = gate.try_commit("attempt-1", &grant, &scope);

        assert_eq!(outcome, Ok(CommitOutcome::Committed { sequence: 1 }));
        assert_eq!(gate.try_commit("attempt-1", &grant, &scope), outcome);
        assert_eq!(
            gate.try_commit(
                "attempt-1",
                &grant,
                &AuthorityScope {
                    capability: "palaco.observe".to_string(),
                },
            ),
            Err(crate::CommitGateError::IdempotencyConflict)
        );
        assert_eq!(gate.records().map(|records| records.len()), Ok(1));
    }

    #[test]
    fn commit_gate_serializes_concurrent_commits_and_revocation() {
        use std::sync::{Arc, Barrier};

        let gate = Arc::new(InMemoryCommitGate::new());
        let start = Arc::new(Barrier::new(9));
        let grant = grant();
        let scope = grant.scope.clone();
        let mut workers = Vec::new();

        for index in 0..8 {
            let gate = Arc::clone(&gate);
            let start = Arc::clone(&start);
            let grant = grant.clone();
            let scope = scope.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                gate.try_commit(format!("attempt-{index}"), &grant, &scope)
            }));
        }

        let revoke_gate = Arc::clone(&gate);
        let revoke_start = Arc::clone(&start);
        let authorization_id = grant.authorization_id.clone();
        let revoker = std::thread::spawn(move || {
            revoke_start.wait();
            revoke_gate.record_revocation(&palaco_constitution::RevocationRecord {
                authorization_id,
                reason: "withdrawn".to_string(),
                provenance: ProvenanceRecord {
                    source: "governance".to_string(),
                    record_locator: "revocation-1".to_string(),
                },
            })
        });

        for worker in workers {
            assert!(worker.join().is_ok_and(|result| result.is_ok()));
        }
        assert!(revoker.join().is_ok_and(|result| result.is_ok()));

        let records = gate.records();
        assert!(records.is_ok());
        let records = records.unwrap_or_default();
        assert_eq!(records.len(), 9);
        assert!(records
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));

        let revocation_sequence = records.iter().find_map(|record| match &record.event {
            crate::CommitRegistryEvent::Revocation { .. } => Some(record.sequence),
            crate::CommitRegistryEvent::Attempt { .. } => None,
        });
        assert!(revocation_sequence.is_some());
        let revocation_sequence = revocation_sequence.unwrap_or_default();
        for record in records {
            if let crate::CommitRegistryEvent::Attempt { outcome, .. } = record.event {
                let ordered_consistently = match outcome {
                    CommitOutcome::Committed { sequence } => sequence < revocation_sequence,
                    CommitOutcome::Denied {
                        sequence,
                        reason: CommitDenialReason::AuthorizationRevoked,
                    } => sequence > revocation_sequence,
                    CommitOutcome::Denied { .. } => false,
                };
                assert!(ordered_consistently);
            }
        }
    }
}
