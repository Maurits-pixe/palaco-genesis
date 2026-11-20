//! Operation-scoped audit service boundary.
//!
//! A verified historical journal is never an execution permit. A production
//! host MUST authenticate callers independently of any request payload and
//! bind this boundary to a trusted, consistently enforced audit backend.

use palaco_runtime::orcheastra::persistence::{JournalSnapshot, TrustedRecoveryAnchor};

use super::{
    authority_transaction::{publish_with_epoch, EpochGuardedAuthority, TransactionError},
    AnchorError, AuditAnchorVerifier,
};

/// Disjoint audit operations; reading does not imply publishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperation {
    /// Verify the current authenticated audit anchor for read-only recovery.
    Verify,
    /// Publish an extended checkpoint under an epoch-guarded CAS.
    Publish,
}

/// Authentication context furnished by a trusted service adapter.
///
/// This value is an *assertion by the implementation*, not a bearer token.
/// Do not instantiate it from an HTTP header, client-provided role or journal.
pub trait AuthenticatedAuditCaller {
    /// Authenticate and authorize the current caller for a single operation.
    ///
    /// The implementation must check identity, audience, expiry, revocation,
    /// operation and exact journal scope against a trusted policy authority.
    fn authorize(&self, journal_id: &str, operation: AuditOperation) -> Result<(), AnchorError>;
}

/// Read-only verification errors.
#[derive(Debug)]
pub enum VerifyServiceError {
    /// Caller identity, journal scope or operation not permitted.
    Access(AnchorError),
    /// Independently authenticated checkpoint unavailable or invalid.
    Authority(AnchorError),
}

/// Mutation errors. No error grants execution authority.
#[derive(Debug)]
pub enum PublishServiceError {
    /// Caller identity or operation not permitted.
    Access(AnchorError),
    /// Candidate validation or transactional publication failed.
    Transaction(TransactionError),
}

/// Verify an anchor after authorizing the exact journal and operation.
///
/// Returned data is an inert audit checkpoint, not an execution capability.
pub fn verify_for_caller<C: AuthenticatedAuditCaller, V: AuditAnchorVerifier>(
    caller: &C,
    verifier: &V,
    journal_id: &str,
) -> Result<TrustedRecoveryAnchor, VerifyServiceError> {
    if journal_id.trim().is_empty() {
        return Err(VerifyServiceError::Access(AnchorError::UnauthorizedJournal));
    }
    caller
        .authorize(journal_id, AuditOperation::Verify)
        .map_err(VerifyServiceError::Access)?;
    verifier
        .latest_anchor(journal_id)
        .map_err(VerifyServiceError::Authority)
}

/// Publish only after caller authorization and strict history validation.
///
/// The trusted backend MUST re-enforce the caller's journal/operation
/// authority inside the same transaction as the policy-epoch CAS. This
/// function's preliminary authorization check alone cannot close an
/// authorization-revocation race in a separate external service.
pub fn publish_for_caller<C: AuthenticatedAuditCaller, A: EpochGuardedAuthority>(
    caller: &C,
    authority: &mut A,
    journal_id: &str,
    snapshot: &JournalSnapshot,
) -> Result<TrustedRecoveryAnchor, PublishServiceError> {
    if journal_id.trim().is_empty() {
        return Err(PublishServiceError::Access(
            AnchorError::UnauthorizedJournal,
        ));
    }
    caller
        .authorize(journal_id, AuditOperation::Publish)
        .map_err(PublishServiceError::Access)?;
    publish_with_epoch(authority, journal_id, snapshot).map_err(PublishServiceError::Transaction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::authority_transaction::AuthorityView;
    use palaco_runtime::orcheastra::{
        recovery::{export_checkpoint, plan_fingerprint, RecoveryCheckpoint},
        tasks::{TaskCoordinator, TaskPlan, TaskSpec},
        AdmissionDecision,
    };
    use std::cell::Cell;

    struct Caller {
        journal: &'static str,
        may_verify: bool,
        may_publish: bool,
    }

    impl AuthenticatedAuditCaller for Caller {
        fn authorize(
            &self,
            journal_id: &str,
            operation: AuditOperation,
        ) -> Result<(), AnchorError> {
            if journal_id != self.journal {
                return Err(AnchorError::UnauthorizedJournal);
            }
            let allowed = match operation {
                AuditOperation::Verify => self.may_verify,
                AuditOperation::Publish => self.may_publish,
            };
            if allowed {
                Ok(())
            } else {
                Err(AnchorError::Unauthenticated)
            }
        }
    }

    struct Verified {
        anchor: TrustedRecoveryAnchor,
        reads: Cell<u32>,
    }

    impl AuditAnchorVerifier for Verified {
        fn latest_anchor(&self, _: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.anchor)
        }
    }

    struct Store {
        view: AuthorityView,
        reads: u32,
        commits: u32,
    }

    impl EpochGuardedAuthority for Store {
        fn current_view(&self, journal_id: &str) -> Result<AuthorityView, AnchorError> {
            if journal_id != "audit:one" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            Ok(self.view.clone())
        }

        fn publish_if_current(
            &mut self,
            journal_id: &str,
            previous: &AuthorityView,
            next: &TrustedRecoveryAnchor,
        ) -> Result<(), AnchorError> {
            self.reads += 1;
            if journal_id != "audit:one" || self.view != *previous {
                return Err(AnchorError::Stale);
            }
            self.view.anchor = *next;
            self.commits += 1;
            Ok(())
        }
    }

    fn fixture() -> Result<(Store, JournalSnapshot), String> {
        let plan = TaskPlan::build([TaskSpec {
            id: "identity".to_owned(),
            module: "PALACO One".to_owned(),
            dependencies: vec![],
            evidence_ref: "proof:one".to_owned(),
        }])
        .map_err(|error| format!("{error:?}"))?;
        let previous = TrustedRecoveryAnchor {
            generation: 0,
            checkpoint: RecoveryCheckpoint {
                plan_hash: plan_fingerprint(&plan),
                sequence: 0,
                head: [0u8; 32],
            },
        };
        let mut coordinator = TaskCoordinator::new(plan.clone());
        coordinator
            .record("identity", AdmissionDecision::Proposed, "proof:one")
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        Ok((
            Store {
                view: AuthorityView {
                    anchor: previous,
                    active_key_id: "test-key".to_owned(),
                    policy_epoch: 2,
                    revoked: false,
                },
                reads: 0,
                commits: 0,
            },
            JournalSnapshot {
                plan,
                records,
                checkpoint,
            },
        ))
    }

    #[test]
    fn verify_only_caller_cannot_publish() -> Result<(), String> {
        let (mut store, snapshot) = fixture()?;
        let reader = Caller {
            journal: "audit:one",
            may_verify: true,
            may_publish: false,
        };
        let verifier = Verified {
            anchor: store.view.anchor,
            reads: Cell::new(0),
        };
        assert_eq!(
            verify_for_caller(&reader, &verifier, "audit:one")
                .map_err(|error| format!("{error:?}"))?,
            verifier.anchor
        );
        assert_eq!(verifier.reads.get(), 1);
        assert!(matches!(
            publish_for_caller(&reader, &mut store, "audit:one", &snapshot),
            Err(PublishServiceError::Access(AnchorError::Unauthenticated))
        ));
        assert_eq!(store.commits, 0);
        Ok(())
    }

    #[test]
    fn missing_scope_blocks_authority_reads_and_writes() -> Result<(), String> {
        let (mut store, snapshot) = fixture()?;
        let wrong = Caller {
            journal: "audit:other",
            may_verify: true,
            may_publish: true,
        };
        let verifier = Verified {
            anchor: store.view.anchor,
            reads: Cell::new(0),
        };
        assert!(matches!(
            verify_for_caller(&wrong, &verifier, "audit:one"),
            Err(VerifyServiceError::Access(AnchorError::UnauthorizedJournal))
        ));
        assert!(matches!(
            publish_for_caller(&wrong, &mut store, "audit:one", &snapshot),
            Err(PublishServiceError::Access(
                AnchorError::UnauthorizedJournal
            ))
        ));
        assert_eq!(verifier.reads.get(), 0);
        assert_eq!(store.commits, 0);
        Ok(())
    }

    #[test]
    fn authorized_publication_remains_a_nonexecuting_checkpoint() -> Result<(), String> {
        let (mut store, snapshot) = fixture()?;
        let writer = Caller {
            journal: "audit:one",
            may_verify: false,
            may_publish: true,
        };
        let committed = publish_for_caller(&writer, &mut store, "audit:one", &snapshot)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(committed.generation, 1);
        assert_eq!(store.commits, 1);
        assert_eq!(store.view.anchor, committed);
        let verifier = Verified {
            anchor: committed,
            reads: Cell::new(0),
        };
        assert!(matches!(
            verify_for_caller(&writer, &verifier, "audit:one"),
            Err(VerifyServiceError::Access(AnchorError::Unauthenticated))
        ));
        assert_eq!(verifier.reads.get(), 0);
        Ok(())
    }
}
