//! Epoch-bound transactional publication contract for ORCHEASTRA audit.
//!
//! A database backend MUST atomically compare the full previous anchor,
//! key identity, revocation epoch and journal scope while appending its
//! audit history. This protocol never signs, authenticates or executes tasks.

use palaco_runtime::orcheastra::{
    persistence::{JournalSnapshot, TrustedRecoveryAnchor},
};

use super::{
    publish::{prepare_publication, PublishError},
    AnchorError,
};

/// Verified authority view to be compared with a later transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityView {
    /// Exact latest journal checkpoint, supplied by a trusted backend.
    pub anchor: TrustedRecoveryAnchor,
    /// Current pinned key identifier for this journal.
    pub active_key_id: String,
    /// Monotonic key-policy revision, incremented on revocation/rotation.
    pub policy_epoch: u64,
    /// Policy has not revoked this key.
    pub revoked: bool,
}

/// Transactional storage service; it must enforce its own authentication.
///
/// The backend MUST hold a consistent database lock/transaction over the
/// current anchor, key policy and ledger append, rather than trusting an
/// old `AuthorityView` obtained before a race.
pub trait EpochGuardedAuthority {
    /// Obtain a journal-scoped, authenticated state view.
    fn current_view(&self, journal_id: &str) -> Result<AuthorityView, AnchorError>;

    /// Atomically compare and publish the next anchor and journal ledger row.
    ///
    /// Backend checks all `expected` values and rejects a revoked key,
    /// including changes occurring after `current_view`.
    fn publish_if_current(
        &mut self,
        journal_id: &str,
        expected: &AuthorityView,
        next: &TrustedRecoveryAnchor,
    ) -> Result<(), AnchorError>;
}

/// Errors that prohibit an epoch-guarded checkpoint publication.
#[derive(Debug)]
pub enum TransactionError {
    /// Journal not authorized, key revoked or backend unavailable.
    Authority(AnchorError),
    /// Candidate is not a strictly valid continuation of audit history.
    Proposal(PublishError),
}

/// Prepare a valid extension, then request an epoch-guarded atomic CAS.
///
/// This is an adapter for a trusted service: a successful return is only
/// proof of accepted audit publication, NOT permission to execute tasks.
pub fn publish_with_epoch<A: EpochGuardedAuthority>(
    authority: &mut A,
    journal_id: &str,
    candidate: &JournalSnapshot,
) -> Result<TrustedRecoveryAnchor, TransactionError> {
    if journal_id.trim().is_empty() {
        return Err(TransactionError::Authority(
            AnchorError::UnauthorizedJournal,
        ));
    }
    let view = authority
        .current_view(journal_id)
        .map_err(TransactionError::Authority)?;
    if view.active_key_id.trim().is_empty() || view.revoked {
        return Err(TransactionError::Authority(
            AnchorError::Unauthenticated,
        ));
    }
    let proposal =
        prepare_publication(&view.anchor, candidate).map_err(TransactionError::Proposal)?;
    authority
        .publish_if_current(journal_id, &view, &proposal.next)
        .map_err(TransactionError::Authority)?;
    Ok(proposal.next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_runtime::orcheastra::{
        recovery::{export_checkpoint, plan_fingerprint, RecoveryCheckpoint},
        tasks::{TaskCoordinator, TaskPlan, TaskSpec},
        AdmissionDecision,
    };

    fn fixture() -> Result<(AuthorityView, JournalSnapshot), String> {
        let plan = TaskPlan::build([TaskSpec {
            id: "one".to_owned(),
            module: "PALACO One".to_owned(),
            dependencies: vec![],
            evidence_ref: "proof:one".to_owned(),
        }])
        .map_err(|error| format!("{error:?}"))?;
        let anchor = TrustedRecoveryAnchor {
            generation: 0,
            checkpoint: RecoveryCheckpoint {
                plan_hash: plan_fingerprint(&plan),
                sequence: 0,
                head: [0u8; 32],
            },
        };
        let mut coordinator = TaskCoordinator::new(plan.clone());
        coordinator
            .record("one", AdmissionDecision::Proposed, "proof:one")
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        Ok((
            AuthorityView {
                anchor,
                active_key_id: "key-v1".to_owned(),
                policy_epoch: 3,
                revoked: false,
            },
            JournalSnapshot {
                plan,
                records,
                checkpoint,
            },
        ))
    }

    // Simulated transaction backend. A real PostgreSQL service MUST perform
    // CAS+ledger append in one database transaction and protect credentials.
    struct Backend {
        live: AuthorityView,
        revise_before_commit: bool,
        published: Vec<TrustedRecoveryAnchor>,
    }

    impl EpochGuardedAuthority for Backend {
        fn current_view(&self, journal_id: &str) -> Result<AuthorityView, AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            Ok(self.live.clone())
        }

        fn publish_if_current(
            &mut self,
            journal_id: &str,
            expected: &AuthorityView,
            next: &TrustedRecoveryAnchor,
        ) -> Result<(), AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            if self.revise_before_commit {
                self.live.policy_epoch += 1;
                self.live.revoked = true;
            }
            if self.live != *expected || self.live.revoked {
                return Err(AnchorError::Stale);
            }
            self.live.anchor = *next;
            self.published.push(*next);
            Ok(())
        }
    }

    #[test]
    fn one_transaction_updates_anchor_and_ledger() -> Result<(), String> {
        let (view, snapshot) = fixture()?;
        let mut backend = Backend {
            live: view,
            revise_before_commit: false,
            published: Vec::new(),
        };
        let anchor = publish_with_epoch(&mut backend, "orcheastra:test", &snapshot)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(anchor.generation, 1);
        assert_eq!(backend.published, vec![anchor]);
        assert_eq!(backend.live.anchor, anchor);
        assert!(matches!(
            publish_with_epoch(&mut backend, "orcheastra:test", &snapshot),
            Err(TransactionError::Proposal(PublishError::NotExtended))
        ));
        Ok(())
    }

    #[test]
    fn revocation_race_rejects_entire_transaction() -> Result<(), String> {
        let (view, snapshot) = fixture()?;
        let mut backend = Backend {
            live: view.clone(),
            revise_before_commit: true,
            published: Vec::new(),
        };
        assert!(matches!(
            publish_with_epoch(&mut backend, "orcheastra:test", &snapshot),
            Err(TransactionError::Authority(AnchorError::Stale))
        ));
        assert_eq!(backend.live.anchor, view.anchor);
        assert!(backend.published.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_journal_and_already_revoked_key_fail_closed() -> Result<(), String> {
        let (mut view, snapshot) = fixture()?;
        view.revoked = true;
        let mut backend = Backend {
            live: view,
            revise_before_commit: false,
            published: Vec::new(),
        };
        assert!(matches!(
            publish_with_epoch(&mut backend, "orcheastra:test", &snapshot),
            Err(TransactionError::Authority(AnchorError::Unauthenticated))
        ));
        assert!(matches!(
            publish_with_epoch(&mut backend, "", &snapshot),
            Err(TransactionError::Authority(AnchorError::UnauthorizedJournal))
        ));
        assert!(backend.published.is_empty());
        Ok(())
    }
}
