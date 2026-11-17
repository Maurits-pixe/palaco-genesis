//! PALACO Audit boundary for ORCHEASTRA recovery checkpoints.
//!
//! This adapter asks a separate trusted source for the latest checkpoint
//! before reading a local journal. The audit crate does not sign checkpoints
//! and cannot grant authority to execute a recovered proposal.

/// Local immutable audit checkpoint archive (untrusted without external generation).
pub mod archive;

/// Reconciliation of interrupted or ambiguous audit publication results.
pub mod reconcile;

/// Staged snapshot publication and unanchored-file recovery safeguards.
pub mod staged_commit;

/// Fail-closed monotonic checkpoint publication and prefix integrity contract.
pub mod publish;

/// Scoped HMAC-SHA-256 checkpoint verifier and monotonic-generation boundary.
pub mod mac;

use std::path::Path;

use palaco_runtime::orcheastra::{
    persistence::TrustedRecoveryAnchor,
    snapshot_file::{load_verified_snapshot, SnapshotFileError},
    tasks::TaskCoordinator,
};

/// A failed request for an independently authenticated audit checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// The verifier cannot establish the latest trusted checkpoint.
    Unavailable,
    /// The checkpoint or its signer cannot be authenticated.
    Unauthenticated,
    /// Requested journal is not authorized for this verifier.
    UnauthorizedJournal,
    /// The trusted monotonic generation cannot be established.
    Stale,
}

/// Trusted checkpoint provider implemented only by an audited integration.
///
/// A production implementation MUST authenticate signatures, journal scope,
/// signer identity, policy version, and the latest monotonic generation.
/// It MUST NOT derive its answer from the untrusted snapshot being loaded.
pub trait AuditAnchorVerifier {
    /// Obtain the authenticated latest checkpoint for an exact journal ID.
    fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError>;
}

/// Recovery output remains explicitly non-executable, even if the journal
/// contains historical `AdmissionDecision::Proposed` entries.
#[derive(Debug)]
pub struct AuditRecovery {
    coordinator: TaskCoordinator,
}

impl AuditRecovery {
    /// Inspect recovered, historical decisions without granting permission.
    #[must_use]
    pub fn coordinator(&self) -> &TaskCoordinator {
        &self.coordinator
    }
}

/// Why PALACO Audit denies a recovery attempt.
#[derive(Debug)]
pub enum AuditRecoveryError {
    /// A journal identifier is absent.
    EmptyJournalId,
    /// Trusted audit-verifier failed closed.
    Anchor(AnchorError),
    /// Snapshot file or historical journal failed verification.
    Snapshot(SnapshotFileError),
}

/// Restore only after an independent audit verifier has supplied a checkpoint.
///
/// The caller cannot pass its own checkpoint to this entrypoint. No
/// scheduling, signing, token creation or task execution occurs.
pub fn recover_from_audit<V: AuditAnchorVerifier>(
    verifier: &V,
    journal_id: &str,
    snapshot_path: &Path,
) -> Result<AuditRecovery, AuditRecoveryError> {
    if journal_id.trim().is_empty() {
        return Err(AuditRecoveryError::EmptyJournalId);
    }
    let trusted = verifier
        .latest_anchor(journal_id)
        .map_err(AuditRecoveryError::Anchor)?;
    let coordinator =
        load_verified_snapshot(snapshot_path, &trusted).map_err(AuditRecoveryError::Snapshot)?;
    Ok(AuditRecovery { coordinator })
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_runtime::orcheastra::{
        persistence::JournalSnapshot,
        recovery::export_checkpoint,
        snapshot_file::stage_snapshot,
        tasks::{TaskPlan, TaskSpec},
        AdmissionDecision,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct FixtureVerifier {
        anchor: Option<TrustedRecoveryAnchor>,
    }

    impl AuditAnchorVerifier for FixtureVerifier {
        fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
            if journal_id != "orcheastra:test" {
                return Err(AnchorError::UnauthorizedJournal);
            }
            self.anchor.ok_or(AnchorError::Unavailable)
        }
    }

    fn snapshot() -> Result<JournalSnapshot, String> {
        let plan = TaskPlan::build([TaskSpec {
            id: "identity".to_owned(),
            module: "PALACO One".to_owned(),
            dependencies: vec![],
            evidence_ref: "proof:identity".to_owned(),
        }])
        .map_err(|error| format!("{error:?}"))?;
        let mut coordinator = TaskCoordinator::new(plan.clone());
        coordinator
            .record("identity", AdmissionDecision::Proposed, "proof:identity")
            .map_err(|error| format!("{error:?}"))?;
        let (checkpoint, records) =
            export_checkpoint(&coordinator).map_err(|error| format!("{error:?}"))?;
        Ok(JournalSnapshot {
            plan,
            records,
            checkpoint,
        })
    }

    #[test]
    fn missing_anchor_and_empty_journal_are_blocked() {
        let verifier = FixtureVerifier { anchor: None };
        assert!(matches!(
            recover_from_audit(&verifier, "", Path::new("missing")),
            Err(AuditRecoveryError::EmptyJournalId)
        ));
        assert!(matches!(
            recover_from_audit(&verifier, "orcheastra:test", Path::new("missing")),
            Err(AuditRecoveryError::Anchor(AnchorError::Unavailable))
        ));
        assert!(matches!(
            recover_from_audit(&verifier, "other", Path::new("missing")),
            Err(AuditRecoveryError::Anchor(AnchorError::UnauthorizedJournal))
        ));
    }

    #[test]
    fn external_anchor_restores_history_without_executing() -> Result<(), String> {
        let source = snapshot()?;
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let folder = std::env::temp_dir().join(format!(
            "palaco-audit-orcheastra-{}-{sequence}",
            std::process::id()
        ));
        let path = stage_snapshot(&folder, 4, &source, &source.checkpoint)
            .map_err(|error| format!("{error:?}"))?;
        let verifier = FixtureVerifier {
            anchor: Some(TrustedRecoveryAnchor {
                generation: 4,
                checkpoint: source.checkpoint,
            }),
        };
        let recovered = recover_from_audit(&verifier, "orcheastra:test", &path)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(recovered.coordinator().entries().len(), 1);
        assert_eq!(
            recovered.coordinator().entries()[0].decision,
            AdmissionDecision::Proposed
        );
        fs::remove_dir_all(folder).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn wrong_generation_is_rejected() -> Result<(), String> {
        let source = snapshot()?;
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let folder = std::env::temp_dir().join(format!(
            "palaco-audit-orcheastra-{}-{sequence}",
            std::process::id()
        ));
        let path = stage_snapshot(&folder, 4, &source, &source.checkpoint)
            .map_err(|error| format!("{error:?}"))?;
        let verifier = FixtureVerifier {
            anchor: Some(TrustedRecoveryAnchor {
                generation: 5,
                checkpoint: source.checkpoint,
            }),
        };
        assert!(matches!(
            recover_from_audit(&verifier, "orcheastra:test", &path),
            Err(AuditRecoveryError::Snapshot(_))
        ));
        fs::remove_dir_all(folder).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }
}
