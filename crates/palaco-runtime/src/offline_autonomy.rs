//! Conservative offline action classifications for ORCHEASTRA.
//!
//! This policy distinguishes useful local work from protected execution.
//! It neither persists data nor authorizes mutation, issuance, or sync.

/// Action requested while disconnected from trusted online services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineAction {
    /// Display local cached information with its freshness label.
    ReadCached,
    /// Create or edit a device-local draft without authoritative state change.
    EditLocalDraft,
    /// Stage an untrusted proposal for later online revalidation.
    StageIntent,
    /// Change protected system or world state.
    ExecuteProtectedMutation,
    /// Issue or renew an authority or identity credential.
    IssueAuthority,
}

/// Conservative result of offline action classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineDecision {
    /// Local-only interaction may proceed; it proves no data freshness.
    AllowLocal,
    /// Proposal may be staged but must never execute before later checks.
    StageWithoutAuthority,
    /// Operation cannot proceed without fresh trusted authorization.
    Hold,
}

/// Classifies offline actions without creating authority.
///
/// The caller is responsible for local durability, encryption, integrity,
/// stale-data labeling and eventual reconciliation. No returned value may
/// be used as authorization for network or protected state mutations.
#[must_use]
pub fn classify_offline_action(action: OfflineAction) -> OfflineDecision {
    match action {
        OfflineAction::ReadCached | OfflineAction::EditLocalDraft => {
            OfflineDecision::AllowLocal
        }
        OfflineAction::StageIntent => OfflineDecision::StageWithoutAuthority,
        OfflineAction::ExecuteProtectedMutation | OfflineAction::IssueAuthority => {
            OfflineDecision::Hold
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_offline_action, OfflineAction, OfflineDecision};

    #[test]
    fn cached_data_may_be_viewed_locally() {
        assert_eq!(
            classify_offline_action(OfflineAction::ReadCached),
            OfflineDecision::AllowLocal
        );
    }

    #[test]
    fn local_draft_may_be_edited() {
        assert_eq!(
            classify_offline_action(OfflineAction::EditLocalDraft),
            OfflineDecision::AllowLocal
        );
    }

    #[test]
    fn staged_intent_does_not_receive_authority() {
        assert_eq!(
            classify_offline_action(OfflineAction::StageIntent),
            OfflineDecision::StageWithoutAuthority
        );
    }

    #[test]
    fn protected_mutation_is_held_offline() {
        assert_eq!(
            classify_offline_action(OfflineAction::ExecuteProtectedMutation),
            OfflineDecision::Hold
        );
    }

    #[test]
    fn authority_issuance_is_held_offline() {
        assert_eq!(
            classify_offline_action(OfflineAction::IssueAuthority),
            OfflineDecision::Hold
        );
    }
}
