//! Compare-and-swap governance checkpoint publication contract.
//!
//! This is a protocol and scripted test adapter, NOT a deployed independent
//! anti-rollback store. Store integrity, governance authorization, signatures,
//! durable atomicity and time must be provided and audited independently.
//! A successful CAS is no Harbor admission, execution or release permission.

use std::collections::BTreeSet;

/// Whole published checkpoint policy, treated as untrusted until authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRecord {
    pub revision: u64,
    pub signer_epoch: u64,
    pub sequence: u64,
    pub chain_digest: [u8; 32],
    pub signer_id: String,
    pub retired_signers: BTreeSet<String>,
}

/// The storage backend must compare against the exact expected record and
/// atomically publish one new version after durable persistence.
pub trait AtomicAnchorStore {
    fn load(&self) -> Result<AnchorRecord, StoreError>;
    fn compare_and_swap(
        &mut self,
        expected: &AnchorRecord,
        next: &AnchorRecord,
    ) -> Result<SwapOutcome, StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Unavailable,
    UncertainCompletion,
    IntegrityUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapOutcome {
    Committed,
    Conflict,
}

/// Reasons a transition is held before a storage write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    Store(StoreError),
    Conflict,
    InvalidCurrent,
    InvalidSuccessor,
    RevisionOverflow,
}

/// Proposed complete successor; revocations must be carried forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorProposal {
    pub signer_epoch: u64,
    pub sequence: u64,
    pub chain_digest: [u8; 32],
    pub signer_id: String,
    pub retired_signers: BTreeSet<String>,
}

fn id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

/// Structural validation shared by checkpoint adapters before trust verification.
pub(crate) fn record_is_valid(record: &AnchorRecord) -> bool {
    record.revision != 0
        && record.signer_epoch != 0
        && record.sequence != 0
        && id_valid(&record.signer_id)
        && !record.retired_signers.contains(&record.signer_id)
        && record.retired_signers.iter().all(|id| id_valid(id))
}

/// Publish through one independently governed atomic CAS operation.
///
/// On uncertain completion, do NOT return success, reuse a stale snapshot, or
/// blindly retry: reload from the independent backend and reconcile manually.
pub fn publish_next<S: AtomicAnchorStore>(
    store: &mut S,
    proposal: AnchorProposal,
) -> Result<AnchorRecord, PublishError> {
    let current = store.load().map_err(PublishError::Store)?;
    if !record_valid(&current) {
        return Err(PublishError::InvalidCurrent);
    }
    if proposal.signer_epoch < current.signer_epoch
        || proposal.sequence < current.sequence
        || !id_valid(&proposal.signer_id)
        || proposal.retired_signers.iter().any(|id| !id_valid(id))
        || !current.retired_signers.is_subset(&proposal.retired_signers)
        || proposal.retired_signers.contains(&proposal.signer_id)
    {
        return Err(PublishError::InvalidSuccessor);
    }

    // A rotation must advance the epoch and permanently retire the old signer.
    if proposal.signer_id != current.signer_id
        && (proposal.signer_epoch <= current.signer_epoch
            || !proposal.retired_signers.contains(&current.signer_id))
    {
        return Err(PublishError::InvalidSuccessor);
    }
    // No arbitrary rewrite at the same sequence (including digest rewrite).
    if proposal.sequence == current.sequence && proposal.chain_digest != current.chain_digest {
        return Err(PublishError::InvalidSuccessor);
    }
    // A changed digest must advance the sequence. An epoch-only rotation may
    // retain the chain digest and sequence.
    if proposal.sequence > current.sequence && proposal.chain_digest == current.chain_digest {
        return Err(PublishError::InvalidSuccessor);
    }
    // Prevent identical, no-op records from being republished.
    if proposal.sequence == current.sequence
        && proposal.signer_epoch == current.signer_epoch
        && proposal.signer_id == current.signer_id
        && proposal.retired_signers == current.retired_signers
    {
        return Err(PublishError::InvalidSuccessor);
    }

    let next = AnchorRecord {
        revision: current
            .revision
            .checked_add(1)
            .ok_or(PublishError::RevisionOverflow)?,
        signer_epoch: proposal.signer_epoch,
        sequence: proposal.sequence,
        chain_digest: proposal.chain_digest,
        signer_id: proposal.signer_id,
        retired_signers: proposal.retired_signers,
    };
    match store.compare_and_swap(&current, &next) {
        Ok(SwapOutcome::Committed) => Ok(next),
        Ok(SwapOutcome::Conflict) => Err(PublishError::Conflict),
        Err(error) => Err(PublishError::Store(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        publish_next, AnchorProposal, AnchorRecord, AtomicAnchorStore, PublishError, StoreError,
        SwapOutcome,
    };
    use std::collections::BTreeSet;

    struct ScriptedStore {
        state: AnchorRecord,
        error: Option<StoreError>,
        race: bool,
        lose_ack: bool,
    }

    impl AtomicAnchorStore for ScriptedStore {
        fn load(&self) -> Result<AnchorRecord, StoreError> {
            match self.error {
                Some(error) => Err(error),
                None => Ok(self.state.clone()),
            }
        }

        fn compare_and_swap(
            &mut self,
            expected: &AnchorRecord,
            next: &AnchorRecord,
        ) -> Result<SwapOutcome, StoreError> {
            if self.race || self.state != *expected {
                return Ok(SwapOutcome::Conflict);
            }
            self.state = next.clone();
            if self.lose_ack {
                Err(StoreError::UncertainCompletion)
            } else {
                Ok(SwapOutcome::Committed)
            }
        }
    }

    fn store() -> ScriptedStore {
        ScriptedStore {
            state: AnchorRecord {
                revision: 1,
                signer_epoch: 5,
                sequence: 2,
                chain_digest: [1; 32],
                signer_id: "signer-a".to_owned(),
                retired_signers: BTreeSet::new(),
            },
            error: None,
            race: false,
            lose_ack: false,
        }
    }

    fn proposal() -> AnchorProposal {
        AnchorProposal {
            signer_epoch: 6,
            sequence: 2,
            chain_digest: [1; 32],
            signer_id: "signer-b".to_owned(),
            retired_signers: BTreeSet::from(["signer-a".to_owned()]),
        }
    }

    #[test]
    fn rotation_advances_epoch_and_retires_prior_signer() {
        let mut state = store();
        let result = publish_next(&mut state, proposal());
        assert!(matches!(result, Ok(ref value) if value.revision == 2));
        assert_eq!(state.state.signer_id, "signer-b");
        assert!(state.state.retired_signers.contains("signer-a"));
    }

    #[test]
    fn old_or_resurrected_signer_is_denied() {
        let mut state = store();
        let mut invalid = proposal();
        invalid.signer_epoch = 5;
        assert_eq!(
            publish_next(&mut state, invalid),
            Err(PublishError::InvalidSuccessor)
        );
        let _ = publish_next(&mut state, proposal());
        let resurrect = AnchorProposal {
            signer_epoch: 7,
            signer_id: "signer-a".to_owned(),
            retired_signers: state.state.retired_signers.clone(),
            ..proposal()
        };
        assert_eq!(
            publish_next(&mut state, resurrect),
            Err(PublishError::InvalidSuccessor)
        );
    }

    #[test]
    fn digest_rewrite_and_revocation_rollback_are_denied() {
        let mut state = store();
        let mut invalid = proposal();
        invalid.chain_digest = [9; 32];
        assert_eq!(
            publish_next(&mut state, invalid),
            Err(PublishError::InvalidSuccessor)
        );
        let _ = publish_next(&mut state, proposal());
        let mut invalid = proposal();
        invalid.signer_epoch = 7;
        invalid.signer_id = "signer-c".to_owned();
        invalid.retired_signers.clear();
        assert_eq!(
            publish_next(&mut state, invalid),
            Err(PublishError::InvalidSuccessor)
        );
    }

    #[test]
    fn race_does_not_overwrite_other_writer() {
        let mut state = store();
        state.race = true;
        assert_eq!(
            publish_next(&mut state, proposal()),
            Err(PublishError::Conflict)
        );
        assert_eq!(state.state.revision, 1);
    }

    #[test]
    fn ambiguous_ack_never_reports_success_or_blindly_retries() {
        let mut state = store();
        state.lose_ack = true;
        assert_eq!(
            publish_next(&mut state, proposal()),
            Err(PublishError::Store(StoreError::UncertainCompletion))
        );
        assert_eq!(state.state.revision, 2);
        assert_eq!(
            publish_next(&mut state, proposal()),
            Err(PublishError::InvalidSuccessor)
        );
    }

    #[test]
    fn unavailable_backend_fails_closed() {
        let mut state = store();
        state.error = Some(StoreError::Unavailable);
        assert_eq!(
            publish_next(&mut state, proposal()),
            Err(PublishError::Store(StoreError::Unavailable))
        );
    }
}
