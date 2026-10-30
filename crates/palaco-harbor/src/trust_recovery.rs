//! Monotone trust-state journal and crash-recovery reference contract.
//!
//! A journal implementation MUST durably sync each append and independently
//! attest its integrity. This module provides no filesystem backend, hardware
//! anti-rollback anchor, signature authentication or production authorization.

use std::collections::BTreeSet;

/// A full state record after one committed trust transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustFrame {
    pub sequence: u64,
    pub trust_epoch: u64,
    pub highest_trusted_time_ms: u64,
    pub revoked_keys: BTreeSet<String>,
}

/// A separately authenticated recovery floor. It cannot safely be obtained
/// from the same rollbackable journal that is being recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFloor {
    pub minimum_sequence: u64,
    pub minimum_trust_epoch: u64,
    pub minimum_trusted_time_ms: u64,
}

/// A durable append may have happened even if its acknowledgement was lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    Unavailable,
    UncertainCompletion,
    Corrupt,
}

/// Only implementations with atomic append, fsync and trusted integrity
/// validation may be considered for production.
pub trait TrustJournal {
    fn load(&self) -> Result<Vec<TrustFrame>, JournalError>;
    fn append_sync(&mut self, frame: &TrustFrame) -> Result<(), JournalError>;
}

/// No transition grants trust when storage or recovery is uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    Journal(JournalError),
    MissingGenesis,
    SequenceGap,
    StateRollback,
    MissingExternalAnchor,
    Overflow,
    InvalidRevocation,
}

/// One independently proposed monotone transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustTransition {
    AdvanceTime(u64),
    AdvanceEpoch(u64),
    Revoke(String),
}

/// Replay the journal without making any mutable or authorization decision.
///
/// Each frame must retain earlier revocations. Strictly sequential records
/// detect truncation within a visible chain; only an independent floor can
/// detect replacement with an older, otherwise well-formed chain.
pub fn recover<J: TrustJournal>(
    journal: &J,
    floor: RecoveryFloor,
) -> Result<TrustFrame, RecoveryError> {
    let frames = journal.load().map_err(RecoveryError::Journal)?;
    recover_frames(&frames, floor)
}

/// Recover a single, immutable in-memory snapshot of journal frames.
///
/// This prevents a verifier from checking monotonicity against one read and
/// authenticating a different read after a concurrent storage mutation.
pub fn recover_frames(
    frames: &[TrustFrame],
    floor: RecoveryFloor,
) -> Result<TrustFrame, RecoveryError> {
    if floor.minimum_sequence == 0
        || floor.minimum_trust_epoch == 0
        || floor.minimum_trusted_time_ms == 0
    {
        return Err(RecoveryError::MissingExternalAnchor);
    }

    let (first, rest) = frames.split_first().ok_or(RecoveryError::MissingGenesis)?;
    if first.sequence != 1 || first.trust_epoch == 0 || first.highest_trusted_time_ms == 0 {
        return Err(RecoveryError::MissingGenesis);
    }

    let mut previous = first;
    for current in rest {
        let next = previous
            .sequence
            .checked_add(1)
            .ok_or(RecoveryError::Overflow)?;
        if current.sequence != next {
            return Err(RecoveryError::SequenceGap);
        }
        if current.trust_epoch < previous.trust_epoch
            || current.highest_trusted_time_ms < previous.highest_trusted_time_ms
            || !previous.revoked_keys.is_subset(&current.revoked_keys)
        {
            return Err(RecoveryError::StateRollback);
        }
        previous = current;
    }

    if previous.sequence < floor.minimum_sequence
        || previous.trust_epoch < floor.minimum_trust_epoch
        || previous.highest_trusted_time_ms < floor.minimum_trusted_time_ms
    {
        return Err(RecoveryError::StateRollback);
    }
    Ok(previous.clone())
}

/// Persist exactly one transition after independently checked recovery.
///
/// An error, including an ambiguous fsync acknowledgement, returns no
/// supposedly committed state. Reload and reconcile with the external anchor
/// before any retry; never blindly append the same transition.
pub fn persist_transition<J: TrustJournal>(
    journal: &mut J,
    floor: RecoveryFloor,
    transition: TrustTransition,
) -> Result<TrustFrame, RecoveryError> {
    let mut next = recover(journal, floor)?;
    next.sequence = next
        .sequence
        .checked_add(1)
        .ok_or(RecoveryError::Overflow)?;

    match transition {
        TrustTransition::AdvanceTime(value) => {
            if value < next.highest_trusted_time_ms {
                return Err(RecoveryError::StateRollback);
            }
            next.highest_trusted_time_ms = value;
        }
        TrustTransition::AdvanceEpoch(value) => {
            if value < next.trust_epoch {
                return Err(RecoveryError::StateRollback);
            }
            next.trust_epoch = value;
        }
        TrustTransition::Revoke(key) => {
            if key.is_empty() {
                return Err(RecoveryError::InvalidRevocation);
            }
            next.revoked_keys.insert(key);
        }
    }

    journal.append_sync(&next).map_err(RecoveryError::Journal)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::{
        persist_transition, recover, JournalError, RecoveryError, RecoveryFloor, TrustFrame,
        TrustJournal, TrustTransition,
    };
    use std::collections::BTreeSet;

    #[derive(Clone)]
    struct ScriptedJournal {
        frames: Vec<TrustFrame>,
        fail_load: Option<JournalError>,
        append_behavior: AppendBehavior,
    }

    #[derive(Clone, Copy)]
    enum AppendBehavior {
        Confirm,
        FailBeforeWrite,
        WriteThenLoseAck,
    }

    impl TrustJournal for ScriptedJournal {
        fn load(&self) -> Result<Vec<TrustFrame>, JournalError> {
            match self.fail_load {
                Some(error) => Err(error),
                None => Ok(self.frames.clone()),
            }
        }

        fn append_sync(&mut self, frame: &TrustFrame) -> Result<(), JournalError> {
            match self.append_behavior {
                AppendBehavior::Confirm => {
                    self.frames.push(frame.clone());
                    Ok(())
                }
                AppendBehavior::FailBeforeWrite => Err(JournalError::Unavailable),
                AppendBehavior::WriteThenLoseAck => {
                    self.frames.push(frame.clone());
                    Err(JournalError::UncertainCompletion)
                }
            }
        }
    }

    fn genesis() -> TrustFrame {
        TrustFrame {
            sequence: 1,
            trust_epoch: 5,
            highest_trusted_time_ms: 100,
            revoked_keys: BTreeSet::new(),
        }
    }

    fn floor() -> RecoveryFloor {
        RecoveryFloor {
            minimum_sequence: 1,
            minimum_trust_epoch: 5,
            minimum_trusted_time_ms: 100,
        }
    }

    fn journal() -> ScriptedJournal {
        ScriptedJournal {
            frames: vec![genesis()],
            fail_load: None,
            append_behavior: AppendBehavior::Confirm,
        }
    }

    #[test]
    fn monotone_time_epoch_and_revocation_survive_replay() {
        let mut storage = journal();
        assert!(
            persist_transition(&mut storage, floor(), TrustTransition::AdvanceTime(150)).is_ok()
        );
        assert!(
            persist_transition(&mut storage, floor(), TrustTransition::AdvanceEpoch(6)).is_ok()
        );
        let last = persist_transition(
            &mut storage,
            floor(),
            TrustTransition::Revoke("key-7".to_owned()),
        );
        assert!(last.is_ok());
        let restarted = storage.clone();
        let recovered = recover(&restarted, floor());
        assert!(recovered.is_ok());
        if let Ok(frame) = recovered {
            assert_eq!(frame.sequence, 4);
            assert_eq!(frame.trust_epoch, 6);
            assert_eq!(frame.highest_trusted_time_ms, 150);
            assert!(frame.revoked_keys.contains("key-7"));
        }
    }

    #[test]
    fn crash_before_append_does_not_advance_state() {
        let mut storage = journal();
        storage.append_behavior = AppendBehavior::FailBeforeWrite;
        assert_eq!(
            persist_transition(&mut storage, floor(), TrustTransition::AdvanceTime(150)),
            Err(RecoveryError::Journal(JournalError::Unavailable))
        );
        assert_eq!(recover(&storage, floor()), Ok(genesis()));
    }

    #[test]
    fn lost_ack_never_reports_success_but_replay_can_find_write() {
        let mut storage = journal();
        storage.append_behavior = AppendBehavior::WriteThenLoseAck;
        assert_eq!(
            persist_transition(
                &mut storage,
                floor(),
                TrustTransition::Revoke("key-7".to_owned())
            ),
            Err(RecoveryError::Journal(JournalError::UncertainCompletion))
        );
        let recovered = recover(&storage, floor());
        assert!(recovered.is_ok());
        if let Ok(frame) = recovered {
            assert!(frame.revoked_keys.contains("key-7"));
            assert_eq!(frame.sequence, 2);
        }
    }

    #[test]
    fn externally_anchored_floor_detects_old_snapshot_restore() {
        let older = journal();
        let new_floor = RecoveryFloor {
            minimum_sequence: 2,
            minimum_trust_epoch: 5,
            minimum_trusted_time_ms: 150,
        };
        assert_eq!(
            recover(&older, new_floor),
            Err(RecoveryError::StateRollback)
        );
    }

    #[test]
    fn gaps_and_backward_values_fail_closed() {
        let mut storage = journal();
        let mut bad = genesis();
        bad.sequence = 3;
        storage.frames.push(bad);
        assert_eq!(recover(&storage, floor()), Err(RecoveryError::SequenceGap));

        storage.frames[1].sequence = 2;
        storage.frames[1].trust_epoch = 4;
        assert_eq!(
            recover(&storage, floor()),
            Err(RecoveryError::StateRollback)
        );

        storage.frames[1].trust_epoch = 5;
        storage.frames[1].highest_trusted_time_ms = 99;
        assert_eq!(
            recover(&storage, floor()),
            Err(RecoveryError::StateRollback)
        );
    }

    #[test]
    fn revoked_identity_cannot_disappear_in_next_frame() {
        let mut storage = journal();
        storage.frames[0].revoked_keys.insert("key-7".to_owned());
        let mut next = genesis();
        next.sequence = 2;
        storage.frames.push(next);
        assert_eq!(
            recover(&storage, floor()),
            Err(RecoveryError::StateRollback)
        );
    }

    #[test]
    fn invalid_anchor_load_and_transition_fail_closed() {
        let mut storage = journal();
        assert_eq!(
            recover(
                &storage,
                RecoveryFloor {
                    minimum_sequence: 0,
                    ..floor()
                }
            ),
            Err(RecoveryError::MissingExternalAnchor)
        );
        storage.fail_load = Some(JournalError::Corrupt);
        assert_eq!(
            recover(&storage, floor()),
            Err(RecoveryError::Journal(JournalError::Corrupt))
        );
        storage.fail_load = None;
        assert_eq!(
            persist_transition(&mut storage, floor(), TrustTransition::AdvanceTime(99)),
            Err(RecoveryError::StateRollback)
        );
        assert_eq!(
            persist_transition(
                &mut storage,
                floor(),
                TrustTransition::Revoke(String::new())
            ),
            Err(RecoveryError::InvalidRevocation)
        );
        assert_eq!(storage.frames.len(), 1);
    }
}
