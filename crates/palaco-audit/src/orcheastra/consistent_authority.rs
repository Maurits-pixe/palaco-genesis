//! Single-authority, journal-scoped checkpoint verification boundary.
//!
//! The authoritative service MUST assess the latest generation, key policy,
//! revocation and MAC against one consistent state view. Separate reads of
//! two independent authorities do not provide that guarantee. This file
//! defines the integration contract; no production service is deployed.

use palaco_runtime::orcheastra::persistence::TrustedRecoveryAnchor;

use super::{
    mac::{MacCheckpoint, MacCheckpointSource},
    AnchorError, AuditAnchorVerifier,
};

/// Independent authority required to check the complete proof consistently.
///
/// An implementation MUST authenticate caller and journal scope, use a
/// linearizable view of generation, signing key policy and revocations,
/// verify the MAC internally, and return the anchor only if it is current.
/// Unknown keys, policy changes, stale generations and unavailable state
/// must fail closed. Key material must not be obtained from `record`.
pub trait ConsistentAuditAuthority {
    /// Verify an untrusted candidate using one authoritative state view.
    fn verify_current(
        &self,
        journal_id: &str,
        record: &MacCheckpoint,
    ) -> Result<TrustedRecoveryAnchor, AnchorError>;
}

/// Read-only adapter for a consistent, externally authenticated authority.
///
/// It pins the untrusted checkpoint before entering the authority boundary,
/// which must provide the atomic policy/generation/MAC verification itself.
/// No scheduling or task execution API is exposed here.
pub struct ConsistentAnchorVerifier<'a, S, A> {
    /// Transport of untrusted audit checkpoint records.
    pub source: &'a S,
    /// Separately trusted service with consistent security-state reads.
    pub authority: &'a A,
}

impl<S: MacCheckpointSource, A: ConsistentAuditAuthority> AuditAnchorVerifier
    for ConsistentAnchorVerifier<'_, S, A>
{
    fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
        if journal_id.trim().is_empty() {
            return Err(AnchorError::UnauthorizedJournal);
        }
        let record = self.source.checkpoint(journal_id)?;
        if record.journal_id != journal_id || record.key_id.trim().is_empty() {
            return Err(AnchorError::Unauthenticated);
        }
        self.authority.verify_current(journal_id, &record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::mac::{
        authenticate_checkpoint, GenerationAuthority, HmacAnchorVerifier, MAC_FORMAT_VERSION,
    };
    use palaco_runtime::orcheastra::recovery::RecoveryCheckpoint;
    use std::cell::{Cell, RefCell};

    const SECRET: [u8; 32] = [0x79; 32];

    struct Source {
        record: MacCheckpoint,
        reads: Cell<u32>,
    }

    impl MacCheckpointSource for Source {
        fn checkpoint(&self, _: &str) -> Result<MacCheckpoint, AnchorError> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.record.clone())
        }
    }

    // The fixture's single RefCell borrow models a consistent read lock.
    // It is NOT a trusted or durable service, a multi-process database or
    // production secret storage.
    struct SecurityState {
        generation: u64,
        revoked: bool,
        active_key: &'static str,
        secret: [u8; 32],
    }

    struct FixtureAuthority {
        state: RefCell<SecurityState>,
        available: Cell<bool>,
    }

    struct Pinned(MacCheckpoint);

    impl MacCheckpointSource for Pinned {
        fn checkpoint(&self, _: &str) -> Result<MacCheckpoint, AnchorError> {
            Ok(self.0.clone())
        }
    }

    struct HighWater(u64);

    impl GenerationAuthority for HighWater {
        fn latest_generation(&self, _: &str) -> Result<u64, AnchorError> {
            Ok(self.0)
        }
    }

    impl ConsistentAuditAuthority for FixtureAuthority {
        fn verify_current(
            &self,
            journal_id: &str,
            record: &MacCheckpoint,
        ) -> Result<TrustedRecoveryAnchor, AnchorError> {
            if !self.available.get() {
                return Err(AnchorError::Unavailable);
            }
            let current = self.state.borrow();
            if journal_id != "orcheastra:test"
                || record.journal_id != journal_id
                || record.version != MAC_FORMAT_VERSION
                || record.key_id != current.active_key
                || current.revoked
            {
                return Err(AnchorError::Unauthenticated);
            }
            // All checks, including the MAC, take place while one state
            // borrow is held; a production service must offer equivalent
            // cross-process consistency and true key isolation.
            let pinned = Pinned(record.clone());
            let generation = HighWater(current.generation);
            let verifier = HmacAnchorVerifier {
                source: &pinned,
                generations: &generation,
                key_id: current.active_key,
                key: &current.secret,
            };
            verifier.latest_anchor(journal_id)
        }
    }

    fn record(generation: u64) -> MacCheckpoint {
        let anchor = TrustedRecoveryAnchor {
            generation,
            checkpoint: RecoveryCheckpoint {
                plan_hash: [1u8; 32],
                sequence: 2,
                head: [3u8; 32],
            },
        };
        authenticate_checkpoint("orcheastra:test", "key-v1", anchor, &SECRET)
    }

    fn authority(generation: u64) -> FixtureAuthority {
        FixtureAuthority {
            state: RefCell::new(SecurityState {
                generation,
                revoked: false,
                active_key: "key-v1",
                secret: SECRET,
            }),
            available: Cell::new(true),
        }
    }

    #[test]
    fn consistent_view_accepts_valid_record_once() {
        let source = Source {
            record: record(4),
            reads: Cell::new(0),
        };
        let authority = authority(4);
        let verifier = ConsistentAnchorVerifier {
            source: &source,
            authority: &authority,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Ok(source.record.anchor)
        );
        assert_eq!(source.reads.get(), 1);
    }

    #[test]
    fn revocation_or_generation_change_blocks_recovery() {
        let source = Source {
            record: record(4),
            reads: Cell::new(0),
        };
        let authority = authority(4);
        authority.state.borrow_mut().revoked = true;
        let verifier = ConsistentAnchorVerifier {
            source: &source,
            authority: &authority,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unauthenticated)
        );
        authority.state.borrow_mut().revoked = false;
        authority.state.borrow_mut().generation = 5;
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Stale)
        );
    }

    #[test]
    fn key_change_or_corrupted_mac_blocks_recovery() {
        let source = Source {
            record: record(4),
            reads: Cell::new(0),
        };
        let authority = authority(4);
        authority.state.borrow_mut().active_key = "key-v2";
        let verifier = ConsistentAnchorVerifier {
            source: &source,
            authority: &authority,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unauthenticated)
        );
        authority.state.borrow_mut().active_key = "key-v1";
        let mut modified = source.record.clone();
        modified.tag[0] ^= 1;
        let tampered = Source {
            record: modified,
            reads: Cell::new(0),
        };
        let verifier = ConsistentAnchorVerifier {
            source: &tampered,
            authority: &authority,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unauthenticated)
        );
    }

    #[test]
    fn unavailable_authority_and_wrong_journal_fail_closed() {
        let source = Source {
            record: record(4),
            reads: Cell::new(0),
        };
        let authority = authority(4);
        authority.available.set(false);
        let verifier = ConsistentAnchorVerifier {
            source: &source,
            authority: &authority,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unavailable)
        );
        assert_eq!(
            verifier.latest_anchor("different"),
            Err(AnchorError::Unauthenticated)
        );
    }
}
