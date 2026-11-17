//! Independent key-policy checks for rotated ORCHEASTRA audit MAC keys.
//!
//! This is an adapter contract, not a key vault. The external policy source
//! must authenticate journal scope, key identity, revocation and generations.
//! Historical MAC validity never creates present-day execution authority.

use palaco_runtime::orcheastra::persistence::TrustedRecoveryAnchor;

use super::{
    mac::{GenerationAuthority, HmacAnchorVerifier, MacCheckpoint, MacCheckpointSource},
    AnchorError, AuditAnchorVerifier,
};

/// A separately trusted key policy, never parsed from a snapshot or MAC record.
///
/// Key bytes are copied only within this integration boundary. A production
/// deployment should keep them inside a hardened key service instead.
pub struct VerificationKeyPolicy {
    /// Secret 256-bit verification material.
    pub secret: [u8; 32],
    /// First journal generation permitted to use this key, inclusive.
    pub first_generation: u64,
    /// Last journal generation permitted to use this key, inclusive.
    pub last_generation: u64,
    /// Emergency key revocation, overriding historic validity.
    pub revoked: bool,
}

/// Authenticated, independently operated key policy provider.
///
/// The producer of untrusted checkpoint files MUST NOT choose or supply
/// trusted key policy. Unavailable/revoked/unknown policies fail closed.
pub trait KeyPolicyAuthority {
    /// Return the current trusted policy for the exact journal/key pair.
    fn current_policy(
        &self,
        journal_id: &str,
        key_id: &str,
    ) -> Result<VerificationKeyPolicy, AnchorError>;
}

/// Verifier supporting historical keys only within explicitly trusted,
/// non-revoked generation windows.
pub struct RotatingAnchorVerifier<'a, S, G, K> {
    /// Untrusted checkpoint transport.
    pub source: &'a S,
    /// Independently authenticated latest-generation authority.
    pub generations: &'a G,
    /// Independent key status and secret authority.
    pub key_policies: &'a K,
}

struct SingleRecordSource(MacCheckpoint);

impl MacCheckpointSource for SingleRecordSource {
    fn checkpoint(&self, _: &str) -> Result<MacCheckpoint, AnchorError> {
        Ok(self.0.clone())
    }
}

impl<S: MacCheckpointSource, G: GenerationAuthority, K: KeyPolicyAuthority> AuditAnchorVerifier
    for RotatingAnchorVerifier<'_, S, G, K>
{
    fn latest_anchor(&self, journal_id: &str) -> Result<TrustedRecoveryAnchor, AnchorError> {
        if journal_id.trim().is_empty() {
            return Err(AnchorError::UnauthorizedJournal);
        }
        let record = self.source.checkpoint(journal_id)?;
        if record.journal_id != journal_id || record.key_id.trim().is_empty() {
            return Err(AnchorError::Unauthenticated);
        }
        let policy = self
            .key_policies
            .current_policy(journal_id, &record.key_id)?;
        if policy.revoked
            || policy.first_generation > policy.last_generation
            || record.anchor.generation < policy.first_generation
            || record.anchor.generation > policy.last_generation
        {
            return Err(AnchorError::Unauthenticated);
        }
        // Pin the fetched record to prevent a second untrusted source read
        // from silently switching the key ID or the candidate checkpoint.
        let pinned = SingleRecordSource(record);
        let verifier = HmacAnchorVerifier {
            source: &pinned,
            generations: self.generations,
            key_id: &pinned.0.key_id,
            key: &policy.secret,
        };
        verifier.latest_anchor(journal_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::mac::authenticate_checkpoint;
    use palaco_runtime::orcheastra::recovery::RecoveryCheckpoint;

    const OLD: [u8; 32] = [0x41; 32];
    const NEW: [u8; 32] = [0x42; 32];

    struct Source(MacCheckpoint);
    impl MacCheckpointSource for Source {
        fn checkpoint(&self, _: &str) -> Result<MacCheckpoint, AnchorError> {
            Ok(self.0.clone())
        }
    }

    struct Latest(u64);
    impl GenerationAuthority for Latest {
        fn latest_generation(&self, _: &str) -> Result<u64, AnchorError> {
            Ok(self.0)
        }
    }

    struct Keys {
        revoked: bool,
        known: bool,
    }
    impl KeyPolicyAuthority for Keys {
        fn current_policy(
            &self,
            journal_id: &str,
            key_id: &str,
        ) -> Result<VerificationKeyPolicy, AnchorError> {
            if journal_id != "orcheastra:test" || !self.known {
                return Err(AnchorError::UnauthorizedJournal);
            }
            let (secret, first, last) = match key_id {
                "old" => (OLD, 1, 4),
                "new" => (NEW, 5, u64::MAX),
                _ => return Err(AnchorError::Unauthenticated),
            };
            Ok(VerificationKeyPolicy {
                secret,
                first_generation: first,
                last_generation: last,
                revoked: self.revoked,
            })
        }
    }

    fn anchor(generation: u64) -> TrustedRecoveryAnchor {
        TrustedRecoveryAnchor {
            generation,
            checkpoint: RecoveryCheckpoint {
                plan_hash: [5u8; 32],
                sequence: 2,
                head: [9u8; 32],
            },
        }
    }

    #[test]
    fn rotation_accepts_only_correct_current_key() {
        let source = Source(authenticate_checkpoint(
            "orcheastra:test",
            "new",
            anchor(5),
            &NEW,
        ));
        let keys = Keys {
            revoked: false,
            known: true,
        };
        let verifier = RotatingAnchorVerifier {
            source: &source,
            generations: &Latest(5),
            key_policies: &keys,
        };
        assert_eq!(verifier.latest_anchor("orcheastra:test"), Ok(anchor(5)));
    }

    #[test]
    fn old_key_cannot_sign_after_rotation_boundary() {
        let source = Source(authenticate_checkpoint(
            "orcheastra:test",
            "old",
            anchor(5),
            &OLD,
        ));
        let keys = Keys {
            revoked: false,
            known: true,
        };
        let verifier = RotatingAnchorVerifier {
            source: &source,
            generations: &Latest(5),
            key_policies: &keys,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unauthenticated)
        );
    }

    #[test]
    fn revoked_key_overrides_valid_historic_mac() {
        let source = Source(authenticate_checkpoint(
            "orcheastra:test",
            "old",
            anchor(3),
            &OLD,
        ));
        let keys = Keys {
            revoked: true,
            known: true,
        };
        let verifier = RotatingAnchorVerifier {
            source: &source,
            generations: &Latest(3),
            key_policies: &keys,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unauthenticated)
        );
    }

    #[test]
    fn missing_policy_and_stale_generation_fail_closed() {
        let source = Source(authenticate_checkpoint(
            "orcheastra:test",
            "new",
            anchor(6),
            &NEW,
        ));
        let missing = Keys {
            revoked: false,
            known: false,
        };
        let verifier = RotatingAnchorVerifier {
            source: &source,
            generations: &Latest(6),
            key_policies: &missing,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::UnauthorizedJournal)
        );
        let keys = Keys {
            revoked: false,
            known: true,
        };
        let verifier = RotatingAnchorVerifier {
            source: &source,
            generations: &Latest(7),
            key_policies: &keys,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Stale)
        );
    }
}
