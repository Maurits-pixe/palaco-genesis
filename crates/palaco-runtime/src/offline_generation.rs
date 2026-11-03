//! Non-authoritative offline generation selection.
//!
//! This state machine does not perform filesystem writes, hashing or encryption.
//! Its confirmation method is only for a caller that has separately verified
//! content and durable storage. It cannot attest such verification itself.

/// A manifest generation identifier and declared content count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    /// Caller-assigned monotonic identifier within a catalog.
    pub sequence: u64,
    /// Number of declared artifacts in the generation.
    pub artifacts: u32,
}

/// Error returned by the offline generation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationError {
    /// An invalid or non-increasing generation identifier.
    InvalidGeneration,
    /// A pending generation must be resolved first.
    AlreadyStaged,
    /// No pending generation is available.
    NothingStaged,
    /// Caller supplied evidence does not match the staged generation.
    ConfirmationMismatch,
}

/// A pending generation never replaces the last confirmed generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenerationGate {
    active: Option<Generation>,
    pending: Option<Generation>,
}

impl GenerationGate {
    /// Construct an empty selection gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Last confirmed generation. None means no usable generation.
    #[must_use]
    pub fn active(&self) -> Option<Generation> {
        self.active
    }

    /// Unconfirmed generation that must not be advertised as ready.
    #[must_use]
    pub fn pending(&self) -> Option<Generation> {
        self.pending
    }

    /// Stage a new generation without changing the active version.
    pub fn stage(&mut self, generation: Generation) -> Result<(), GenerationError> {
        if self.pending.is_some() {
            return Err(GenerationError::AlreadyStaged);
        }
        if generation.sequence == 0
            || generation.artifacts == 0
            || self
                .active
                .is_some_and(|current| generation.sequence <= current.sequence)
        {
            return Err(GenerationError::InvalidGeneration);
        }
        self.pending = Some(generation);
        Ok(())
    }

    /// Complete a transition only when a trusted caller supplies a matching
    /// verified, durable generation identifier. This method cannot verify it.
    pub fn confirm_verified(
        &mut self,
        verified_durable_generation: Generation,
    ) -> Result<(), GenerationError> {
        match self.pending {
            None => Err(GenerationError::NothingStaged),
            Some(pending) if pending != verified_durable_generation => {
                Err(GenerationError::ConfirmationMismatch)
            }
            Some(pending) => {
                self.active = Some(pending);
                self.pending = None;
                Ok(())
            }
        }
    }

    /// Abandon a staging attempt, preserving the previous known-good choice.
    pub fn abort_pending(&mut self) -> Result<(), GenerationError> {
        if self.pending.take().is_some() {
            Ok(())
        } else {
            Err(GenerationError::NothingStaged)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Generation, GenerationError, GenerationGate};

    fn generation(sequence: u64) -> Generation {
        Generation {
            sequence,
            artifacts: 2,
        }
    }

    #[test]
    fn pending_is_not_active() {
        let mut gate = GenerationGate::new();
        assert_eq!(gate.stage(generation(1)), Ok(()));
        assert_eq!(gate.active(), None);
        assert_eq!(gate.pending(), Some(generation(1)));
    }

    #[test]
    fn confirmation_requires_exact_match() {
        let mut gate = GenerationGate::new();
        assert_eq!(gate.stage(generation(1)), Ok(()));
        assert_eq!(
            gate.confirm_verified(generation(2)),
            Err(GenerationError::ConfirmationMismatch)
        );
        assert_eq!(gate.active(), None);
        assert_eq!(gate.confirm_verified(generation(1)), Ok(()));
        assert_eq!(gate.active(), Some(generation(1)));
    }

    #[test]
    fn aborted_update_preserves_previous_generation() {
        let mut gate = GenerationGate::new();
        assert_eq!(gate.stage(generation(1)), Ok(()));
        assert_eq!(gate.confirm_verified(generation(1)), Ok(()));
        assert_eq!(gate.stage(generation(2)), Ok(()));
        assert_eq!(gate.abort_pending(), Ok(()));
        assert_eq!(gate.active(), Some(generation(1)));
        assert_eq!(gate.pending(), None);
    }

    #[test]
    fn duplicate_or_rollback_sequence_is_rejected() {
        let mut gate = GenerationGate::new();
        assert_eq!(gate.stage(generation(2)), Ok(()));
        assert_eq!(gate.confirm_verified(generation(2)), Ok(()));
        assert_eq!(
            gate.stage(generation(2)),
            Err(GenerationError::InvalidGeneration)
        );
        assert_eq!(
            gate.stage(generation(1)),
            Err(GenerationError::InvalidGeneration)
        );
    }

    #[test]
    fn overlapping_stage_is_blocked() {
        let mut gate = GenerationGate::new();
        assert_eq!(gate.stage(generation(1)), Ok(()));
        assert_eq!(
            gate.stage(generation(2)),
            Err(GenerationError::AlreadyStaged)
        );
    }

    #[test]
    fn zero_or_empty_generation_is_rejected() {
        let mut gate = GenerationGate::new();
        assert_eq!(
            gate.stage(generation(0)),
            Err(GenerationError::InvalidGeneration)
        );
        assert_eq!(
            gate.stage(Generation {
                sequence: 1,
                artifacts: 0,
            }),
            Err(GenerationError::InvalidGeneration)
        );
    }
}
