//! Compile-time guarantees and invariant traits.

use crate::Result;

/// Trait for types that can validate their invariants.
pub trait Invariant: Sized {
    /// Validate that all invariants are satisfied.
    ///
    /// # Errors
    ///
    /// Returns an error if any invariant is violated.
    fn validate(&self) -> Result<()>;
}

/// Trait for types that can be created from unvalidated input.
pub trait Validatable: Sized {
    /// The unvalidated input type.
    type Input;

    /// Create from input, validating invariants.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    fn from_input(input: Self::Input) -> Result<Self>;
}

/// Trait for types with a canonical representation.
pub trait Canonical: Sized {
    /// The canonical form of this type.
    type Canonical;

    /// Convert to canonical form.
    fn to_canonical(&self) -> Self::Canonical;

    /// Reconstruct from canonical form.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical form is invalid.
    fn from_canonical(canonical: Self::Canonical) -> Result<Self>;
}

/// Trait for types that support comparison with invariant guarantees.
pub trait Comparable {
    /// Check if this value is equal to another, with invariant guarantees.
    fn eq_invariant(&self, other: &Self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestInvariant {
        value: i32,
    }

    impl Invariant for TestInvariant {
        fn validate(&self) -> Result<()> {
            if self.value >= 0 {
                Ok(())
            } else {
                Err(crate::Error::Validation("value must be non-negative".to_string()))
            }
        }
    }

    #[test]
    fn test_invariant_valid() {
        let val = TestInvariant { value: 42 };
        assert!(val.validate().is_ok());
    }

    #[test]
    fn test_invariant_invalid() {
        let val = TestInvariant { value: -1 };
        assert!(val.validate().is_err());
    }
}
