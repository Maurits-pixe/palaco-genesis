//! Shared PALACO error contracts.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Shared workspace error type.
#[derive(Debug, thiserror::Error)]
pub enum PalacoError {
    /// Returned when a requested capability has not been implemented yet.
    #[error("capability not implemented: {0}")]
    NotImplemented(&'static str),
}
