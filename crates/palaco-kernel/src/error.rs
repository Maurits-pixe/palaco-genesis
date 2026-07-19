//! Core error types for PALACO platform.

use std::fmt;

/// PALACO platform error type.
#[derive(Debug, Clone)]
pub enum Error {
    /// Invalid argument error.
    InvalidArgument(String),
    /// Resource not found error.
    NotFound(String),
    /// State conflict error.
    Conflict(String),
    /// Internal platform error.
    Internal(String),
    /// Validation error.
    Validation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Error::NotFound(msg) => write!(f, "Not found: {}", msg),
            Error::Conflict(msg) => write!(f, "Conflict: {}", msg),
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
            Error::Validation(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result type alias for PALACO operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::NotFound("service not found".to_string());
        assert_eq!(err.to_string(), "Not found: service not found");
    }
}
