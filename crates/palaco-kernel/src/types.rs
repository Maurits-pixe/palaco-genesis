//! Type definitions and identifiers for PALACO platform.

use std::fmt;

/// Unique identifier for entities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    /// Create a new identifier.
    pub fn new(value: impl Into<String>) -> Self {
        Id(value.into())
    }

    /// Get the identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for services.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceId(String);

impl ServiceId {
    /// Create a new service identifier.
    pub fn new(value: impl Into<String>) -> Self {
        ServiceId(value.into())
    }

    /// Get the service ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventId(String);

impl EventId {
    /// Create a new event identifier.
    pub fn new(value: impl Into<String>) -> Self {
        EventId(value.into())
    }

    /// Get the event ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Timestamp in ISO 8601 format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Timestamp(String);

impl Timestamp {
    /// Create a new timestamp.
    pub fn new(value: impl Into<String>) -> Self {
        Timestamp(value.into())
    }

    /// Get the timestamp as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version identifier (semantic versioning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    /// Create a new version.
    pub fn new(value: impl Into<String>) -> Self {
        Version(value.into())
    }

    /// Get the version as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_creation() {
        let id = Id::new("test-id");
        assert_eq!(id.as_str(), "test-id");
    }

    #[test]
    fn test_id_equality() {
        let id1 = Id::new("test");
        let id2 = Id::new("test");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_service_id_display() {
        let id = ServiceId::new("svc-123");
        assert_eq!(id.to_string(), "svc-123");
    }

    #[test]
    fn test_event_id_hash() {
        use std::collections::HashSet;
        let id1 = EventId::new("evt-1");
        let id2 = EventId::new("evt-1");
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }
}
