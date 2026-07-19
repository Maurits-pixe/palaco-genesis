//! Runtime state management and coordination.

use std::collections::HashMap;

/// Service state snapshot.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Arbitrary key-value state data.
    pub data: HashMap<String, String>,
}

impl StateSnapshot {
    /// Create a new empty state snapshot.
    pub fn new() -> Self {
        StateSnapshot {
            data: HashMap::new(),
        }
    }

    /// Get a state value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }

    /// Set a state value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }
}

impl Default for StateSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_snapshot() {
        let mut snapshot = StateSnapshot::new();
        snapshot.set("key1", "value1");
        assert_eq!(snapshot.get("key1"), Some("value1"));
        assert_eq!(snapshot.get("nonexistent"), None);
    }
}
