//! Service lifecycle and state machine.

use std::fmt;

/// Service lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceState {
    /// Service is initialized but not yet started.
    Initialized,
    /// Service is currently running.
    Running,
    /// Service is shutting down.
    ShuttingDown,
    /// Service has stopped.
    Stopped,
    /// Service encountered a fatal error.
    Failed,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceState::Initialized => write!(f, "Initialized"),
            ServiceState::Running => write!(f, "Running"),
            ServiceState::ShuttingDown => write!(f, "ShuttingDown"),
            ServiceState::Stopped => write!(f, "Stopped"),
            ServiceState::Failed => write!(f, "Failed"),
        }
    }
}

impl ServiceState {
    /// Check if state transition is valid.
    pub fn can_transition_to(&self, next: ServiceState) -> bool {
        match (self, next) {
            // From Initialized
            (ServiceState::Initialized, ServiceState::Running) => true,
            (ServiceState::Initialized, ServiceState::Stopped) => true,
            (ServiceState::Initialized, ServiceState::Failed) => true,
            // From Running
            (ServiceState::Running, ServiceState::ShuttingDown) => true,
            (ServiceState::Running, ServiceState::Failed) => true,
            // From ShuttingDown
            (ServiceState::ShuttingDown, ServiceState::Stopped) => true,
            (ServiceState::ShuttingDown, ServiceState::Failed) => true,
            // Self-transitions (no-op)
            (s, next) if s == &next => true,
            // All other transitions are invalid
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        let mut state = ServiceState::Initialized;
        assert!(state.can_transition_to(ServiceState::Running));
        state = ServiceState::Running;
        assert!(state.can_transition_to(ServiceState::ShuttingDown));
        state = ServiceState::ShuttingDown;
        assert!(state.can_transition_to(ServiceState::Stopped));
    }

    #[test]
    fn test_invalid_transitions() {
        let state = ServiceState::Stopped;
        assert!(!state.can_transition_to(ServiceState::Running));
        assert!(!state.can_transition_to(ServiceState::Initialized));
    }
}
