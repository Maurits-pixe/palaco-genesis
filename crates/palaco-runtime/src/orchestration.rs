//! Service orchestration and coordination.

use crate::lifecycle::ServiceState;
use std::sync::Arc;

/// Service identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceId(String);

impl ServiceId {
    /// Create a new service ID.
    pub fn new(id: impl Into<String>) -> Self {
        ServiceId(id.into())
    }

    /// Get the service ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Service configuration.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Unique service identifier.
    pub id: ServiceId,
    /// Service name (human-readable).
    pub name: String,
    /// Service version.
    pub version: String,
}

impl ServiceConfig {
    /// Create a new service configuration.
    pub fn new(id: ServiceId, name: impl Into<String>, version: impl Into<String>) -> Self {
        ServiceConfig {
            id,
            name: name.into(),
            version: version.into(),
        }
    }
}

/// Service orchestrator managing service lifecycle and coordination.
pub struct Orchestrator {
    /// Map of service IDs to their current states.
    states: std::sync::Mutex<std::collections::HashMap<ServiceId, ServiceState>>,
}

impl Orchestrator {
    /// Create a new orchestrator.
    pub fn new() -> Self {
        Orchestrator {
            states: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Register a service.
    pub fn register_service(&self, id: ServiceId) -> Result<(), String> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("Failed to lock states: {}", e))?;

        if states.contains_key(&id) {
            return Err(format!("Service {} already registered", id));
        }

        states.insert(id, ServiceState::Initialized);
        Ok(())
    }

    /// Get the current state of a service.
    pub fn get_service_state(&self, id: &ServiceId) -> Result<ServiceState, String> {
        let states = self
            .states
            .lock()
            .map_err(|e| format!("Failed to lock states: {}", e))?;

        states
            .get(id)
            .copied()
            .ok_or_else(|| format!("Service {} not found", id))
    }

    /// Transition a service to a new state.
    pub fn transition_service(&self, id: &ServiceId, new_state: ServiceState) -> Result<(), String> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("Failed to lock states: {}", e))?;

        let current_state = states
            .get(id)
            .copied()
            .ok_or_else(|| format!("Service {} not found", id))?;

        if !current_state.can_transition_to(new_state) {
            return Err(format!(
                "Invalid transition from {} to {}",
                current_state, new_state
            ));
        }

        states.insert(id.clone(), new_state);
        Ok(())
    }
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_register() {
        let orch = Orchestrator::new();
        let id = ServiceId::new("svc-1");
        assert!(orch.register_service(id.clone()).is_ok());
        assert!(orch.register_service(id).is_err()); // Duplicate registration
    }

    #[test]
    fn test_orchestrator_state_transition() {
        let orch = Orchestrator::new();
        let id = ServiceId::new("svc-1");
        orch.register_service(id.clone()).unwrap();

        assert_eq!(
            orch.get_service_state(&id).unwrap(),
            ServiceState::Initialized
        );

        orch.transition_service(&id, ServiceState::Running)
            .unwrap();
        assert_eq!(orch.get_service_state(&id).unwrap(), ServiceState::Running);
    }

    #[test]
    fn test_orchestrator_invalid_transition() {
        let orch = Orchestrator::new();
        let id = ServiceId::new("svc-1");
        orch.register_service(id.clone()).unwrap();
        orch.transition_service(&id, ServiceState::Running).unwrap();

        // Invalid: cannot go from Running directly to Initialized
        assert!(orch
            .transition_service(&id, ServiceState::Initialized)
            .is_err());
    }
}
