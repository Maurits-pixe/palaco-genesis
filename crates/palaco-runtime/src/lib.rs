//! # palaco-runtime
//!
//! Runtime orchestration layer managing service lifecycle, state coordination,
//! and subsystem interaction for the PALACO platform.
//!
//! ## Key Components
//!
//! - **Orchestration** — Service registration and coordination
//! - **Lifecycle** — State machine for service states
//! - **State** — Runtime state snapshots and management
//!
//! ## Example
//!
//! ```ignore
//! use palaco_runtime::Orchestrator;
//! use palaco_runtime::orchestration::{ServiceId, ServiceConfig};
//! use palaco_runtime::lifecycle::ServiceState;
//!
//! let orchestrator = Orchestrator::new();
//! let service_id = ServiceId::new("my-service");
//!
//! // Register service
//! orchestrator.register_service(service_id.clone()).ok();
//!
//! // Transition to running
//! orchestrator.transition_service(&service_id, ServiceState::Running).ok();
//!
//! // Check state
//! let state = orchestrator.get_service_state(&service_id).ok();
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod lifecycle;
pub mod orchestration;
pub mod state;

pub use lifecycle::ServiceState;
pub use orchestration::{Orchestrator, ServiceConfig, ServiceId};
pub use state::StateSnapshot;
