//! # palaco-kernel
//!
//! Core kernel crate providing compile-time guaranteed invariants, canonical types,
//! and foundational abstractions for the PALACO platform.
//!
//! ## Key Components
//!
//! - **Types** — Canonical identifiers and value types (Id, ServiceId, EventId, Version)
//! - **Invariants** — Traits for validating compile-time and runtime guarantees
//! - **Error** — Platform error types and result handling
//!
//! ## Principles
//!
//! - **Type Safety** — Invalid states are unrepresentable
//! - **Determinism** — All operations have predictable outcomes
//! - **Auditability** — All types preserve trace information
//!
//! ## Example
//!
//! ```ignore
//! use palaco_kernel::{ServiceId, EventId, Timestamp, Result};
//!
//! let service = ServiceId::new("my-service");
//! let event = EventId::new("evt-123");
//! let timestamp = Timestamp::new("2026-07-19T15:07:56Z");
//!
//! println!("Service: {}", service);
//! println!("Event: {}", event);
//! println!("Time: {}", timestamp);
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod invariants;
mod types;

pub use error::{Error, Result};
pub use invariants::{Canonical, Comparable, Invariant, Validatable};
pub use types::{EventId, Id, ServiceId, Timestamp, Version};
