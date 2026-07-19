//! # palaco-kernel
//!
//! Core kernel crate providing compile-time guaranteed invariants and foundational types
//! for the PALACO platform.
//!
//! This crate defines the canonical types and constraints that all other subsystems depend on.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod invariants;
pub mod types;

pub use invariants::*;
pub use types::*;
