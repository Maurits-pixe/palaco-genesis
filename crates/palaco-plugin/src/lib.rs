//! # palaco-plugin
//!
//! Plugin system and extensibility framework for the PALACO platform.
//!
//! Allows third-party extensions with proper isolation and lifecycle management.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;

pub mod traits;
pub mod loader;
pub mod lifecycle;

pub use traits::*;
pub use loader::*;
pub use lifecycle::*;
