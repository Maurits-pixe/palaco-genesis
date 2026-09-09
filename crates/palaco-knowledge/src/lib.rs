//! # palaco-knowledge
//!
//! Knowledge base and semantic layer for the PALACO platform.
//!
//! Manages domain models, metadata, and semantic information about services and their relationships.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;

pub mod models;
pub mod metadata;
pub mod semantics;

pub use models::*;
pub use metadata::*;
pub use semantics::*;
