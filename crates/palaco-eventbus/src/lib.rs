//! # palaco-eventbus
//!
//! Event bus implementation providing deterministic, ordered event dispatch
//! for the PALACO platform.
//!
//! Events are guaranteed to be processed in order with full traceability.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;

pub mod events;
pub mod dispatcher;

pub use events::*;
pub use dispatcher::*;
