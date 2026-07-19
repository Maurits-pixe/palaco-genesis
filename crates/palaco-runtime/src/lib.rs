//! # palaco-runtime
//!
//! Runtime orchestration layer managing service lifecycle, state coordination,
//! and subsystem interaction for the PALACO platform.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;

pub mod orchestration;
pub mod state;
pub mod lifecycle;

pub use orchestration::*;
pub use state::*;
pub use lifecycle::*;
