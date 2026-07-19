//! # palaco-security
//!
//! Security policies, access control, and audit trail management
//! for the PALACO platform.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;

pub mod policies;
pub mod access_control;
pub mod audit;

pub use policies::*;
pub use access_control::*;
pub use audit::*;
