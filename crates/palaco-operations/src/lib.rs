//! # palaco-operations
//!
//! Operational concerns including logging, monitoring, tracing,
//! and observability for the PALACO platform.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;

pub mod logging;
pub mod metrics;
pub mod tracing;

pub use logging::*;
pub use metrics::*;
pub use tracing::*;
