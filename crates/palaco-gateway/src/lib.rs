//! # palaco-gateway
//!
//! API gateway and external interface for the PALACO platform.
//!
//! Provides HTTP/gRPC endpoints, request routing, and external protocol handling.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;
use palaco_runtime::*;
use palaco_security::*;

pub mod http;
pub mod routing;
pub mod protocols;

pub use http::*;
pub use routing::*;
pub use protocols::*;
