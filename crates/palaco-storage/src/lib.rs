//! # palaco-storage
//!
//! State persistence and data management layer for the PALACO platform.
//!
//! Handles storage abstraction, transactions, and data durability guarantees.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use palaco_kernel::*;
use palaco_eventbus::*;

pub mod persistence;
pub mod transactions;
pub mod schema;

pub use persistence::*;
pub use transactions::*;
pub use schema::*;
