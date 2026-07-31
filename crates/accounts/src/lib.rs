//! Account management and request routing.
//!
//! `pool` owns provider-bucketed account acquisition; `affinity` keeps
//! session ids pinned to accounts across related requests; `routing`
//! resolves a requested model into a route mode + upstream selector for the
//! pool to consume.

pub mod affinity;
pub mod inventory;
pub mod link;
pub mod registry;
pub mod routing;

mod handle;
mod pool;

pub use handle::AccountHandle;
pub use inventory::{AccountInventory, AccountPoolRuleset};
pub use pool::{AccountPool, EndpointAcquire, Error, Result, SessionAcquire};
pub use routing::{ResolveError, RouteResolution, RouteResolver, RouteSelector};
