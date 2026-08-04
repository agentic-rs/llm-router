//! Provider bindings and account selection for compiled gateway policy.
//!
//! This crate links configured upstreams and accounts, materializes immutable
//! account pools, selects one request target, and settles the resulting
//! selection state. Listener admission and route matching belong to the
//! router.

pub mod affinity;
pub mod link;
pub mod registry;
