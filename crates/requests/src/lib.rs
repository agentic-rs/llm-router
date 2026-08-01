//! HTTP execution contracts for selected gateway targets.
//!
//! This crate owns one-attempt managed and opaque transports plus managed
//! request and response adaptation. Routing, policy matching, and account
//! selection live in their owning crates.

pub mod execution;
