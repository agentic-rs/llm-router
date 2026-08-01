//! Resolve stage — picks the upstream account and upstream model for an
//! extracted request.
//!
//! * [`stage`] — the generic [`PoolResolve`] stage and the
//!   [`AccountSelector`] trait it consults.
//! * [`pool`] — [`PoolAccountSelector`], the production [`AccountSelector`]
//!   implementation backed by [`tokn_accounts::AccountPool`] +
//!   [`tokn_accounts::RouteResolver`].

mod pool;
mod stage;

pub use pool::{PoolAccountSelector, ACCESS_ALLOWED_PROVIDERS_KEY};
pub use stage::{AccountSelector, PoolResolve, SelectorOutcome};
