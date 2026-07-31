use anyhow::{anyhow, Result};

pub mod api;
pub mod pipeline;
pub mod proxy;
pub mod runtime;

pub use tokn_accounts as accounts;
pub use tokn_config as config;
pub use tokn_convert as convert;
pub use tokn_core::{db, provider, util};

/// Read-only view of the router's intercept-host allow-list. Exposed so the
/// `tokn-accounts` registry coverage test (now living in
/// `crates/router/tests/intercept_hosts_coverage.rs`) can verify that every
/// descriptor host is intercepted without making the constant itself `pub`.
pub fn proxy_intercept_hosts() -> &'static [&'static str] {
  proxy::INTERCEPT_HOSTS
}

pub fn install_rustls_crypto_provider() -> Result<()> {
  rustls::crypto::ring::default_provider()
    .install_default()
    .map_err(|_| anyhow!("failed to install rustls ring crypto provider"))?;
  Ok(())
}
