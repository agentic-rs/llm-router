use anyhow::{anyhow, Result};

pub mod runtime;

pub fn install_rustls_crypto_provider() -> Result<()> {
  rustls::crypto::ring::default_provider()
    .install_default()
    .map_err(|_| anyhow!("failed to install rustls ring crypto provider"))?;
  Ok(())
}
