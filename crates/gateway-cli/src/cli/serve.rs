use anyhow::{Context, Result};
use std::path::PathBuf;

pub async fn run(config_path: Option<PathBuf>) -> Result<()> {
  let config_path = match config_path {
    Some(path) => path,
    None => tokn_config::paths::config_path().context("resolve the default gateway config path")?,
  };
  let compiled = tokn_config::v2::load(&config_path)
    .with_context(|| format!("load compiled gateway config `{}`", config_path.display()))?;
  let accounts = crate::server_runtime::load_accounts(Some(&config_path))?;
  let listener_count = compiled.gateway().listeners().len();
  let account_count = accounts.len();
  let bound = crate::server_runtime::bind_compiled_gateway(&compiled, &accounts, None).await?;

  tracing::info!(
    config = %config_path.display(),
    listeners = listener_count,
    accounts = account_count,
    "compiled gateway generation ready"
  );
  tokn_router::runtime::serve_gateway_listeners(bound, async {
    if let Err(error) = tokio::signal::ctrl_c().await {
      tracing::warn!(%error, "failed to install the interrupt signal handler");
    }
  })
  .await
  .context("serve compiled gateway listeners")
}
