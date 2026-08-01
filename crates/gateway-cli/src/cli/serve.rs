use anyhow::{Context, Result};
use std::path::PathBuf;

pub async fn run(config_path: Option<PathBuf>) -> Result<()> {
  let config_path = tokn_config::paths::resolve_config_path(config_path.as_deref())
    .context("resolve the default gateway config path")?;
  let compiled = tokn_config::v2::load(&config_path)
    .with_context(|| format!("load compiled gateway config `{}`", config_path.display()))?;
  let accounts = crate::server_runtime::load_default_accounts()?;
  let listener_count = compiled.gateway().listeners().len();
  let account_count = accounts.len();
  let events = crate::server_runtime::build_gateway_event_runtime(compiled.service().persistence())?;
  let bound = match crate::server_runtime::bind_compiled_gateway_with_events(
    &compiled,
    &accounts,
    None,
    events.emitter(),
  )
  .await
  {
    Ok(bound) => bound,
    Err(error) => {
      return match events.shutdown().await {
        Ok(()) => Err(error),
        Err(shutdown_error) => {
          Err(error.context(format!("gateway event runtime cleanup also failed: {shutdown_error}")))
        }
      };
    }
  };

  tracing::info!(
    config = %config_path.display(),
    listeners = listener_count,
    accounts = account_count,
    "compiled gateway generation ready"
  );
  crate::server_runtime::serve_bound_gateway(bound, events, async {
    if let Err(error) = tokio::signal::ctrl_c().await {
      tracing::warn!(%error, "failed to install the interrupt signal handler");
    }
  })
  .await
}
