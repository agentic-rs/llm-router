use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct InspectArgs {
  /// Loopback TCP port for the viewer. The default picks an available port.
  #[arg(long, default_value_t = 0)]
  pub port: u16,

  /// Override the configured requests directory.
  #[arg(long)]
  pub requests_dir: Option<PathBuf>,

  /// Override the configured sessions database.
  #[arg(long)]
  pub sessions_db: Option<PathBuf>,

  /// Override the configured usage database.
  #[arg(long)]
  pub usage_db: Option<PathBuf>,
}

pub async fn run(cfg_path: Option<PathBuf>, args: InspectArgs) -> Result<()> {
  let config = super::command_config::CommandConfig::load(cfg_path.as_deref())?;
  let mut paths = config.persistence_paths()?;
  if let Some(requests_dir) = args.requests_dir {
    paths.requests_dir = requests_dir;
  }
  if let Some(sessions_db) = args.sessions_db {
    paths.sessions_db = sessions_db;
  }
  if let Some(usage_db) = args.usage_db {
    paths.usage_db = usage_db;
  }
  tokn_router_inspect::serve(paths.requests_dir, paths.sessions_db, paths.usage_db, args.port)
    .await
    .context("run inspect viewer")
}
