use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

mod model;
mod provider;
mod send;

pub use model::ModelArgs;
pub use provider::ProviderArgs;
pub use send::SendArgs;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
  Text,
  Json,
}

#[derive(Subcommand, Debug)]
pub enum SmokeCmd {
  /// Send a request through a configured v2 LLM API listener.
  Send(SendArgs),
  /// Show providers that support a model.
  Model(ModelArgs),
  /// Show configuration, driver metadata, and models for a v2 provider.
  Provider(ProviderArgs),
}

pub async fn run_cmd(cfg_path: Option<PathBuf>, cmd: SmokeCmd) -> Result<()> {
  match cmd {
    SmokeCmd::Send(args) => send::run(cfg_path, args).await,
    SmokeCmd::Model(args) => model::run(args).await,
    SmokeCmd::Provider(args) => provider::run(cfg_path, args).await,
  }
}

fn resolve_v2_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
  explicit
    .map(Path::to_path_buf)
    .map_or_else(|| tokn_config::paths::config_path().map_err(Into::into), Ok)
}

fn load_v2_plan(explicit: Option<&Path>) -> Result<(tokn_policy::GatewayPlan, PathBuf)> {
  let path = resolve_v2_config_path(explicit)?;
  let plan = tokn_config::v2::load(&path)?;
  Ok((plan, path))
}
