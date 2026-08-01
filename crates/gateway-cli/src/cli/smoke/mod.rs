use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

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
  /// Send a single smoke-test request to verify account/provider connectivity.
  Send(SendArgs),
  /// Show providers that support a model.
  Model(ModelArgs),
  /// Show metadata, endpoints, and models for a registered provider.
  Provider(ProviderArgs),
}

impl SmokeCmd {
  /// Static catalogue inspection and v2 live-provider inspection must not
  /// trigger legacy config migration or partial legacy loading.
  pub(super) fn bypasses_legacy_startup(&self) -> bool {
    matches!(self, Self::Model(_) | Self::Provider(_))
  }
}

pub async fn run_cmd(cfg_path: Option<PathBuf>, cmd: SmokeCmd) -> Result<()> {
  match cmd {
    SmokeCmd::Send(args) => send::run(cfg_path, args).await,
    SmokeCmd::Model(args) => model::run(args).await,
    SmokeCmd::Provider(args) => provider::run(cfg_path, args).await,
  }
}
