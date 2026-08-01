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
  /// Smoke commands are either config-free or load strict version 2 state
  /// themselves. None may trigger legacy migration or partial legacy loading.
  pub(super) fn bypasses_legacy_startup(&self) -> bool {
    true
  }
}

pub async fn run_cmd(cfg_path: Option<PathBuf>, cmd: SmokeCmd) -> Result<()> {
  match cmd {
    SmokeCmd::Send(args) => send::run(cfg_path, args).await,
    SmokeCmd::Model(args) => model::run(args).await,
    SmokeCmd::Provider(args) => provider::run(cfg_path, args).await,
  }
}

#[cfg(test)]
mod tests {
  use crate::cli::{Cli, Cmd};
  use clap::error::ErrorKind;
  use clap::Parser;

  #[test]
  fn send_requires_an_explicit_profile_and_bypasses_legacy_startup() {
    let error =
      Cli::try_parse_from(["tokn-router", "smoke", "send", "--model", "provider/model", "hello"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);

    let cli = Cli::try_parse_from([
      "tokn-router",
      "smoke",
      "send",
      "--profile",
      "work",
      "--model",
      "provider/model",
      "hello",
    ])
    .unwrap();
    let Cmd::Smoke(command) = cli.cmd else {
      panic!("expected smoke command")
    };
    assert!(command.bypasses_legacy_startup());
  }

  #[test]
  fn send_rejects_retired_request_scoped_routing_flags() {
    for legacy_flag in [
      &["--route", "exact"][..],
      &["--provider", "openai"][..],
      &["--account", "personal"][..],
      &["--dry-run"][..],
    ] {
      let mut args = vec![
        "tokn-router",
        "smoke",
        "send",
        "--profile",
        "work",
        "--model",
        "provider/model",
      ];
      args.extend_from_slice(legacy_flag);
      args.push("hello");

      let error = Cli::try_parse_from(args).unwrap_err();
      assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{legacy_flag:?}");
    }
  }
}
