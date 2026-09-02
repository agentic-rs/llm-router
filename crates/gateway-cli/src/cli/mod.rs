use clap::{Parser, Subcommand};
use std::path::Path;
use std::path::PathBuf;

use crate::config::LogTarget;
use crate::logging::{self, RunMode};

mod account;
mod agent;
mod api_key;
mod config_cmd;
mod config_context;
mod error;
mod headers;
mod import;
mod inspect;
mod lan_bootstrap;
mod login;
mod migration;
mod onboarding;
mod proxy;
mod requests;
mod serve;
mod sessions;
mod smoke;
mod update;
mod usage;
mod v2_projection;

pub use error::{Error, Result};

#[derive(Parser, Debug)]
#[command(name = "tokn-router", about = "GitHub Copilot -> OpenAI-compatible API")]
pub struct Cli {
  /// Path to config file (default: ~/.tokn/router/config.toml)
  #[arg(long, global = true)]
  pub config: Option<PathBuf>,

  #[command(subcommand)]
  pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
  /// Manage stored accounts (add / login / import / list / switch / refresh / status / show / remove)
  #[command(subcommand)]
  Account(account::AccountCmd),
  /// Manage agent account imports and gateway bindings
  #[command(subcommand)]
  Agent(agent::AgentCmd),
  /// Manage client API keys and their allowed providers
  #[command(name = "api-key", subcommand)]
  ApiKey(api_key::ApiKeyCmd),
  /// Show the Copilot identity headers that will be sent upstream
  Headers(headers::HeadersArgs),
  /// Run the local OpenAI-compatible server
  Serve(serve::ServeArgs),
  /// Run the local MITM forward proxy or print proxy env exports
  Proxy(proxy::ProxyArgs),
  /// Query usage statistics from the local SQLite log
  Usage(usage::UsageArgs),
  /// Open a loopback-only viewer for persisted requests and inferred sessions
  Inspect(inspect::InspectArgs),
  /// Manage archived per-day request databases using a v2 configuration.
  #[command(subcommand)]
  Requests(requests::RequestsCmd),
  /// Inspect and build semantic session views
  #[command(subcommand)]
  Sessions(sessions::SessionsCmd),
  /// Get/set/list config values (git-style); preserves comments
  Config(config_cmd::ConfigArgs),
  /// Refresh the on-disk models.dev catalogue cache
  Update(update::UpdateArgs),
  /// Apply pending DB migrations (or restore from `.bak` with --rollback)
  Migration(migration::MigrationArgs),
  /// Smoke-test the v2 request runtime or inspect catalogue metadata
  #[command(subcommand)]
  Smoke(smoke::SmokeCmd),
}

impl Cli {
  pub async fn run(self) -> Result<()> {
    let cfg_path = self.config.clone();
    let is_inspect = matches!(&self.cmd, Cmd::Inspect(_));
    let uses_v2_config = matches!(&self.cmd, Cmd::Requests(_) | Cmd::Smoke(_));
    if matches!(&self.cmd, Cmd::Config(args) if args.requires_pristine_startup()) {
      let Cmd::Config(args) = self.cmd else {
        unreachable!("the pristine startup predicate only matches config commands")
      };
      return config_cmd::run(cfg_path, args).await.map_err(Error::from);
    }
    if !is_inspect && !uses_v2_config {
      prepare_default_config_home(cfg_path.as_deref())?;
    }

    // Initialize logging *before* dispatching with the schema-aware settings:
    // legacy [logging] or native-v2 [service.logging]. If
    // config loading fails we fall back to a stderr-only emergency
    // subscriber so the resulting error still gets logged sanely.
    let mode = run_mode_for(&self.cmd);
    let _guard = match config_context::ConfigContext::load(cfg_path.as_deref()) {
      Ok(context) => {
        let mut logging_cfg = context.logging().clone();
        if is_inspect {
          logging_cfg.target = LogTarget::Stderr;
        }
        Some(logging::init(&logging_cfg, mode))
      }
      Err(_) => {
        logging::init_basic();
        None
      }
    };

    let r: anyhow::Result<()> = match self.cmd {
      Cmd::Account(c) => account::run(cfg_path, c).await,
      Cmd::Agent(c) => agent::run(cfg_path, c).await,
      Cmd::ApiKey(c) => api_key::run(c).await,
      Cmd::Headers(a) => headers::run(cfg_path, a).await,
      Cmd::Serve(a) => serve::run(cfg_path, a).await,
      Cmd::Proxy(a) => proxy::run(cfg_path, a).await,
      Cmd::Usage(a) => usage::run(cfg_path, a).await,
      Cmd::Inspect(a) => inspect::run(cfg_path, a).await,
      Cmd::Requests(c) => requests::run(cfg_path, c).await,
      Cmd::Sessions(c) => sessions::run(c).await,
      Cmd::Config(a) => config_cmd::run(cfg_path, a).await,
      Cmd::Update(a) => update::run(a).await,
      Cmd::Migration(a) => migration::run(cfg_path, a).await,
      Cmd::Smoke(c) => smoke::run_cmd(cfg_path, c).await,
    };
    r.map_err(Error::from)
  }
}

fn prepare_default_config_home(cfg_path: Option<&Path>) -> anyhow::Result<()> {
  if cfg_path.is_some() {
    return Ok(());
  }
  let Some(home) = tokn_core::util::paths::router_home() else {
    return Ok(());
  };
  let report = tokn_router_legacy_config::ensure_latest_home(&home)?;
  if !report.is_empty() {
    eprintln!("migrated legacy tokn-router config into {}", home.display());
  }
  Ok(())
}

/// Read-only subcommands keep stdout uncluttered by suppressing
/// info-level chatter from `tokn_router`. Mutating commands surface
/// progress at info; the long-running server gets full info logging.
fn run_mode_for(cmd: &Cmd) -> RunMode {
  use account::AccountCmd;
  use config_cmd::ConfigCmd::*;
  match cmd {
    Cmd::Serve(_) | Cmd::Proxy(_) => RunMode::Server,
    Cmd::Inspect(_) | Cmd::Requests(requests::RequestsCmd::Prune(requests::PruneArgs { commit: false })) => {
      RunMode::ReadOnlyCli
    }
    Cmd::Requests(requests::RequestsCmd::Prune(requests::PruneArgs { commit: true })) => RunMode::MutatingCli,
    Cmd::Update(_) | Cmd::Migration(_) => RunMode::MutatingCli,
    Cmd::Sessions(_) => RunMode::MutatingCli,
    Cmd::ApiKey(api_key::ApiKeyCmd::List) => RunMode::ReadOnlyCli,
    Cmd::ApiKey(api_key::ApiKeyCmd::Create(_) | api_key::ApiKeyCmd::Revoke { .. }) => RunMode::MutatingCli,
    Cmd::Agent(c) => match c {
      agent::AgentCmd::List | agent::AgentCmd::Show(_) => RunMode::ReadOnlyCli,
      agent::AgentCmd::Import(_) | agent::AgentCmd::Link(_) | agent::AgentCmd::Sync(_) | agent::AgentCmd::Unlink(_) => {
        RunMode::MutatingCli
      }
    },
    Cmd::Account(c) => match c {
      AccountCmd::List(_) | AccountCmd::Show(_) | AccountCmd::Status(_) => RunMode::ReadOnlyCli,
      AccountCmd::Add(_)
      | AccountCmd::Login(_)
      | AccountCmd::Import(_)
      | AccountCmd::Refresh { .. }
      | AccountCmd::Remove { .. }
      | AccountCmd::Switch(_) => RunMode::MutatingCli,
    },
    Cmd::Config(args) => match args.cmd {
      Set(_) | Unset(_) | Edit | Init(_) => RunMode::MutatingCli,
      _ => RunMode::ReadOnlyCli,
    },
    _ => RunMode::ReadOnlyCli,
  }
}
