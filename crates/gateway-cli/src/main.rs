use clap::{CommandFactory, FromArgMatches};
use std::error::Error as StdError;
use std::process::ExitCode;

use tokn_config as config;
mod auth_registry;
mod cli;
use tokn_persistence as db;
mod error;
mod logging;
mod progress;
mod provider;
mod server_runtime;
mod util;

fn main() -> ExitCode {
  let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
    Ok(runtime) => runtime,
    Err(error) => {
      eprintln!("error: initialize async runtime: {error}");
      return ExitCode::FAILURE;
    }
  };
  let result = runtime.block_on(run());
  // The serving path already drained connections and persistence. Tokio's
  // default drop waits forever for spawn_blocking work, including a stuck
  // archive scan after the cleanup deadline, so bound this final wait too.
  runtime.shutdown_timeout(std::time::Duration::from_secs(1));
  result
}

async fn run() -> ExitCode {
  if let Err(e) = tokn_router::install_rustls_crypto_provider() {
    eprintln!("error: {e}");
    return ExitCode::FAILURE;
  }

  // The CLI installs its own subscriber once it has loaded config + decided
  // on a [`logging::RunMode`]. We do NOT call `logging::init_basic()` here
  // anymore: that races against the real subscriber.
  let parsed = parse_cli();
  match parsed.run().await {
    Ok(()) => ExitCode::SUCCESS,
    Err(e) => {
      report(&e);
      ExitCode::FAILURE
    }
  }
}

fn parse_cli() -> cli::Cli {
  let mut cmd = cli::Cli::command();
  cmd = cmd.version(tokn_core::util::version::full());
  let matches = cmd.get_matches();
  cli::Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

/// Print an error and its full source chain to stderr.
fn report(e: &dyn StdError) {
  eprintln!("error: {e}");
  let mut src = e.source();
  while let Some(s) = src {
    eprintln!("  caused by: {s}");
    src = s.source();
  }
}
