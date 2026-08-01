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

#[tokio::main]
async fn main() -> ExitCode {
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
