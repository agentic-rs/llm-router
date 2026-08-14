use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use tokn_persistence::archive::{PruneOutcome, PruneReport};

#[derive(Subcommand, Debug)]
pub enum RequestsCmd {
  /// Verify archived request databases and remove matching source files.
  Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct PruneArgs {
  /// Delete SHA-256-verified source databases. Without this flag, only report candidates.
  #[arg(long)]
  pub commit: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, cmd: RequestsCmd) -> Result<()> {
  match cmd {
    RequestsCmd::Prune(args) => prune(cfg_path.as_deref(), args),
  }
}

fn prune(explicit_config: Option<&Path>, args: PruneArgs) -> Result<()> {
  let config_path = match explicit_config {
    Some(path) => path.to_path_buf(),
    None => tokn_config::paths::config_path()?,
  };
  let compiled = tokn_config::v2::load_config(&config_path)?;
  let persistence = compiled.service().persistence();
  let paths = persistence.resolve_paths()?;
  let report =
    tokn_persistence::archive::prune_request_dbs(&paths.requests_dir, persistence.archive_extension(), args.commit)?;

  print_report(&paths.requests_dir, &report, args.commit);
  let failures = report
    .entries
    .iter()
    .filter(|entry| {
      matches!(
        entry.outcome,
        PruneOutcome::HashMismatch { .. } | PruneOutcome::Failed { .. }
      )
    })
    .count();
  if failures > 0 {
    bail!("{failures} request database(s) could not be verified; unverified source files were retained");
  }
  Ok(())
}

fn print_report(requests_dir: &Path, report: &PruneReport, commit: bool) {
  println!("request database prune {}", if commit { "commit" } else { "dry-run" });
  println!("requests_dir={}", requests_dir.display());
  println!("cutoff={} (inclusive)", report.cutoff);

  let mut verified = 0usize;
  let mut deleted = 0usize;
  let mut missing = 0usize;
  let mut mismatched = 0usize;
  let mut failed = 0usize;
  for entry in &report.entries {
    match &entry.outcome {
      PruneOutcome::Verified { sha256 } => {
        verified += 1;
        println!(
          "verified {} -> {} sha256={sha256}",
          entry.path.display(),
          entry.archive.display()
        );
      }
      PruneOutcome::Deleted { sha256 } => {
        verified += 1;
        deleted += 1;
        println!(
          "deleted {} (archive={} sha256={sha256})",
          entry.path.display(),
          entry.archive.display()
        );
      }
      PruneOutcome::MissingArchive => {
        missing += 1;
        println!(
          "retained {} (archive missing: {})",
          entry.path.display(),
          entry.archive.display()
        );
      }
      PruneOutcome::HashMismatch {
        source_sha256,
        archived_sha256,
      } => {
        mismatched += 1;
        println!(
          "retained {} (sha256 mismatch: source={source_sha256} archived={archived_sha256})",
          entry.path.display()
        );
      }
      PruneOutcome::Failed { error } => {
        failed += 1;
        println!("retained {} (verification failed: {error})", entry.path.display());
      }
    }
  }
  println!(
    "summary: eligible={} verified={verified} deleted={deleted} missing_archive={missing} mismatched={mismatched} failed={failed}",
    report.entries.len()
  );
  if !commit && verified > 0 {
    println!("dry-run: rerun with --commit to delete verified source databases");
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::{Cli, Cmd};
  use clap::Parser;

  #[test]
  fn parses_prune_as_dry_run_by_default() {
    let cli = Cli::try_parse_from(["tokn-router", "requests", "prune"]).unwrap();
    let Cmd::Requests(RequestsCmd::Prune(args)) = cli.cmd else {
      panic!("expected requests prune command");
    };
    assert!(!args.commit);
  }

  #[test]
  fn parses_prune_commit() {
    let cli = Cli::try_parse_from(["tokn-router", "requests", "prune", "--commit"]).unwrap();
    let Cmd::Requests(RequestsCmd::Prune(args)) = cli.cmd else {
      panic!("expected requests prune command");
    };
    assert!(args.commit);
  }

  #[tokio::test]
  async fn prune_loads_v2_persistence_settings() {
    let directory = tempfile::tempdir().unwrap();
    let requests_dir = directory.path().join("requests");
    std::fs::create_dir(&requests_dir).unwrap();
    let config_path = directory.path().join("config.toml");
    let requests_dir = serde_json::to_string(&requests_dir).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../smoke.toml");
    let mut config = std::fs::read_to_string(fixture).unwrap();
    config.push_str(&format!(
      "\n[service.persistence]\nrequests_dir = {requests_dir}\narchive_extension = \"db.zstd\"\n"
    ));
    std::fs::write(&config_path, config).unwrap();

    run(Some(config_path), RequestsCmd::Prune(PruneArgs { commit: false }))
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn prune_rejects_legacy_config() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    std::fs::write(&config_path, "[db]\nenabled = true\n").unwrap();

    let error = run(Some(config_path), RequestsCmd::Prune(PruneArgs { commit: false }))
      .await
      .unwrap_err();

    assert!(error.to_string().contains("schema_version"));
  }
}
