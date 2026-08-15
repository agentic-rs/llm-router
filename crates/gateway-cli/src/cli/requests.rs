use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tokn_persistence::archive::{PruneOutcome, PruneProgressEvent, PruneReport};

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
  let mut progress = PruneProgressDisplay::new(std::io::stdout().is_terminal());
  let result = tokn_persistence::archive::prune_request_dbs_with_progress(
    &paths.requests_dir,
    persistence.archive_extension(),
    persistence.prune_after_days(),
    args.commit,
    |event| progress.on_event(event),
  );
  progress.finish();
  let report = result?;

  print_report(&paths.requests_dir, &report, args.commit);
  let missing_archives = report
    .entries
    .iter()
    .filter(|entry| matches!(entry.outcome, PruneOutcome::MissingArchive))
    .count();
  let verification_failures = report
    .entries
    .iter()
    .filter(|entry| {
      matches!(
        entry.outcome,
        PruneOutcome::HashMismatch { .. } | PruneOutcome::Failed { .. }
      )
    })
    .count();
  let failures = missing_archives + verification_failures;
  if failures > 0 {
    bail!(
      "{failures} request database(s) were retained: {missing_archives} missing archive(s), \
       {verification_failures} verification failure(s)"
    );
  }
  Ok(())
}

struct PruneProgressDisplay {
  enabled: bool,
  multi: MultiProgress,
  file_bar: Option<ProgressBar>,
  global_bar: Option<ProgressBar>,
  file_style: ProgressStyle,
  global_style: ProgressStyle,
}

impl PruneProgressDisplay {
  fn new(enabled: bool) -> Self {
    Self::with_multi(enabled, crate::progress::multi().clone())
  }

  fn with_multi(enabled: bool, multi: MultiProgress) -> Self {
    Self {
      enabled,
      multi,
      file_bar: None,
      global_bar: None,
      file_style: ProgressStyle::with_template("{spinner:.cyan} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> "),
      global_style: ProgressStyle::with_template("{spinner:.green} {msg} [{wide_bar:.green/blue}] {pos}/{len}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> "),
    }
  }

  fn on_event(&mut self, event: PruneProgressEvent) {
    if !self.enabled {
      return;
    }
    match event {
      PruneProgressEvent::Started { files_total } => {
        let bar = self.multi.add(ProgressBar::new(files_total as u64));
        bar.set_style(self.global_style.clone());
        bar.set_message("request databases");
        self.global_bar = Some(bar);
      }
      PruneProgressEvent::FileStarted {
        path,
        file_index,
        files_total,
        bytes_total,
      } => {
        if let Some(bar) = self.file_bar.take() {
          bar.finish_and_clear();
        }
        let bar = if let Some(global_bar) = &self.global_bar {
          self.multi.insert_before(global_bar, ProgressBar::new(bytes_total))
        } else {
          self.multi.add(ProgressBar::new(bytes_total))
        };
        bar.set_style(self.file_style.clone());
        bar.set_message(format!(
          "verify {} {}/{}",
          prune_filename(&path),
          file_index + 1,
          files_total
        ));
        self.file_bar = Some(bar);
      }
      PruneProgressEvent::FileProgress {
        bytes_processed,
        bytes_total,
      } => {
        if let Some(bar) = &self.file_bar {
          bar.set_length(bytes_total.max(bytes_processed));
          bar.set_position(bytes_processed);
          bar.tick();
        }
      }
      PruneProgressEvent::FileFinished {
        path,
        file_index,
        files_total,
      } => {
        if let Some(bar) = self.file_bar.take() {
          bar.finish_and_clear();
        }
        if let Some(bar) = &self.global_bar {
          bar.set_position((file_index + 1) as u64);
          bar.set_message(format!(
            "processed {} {}/{}",
            prune_filename(&path),
            file_index + 1,
            files_total
          ));
          bar.tick();
        }
      }
      PruneProgressEvent::Finished { files_total } => {
        if let Some(bar) = &self.global_bar {
          bar.set_position(files_total as u64);
          bar.set_message("request databases processed");
        }
      }
    }
  }

  fn finish(&mut self) {
    if let Some(bar) = self.file_bar.take() {
      bar.finish_and_clear();
    }
    if let Some(bar) = self.global_bar.take() {
      bar.finish_and_clear();
    }
  }
}

fn prune_filename(path: &Path) -> String {
  path
    .file_name()
    .map(|name| name.to_string_lossy().into_owned())
    .unwrap_or_else(|| path.display().to_string())
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
    "summary: eligible={} verified={verified} deleted={deleted} retained={} missing_archive={missing} mismatched={mismatched} failed={failed}",
    report.entries.len(),
    missing + mismatched + failed
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
  use indicatif::ProgressDrawTarget;

  fn write_v2_config(directory: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let requests_dir = directory.path().join("requests");
    std::fs::create_dir(&requests_dir).unwrap();
    let config_path = directory.path().join("config.toml");
    let serialized_requests_dir = serde_json::to_string(&requests_dir).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../smoke.toml");
    let mut config = std::fs::read_to_string(fixture).unwrap();
    config.push_str(&format!(
      "\n[service.persistence]\nrequests_dir = {serialized_requests_dir}\narchive_extension = \"db.zstd\"\n"
    ));
    std::fs::write(&config_path, config).unwrap();
    (config_path, requests_dir)
  }

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

  #[test]
  fn progress_display_tracks_file_and_global_progress() {
    let multi = MultiProgress::with_draw_target(ProgressDrawTarget::hidden());
    let mut display = PruneProgressDisplay::with_multi(true, multi);
    let path = PathBuf::from("2026-05-01.db");

    display.on_event(PruneProgressEvent::Started { files_total: 1 });
    assert_eq!(display.global_bar.as_ref().and_then(ProgressBar::length), Some(1));
    display.on_event(PruneProgressEvent::FileStarted {
      path: path.clone(),
      file_index: 0,
      files_total: 1,
      bytes_total: 20,
    });
    display.on_event(PruneProgressEvent::FileProgress {
      bytes_processed: 10,
      bytes_total: 20,
    });
    assert_eq!(display.file_bar.as_ref().map(ProgressBar::position), Some(10));
    display.on_event(PruneProgressEvent::FileFinished {
      path,
      file_index: 0,
      files_total: 1,
    });
    assert!(display.file_bar.is_none());
    assert_eq!(display.global_bar.as_ref().map(ProgressBar::position), Some(1));
    display.on_event(PruneProgressEvent::Finished { files_total: 1 });
    display.finish();
    assert!(display.global_bar.is_none());
  }

  #[tokio::test]
  async fn prune_loads_v2_persistence_settings() {
    let directory = tempfile::tempdir().unwrap();
    let (config_path, _) = write_v2_config(&directory);

    run(Some(config_path), RequestsCmd::Prune(PruneArgs { commit: false }))
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn prune_default_cutoff_excludes_a_seven_day_database() {
    let directory = tempfile::tempdir().unwrap();
    let (config_path, requests_dir) = write_v2_config(&directory);
    let day = time::OffsetDateTime::now_utc().date() - time::Duration::days(7);
    let database = requests_dir.join(format!("{day}.db"));
    std::fs::write(&database, b"request database awaiting archive").unwrap();

    run(Some(config_path), RequestsCmd::Prune(PruneArgs { commit: false }))
      .await
      .unwrap();

    assert!(database.exists());
  }

  #[tokio::test]
  async fn prune_errors_and_distinguishes_missing_archives() {
    let directory = tempfile::tempdir().unwrap();
    let (config_path, requests_dir) = write_v2_config(&directory);
    std::fs::write(requests_dir.join("2000-01-01.db"), b"request database").unwrap();
    std::fs::write(requests_dir.join("2000-01-02.db"), b"another request database").unwrap();
    std::fs::write(requests_dir.join("2000-01-02.db.zstd"), b"corrupt archive").unwrap();

    let error = run(Some(config_path), RequestsCmd::Prune(PruneArgs { commit: false }))
      .await
      .unwrap_err();

    assert_eq!(
      error.to_string(),
      "2 request database(s) were retained: 1 missing archive(s), 1 verification failure(s)"
    );
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
