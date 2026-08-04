//! `tokn-router migration` subcommand.
//!
//! Default mode is a dry-run: inspect configured DB files and their `.bak`
//! snapshots, then print current/latest versions and aggregate row counts.
//! `--commit` applies pending migrations; `--rollback` restores backups.

use crate::db::{migrate, requests, sessions::SessionsDb, usage::UsageDb};
use anyhow::Result;
use clap::Args;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct MigrationArgs {
  /// Restore each database from its `<path>.bak` snapshot.
  #[arg(long)]
  pub rollback: bool,

  /// Apply pending migrations. Without this flag, only prints a dry-run
  /// status report unless `--rollback` is supplied.
  #[arg(long)]
  pub commit: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, args: MigrationArgs) -> Result<()> {
  let config = super::command_config::CommandConfig::load(cfg_path.as_deref())?;
  let paths = config.persistence_paths()?;
  let usage_db = paths.usage_db;
  let sessions_db = paths.sessions_db;
  let requests_dir = paths.requests_dir;

  if args.rollback {
    rollback_one("usage", &usage_db)?;
    rollback_one("sessions", &sessions_db)?;
    for path in requests::day_files(&requests_dir)? {
      rollback_one("requests", &path)?;
    }
    return Ok(());
  }

  if !args.commit {
    println!("migration dry-run (use --commit to apply migrations, or --rollback to restore .bak files)");
    print_status("usage", &usage_db, crate::db::usage::latest_version())?;
    print_status("sessions", &sessions_db, crate::db::sessions::latest_version())?;
    for path in requests::day_files(&requests_dir)? {
      print_status("requests", &path, crate::db::requests::latest_version())?;
    }
    return Ok(());
  }

  apply_one("usage", &usage_db, |p| UsageDb::open(p).map(|_| ()))?;
  apply_one("sessions", &sessions_db, |p| SessionsDb::open(p).map(|_| ()))?;
  for path in requests::day_files(&requests_dir)? {
    apply_one("requests", &path, |p| requests::open_day_db(p).map(|_| ()))?;
  }
  Ok(())
}

fn print_status(label: &str, path: &Path, latest: u32) -> Result<()> {
  let current = inspect(path)?;
  let backup = inspect(&migrate::backup_path(path))?;
  println!(
    "{:<8} {:<48} current={} rows={} bak_current={} bak_rows={} latest={}",
    label,
    path.display(),
    version_text(current.version),
    count_text(current.rows),
    version_text(backup.version),
    count_text(backup.rows),
    latest,
  );
  Ok(())
}

fn inspect(path: &Path) -> Result<DbInfo> {
  if !path.exists() {
    return Ok(DbInfo {
      version: None,
      rows: None,
    });
  }
  let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
  Ok(DbInfo {
    version: Some(migrate::read_current_version(&conn)?),
    rows: Some(migrate::user_row_count(&conn)?),
  })
}

fn version_text(v: Option<u32>) -> String {
  v.map(|v| v.to_string()).unwrap_or_else(|| "missing".to_string())
}

fn count_text(v: Option<u64>) -> String {
  v.map(|v| v.to_string()).unwrap_or_else(|| "missing".to_string())
}

#[derive(Debug)]
struct DbInfo {
  version: Option<u32>,
  rows: Option<u64>,
}

fn apply_one(label: &str, path: &Path, open: impl FnOnce(&Path) -> crate::db::Result<()>) -> Result<()> {
  if !path.exists() && label != "requests" {
    println!("{label}: {} (not present, will be created)", path.display());
  }
  open(path)?;
  println!("{label}: {} ok", path.display());
  Ok(())
}

fn rollback_one(label: &str, path: &Path) -> Result<()> {
  let bak = migrate::backup_path(path);
  if !bak.exists() {
    println!("{label}: {} (no backup, skipped)", path.display());
    return Ok(());
  }
  let restored = migrate::rollback(path)?;
  if restored {
    println!("{label}: {} rolled back from {}", path.display(), bak.display());
  } else {
    println!("{label}: {} (no backup, skipped)", path.display());
  }
  Ok(())
}
