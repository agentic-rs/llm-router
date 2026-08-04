use crate::db::UsageDb;
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct UsageArgs {
  /// Time window, e.g. "24h", "7d", "30m". Default 24h.
  #[arg(long, default_value = "24h")]
  pub since: String,

  /// Filter by account id.
  #[arg(long)]
  pub account: Option<String>,

  /// Filter by provider id.
  #[arg(long)]
  pub provider: Option<String>,
}

pub async fn run(cfg_path: Option<PathBuf>, args: UsageArgs) -> Result<()> {
  let config = super::command_config::CommandConfig::load(cfg_path.as_deref())?;
  let path = config.persistence_paths()?.usage_db;
  let db = UsageDb::open(&path)?;

  let since: Duration = humantime::parse_duration(&args.since)?;
  let since_ts = time::OffsetDateTime::now_utc().unix_timestamp() - since.as_secs() as i64;

  let rows = db.summary(since_ts, args.account.as_deref(), args.provider.as_deref())?;
  if rows.is_empty() {
    println!("(no requests in window)");
    return Ok(());
  }
  println!(
    "{:<16}  {:<18}  {:<24}  {:<7}  {:>6}  {:>9}  {:>10}  {:>9}  {:>10}  {:>10}",
    "account", "provider", "model", "init", "calls", "input", "output", "cached", "reasoning", "avg_ms"
  );
  for r in rows {
    println!(
      "{:<16}  {:<18}  {:<24}  {:<7}  {:>6}  {:>9}  {:>10}  {:>9}  {:>10}  {:>10.0}",
      r.account,
      r.provider,
      r.model,
      r.initiator.as_deref().unwrap_or("unknown"),
      r.count,
      r.input_tokens,
      r.output_tokens,
      r.cached_tokens,
      r.reasoning_tokens,
      r.avg_latency_ms
    );
  }
  Ok(())
}
