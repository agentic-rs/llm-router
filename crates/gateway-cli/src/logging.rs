//! Tracing subscriber wiring.
//!
//! Resolution precedence for filter directive (high → low):
//! 1. `RUST_LOG` env var
//! 2. `[logging].level` (v1) or `[service.logging].level` (v2) from config
//! 3. Per-[`RunMode`] default
//!
//! Output composition is config-driven via [`crate::config::LoggingConfig`]:
//! - `target = stderr`: pretty/compact/json layer to stderr
//! - `target = file`: rotating daily file in `dir` (or `<state>/logs/`)
//! - `target = both` *(default)*: stderr + rotating file
//!
//! File output uses [`tracing_appender::rolling::daily`] with names like
//! `tokn-router.log.2026-04-28`. The returned [`Guard`] must outlive the
//! process-wide subscriber; drop it during shutdown to flush.

use crate::config::{LogFormat, LogTarget, LoggingConfig};
use std::io::{self, Write};
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Determines the default log filter applied when neither env nor config
/// provide one — also lets read-only CLI subcommands suppress info-level
/// noise from `tokn_router`.
#[derive(Copy, Clone, Debug)]
pub enum RunMode {
  /// Long-running server process: full info-level logging.
  Server,
  /// Read-only CLI subcommand (account ls, usage stats, config get).
  /// Suppresses our own info-level chatter to keep stdout clean.
  ReadOnlyCli,
  /// Mutating CLI subcommand (login, import, config set).
  MutatingCli,
}

impl RunMode {
  fn default_directive(self) -> &'static str {
    match self {
      RunMode::Server => "info,tokn_router=info",
      RunMode::ReadOnlyCli => "warn,tokn_router=warn",
      RunMode::MutatingCli => "warn,tokn_router=info",
    }
  }
}

/// Opaque flush guard for the rolling-file appender. Drop on shutdown.
pub struct Guard {
  _file: Option<WorkerGuard>,
  _stderr: Option<WorkerGuard>,
}

/// Initialize the global tracing subscriber from config + run-mode.
///
/// Safe to call exactly once per process; subsequent calls return a no-op
/// guard because [`SubscriberInitExt::init`] panics on second use.
pub fn init(cfg: &LoggingConfig, mode: RunMode) -> Guard {
  let filter = build_filter(cfg, mode);

  let stderr_layer = match cfg.target {
    LogTarget::Stderr | LogTarget::Both => Some(make_layer(cfg, SuspendingStderr, cfg.ansi)),
    LogTarget::File => None,
  };

  let (file_layer, file_guard) = match cfg.target {
    LogTarget::File | LogTarget::Both => match resolve_logs_dir(cfg) {
      Ok(dir) => match std::fs::create_dir_all(&dir) {
        Ok(()) => {
          let appender = tracing_appender::rolling::daily(&dir, "tokn-router.log");
          let (nb, g) = tracing_appender::non_blocking(appender);
          (Some(make_layer(cfg, nb, false)), Some(g))
        }
        Err(e) => {
          eprintln!("warning: failed to create log dir {dir:?}: {e} (file logging disabled)");
          (None, None)
        }
      },
      Err(e) => {
        eprintln!("warning: cannot resolve log dir: {e} (file logging disabled)");
        (None, None)
      }
    },
    LogTarget::Stderr => (None, None),
  };

  tracing_subscriber::registry()
    .with(filter)
    .with(stderr_layer)
    .with(file_layer)
    .init();

  Guard {
    _file: file_guard,
    _stderr: None,
  }
}

/// Minimal stderr-only subscriber for early-startup diagnostics (before
/// the config is loaded). Honors `RUST_LOG`; never panics.
pub fn init_basic() {
  let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tokn_router=info"));
  let _ = tracing_subscriber::fmt()
    .with_writer(std::io::stderr)
    .with_env_filter(filter)
    .try_init();
}

pub(crate) fn build_filter(cfg: &LoggingConfig, mode: RunMode) -> EnvFilter {
  if let Ok(env) = std::env::var("RUST_LOG") {
    if !env.is_empty() {
      if let Ok(f) = EnvFilter::try_new(&env) {
        return f;
      }
    }
  }
  if !cfg.level.is_empty() {
    if let Ok(f) = EnvFilter::try_new(&cfg.level) {
      return f;
    }
  }
  EnvFilter::new(mode.default_directive())
}

fn make_layer<S, W>(cfg: &LoggingConfig, writer: W, ansi: bool) -> Box<dyn Layer<S> + Send + Sync + 'static>
where
  S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
  W: for<'a> fmt::MakeWriter<'a> + Send + Sync + 'static,
{
  // Span events: closed by default for low overhead, open+close if requested.
  let span_events = if cfg.include_spans {
    fmt::format::FmtSpan::NEW | fmt::format::FmtSpan::CLOSE
  } else {
    fmt::format::FmtSpan::NONE
  };

  match cfg.format {
    LogFormat::Pretty => fmt::layer()
      .with_writer(writer)
      .with_ansi(ansi)
      .with_span_events(span_events)
      .pretty()
      .boxed(),
    LogFormat::Compact => fmt::layer()
      .with_writer(writer)
      .with_ansi(ansi)
      .with_span_events(span_events)
      .compact()
      .boxed(),
    LogFormat::Json => fmt::layer()
      .with_writer(writer)
      .with_ansi(false)
      .with_span_events(span_events)
      .json()
      .boxed(),
  }
}

pub(crate) fn resolve_logs_dir(cfg: &LoggingConfig) -> Result<PathBuf, String> {
  if let Some(d) = &cfg.dir {
    return Ok(d.clone());
  }
  crate::config::paths::default_logs_dir().map_err(|e| e.to_string())
}

/// `MakeWriter` that emits each log record to stderr, but wraps the
/// write inside `MultiProgress::suspend` so any active indicatif bars
/// (rendered on stdout) are temporarily cleared during emission and
/// redrawn afterwards. Avoids visible garbling when bars and logs are
/// active in the same terminal.
#[derive(Clone, Copy)]
struct SuspendingStderr;

/// Per-emission buffer. tracing-subscriber's fmt layer writes the full
/// formatted line via repeated `write` calls and a final `flush`. We
/// accumulate into the buffer and emit atomically on `flush` (or on
/// `drop` as a safety net).
struct SuspendingWriter {
  buf: Vec<u8>,
}

impl Write for SuspendingWriter {
  fn write(&mut self, data: &[u8]) -> io::Result<usize> {
    self.buf.extend_from_slice(data);
    Ok(data.len())
  }

  fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
    self.buf.extend_from_slice(data);
    Ok(())
  }

  fn flush(&mut self) -> io::Result<()> {
    if self.buf.is_empty() {
      return Ok(());
    }
    let buf = std::mem::take(&mut self.buf);
    crate::progress::multi().suspend(|| {
      let mut err = io::stderr().lock();
      let _ = err.write_all(&buf);
      let _ = err.flush();
    });
    Ok(())
  }
}

impl Drop for SuspendingWriter {
  fn drop(&mut self) {
    let _ = self.flush();
  }
}

impl<'a> fmt::MakeWriter<'a> for SuspendingStderr {
  type Writer = SuspendingWriter;
  fn make_writer(&'a self) -> Self::Writer {
    SuspendingWriter { buf: Vec::new() }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Run filter-precedence checks sequentially in one `#[test]` because
  /// they mutate the process-wide `RUST_LOG` env var.
  #[test]
  fn filter_precedence_env_then_config_then_default() {
    let mut cfg = LoggingConfig::default();

    // 1. RUST_LOG wins.
    std::env::set_var("RUST_LOG", "trace,tokn_router=trace");
    cfg.level = "warn,tokn_router=warn".into();
    let f = build_filter(&cfg, RunMode::Server);
    assert!(format!("{f}").contains("trace"), "env should win: {f}");

    // 2. Config level wins over RunMode default when env is unset.
    std::env::remove_var("RUST_LOG");
    cfg.level = "warn,tokn_router=debug".into();
    let f = build_filter(&cfg, RunMode::Server);
    let s = format!("{f}");
    assert!(s.contains("tokn_router=debug"), "config should win: {s}");

    // 3. RunMode default applies when both env and config are empty/unset.
    cfg.level = String::new();
    let f = build_filter(&cfg, RunMode::ReadOnlyCli);
    let s = format!("{f}");
    assert!(s.contains("tokn_router=warn"), "run-mode default: {s}");

    // 4. Malformed env directive falls through to config.
    std::env::set_var("RUST_LOG", "this is not a filter ===");
    cfg.level = "info,tokn_router=info".into();
    let f = build_filter(&cfg, RunMode::Server);
    let s = format!("{f}");
    assert!(s.contains("tokn_router=info"), "fallback on bad env: {s}");

    std::env::remove_var("RUST_LOG");
  }
}
