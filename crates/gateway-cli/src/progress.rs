//! Shared terminal progress surface and request lifecycle display.

use console::{style, StyledObject};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokn_events::{
  AttemptFinished, AttemptNo, AttemptStarted, BodyLeg, BodyOutcome, BodyResult, ConsumerResult, EventConsumer,
  EventSeq, GatewayEvent, RequestAdmitted, RequestFinished, RequestOutcome, RequestStarted, TokenUsage, TrafficEvent,
  TrafficEventKind,
};
use tokn_persistence::archive::{ArchiveEvent, ArchiveEventHandler};

static MULTI: OnceLock<MultiProgress> = OnceLock::new();

/// Returns the process-wide progress surface shared by interactive commands
/// and the tracing writer.
pub fn multi() -> &'static MultiProgress {
  MULTI.get_or_init(|| MultiProgress::with_draw_target(ProgressDrawTarget::stdout()))
}

#[derive(Debug)]
struct RequestState {
  provider: String,
  model: String,
  account: String,
  endpoint: String,
  attempt: Option<AttemptNo>,
  sent_bytes: u64,
  recv_bytes: u64,
  usage: TokenUsage,
  final_status: Option<u16>,
  error: Option<String>,
  elapsed_ms: u64,
}

impl RequestState {
  fn new(started: &RequestStarted, elapsed_ms: u64) -> Self {
    Self {
      provider: String::new(),
      model: String::new(),
      account: String::new(),
      endpoint: initial_endpoint(started),
      attempt: None,
      sent_bytes: 0,
      recv_bytes: 0,
      usage: TokenUsage::default(),
      final_status: None,
      error: None,
      elapsed_ms,
    }
  }

  fn id_short(request_id: &str) -> String {
    request_id.chars().take(8).collect()
  }

  fn render_in_flight(&self, request_id: &str) -> String {
    let elapsed = self.elapsed_ms as f64 / 1_000.0;
    let speed_kbs = if self.elapsed_ms > 50 {
      self.recv_bytes as f64 / 1024.0 / elapsed
    } else {
      0.0
    };
    let attempt_part = self
      .attempt
      .map(AttemptNo::get)
      .and_then(|attempt| attempt.checked_sub(1))
      .filter(|retry| *retry > 0)
      .map(|retry| format!(" {}", style(format!("a={retry}")).yellow()))
      .unwrap_or_default();
    format!(
      "[{}] {} {} {}{} {} sent={:.1}kB recv={:.1}kB {:.1}kB/s elapsed={:.1}s",
      style(Self::id_short(request_id)).dim(),
      style(&self.provider).blue(),
      style(truncate(&self.model, 28)).cyan(),
      style(truncate(&self.account, 16)).magenta(),
      attempt_part,
      style(&self.endpoint).dim(),
      self.sent_bytes as f64 / 1024.0,
      self.recv_bytes as f64 / 1024.0,
      speed_kbs,
      elapsed,
    )
  }

  fn render_completed(&self, request_id: &str, finished: &RequestFinished) -> String {
    let id_short = Self::id_short(request_id);
    let latency_s = self.elapsed_ms as f64 / 1_000.0;
    let attempts_part = if finished.attempt_count > 1 {
      format!(" attempts={}", finished.attempt_count)
    } else {
      String::new()
    };
    let status_part = self
      .final_status
      .map(|status| format!(" {}", style_status(status)))
      .unwrap_or_default();

    if matches!(finished.outcome, RequestOutcome::Delivered) {
      format!(
        "[{}] {}{} {} {} {} {} sent={:.1}kB recv={:.1}kB{} latency={:.1}s{}",
        style(&id_short).dim(),
        style("✓").green().bold(),
        status_part,
        style(&self.provider).blue(),
        style(truncate(&self.model, 28)).cyan(),
        style(truncate(&self.account, 16)).magenta(),
        style(&self.endpoint).dim(),
        self.sent_bytes as f64 / 1024.0,
        self.recv_bytes as f64 / 1024.0,
        format_usage(&self.usage),
        latency_s,
        attempts_part,
      )
    } else {
      let error = self.error.as_deref().unwrap_or("failed");
      format!(
        "[{}] {}{} {} {} {} {} sent={:.1}kB recv={:.1}kB latency={:.1}s{} error={}",
        style(&id_short).dim(),
        style("✗").red().bold(),
        status_part,
        style(&self.provider).blue(),
        style(truncate(&self.model, 28)).cyan(),
        style(truncate(&self.account, 16)).magenta(),
        style(&self.endpoint).dim(),
        self.sent_bytes as f64 / 1024.0,
        self.recv_bytes as f64 / 1024.0,
        latency_s,
        attempts_part,
        style(truncate(error, 80)).red(),
      )
    }
  }

  fn render_interrupted(&self, request_id: &str) -> String {
    let model_part = if self.model.is_empty() {
      String::new()
    } else {
      format!(" {}", style(truncate(&self.model, 28)).cyan())
    };
    let account_part = if self.account.is_empty() {
      String::new()
    } else {
      format!(" {}", style(truncate(&self.account, 16)).magenta())
    };
    format!(
      "[{}] {}{}{} sent={:.1}kB recv={:.1}kB elapsed={:.1}s",
      style(Self::id_short(request_id)).dim(),
      style("⚠ interrupted").yellow().bold(),
      model_part,
      account_part,
      self.sent_bytes as f64 / 1024.0,
      self.recv_bytes as f64 / 1024.0,
      self.elapsed_ms as f64 / 1_000.0,
    )
  }

  fn observe(&mut self, event: &TrafficEvent) {
    self.elapsed_ms = event.elapsed_ms;
    match &event.kind {
      TrafficEventKind::Admitted(admitted) => self.observe_admitted(admitted),
      TrafficEventKind::RequestBody(body) => {
        if let Some(model) = &body.requested_model {
          self.model = model.to_string();
        }
        if let BodyOutcome::Rejected(failure) = &body.outcome {
          self.error = Some(failure.message.to_string());
        }
      }
      TrafficEventKind::AttemptStarted(started) => self.begin_attempt(started),
      TrafficEventKind::AttemptRequest(request) if self.is_current_attempt(request.attempt) => {
        self.sent_bytes = request.request.body.bytes_seen();
      }
      TrafficEventKind::AttemptResponseHead(response) if self.is_current_attempt(response.attempt) => {
        self.final_status = Some(response.response.status);
      }
      TrafficEventKind::BodyProgress(progress) => {
        if matches!(progress.leg, BodyLeg::Downstream) {
          self.recv_bytes = progress.bytes_seen;
        }
      }
      TrafficEventKind::BodyFinished(body) => {
        match body.leg {
          BodyLeg::Downstream => self.recv_bytes = self.recv_bytes.max(body.capture.bytes_seen()),
          BodyLeg::Upstream { attempt } if !self.is_current_attempt(attempt) => return,
          BodyLeg::Upstream { .. } => {}
          _ => {}
        }
        self.observe_body_result(&body.result);
      }
      TrafficEventKind::DownstreamResponseHead(response) => {
        self.final_status = Some(response.status);
      }
      TrafficEventKind::AttemptUsage(usage) if self.is_current_attempt(usage.attempt) => {
        self.usage.merge_from(&usage.usage);
      }
      TrafficEventKind::AttemptFinished(finished) if self.is_current_attempt(finished.attempt) => {
        self.observe_attempt_finished(finished);
      }
      TrafficEventKind::ConnectReady(ready) => {
        self.endpoint = format!("CONNECT {}", ready.authority);
      }
      TrafficEventKind::ConnectClosed(closed) => {
        if let Some(bytes) = closed.client_to_upstream_bytes {
          self.sent_bytes = bytes;
        }
        if let Some(bytes) = closed.upstream_to_client_bytes {
          self.recv_bytes = bytes;
        }
        self.observe_body_result(&closed.result);
      }
      _ => {}
    }
  }

  fn observe_admitted(&mut self, admitted: &RequestAdmitted) {
    match admitted {
      RequestAdmitted::Http {
        path_and_query,
        operation,
        ..
      } => {
        self.endpoint = operation
          .as_deref()
          .filter(|operation| !operation.trim().is_empty())
          .unwrap_or_else(|| path_and_query.as_str())
          .to_string();
      }
      RequestAdmitted::Connect { authority } => {
        self.endpoint = format!("CONNECT {authority}");
      }
      _ => {}
    }
  }

  fn begin_attempt(&mut self, started: &AttemptStarted) {
    if self.attempt.is_some_and(|attempt| attempt > started.attempt) {
      return;
    }
    self.attempt = Some(started.attempt);
    self.provider = started.target.provider_id.as_deref().unwrap_or_default().to_string();
    self.account = started.target.account_id.as_deref().unwrap_or_default().to_string();
    if let Some(model) = &started.target.requested_model {
      self.model = model.to_string();
    } else if self.model.is_empty() {
      if let Some(model) = &started.target.upstream_model {
        self.model = model.to_string();
      }
    }
    if let Some(operation) = &started.target.requested_operation {
      self.endpoint = operation.to_string();
    } else if self.endpoint.is_empty() {
      if let Some(operation) = &started.target.upstream_operation {
        self.endpoint = operation.to_string();
      }
    }
    self.sent_bytes = 0;
    self.recv_bytes = 0;
    self.usage = TokenUsage::default();
    self.final_status = None;
    self.error = None;
  }

  fn observe_attempt_finished(&mut self, finished: &AttemptFinished) {
    if let Some(status) = finished.upstream_status {
      self.final_status = Some(status);
    }
    if let Some(failure) = &finished.failure {
      self.error = Some(failure.message.to_string());
    } else if let Some(retry) = &finished.retry {
      self.error = Some(retry.reason.message.to_string());
    }
  }

  fn observe_body_result(&mut self, result: &BodyResult) {
    match result {
      BodyResult::Complete => {}
      BodyResult::Failed(failure) => self.error = Some(failure.message.to_string()),
      BodyResult::Cancelled => self.error = Some("cancelled".to_string()),
      _ => {}
    }
  }

  fn is_current_attempt(&self, attempt: AttemptNo) -> bool {
    self.attempt == Some(attempt)
  }
}

struct BarState {
  bar: ProgressBar,
  request: RequestState,
}

/// Interactive request lifecycle display used by the gateway CLI.
///
/// The public event contract remains presentation-neutral; this consumer folds
/// stable traffic observations into the historical terminal layout.
pub struct ProgressEventHandler {
  multi: MultiProgress,
  bars: HashMap<tokn_events::RequestId, BarState>,
  style: ProgressStyle,
  footer: ProgressBar,
  in_flight: u64,
  completed: u64,
  errors: u64,
  finished: bool,
}

impl ProgressEventHandler {
  pub fn new() -> Self {
    Self::with_multi(multi().clone())
  }

  fn with_multi(multi: MultiProgress) -> Self {
    let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
      .unwrap_or_else(|_| ProgressStyle::default_spinner())
      .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
    let footer = multi.add(ProgressBar::new_spinner());
    footer.set_style(ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_spinner()));

    let handler = Self {
      multi,
      bars: HashMap::new(),
      style,
      footer,
      in_flight: 0,
      completed: 0,
      errors: 0,
      finished: false,
    };
    handler.refresh_footer();
    handler
  }

  fn handle_traffic(&mut self, event: &TrafficEvent) {
    if self.finished {
      return;
    }
    match &event.kind {
      TrafficEventKind::Started(started) => self.start_request(event, started),
      TrafficEventKind::Finished(finished) => self.finish_request(event, finished),
      _ => {
        if let Some(state) = self.bars.get_mut(&event.request_id) {
          state.request.observe(event);
        }
        self.refresh(&event.request_id);
      }
    }
  }

  fn start_request(&mut self, event: &TrafficEvent, started: &RequestStarted) {
    if let Some(state) = self.bars.get_mut(&event.request_id) {
      state.request.elapsed_ms = event.elapsed_ms;
      self.refresh(&event.request_id);
      return;
    }

    let bar = self.multi.insert_before(&self.footer, ProgressBar::new_spinner());
    bar.set_style(self.style.clone());
    bar.enable_steady_tick(Duration::from_millis(120));
    self.bars.insert(
      event.request_id.clone(),
      BarState {
        bar,
        request: RequestState::new(started, event.elapsed_ms),
      },
    );
    self.in_flight = self.in_flight.saturating_add(1);
    self.refresh(&event.request_id);
    self.refresh_footer();
  }

  fn finish_request(&mut self, event: &TrafficEvent, finished: &RequestFinished) {
    let Some(mut state) = self.bars.remove(&event.request_id) else {
      return;
    };
    state.request.elapsed_ms = event.elapsed_ms;
    if let Some(status) = finished.downstream_status {
      state.request.final_status = Some(status);
    }
    if let Some(failure) = &finished.failure {
      state.request.error = Some(failure.message.to_string());
    } else if matches!(finished.outcome, RequestOutcome::Cancelled) {
      state.request.error = Some("cancelled".to_string());
    }

    let line = state.request.render_completed(event.request_id.as_str(), finished);
    state.bar.disable_steady_tick();
    let _ = self.multi.println(line);
    state.bar.finish_and_clear();
    self.in_flight = self.in_flight.saturating_sub(1);
    self.completed = self.completed.saturating_add(1);
    if !matches!(finished.outcome, RequestOutcome::Delivered) {
      self.errors = self.errors.saturating_add(1);
    }
    self.refresh_footer();
  }

  fn refresh(&self, request_id: &tokn_events::RequestId) {
    if let Some(state) = self.bars.get(request_id) {
      state
        .bar
        .set_message(state.request.render_in_flight(request_id.as_str()));
      state.bar.tick();
    }
  }

  fn refresh_footer(&self) {
    let errors_part = if self.errors > 0 {
      format!("errors={}", style(self.errors).red())
    } else {
      format!("errors={}", self.errors)
    };
    self.footer.set_message(format!(
      "─── in-flight={} completed={} {} ───",
      style(self.in_flight).bold(),
      style(self.completed).green(),
      errors_part,
    ));
    self.footer.tick();
  }

  fn finish_session(&mut self) {
    if self.finished {
      return;
    }
    self.finished = true;
    let stragglers = self.bars.drain().collect::<Vec<_>>();
    for (request_id, state) in stragglers {
      let _ = self
        .multi
        .println(state.request.render_interrupted(request_id.as_str()));
      state.bar.disable_steady_tick();
      state.bar.finish_and_clear();
    }

    let interrupted_part = if self.in_flight > 0 {
      format!(" interrupted={}", style(self.in_flight).yellow())
    } else {
      String::new()
    };
    let errors_part = if self.errors > 0 {
      format!("errors={}", style(self.errors).red())
    } else {
      format!("errors={}", self.errors)
    };
    let _ = self.multi.println(format!(
      "─── session ended: completed={} {}{} ───",
      style(self.completed).green(),
      errors_part,
      interrupted_part,
    ));
    self.footer.finish_and_clear();
  }
}

impl Default for ProgressEventHandler {
  fn default() -> Self {
    Self::new()
  }
}

impl EventConsumer<GatewayEvent> for ProgressEventHandler {
  fn name(&self) -> &str {
    "cli.request_progress"
  }

  fn handle(&mut self, _sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
    if let GatewayEvent::Traffic(event) = event {
      self.handle_traffic(event);
    }
    Ok(())
  }

  // Hub flush barriers are not terminal. Final scrollback and interruption
  // summaries are emitted from Drop when the dispatcher releases consumers.
  fn flush(&mut self) -> ConsumerResult {
    Ok(())
  }
}

impl Drop for ProgressEventHandler {
  fn drop(&mut self) {
    self.finish_session();
  }
}

struct ArchiveBarState {
  bar: ProgressBar,
  started: Instant,
  path: PathBuf,
  archive: PathBuf,
  total_bytes: u64,
}

/// Interactive progress display for the compatibility request-DB archiver.
///
/// This shares the process-wide [`MultiProgress`] with request rendering so
/// archive scans never garble active request bars.
pub struct ArchiveProgressEventHandler {
  multi: MultiProgress,
  bars: HashMap<String, ArchiveBarState>,
  style: ProgressStyle,
}

impl ArchiveProgressEventHandler {
  pub fn new() -> Self {
    Self::with_multi(multi().clone())
  }

  fn with_multi(multi: MultiProgress) -> Self {
    let style = ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap_or_else(|_| ProgressStyle::default_spinner())
      .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
    Self {
      multi,
      bars: HashMap::new(),
      style,
    }
  }

  fn refresh(&self, id: &str, bytes_read: u64, total_bytes: u64) {
    if let Some(state) = self.bars.get(id) {
      let percent = if total_bytes > 0 {
        (bytes_read as f64 * 100.0) / total_bytes as f64
      } else {
        100.0
      };
      let elapsed = state.started.elapsed().as_secs_f64();
      let speed_kbs = if elapsed > 0.05 {
        bytes_read as f64 / 1024.0 / elapsed
      } else {
        0.0
      };
      state.bar.set_message(format!(
        "archive {} {:.1}% {:.1}/{:.1}MB {:.1}kB/s -> {}",
        style(file_label(&state.path)).yellow(),
        percent.min(100.0),
        bytes_read as f64 / 1024.0 / 1024.0,
        state.total_bytes as f64 / 1024.0 / 1024.0,
        speed_kbs,
        style(file_label(&state.archive)).dim(),
      ));
      state.bar.tick();
    }
  }
}

impl Default for ArchiveProgressEventHandler {
  fn default() -> Self {
    Self::new()
  }
}

impl ArchiveEventHandler for ArchiveProgressEventHandler {
  fn handle(&mut self, event: &ArchiveEvent) {
    match event {
      ArchiveEvent::ScanStarted { dir } => {
        tracing::debug!(path = %dir.display(), "request db archival progress scan started");
      }
      ArchiveEvent::FileStarted {
        id,
        path,
        archive,
        total_bytes,
      } => {
        let bar = self.multi.add(ProgressBar::new_spinner());
        bar.set_style(self.style.clone());
        bar.enable_steady_tick(Duration::from_millis(120));
        self.bars.insert(
          id.clone(),
          ArchiveBarState {
            bar,
            started: Instant::now(),
            path: path.clone(),
            archive: archive.clone(),
            total_bytes: *total_bytes,
          },
        );
        self.refresh(id, 0, *total_bytes);
      }
      ArchiveEvent::FileProgress {
        id,
        bytes_read,
        total_bytes,
      } => self.refresh(id, *bytes_read, *total_bytes),
      ArchiveEvent::FileCompleted {
        id,
        path,
        archive,
        bytes_in,
        bytes_out,
      } => {
        if let Some(state) = self.bars.remove(id) {
          state.bar.disable_steady_tick();
          state.bar.finish_and_clear();
        }
        let ratio = if *bytes_in > 0 {
          (*bytes_out as f64 * 100.0) / *bytes_in as f64
        } else {
          0.0
        };
        let _ = self.multi.println(format!(
          "{} archived {} -> {} {:.1}MB to {:.1}MB ({:.1}%)",
          style("✓").green().bold(),
          style(file_label(path)).yellow(),
          style(file_label(archive)).dim(),
          *bytes_in as f64 / 1024.0 / 1024.0,
          *bytes_out as f64 / 1024.0 / 1024.0,
          ratio,
        ));
      }
      ArchiveEvent::FileSkipped { path, archive } => {
        tracing::debug!(path = %path.display(), archive = %archive.display(), "request db archive already exists");
      }
      ArchiveEvent::FileFailed {
        id,
        path,
        archive,
        error,
      } => {
        if let Some(state) = self.bars.remove(id) {
          state.bar.disable_steady_tick();
          state.bar.finish_and_clear();
        }
        let _ = self.multi.println(format!(
          "{} archive {} -> {} failed: {}",
          style("✗").red().bold(),
          style(file_label(path)).yellow(),
          style(file_label(archive)).dim(),
          style(truncate(error, 120)).red(),
        ));
      }
      ArchiveEvent::ScanCompleted { dir, stats } => {
        tracing::debug!(path = %dir.display(), archived = stats.archived, skipped_existing = stats.skipped_existing, failed = stats.failed, "request db archival progress scan completed");
      }
    }
  }

  fn flush(&mut self) {
    let bars = self.bars.drain().map(|(_, state)| state).collect::<Vec<_>>();
    for state in bars {
      let _ = self.multi.println(format!(
        "{} archive {} interrupted",
        style("⚠").yellow().bold(),
        style(file_label(&state.path)).yellow(),
      ));
      state.bar.disable_steady_tick();
      state.bar.finish_and_clear();
    }
  }
}

fn initial_endpoint(started: &RequestStarted) -> String {
  let target = started.target.as_str().trim();
  if started.method.eq_ignore_ascii_case("CONNECT") {
    if target.is_empty() {
      "CONNECT".to_string()
    } else {
      format!("CONNECT {target}")
    }
  } else if target.is_empty() {
    "unknown".to_string()
  } else {
    target.to_string()
  }
}

fn file_label(path: &Path) -> String {
  path
    .file_name()
    .and_then(|value| value.to_str())
    .unwrap_or_else(|| path.to_str().unwrap_or("unknown"))
    .to_string()
}

fn truncate(value: &str, max_chars: usize) -> Cow<'_, str> {
  if value.chars().count() <= max_chars {
    Cow::Borrowed(value)
  } else {
    Cow::Owned(value.chars().take(max_chars).collect())
  }
}

fn style_status(status: u16) -> StyledObject<u16> {
  match status {
    200..=299 => style(status).green(),
    300..=399 => style(status).cyan(),
    400..=499 => style(status).yellow(),
    500..=599 => style(status).red(),
    _ => style(status),
  }
}

fn format_usage(usage: &TokenUsage) -> String {
  let mut parts = Vec::with_capacity(6);
  for (label, value) in [
    ("in", usage.input),
    ("out", usage.output),
    ("total", usage.total),
    ("cache_read", usage.cache_read),
    ("cache_write", usage.cache_write),
    ("reason", usage.reasoning),
  ] {
    if let Some(value) = value.filter(|value| *value > 0) {
      parts.push(format!("{label}={value}"));
    }
  }
  if parts.is_empty() {
    String::new()
  } else {
    format!(" {}", parts.join(" "))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use console::strip_ansi_codes;
  use tokn_events::{
    AttemptHttpRequest, AttemptHttpResponseHead, AttemptOutcome, AttemptUsage, BodyCapture, BodyProgress,
    CaptureOmission, CapturedHeaders, CapturedUri, ConnectAction, ConnectClosed, ConnectReady, Correlation,
    EventFailure, HttpFamily, HttpRequestSnapshot, HttpResponseHead, RequestBodyObservation, RequestPhase,
    RequestSource, RetryDecision, TargetSelection, UsageKind,
  };

  const REQUEST_ID: &str = "request-123456";

  fn hidden_handler() -> ProgressEventHandler {
    ProgressEventHandler::with_multi(MultiProgress::with_draw_target(ProgressDrawTarget::hidden()))
  }

  fn hidden_archive_handler() -> ArchiveProgressEventHandler {
    ArchiveProgressEventHandler::with_multi(MultiProgress::with_draw_target(ProgressDrawTarget::hidden()))
  }

  fn plain(value: &str) -> String {
    strip_ansi_codes(value).into_owned()
  }

  fn request_id() -> tokn_events::RequestId {
    tokn_events::RequestId::new(REQUEST_ID).unwrap()
  }

  fn emit(handler: &mut ProgressEventHandler, sequence: u64, elapsed_ms: u64, kind: TrafficEventKind) {
    handler
      .handle(
        EventSeq::ZERO,
        &GatewayEvent::Traffic(TrafficEvent {
          request_id: request_id(),
          sequence,
          at_unix_ms: sequence as i64,
          elapsed_ms,
          kind,
        }),
      )
      .unwrap();
  }

  #[test]
  fn archive_progress_preserves_the_historical_transfer_layout() {
    let mut handler = hidden_archive_handler();
    let path = PathBuf::from("/tmp/requests/2026-07-01.db");
    let archive = PathBuf::from("/tmp/requests/2026-07-01.db.zstd");
    handler.handle(&ArchiveEvent::FileStarted {
      id: "archive-1".to_string(),
      path: path.clone(),
      archive: archive.clone(),
      total_bytes: 2 * 1024 * 1024,
    });
    handler.handle(&ArchiveEvent::FileProgress {
      id: "archive-1".to_string(),
      bytes_read: 1024 * 1024,
      total_bytes: 2 * 1024 * 1024,
    });

    let message = handler.bars["archive-1"].bar.message();
    let message = plain(message.as_ref());
    assert!(
      message.starts_with("archive 2026-07-01.db 50.0% 1.0/2.0MB"),
      "{message}"
    );
    assert!(message.ends_with("-> 2026-07-01.db.zstd"), "{message}");

    handler.handle(&ArchiveEvent::FileCompleted {
      id: "archive-1".to_string(),
      path,
      archive,
      bytes_in: 2 * 1024 * 1024,
      bytes_out: 1024 * 1024,
    });
    assert!(handler.bars.is_empty());
  }

  #[test]
  fn archive_progress_flush_clears_interrupted_transfers() {
    let mut handler = hidden_archive_handler();
    handler.handle(&ArchiveEvent::FileStarted {
      id: "archive-1".to_string(),
      path: PathBuf::from("2026-07-01.db"),
      archive: PathBuf::from("2026-07-01.db.xz"),
      total_bytes: 128,
    });

    handler.flush();

    assert!(handler.bars.is_empty());
  }

  fn started(method: &str, target: &str) -> RequestStarted {
    RequestStarted {
      source: RequestSource::Embedded {
        profile_id: "test-profile".into(),
      },
      http_version: Some("HTTP/1.1".into()),
      method: method.into(),
      target: CapturedUri::exact(target),
      headers: CapturedHeaders::default(),
      body_present: method != "CONNECT",
      correlation: Correlation::default(),
    }
  }

  fn target(provider: &str, account: &str, model: &str) -> TargetSelection {
    TargetSelection {
      family: HttpFamily::Managed,
      account_id: Some(account.into()),
      provider_id: Some(provider.into()),
      upstream_id: Some("primary".into()),
      requested_model: Some(model.into()),
      upstream_model: Some(model.into()),
      requested_operation: Some("responses".into()),
      upstream_operation: Some("responses".into()),
    }
  }

  fn request_body(model: Option<&str>, outcome: BodyOutcome) -> RequestBodyObservation {
    RequestBodyObservation {
      wire: BodyCapture::Omitted {
        reason: CaptureOmission::Disabled,
        bytes_seen: 512,
      },
      decoded: None,
      requested_model: model.map(Into::into),
      stream: Some(true),
      initiator: None,
      outcome,
    }
  }

  fn attempt_request(attempt: AttemptNo, bytes_seen: u64) -> AttemptHttpRequest {
    AttemptHttpRequest {
      attempt,
      request: HttpRequestSnapshot {
        method: "POST".into(),
        uri: CapturedUri::exact("https://api.example/v1/responses"),
        headers: CapturedHeaders::default(),
        body: BodyCapture::Omitted {
          reason: CaptureOmission::Disabled,
          bytes_seen,
        },
      },
    }
  }

  fn response_head(attempt: AttemptNo, status: u16) -> AttemptHttpResponseHead {
    AttemptHttpResponseHead {
      attempt,
      response: HttpResponseHead {
        status,
        headers: CapturedHeaders::default(),
      },
    }
  }

  fn finished(outcome: RequestOutcome, status: Option<u16>, attempt_count: u32) -> RequestFinished {
    RequestFinished {
      outcome,
      phase: RequestPhase::Complete,
      downstream_status: status,
      failure: None,
      attempt_count,
    }
  }

  #[test]
  fn managed_request_preserves_historical_fields_and_usage_order() {
    let mut handler = hidden_handler();
    emit(
      &mut handler,
      1,
      0,
      TrafficEventKind::Started(started("POST", "/v1/responses")),
    );
    emit(
      &mut handler,
      2,
      2,
      TrafficEventKind::Admitted(RequestAdmitted::Http {
        scheme: "http".into(),
        authority: "localhost".into(),
        path_and_query: CapturedUri::exact("/v1/responses"),
        operation: Some("responses".into()),
      }),
    );
    emit(
      &mut handler,
      3,
      3,
      TrafficEventKind::RequestBody(request_body(Some("gpt-5.4"), BodyOutcome::Accepted)),
    );
    emit(
      &mut handler,
      4,
      5,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("openai", "acct-1", "gpt-5.4"),
      }),
    );
    emit(
      &mut handler,
      5,
      10,
      TrafficEventKind::AttemptRequest(attempt_request(AttemptNo::FIRST, 2_048)),
    );
    emit(
      &mut handler,
      6,
      1_000,
      TrafficEventKind::BodyProgress(BodyProgress {
        leg: BodyLeg::Downstream,
        bytes_seen: 4_096,
        chunks: 4,
      }),
    );
    emit(
      &mut handler,
      7,
      1_000,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          kind: Some(UsageKind::Responses),
          input: Some(11),
          output: Some(13),
          total: Some(24),
          cache_read: Some(3),
          cache_write: Some(4),
          reasoning: Some(5),
        },
      }),
    );
    emit(
      &mut handler,
      8,
      1_000,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }),
    );

    let state = &handler.bars.get(&request_id()).unwrap().request;
    assert_eq!(
      plain(&state.render_in_flight(REQUEST_ID)),
      "[request-] openai gpt-5.4 acct-1 responses sent=2.0kB recv=4.0kB 4.0kB/s elapsed=1.0s"
    );
    assert_eq!(
      plain(&state.render_completed(REQUEST_ID, &finished(RequestOutcome::Delivered, Some(200), 1))),
      "[request-] \u{2713} 200 openai gpt-5.4 acct-1 responses sent=2.0kB recv=4.0kB in=11 out=13 total=24 cache_read=3 cache_write=4 reason=5 latency=1.0s"
    );

    emit(
      &mut handler,
      9,
      1_250,
      TrafficEventKind::Finished(finished(RequestOutcome::Delivered, Some(200), 1)),
    );
    assert!(handler.bars.is_empty());
    assert_eq!(handler.in_flight, 0);
    assert_eq!(handler.completed, 1);
    assert_eq!(handler.errors, 0);
  }

  #[test]
  fn retry_reuses_one_bar_and_projects_attempt_to_historical_retry_index() {
    let mut handler = hidden_handler();
    emit(
      &mut handler,
      1,
      0,
      TrafficEventKind::Started(started("POST", "/v1/responses")),
    );
    emit(
      &mut handler,
      2,
      1,
      TrafficEventKind::RequestBody(request_body(Some("model-1"), BodyOutcome::Accepted)),
    );
    emit(
      &mut handler,
      3,
      2,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("provider-1", "account-1", "model-1"),
      }),
    );
    emit(
      &mut handler,
      4,
      100,
      TrafficEventKind::AttemptRequest(attempt_request(AttemptNo::FIRST, 1_024)),
    );
    emit(
      &mut handler,
      5,
      200,
      TrafficEventKind::BodyProgress(BodyProgress {
        leg: BodyLeg::Downstream,
        bytes_seen: 512,
        chunks: 1,
      }),
    );
    emit(
      &mut handler,
      6,
      250,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(429),
        failure: None,
        retry: Some(RetryDecision {
          delay_ms: Some(25),
          reason: EventFailure {
            code: "rate_limited".into(),
            message: "retry after rate limit".into(),
          },
        }),
      }),
    );
    let second = AttemptNo::new(2).unwrap();
    emit(
      &mut handler,
      7,
      300,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: second,
        target: target("provider-2", "account-2", "model-2"),
      }),
    );

    assert_eq!(handler.bars.len(), 1);
    assert_eq!(handler.in_flight, 1);
    let state = &handler.bars.get(&request_id()).unwrap().request;
    assert_eq!(state.attempt, Some(second));
    assert_eq!(state.sent_bytes, 0);
    assert_eq!(state.recv_bytes, 0);
    assert_eq!(state.final_status, None);
    assert_eq!(state.error, None);
    let in_flight = plain(&state.render_in_flight(REQUEST_ID));
    assert!(in_flight.contains("provider-2 model-2 account-2 a=1 responses"));

    emit(
      &mut handler,
      8,
      400,
      TrafficEventKind::AttemptRequest(attempt_request(second, 2_048)),
    );
    emit(
      &mut handler,
      9,
      500,
      TrafficEventKind::AttemptResponseHead(response_head(second, 200)),
    );
    let state = &handler.bars.get(&request_id()).unwrap().request;
    let final_line = plain(&state.render_completed(REQUEST_ID, &finished(RequestOutcome::Delivered, Some(200), 2)));
    assert!(final_line.ends_with("latency=0.5s attempts=2"));

    emit(
      &mut handler,
      10,
      550,
      TrafficEventKind::Finished(finished(RequestOutcome::Delivered, Some(200), 2)),
    );
    assert_eq!(handler.completed, 1);
    assert_eq!(handler.errors, 0);
  }

  #[test]
  fn parsing_failure_finishes_without_inventing_target_fields() {
    let mut handler = hidden_handler();
    let message = "解析失败".repeat(40);
    let failure = EventFailure {
      code: "invalid_json".into(),
      message: message.clone().into(),
    };
    emit(
      &mut handler,
      1,
      0,
      TrafficEventKind::Started(started("POST", "/v1/responses")),
    );
    emit(
      &mut handler,
      2,
      2,
      TrafficEventKind::Admitted(RequestAdmitted::Http {
        scheme: "http".into(),
        authority: "localhost".into(),
        path_and_query: CapturedUri::exact("/v1/responses"),
        operation: Some("responses".into()),
      }),
    );
    emit(
      &mut handler,
      3,
      4,
      TrafficEventKind::RequestBody(request_body(None, BodyOutcome::Rejected(failure.clone()))),
    );
    emit(
      &mut handler,
      4,
      5,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 400,
        headers: CapturedHeaders::default(),
      }),
    );

    let state = &handler.bars.get(&request_id()).unwrap().request;
    assert!(state.provider.is_empty());
    assert!(state.model.is_empty());
    assert!(state.account.is_empty());
    let line = plain(&state.render_completed(
      REQUEST_ID,
      &RequestFinished {
        outcome: RequestOutcome::Rejected,
        phase: RequestPhase::RequestBody,
        downstream_status: Some(400),
        failure: Some(failure.clone()),
        attempt_count: 0,
      },
    ));
    assert!(line.contains("\u{2717} 400    responses"));
    assert!(line.ends_with(&message.chars().take(80).collect::<String>()));

    emit(
      &mut handler,
      5,
      6,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Rejected,
        phase: RequestPhase::RequestBody,
        downstream_status: Some(400),
        failure: Some(failure),
        attempt_count: 0,
      }),
    );
    assert_eq!(handler.completed, 1);
    assert_eq!(handler.errors, 1);
  }

  #[test]
  fn connect_uses_transport_byte_totals_without_fake_attempts() {
    let mut handler = hidden_handler();
    emit(
      &mut handler,
      1,
      0,
      TrafficEventKind::Started(started("CONNECT", "example.test:443")),
    );
    emit(
      &mut handler,
      2,
      2,
      TrafficEventKind::Admitted(RequestAdmitted::Connect {
        authority: "example.test:443".into(),
      }),
    );
    emit(
      &mut handler,
      3,
      3,
      TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "example.test:443".into(),
      }),
    );
    emit(
      &mut handler,
      4,
      1_000,
      TrafficEventKind::ConnectClosed(ConnectClosed {
        action: ConnectAction::Tunnel,
        client_to_upstream_bytes: Some(2_048),
        upstream_to_client_bytes: Some(4_096),
        result: BodyResult::Complete,
      }),
    );
    emit(
      &mut handler,
      5,
      1_000,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }),
    );

    let state = &handler.bars.get(&request_id()).unwrap().request;
    let line = plain(&state.render_completed(REQUEST_ID, &finished(RequestOutcome::Delivered, Some(200), 0)));
    assert!(line.contains("CONNECT example.test:443 sent=2.0kB recv=4.0kB"));
    assert!(!line.contains("attempts="));
  }

  #[test]
  fn flush_barrier_is_non_terminal_but_drop_cleanup_is_idempotent() {
    let mut handler = hidden_handler();
    emit(
      &mut handler,
      1,
      0,
      TrafficEventKind::Started(started("POST", "/v1/responses")),
    );

    EventConsumer::<GatewayEvent>::flush(&mut handler).unwrap();
    assert_eq!(handler.bars.len(), 1);
    assert!(!handler.footer.is_finished());

    handler.finish_session();
    assert!(handler.bars.is_empty());
    assert!(handler.footer.is_finished());
    assert!(handler.finished);
    handler.finish_session();
  }

  #[test]
  fn truncation_is_unicode_safe_and_usage_updates_do_not_erase_values() {
    assert_eq!(truncate("模型请求", 3), "模型请");

    let mut usage = TokenUsage {
      input: Some(8),
      cache_read: Some(3),
      ..TokenUsage::default()
    };
    usage.merge_from(&TokenUsage {
      output: Some(5),
      cache_read: None,
      ..TokenUsage::default()
    });
    assert_eq!(usage.input, Some(8));
    assert_eq!(usage.output, Some(5));
    assert_eq!(usage.cache_read, Some(3));
    assert_eq!(format_usage(&usage), " in=8 out=5 cache_read=3");
  }
}
