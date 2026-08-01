//! `gateway smoke send` — drives the requests pipeline end-to-end.
//!
//! Two modes:
//!
//! * `--dry-run` builds a [`Profile::without_send`]; the runner halts at
//!   Send via `PipelineError::stop` after every prior stage's event has
//!   fired. A bus subscriber captures the per-stage outputs
//!   (`Resolved` / `BuiltHeaders` / `ConvertedRequest`) and they are
//!   printed as the dry-run report.
//! * Default (live) mode builds a [`Profile::full`] with [`DefaultSend`] and
//!   [`DefaultConvertResponse`] and contacts the upstream provider. The
//!   response (returned from `run`) is either printed as a buffered JSON
//!   payload or streamed chunk-by-chunk to stdout (curl `-N` style).
//!
//! In both modes every [`StageEvent`] is mirrored to stdout via a separate
//! subscriber on the requests [`EventBus`], so the user sees the pipeline
//! progress in real time.

use super::OutputFormat;
use crate::cli::config_cmd::RouteModeArg;
use crate::config::Config;
use crate::provider::Endpoint;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Args;
use futures_util::StreamExt;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokn_config::RouteMode;
use tokn_core::event::Event as CoreEvent;
use tokn_core::request_event::{RecordEvent, RequestEvent, RequestEventPayload};
use tokn_requests::event::{BuiltHeadersSummary, ConvertedRequestSummary, ResolvedSummary};
use tokn_requests::pipeline::stages::{ConvertedBody, ConvertedResponse};
use tokn_requests::stages::{
  DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, DefaultSend, PoolAccountSelector,
  PoolResolve,
};
use tokn_requests::{Event, EventBus, EventPayload, PipelineError, PipelineRunner, Profile, RawInbound, StageEvent};
use tokn_router::api::AppState;

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum EndpointArg {
  ChatCompletions,
  Responses,
  Messages,
}

impl From<EndpointArg> for Endpoint {
  fn from(val: EndpointArg) -> Self {
    match val {
      EndpointArg::ChatCompletions => Endpoint::ChatCompletions,
      EndpointArg::Responses => Endpoint::Responses,
      EndpointArg::Messages => Endpoint::Messages,
    }
  }
}

#[derive(Args, Debug)]
pub struct SendArgs {
  /// Route mode (defaults to the serve route-mode from config).
  #[arg(long, value_enum)]
  pub route: Option<RouteModeArg>,

  /// Constrain account selection to this provider.
  #[arg(long)]
  pub provider: Option<String>,

  /// Pick a specific account by id (requires --provider).
  #[arg(long, requires = "provider")]
  pub account: Option<String>,

  /// Model to use for the smoke request.
  #[arg(long)]
  pub model: Option<String>,

  /// API endpoint to test.
  #[arg(long, value_enum, default_value_t = EndpointArg::ChatCompletions)]
  pub endpoint: EndpointArg,

  /// Request streaming SSE response. The response is forwarded chunk-by-
  /// chunk to stdout as it arrives from upstream.
  #[arg(long)]
  pub stream: bool,

  /// Build and print outbound headers/body without contacting upstream.
  /// Equivalent to running the pipeline up to (and including)
  /// `ConvertRequest` and stopping; nothing is sent.
  #[arg(long)]
  pub dry_run: bool,

  /// Output format.
  #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
  pub format: OutputFormat,

  /// Print outbound and upstream headers verbatim instead of redacting
  /// sensitive values (authorization, cookies, api keys). Off by default
  /// because output is often pasted into bug reports — only set when you
  /// are actively debugging upstream auth and know what you're showing.
  #[arg(long)]
  pub no_redact: bool,

  /// Read the raw JSON request body from a file (or `-` for stdin) instead
  /// of the auto-built body. When set, `message` is optional and `--model`
  /// defaults to whatever the body declares.
  #[arg(long)]
  pub body_file: Option<PathBuf>,

  /// Inject a custom inbound header (`name=value`). Repeatable. Last wins
  /// per header name. Useful for replaying captured requests that depend on
  /// `accept`, `originator`, etc.
  #[arg(long = "header", value_parser = parse_header_kv, num_args = 0..)]
  pub headers: Vec<(String, String)>,

  /// Message to send. Optional when `--body-file` is provided.
  pub message: Option<String>,
}

fn parse_header_kv(raw: &str) -> std::result::Result<(String, String), String> {
  let (k, v) = raw
    .split_once('=')
    .or_else(|| raw.split_once(':').map(|(a, b)| (a, b.trim_start())))
    .ok_or_else(|| format!("expected `name=value` or `name: value`, got `{raw}`"))?;
  let k = k.trim().to_string();
  let v = v.trim().to_string();
  if k.is_empty() {
    return Err("header name must not be empty".into());
  }
  Ok((k, v))
}

pub async fn run(cfg_path: Option<PathBuf>, args: SendArgs) -> Result<()> {
  let (mut cfg, _) = Config::load(cfg_path.as_deref())?;
  let mut accounts = crate::server_runtime::load_default_accounts()?;

  let route_mode = args.route.map(RouteMode::from).unwrap_or(cfg.defaults.mode);
  cfg.defaults.mode = route_mode;

  if route_mode == RouteMode::Passthrough {
    anyhow::bail!("passthrough mode requires the proxy; use a different --route mode");
  }

  filter_accounts(&mut accounts, args.provider.as_deref(), args.account.as_deref())?;

  // The legacy AppState still owns the account pool + route resolver + the
  // legacy `EventBus`. We reuse that same bus for requests events too — the
  // `build_event_bus` handler list already contains `RequestEventHandler`
  // (when `cfg.db.enabled`), so emitting `Event::Requests(_)` on it persists
  // the smoke run into `requests/<YYYY-MM-DD>.db`.
  let (events, receiver, handlers, archive_runtime) = crate::server_runtime::build_event_bus(&cfg)?;
  let _event_thread = tokn_core::event::spawn_event_loop(receiver, handlers);
  let state = crate::server_runtime::build_state(&cfg, &accounts, events.clone())?;
  let requests_dir = if cfg.db.enabled {
    Some(cfg.db.resolve_paths()?.requests_dir)
  } else {
    None
  };

  let custom_body: Option<Value> = match args.body_file.as_deref() {
    Some(path) => Some(load_body_file(path)?),
    None => None,
  };

  let model = match (&args.model, custom_body.as_ref()) {
    (Some(m), _) => m.clone(),
    (None, Some(body)) => body
      .get("model")
      .and_then(|v| v.as_str())
      .map(str::to_string)
      .ok_or_else(|| anyhow!("--body-file does not contain a `model` field; pass --model"))?,
    (None, None) => pick_default_model(&state, args.provider.as_deref())?,
  };

  let endpoint: Endpoint = args.endpoint.into();

  if custom_body.is_none() && args.message.is_none() {
    anyhow::bail!("missing message: pass either a positional message or --body-file");
  }

  // Build the inbound body we'll feed to requests. We keep the body symmetrical
  // with the legacy CLI behaviour so existing fixtures still work.
  let body_value = match custom_body {
    Some(mut v) => {
      if let Some(obj) = v.as_object_mut() {
        if args.model.is_some() {
          obj.insert("model".into(), Value::String(model.clone()));
        }
        if args.stream {
          obj.insert("stream".into(), Value::Bool(true));
        }
      }
      v
    }
    None => build_request_body(endpoint, &model, args.message.as_deref().unwrap_or(""), args.stream),
  };
  let body_bytes = Bytes::from(serde_json::to_vec(&body_value)?);
  let request_id = uuid::Uuid::new_v4().to_string();
  let mut headers = build_inbound_headers(&args.headers)?;
  headers.insert("x-request-id", request_id.clone());

  if args.no_redact {
    eprintln!(
      "warning: --no-redact is set; outbound + upstream headers will be printed verbatim (including authorization, cookies, api keys). Do not paste this output into bug reports."
    );
  }

  if args.format == OutputFormat::Text {
    println!("provider: {}", args.provider.as_deref().unwrap_or("(any)"));
    println!("account:  {}", args.account.as_deref().unwrap_or("(any)"));
    println!("model:    {}", model);
    println!("endpoint: {}", endpoint);
    println!("route:    {}", route_mode_name(route_mode));
    println!("stream:   {}", args.stream);
    if let Some(body_file) = args.body_file.as_ref() {
      println!("body:     {}", body_file.display());
    }
    println!();
  }

  // ---- Build the requests profile ----
  // Reuse the shared bus so `RequestEventHandler` persists smoke runs.
  let bus = events.clone();
  subscribe_event_printer(&bus);
  // Capture per-stage outputs so we can render dry-run / failure reports
  // after `run` returns. The runner no longer carries partial state on
  // its return value; bus subscribers are the source of truth.
  let captured = Captured::install(&bus);

  let selector = Arc::new(PoolAccountSelector::new(state.pool.clone(), state.route.clone()));
  let extract = Arc::new(DefaultExtract);
  let resolve = Arc::new(PoolResolve::new(selector));
  let build_headers = Arc::new(DefaultBuildHeaders::with_provider_defaults());
  let convert_request = Arc::new(DefaultConvertRequest);

  let profile = if args.dry_run {
    Arc::new(Profile::without_send(
      "gateway-smoke",
      extract,
      resolve,
      build_headers,
      convert_request,
    ))
  } else {
    Arc::new(Profile::full(
      "gateway-smoke",
      extract,
      resolve,
      build_headers,
      convert_request,
      Arc::new(DefaultSend::new(state.http.clone())),
      Arc::new(DefaultConvertResponse::new()),
    ))
  };
  let runner = PipelineRunner::new(profile, bus.clone());

  bus.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone().into(),
    attempt: 0,
    ts: tokn_core::util::now_unix_ms(),
    payload: RequestEventPayload::Record(RecordEvent::InboundConnection {
      user: None,
      api_key_id: None,
      local_addr: None,
      peer_addr: None,
      mode: "smoke".into(),
      method: "POST".into(),
      inbound_method: "POST".into(),
      url: None,
    }),
  }));

  let raw = RawInbound {
    request_endpoint: endpoint.into(),
    headers,
    raw_body: body_bytes.clone(),
    decoded_body: body_bytes.clone(),
    body_json: body_value,
    request_id: Some(request_id.into()),
  };

  let result = match runner.run(raw).await {
    Ok(converted) if matches!(&converted.body, ConvertedBody::Stream { .. }) => {
      let snapshot = captured.snapshot();
      print_live_outcome(converted, &snapshot, None, args.format, !args.no_redact).await?;

      // Streaming final records are emitted by the stream finalizer, so we must
      // drain the stream before shutting down the event bus.
      events.shutdown().await;
      if let Some(archive_runtime) = archive_runtime {
        archive_runtime.shutdown().await;
      }

      let persisted = match (requests_dir.as_deref(), snapshot.request_id.as_ref()) {
        (Some(dir), Some(id)) => match tokn_persistence::read_request_row(dir, id.as_str()) {
          Ok(row) => row,
          Err(e) => {
            eprintln!("warning: failed to read persisted request row: {e}");
            None
          }
        },
        _ => None,
      };
      if matches!(args.format, OutputFormat::Text) {
        print_persisted_text(persisted.as_ref());
      }
      return Ok(());
    }
    other => other,
  };

  // Shut down the legacy event plumbing — requests events are independent.
  events.shutdown().await;
  if let Some(archive_runtime) = archive_runtime {
    archive_runtime.shutdown().await;
  }

  let snapshot = captured.snapshot();
  let persisted = match (requests_dir.as_deref(), snapshot.request_id.as_ref()) {
    (Some(dir), Some(id)) => match tokn_persistence::read_request_row(dir, id.as_str()) {
      Ok(row) => row,
      Err(e) => {
        eprintln!("warning: failed to read persisted request row: {e}");
        None
      }
    },
    _ => None,
  };

  match result {
    Ok(converted) => {
      print_live_outcome(converted, &snapshot, persisted.as_ref(), args.format, !args.no_redact).await?;
    }
    Err(err) if err.stop && args.dry_run => {
      print_dry_run_outcome(&snapshot, persisted.as_ref(), args.format, !args.no_redact)?;
    }
    Err(err) => {
      print_failure_outcome(&err, &snapshot, persisted.as_ref(), args.format, !args.no_redact)?;
      anyhow::bail!("pipeline failed: {}: {}", err.stage, err.message());
    }
  }

  Ok(())
}

/// Per-stage outputs captured by a bus subscriber. Cloned out as a
/// [`CapturedSnapshot`] once `run` returns so we can render reports
/// without holding the mutex.
#[derive(Default)]
struct Captured {
  inner: Mutex<CapturedSnapshot>,
}

#[derive(Default, Clone)]
struct CapturedSnapshot {
  started_endpoint: Option<String>,
  resolved: Option<ResolvedSummary>,
  built_headers: Option<BuiltHeadersSummary>,
  converted_request: Option<ConvertedRequestSummary>,
  attempts: Option<u32>,
  request_id: Option<String>,
}

impl Captured {
  fn install(bus: &EventBus) -> Arc<Self> {
    let cap = Arc::new(Captured::default());
    let sink = cap.clone();
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
      loop {
        match rx.recv().await {
          Ok(arc) => {
            if let CoreEvent::Requests(event) = &*arc {
              let mut snap = sink.inner.lock().unwrap();
              if snap.request_id.is_none() {
                snap.request_id = Some(event.request_id.to_string());
              }
              match &event.payload {
                EventPayload::Stage(StageEvent::Started { request_endpoint }) => {
                  snap.started_endpoint = Some(request_endpoint.as_str().to_string())
                }
                EventPayload::Stage(StageEvent::Resolve(r)) => snap.resolved = Some(r.clone()),
                EventPayload::Stage(StageEvent::BuildHeaders(h)) => snap.built_headers = Some(h.clone()),
                EventPayload::Stage(StageEvent::ConvertRequest(c)) => snap.converted_request = Some(c.clone()),
                EventPayload::Stage(StageEvent::Completed { attempts, .. }) => snap.attempts = Some(*attempts),
                _ => {}
              }
            }
          }
          Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
          Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
      }
    });
    cap
  }

  fn snapshot(&self) -> CapturedSnapshot {
    self.inner.lock().unwrap().clone()
  }
}

fn subscribe_event_printer(bus: &EventBus) {
  let mut rx = bus.subscribe();
  tokio::spawn(async move {
    loop {
      match rx.recv().await {
        Ok(arc) => {
          if let CoreEvent::Requests(event) = &*arc {
            print_event(event);
          }
        }
        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
      }
    }
  });
}

fn print_event(event: &Event) {
  match &event.payload {
    EventPayload::Stage(StageEvent::Started { request_endpoint }) => {
      println!("[started]          endpoint={request_endpoint}");
    }
    EventPayload::Stage(StageEvent::Extract(e)) => {
      let cid = e.agent_id.as_ref().map(|c| c.as_str()).unwrap_or("(none)");
      println!(
        "[extract]          model={} stream={} agent_id={cid}",
        e.model, e.stream
      );
    }
    EventPayload::Stage(StageEvent::Resolve(r)) => {
      let cid = r.agent_id.as_ref().map(|c| c.as_str()).unwrap_or("(none)");
      let upstream_endpoint = r
        .upstream_endpoint
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "auto".to_string());
      println!(
        "[resolve]          model={} -> {} account={} provider={} upstream_endpoint={} agent_id={cid}",
        r.model, r.upstream_model, r.account_id, r.provider_id, upstream_endpoint
      );
    }
    EventPayload::Stage(StageEvent::BuildHeaders(_)) => {
      println!("[build_headers]    ok");
    }
    EventPayload::Stage(StageEvent::ConvertRequest(_)) => {
      println!("[convert_request]  ok");
    }
    EventPayload::Stage(StageEvent::Send(_)) => {
      println!("[send]             ok");
    }
    EventPayload::Stage(StageEvent::ConvertResponse(_)) => {
      println!("[convert_response] ok");
    }
    EventPayload::Stage(StageEvent::Error {
      stage,
      message,
      recoverable,
      stop,
    }) => {
      if *stop {
        println!("[stop]             stage={stage} message={message}");
      } else {
        println!("[error]            stage={stage} recoverable={recoverable} message={message}");
      }
    }
    EventPayload::Stage(StageEvent::Completed { success, attempts }) => {
      println!("[completed]        success={success} attempts={attempts}");
    }
    EventPayload::Record(r) => match r {
      RecordEvent::InboundConnection {
        user,
        api_key_id,
        local_addr,
        peer_addr,
        mode,
        method,
        inbound_method,
        url,
      } => {
        println!(
          "[record:inbound_conn] mode={mode} method={method} inbound_method={inbound_method} user={} api_key_id={} local={} peer={} url={}",
          user.as_deref().unwrap_or("-"),
          api_key_id.as_deref().unwrap_or("-"),
          local_addr.as_deref().unwrap_or("-"),
          peer_addr.as_deref().unwrap_or("-"),
          url.as_deref().unwrap_or("-")
        );
      }
      RecordEvent::UpstreamReq {
        method,
        url,
        headers,
        body,
      } => {
        println!(
          "[record:upstream_req] {method} {url} headers={} body_bytes={}",
          headers.len(),
          body.len()
        );
      }
      RecordEvent::UpstreamResp { status, headers } => {
        println!("[record:upstream_resp] status={status} headers={}", headers.len());
      }
      RecordEvent::UpstreamBody { body, error } => {
        println!(
          "[record:upstream_body] bytes={} error={}",
          body.len(),
          error.as_deref().unwrap_or("-")
        );
      }
      RecordEvent::ConvertedBody { body, error } => {
        println!(
          "[record:converted_body] bytes={} error={}",
          body.len(),
          error.as_deref().unwrap_or("-")
        );
      }
      RecordEvent::Usage(usage) => {
        println!(
          "[record:usage] input={:?} output={:?} total={:?} cache_read={:?} cache_write={:?} reasoning={:?}",
          usage.input_tokens,
          usage.output_tokens,
          usage.total_tokens,
          usage.details.cache_read,
          usage.details.cache_write,
          usage.details.reasoning
        );
      }
    },
    EventPayload::Custom(c) => {
      println!("[custom]           kind={}", c.kind);
    }
  }
}

fn print_dry_run_outcome(
  snap: &CapturedSnapshot,
  persisted: Option<&serde_json::Map<String, Value>>,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  let resolved = snap.resolved.as_ref();
  let upstream_endpoint = snapshot_endpoint_label(snap);
  let headers = snap.built_headers.as_ref();
  let converted = snap.converted_request.as_ref();

  match format {
    OutputFormat::Json => {
      let headers_json = headers
        .map(|h| headers_json_value(&h.headers, redact))
        .unwrap_or(Value::Null);
      let body_json = converted.map(|c| (*c.upstream_body).clone()).unwrap_or(Value::Null);
      let report = serde_json::json!({
        "dry_run": true,
        "attempts": snap.attempts.unwrap_or(0),
        "request_id": snap.request_id.as_deref(),
        "account": resolved.map(|r| r.account_id.as_str()),
        "provider": resolved.map(|r| r.provider_id.as_str()),
        "model": resolved.map(|r| r.model.as_str()),
        "upstream_model": resolved.map(|r| r.upstream_model.as_str()),
        "upstream_endpoint": upstream_endpoint,
        "headers": headers_json,
        "body": body_json,
        "content_encoding": converted.and_then(|c| c.content_encoding.as_deref()),
        "persisted": persisted.map(|m| Value::Object(m.clone())).unwrap_or(Value::Null),
      });
      println!("{}", serde_json::to_string_pretty(&report)?);
    }
    OutputFormat::Text => {
      println!();
      println!("--- outcome ---");
      if let Some(n) = snap.attempts {
        println!("attempts: {n}");
      }
      if let Some(id) = snap.request_id.as_ref() {
        println!("request_id: {id}");
      }
      if let Some(r) = resolved {
        println!("account:  {}", r.account_id);
        println!("provider: {}", r.provider_id);
        println!("model:    {} -> {}", r.model, r.upstream_model);
      }
      if let Some(endpoint) = snapshot_endpoint_label(snap) {
        println!("upstream: {}", endpoint);
      }
      if let Some(h) = headers {
        println!("headers:");
        for (name, value) in h.headers.iter() {
          let v = value.as_str();
          println!("  {}: {}", name.as_str(), redact_header(name.as_str(), v, redact));
        }
      }
      if let Some(c) = converted {
        if let Some(enc) = &c.content_encoding {
          println!("content-encoding: {}", enc);
        }
        println!("body:");
        println!("{}", serde_json::to_string_pretty(&*c.upstream_body)?);
      }
      print_persisted_text(persisted);
    }
  }
  Ok(())
}

/// Render the result of a live (non-dry-run) pipeline run. For buffered
/// responses we print a JSON report (`OutputFormat::Json`) or a friendly
/// text preview; for streaming responses we forward the SSE byte chunks
/// to stdout as they arrive (curl `-N` semantics) and finish with a
/// concise summary.
async fn print_live_outcome(
  converted: ConvertedResponse,
  snap: &CapturedSnapshot,
  persisted: Option<&serde_json::Map<String, Value>>,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  let resolved = snap.resolved.as_ref();
  let upstream_endpoint = snapshot_endpoint_label(snap);
  let attempts = snap.attempts.unwrap_or(1);

  let ConvertedResponse { status, headers, body } = converted;
  match body {
    ConvertedBody::Buffered { body_json, .. } => match format {
      OutputFormat::Json => {
        let report = serde_json::json!({
          "dry_run": false,
          "stream": false,
          "attempts": attempts,
          "request_id": snap.request_id.as_deref(),
          "account": resolved.map(|r| r.account_id.as_str()),
          "provider": resolved.map(|r| r.provider_id.as_str()),
          "model": resolved.map(|r| r.model.as_str()),
          "upstream_model": resolved.map(|r| r.upstream_model.as_str()),
          "upstream_endpoint": upstream_endpoint,
          "status": status,
          "headers": headers_json_value(&headers, redact),
          "body": body_json.as_deref(),
          "persisted": persisted.map(|m| Value::Object(m.clone())).unwrap_or(Value::Null),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
      }
      OutputFormat::Text => {
        println!();
        println!("--- response ---");
        println!("attempts: {}", attempts);
        if let Some(id) = snap.request_id.as_ref() {
          println!("request_id: {id}");
        }
        if let Some(r) = resolved {
          println!("account:  {}", r.account_id);
          println!("provider: {}", r.provider_id);
          println!("model:    {} -> {}", r.model, r.upstream_model);
        }
        if let Some(endpoint) = snapshot_endpoint_label(snap) {
          println!("upstream: {}", endpoint);
        }
        println!("status:   {}", status);
        println!("headers:");
        for (name, value) in headers.iter() {
          let v = value.as_str();
          println!("  {}: {}", name.as_str(), redact_header(name.as_str(), v, redact));
        }
        println!("body:");
        println!("{}", serde_json::to_string_pretty(&body_json.as_deref())?);
        print_persisted_text(persisted);
      }
    },
    ConvertedBody::Stream { mut body } => {
      // For text format, print a short header banner first so the user sees
      // metadata before the stream body. For json format we still stream
      // the raw SSE bytes (already endpoint-translated, if applicable) —
      // wrapping that in a JSON envelope would require buffering, which
      // defeats the point of streaming. Tooling that wants structured
      // output should use `--dry-run` or buffered mode.
      if matches!(format, OutputFormat::Text) {
        println!();
        println!("--- response (stream) ---");
        println!("attempts: {}", attempts);
        if let Some(r) = resolved {
          println!("account:  {}", r.account_id);
          println!("provider: {}", r.provider_id);
          println!("model:    {} -> {}", r.model, r.upstream_model);
        }
        if let Some(endpoint) = snapshot_endpoint_label(snap) {
          println!("upstream: {}", endpoint);
        }
        println!("status:   {}", status);
        println!("headers:");
        for (name, value) in headers.iter() {
          let v = value.as_str();
          println!("  {}: {}", name.as_str(), redact_header(name.as_str(), v, redact));
        }
        println!("body:");
      }

      let mut stdout = tokio::io::stdout();
      let mut total_bytes: usize = 0;
      while let Some(chunk) = body.next().await {
        let bytes = chunk.map_err(|e| anyhow!("stream read failed: {e}"))?;
        total_bytes += bytes.len();
        stdout
          .write_all(&bytes)
          .await
          .map_err(|e| anyhow!("stdout write failed: {e}"))?;
        stdout.flush().await.ok();
      }
      if matches!(format, OutputFormat::Text) {
        println!();
        println!("--- end of stream ({total_bytes} bytes) ---");
        print_persisted_text(persisted);
      }
    }
  }
  Ok(())
}

/// Render whatever partial state the pipeline managed to accumulate before
/// failing. Mirrors `print_dry_run_outcome` shape so the user sees the same
/// fields whether the run succeeded, was dry-run, or aborted mid-stream.
fn print_failure_outcome(
  err: &PipelineError,
  snap: &CapturedSnapshot,
  persisted: Option<&serde_json::Map<String, Value>>,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  let resolved = snap.resolved.as_ref();
  let upstream_endpoint = snapshot_endpoint_label(snap);
  let headers = snap.built_headers.as_ref();
  let converted_req = snap.converted_request.as_ref();

  match format {
    OutputFormat::Json => {
      let headers_json = headers
        .map(|h| headers_json_value(&h.headers, redact))
        .unwrap_or(Value::Null);
      let body_json = converted_req.map(|c| (*c.upstream_body).clone()).unwrap_or(Value::Null);
      let report = serde_json::json!({
        "success": false,
        "attempts": snap.attempts.unwrap_or(0),
        "request_id": snap.request_id.as_deref(),
        "error": {
          "stage": err.stage.as_str(),
          "message": err.message().as_ref(),
          "recoverable": err.recoverable,
          "stop": err.stop,
        },
        "account": resolved.map(|r| r.account_id.as_str()),
        "provider": resolved.map(|r| r.provider_id.as_str()),
        "model": resolved.map(|r| r.model.as_str()),
        "upstream_model": resolved.map(|r| r.upstream_model.as_str()),
        "upstream_endpoint": upstream_endpoint,
        "headers": headers_json,
        "body": body_json,
        "content_encoding": converted_req.and_then(|c| c.content_encoding.as_deref()),
        "persisted": persisted.map(|m| Value::Object(m.clone())).unwrap_or(Value::Null),
      });
      println!("{}", serde_json::to_string_pretty(&report)?);
    }
    OutputFormat::Text => {
      println!();
      println!("--- failure ---");
      if let Some(n) = snap.attempts {
        println!("attempts: {n}");
      }
      if let Some(id) = snap.request_id.as_ref() {
        println!("request_id: {id}");
      }
      println!("stage:    {}", err.stage);
      println!("recoverable: {}", err.recoverable);
      println!("message:  {}", err.message());
      if let Some(r) = resolved {
        println!("account:  {}", r.account_id);
        println!("provider: {}", r.provider_id);
        println!("model:    {} -> {}", r.model, r.upstream_model);
      }
      if let Some(endpoint) = snapshot_endpoint_label(snap) {
        println!("upstream: {}", endpoint);
      }
      if let Some(h) = headers {
        println!("headers:");
        for (name, value) in h.headers.iter() {
          let v = value.as_str();
          println!("  {}: {}", name.as_str(), redact_header(name.as_str(), v, redact));
        }
      }
      if let Some(c) = converted_req {
        if let Some(enc) = &c.content_encoding {
          println!("content-encoding: {}", enc);
        }
        println!("body:");
        println!("{}", serde_json::to_string_pretty(&*c.upstream_body)?);
      }
      print_persisted_text(persisted);
    }
  }
  Ok(())
}

fn snapshot_endpoint_label(snap: &CapturedSnapshot) -> Option<String> {
  snap
    .resolved
    .as_ref()
    .and_then(|resolved| resolved.upstream_endpoint.map(|endpoint| endpoint.to_string()))
    .or_else(|| snap.started_endpoint.clone())
}

/// Print the persisted row in a compact, line-per-column form. BLOB columns
/// containing structured JSON (headers, body) are pretty-printed beneath
/// their name; scalar columns appear inline. Null columns are skipped to
/// keep the output focused on what actually got written.
fn print_persisted_text(persisted: Option<&serde_json::Map<String, Value>>) {
  let Some(row) = persisted else {
    return;
  };
  println!();
  println!("--- persisted row ---");
  for (k, v) in row.iter() {
    if v.is_null() {
      continue;
    }
    match v {
      Value::Object(_) | Value::Array(_) => {
        println!("{k}:");
        if let Ok(pretty) = serde_json::to_string_pretty(v) {
          for line in pretty.lines() {
            println!("  {line}");
          }
        }
      }
      Value::String(s) => println!("{k}: {s}"),
      _ => println!("{k}: {v}"),
    }
  }
}

fn headers_json_value(headers: &tokn_headers::HeaderMap, redact: bool) -> Value {
  let mut map = serde_json::Map::new();
  for (name, value) in headers.iter() {
    let v = value.as_str();
    let key = name.as_str().to_string();
    let value = Value::String(redact_header(name.as_str(), v, redact));
    match map.get_mut(&key) {
      Some(Value::Array(values)) => values.push(value),
      Some(_) => unreachable!("header json values are always arrays"),
      None => {
        map.insert(key, Value::Array(vec![value]));
      }
    }
  }
  Value::Object(map)
}

fn redact_header(name: &str, value: &str, redact: bool) -> String {
  // Preserve diagnostic sentinels: empty values and the `<missing>`
  // placeholder emitted by persona builders are not secrets, they are
  // signals that the upstream stage failed to populate something. Hiding
  // them defeats the entire point of dumping headers when debugging.
  if !redact || value.is_empty() || value == "<missing>" {
    return value.to_string();
  }
  match name.to_ascii_lowercase().as_str() {
    "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" => "<redacted>".into(),
    _ => value.to_string(),
  }
}

pub(super) fn filter_accounts(
  accounts: &mut Vec<tokn_core::account::AccountConfig>,
  provider: Option<&str>,
  account: Option<&str>,
) -> Result<()> {
  if provider.is_none() && account.is_none() {
    return Ok(());
  }
  let before = accounts.len();
  accounts.retain(|a| {
    if let Some(p) = provider {
      if a.provider != p {
        return false;
      }
    }
    if let Some(id) = account {
      if a.id != id {
        return false;
      }
    }
    true
  });
  if accounts.is_empty() {
    anyhow::bail!(
      "no accounts match the requested filters (provider={:?}, account={:?}); had {before} configured",
      provider,
      account
    );
  }
  Ok(())
}

fn build_request_body(endpoint: Endpoint, model: &str, message: &str, stream: bool) -> Value {
  match endpoint {
    Endpoint::ChatCompletions => serde_json::json!({
      "model": model,
      "stream": stream,
      "messages": [{"role": "user", "content": message}],
    }),
    Endpoint::Messages => serde_json::json!({
      "model": model,
      "stream": stream,
      "max_tokens": 32_000,
      "messages": [{"role": "user", "content": message}],
    }),
    Endpoint::Responses => serde_json::json!({
      "model": model,
      "stream": stream,
      "input": message,
    }),
  }
}

fn build_inbound_headers(overrides: &[(String, String)]) -> Result<tokn_headers::HeaderMap> {
  use tokn_headers::{HeaderMap, HeaderName, HeaderValue};
  let mut h = HeaderMap::new();
  h.insert(
    HeaderName::new("content-type"),
    HeaderValue::from_static("application/json"),
  );
  h.insert(
    HeaderName::new("x-request-id"),
    HeaderValue::from_string(uuid::Uuid::new_v4().to_string()),
  );
  for (k, v) in overrides {
    h.insert(
      HeaderName::new(k.to_ascii_lowercase()),
      HeaderValue::from_string(v.clone()),
    );
  }
  Ok(h)
}

fn load_body_file(path: &std::path::Path) -> Result<Value> {
  use std::io::Read;
  let raw = if path == std::path::Path::new("-") {
    let mut buf = String::new();
    std::io::stdin()
      .read_to_string(&mut buf)
      .map_err(|e| anyhow!("read stdin: {e}"))?;
    buf
  } else {
    std::fs::read_to_string(path).map_err(|e| anyhow!("read {}: {e}", path.display()))?
  };
  let body_str = extract_body_section(&raw).unwrap_or_else(|| raw.trim_start());
  serde_json::from_str(body_str).map_err(|e| anyhow!("parse body file as JSON: {e}"))
}

fn extract_body_section(raw: &str) -> Option<&str> {
  let body_idx = raw
    .lines()
    .scan(0usize, |offset, line| {
      let start = *offset;
      *offset += line.len() + 1;
      Some((start, line))
    })
    .find_map(|(start, line)| line.trim().eq_ignore_ascii_case("body:").then_some(start + line.len()))?;

  Some(raw[body_idx..].trim_start_matches(['\r', '\n']).trim_start())
}

fn pick_default_model(state: &AppState, provider_filter: Option<&str>) -> Result<String> {
  for acct in state.pool.all() {
    if let Some(p) = provider_filter {
      if acct.provider.info().id != p {
        continue;
      }
    }
    if let Some(m) = acct.provider.info().default_models.first() {
      return Ok(m.id.clone());
    }
  }
  match provider_filter {
    Some(p) => anyhow::bail!("no models available for provider '{}'; pass --model", p),
    None => anyhow::bail!("no models available; pass --model explicitly"),
  }
}

fn route_mode_name(mode: RouteMode) -> &'static str {
  match mode {
    RouteMode::Passthrough => "passthrough",
    RouteMode::Switch => "switch",
    RouteMode::Exact => "exact",
    RouteMode::Route => "route",
    RouteMode::Fuzzy => "fuzzy",
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;
  use tokn_headers::HeaderMap;

  #[test]
  fn build_request_body_messages_includes_required_max_tokens() {
    let body = build_request_body(Endpoint::Messages, "claude", "hi", false);
    assert_eq!(body["max_tokens"], 32_000);
    assert_eq!(body["messages"][0]["content"], "hi");
  }

  #[test]
  fn build_request_body_chat_does_not_add_messages_max_tokens() {
    let body = build_request_body(Endpoint::ChatCompletions, "gpt-4.1", "hi", false);
    assert!(body.get("max_tokens").is_none());
  }

  #[test]
  fn headers_json_value_preserves_multi_values_in_order() {
    let mut headers = HeaderMap::new();
    headers.append("set-cookie", "a=1");
    headers.append("x-test", "first");
    headers.append("set-cookie", "b=2");

    let json = headers_json_value(&headers, false);
    assert_eq!(
      json,
      serde_json::json!({
        "set-cookie": ["a=1", "b=2"],
        "x-test": ["first"],
      })
    );
  }

  #[test]
  fn extract_body_section_accepts_uppercase_capture_format() {
    let raw = "HEADERS:\n{\"accept\":\"*/*\"}\n\nBODY:\n{\"model\":\"glm-5.1\"}\n";
    assert_eq!(
      extract_body_section(raw),
      Some("{\"model\":\"glm-5.1\"}\n".trim_start())
    );
  }

  #[test]
  fn extract_body_section_returns_none_for_plain_json() {
    let raw = "{\"model\":\"glm-5.1\"}";
    assert_eq!(extract_body_section(raw), None);
    let parsed: Value = serde_json::from_str(extract_body_section(raw).unwrap_or(raw)).unwrap();
    assert_eq!(parsed, json!({"model": "glm-5.1"}));
  }
}
