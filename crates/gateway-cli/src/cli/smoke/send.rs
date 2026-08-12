//! `smoke send` executes one request through a configured v2 LLM listener.

use super::OutputFormat;
use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use axum::body::Body;
use bytes::Bytes;
use clap::Args;
use futures_util::StreamExt;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokn_core::event::Event as CoreEvent;
use tokn_core::provider::Endpoint;
use tokn_core::request_event::{
  BuiltHeadersSummary, ConvertedRequestSummary, RequestEvent, RequestEventPayload, ResolvedSummary, StageEvent,
};
use tokn_policy::ClientAuthPlan;
use tower::ServiceExt;

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum EndpointArg {
  ChatCompletions,
  Responses,
  Messages,
}

impl From<EndpointArg> for Endpoint {
  fn from(value: EndpointArg) -> Self {
    match value {
      EndpointArg::ChatCompletions => Endpoint::ChatCompletions,
      EndpointArg::Responses => Endpoint::Responses,
      EndpointArg::Messages => Endpoint::Messages,
    }
  }
}

#[derive(Args, Debug)]
pub struct SendArgs {
  /// V2 LLM API listener to exercise. Required when more than one is configured.
  #[arg(long)]
  pub listener: Option<String>,

  /// Model to use for the smoke request.
  #[arg(long)]
  pub model: Option<String>,

  /// API endpoint to test.
  #[arg(long, value_enum, default_value_t = EndpointArg::ChatCompletions)]
  pub endpoint: EndpointArg,

  /// Request a streaming SSE response.
  #[arg(long)]
  pub stream: bool,

  /// Resolve and convert the request without contacting the upstream.
  #[arg(long)]
  pub dry_run: bool,

  /// Output format. Streaming responses are always emitted as raw SSE bytes.
  #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
  pub format: OutputFormat,

  /// Print response headers verbatim instead of redacting sensitive values.
  #[arg(long)]
  pub no_redact: bool,

  /// Read the raw JSON request body from a file, or `-` for stdin.
  #[arg(long)]
  pub body_file: Option<PathBuf>,

  /// Inject an inbound header (`name=value`). Repeatable; last value wins.
  #[arg(long = "header", value_parser = parse_header_kv)]
  pub headers: Vec<(String, String)>,

  /// Message to send. Optional when `--body-file` is provided.
  pub message: Option<String>,
}

pub async fn run(cfg_path: Option<PathBuf>, args: SendArgs) -> Result<()> {
  let (plan, config_path) = super::load_v2_plan(cfg_path.as_deref())?;
  let accounts = crate::server_runtime::load_accounts(Some(&config_path))?;
  let access = Arc::new(tokn_access::AccessStore::disabled());

  if args.no_redact {
    eprintln!(
      "warning: --no-redact is set; sensitive headers will be printed verbatim. Do not paste this output into bug reports."
    );
  }

  // V2 does not yet expose operational event/database settings. Match `serve`
  // by using the existing defaults until those settings move into v2.
  let operational = Config::default();
  let (events, receiver, handlers, archive_runtime) = crate::server_runtime::build_event_bus(&operational)?;
  let _event_thread = tokn_core::event::spawn_event_loop(receiver, handlers);
  let captured = Captured::install(&events);
  if args.format == OutputFormat::Text {
    subscribe_event_printer(&events);
  }

  let states = if args.dry_run {
    tokn_router::v2::build_dry_run_states(plan, &accounts, access.clone(), events.clone())?
  } else {
    tokn_router::v2::build_states(plan, &accounts, access.clone(), events.clone())?
  };
  let state = select_listener(states, args.listener.as_deref())?;
  let listener_id = state.listener_id().to_string();

  let endpoint: Endpoint = args.endpoint.into();
  let mut body = match args.body_file.as_deref() {
    Some(path) => load_body_file(path)?,
    None => {
      let model = args.model.as_deref().ok_or_else(|| anyhow!("missing --model"))?;
      let message = args
        .message
        .as_deref()
        .ok_or_else(|| anyhow!("missing message: pass a positional message or --body-file"))?;
      build_request_body(endpoint, model, message, args.stream)
    }
  };
  if let Some(object) = body.as_object_mut() {
    if let Some(model) = args.model.as_ref() {
      object.insert("model".into(), Value::String(model.clone()));
    }
    if args.stream {
      object.insert("stream".into(), Value::Bool(true));
    }
  }
  let model = body
    .get("model")
    .and_then(Value::as_str)
    .ok_or_else(|| anyhow!("request body does not contain a string `model`; pass --model"))?
    .to_string();
  let request_id = uuid::Uuid::new_v4().to_string();
  let mut request = http::Request::post(endpoint_path(endpoint))
    .header(http::header::CONTENT_TYPE, "application/json")
    .header("x-request-id", &request_id)
    .body(Body::from(serde_json::to_vec(&body)?))?;
  apply_headers(request.headers_mut(), &args.headers)?;

  // Exercise the real listener authentication middleware without requiring
  // users to expose or supply one of their persistent downstream keys.
  if state.client_auth() == ClientAuthPlan::LocalKeys {
    let token = access.create_key("v2 smoke", Vec::new())?.token;
    request.headers_mut().insert(
      http::header::AUTHORIZATION,
      http::HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
  }

  if args.format == OutputFormat::Text {
    println!("listener: {listener_id}");
    println!("model:    {model}");
    println!("endpoint: {}", endpoint.as_str());
    println!("stream:   {}", args.stream);
    println!("dry_run:  {}", args.dry_run);
    println!();
  }

  let response = tokn_router::v2::router(state)
    .oneshot(request)
    .await
    .context("execute v2 smoke request")?;
  let status = response.status();
  let headers = response.headers().clone();
  let body = response.into_body();

  let mut dry_run_stopped = false;
  if args.stream && !args.dry_run {
    print_stream_response(status, &headers, body, args.format, !args.no_redact).await?;
  } else {
    let bytes = axum::body::to_bytes(body, usize::MAX)
      .await
      .context("read v2 smoke response body")?;
    let mut snapshot = captured.snapshot_after_completion().await;
    snapshot.configured_provider = snapshot.resolved.as_ref().and_then(|resolved| {
      accounts
        .iter()
        .find(|account| account.id == resolved.account_id)
        .map(|account| account.provider.clone())
    });
    dry_run_stopped = args.dry_run && snapshot.stopped;
    if dry_run_stopped {
      print_dry_run_response(&listener_id, &snapshot, args.format, !args.no_redact)?;
    } else {
      print_buffered_response(
        &listener_id,
        status,
        &headers,
        &bytes,
        &snapshot,
        args.format,
        !args.no_redact,
      )?;
    }
  }

  events.shutdown().await;
  if let Some(archive_runtime) = archive_runtime {
    archive_runtime.shutdown().await;
  }
  if args.dry_run && !dry_run_stopped {
    anyhow::bail!("v2 dry-run pipeline did not stop before upstream send");
  }
  if !status.is_success() && !dry_run_stopped {
    anyhow::bail!("v2 smoke request failed with HTTP {status}");
  }
  Ok(())
}

fn select_listener(
  states: Vec<tokn_router::v2::AppState>,
  requested: Option<&str>,
) -> Result<tokn_router::v2::AppState> {
  if let Some(requested) = requested {
    return states
      .into_iter()
      .find(|state| state.listener_id().as_str() == requested)
      .ok_or_else(|| anyhow!("unknown v2 LLM API listener '{requested}'"));
  }
  match states.len() {
    0 => anyhow::bail!("v2 config has no LLM API listener for `smoke send`"),
    1 => Ok(states.into_iter().next().expect("one state")),
    _ => {
      let listeners = states
        .iter()
        .map(|state| state.listener_id().as_str())
        .collect::<Vec<_>>()
        .join(", ");
      anyhow::bail!("multiple v2 LLM API listeners are configured ({listeners}); pass --listener")
    }
  }
}

async fn print_stream_response(
  status: http::StatusCode,
  headers: &http::HeaderMap,
  body: Body,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  if format == OutputFormat::Text {
    println!("--- response (stream) ---");
    println!("status: {status}");
    print_headers_text(headers, redact);
    println!("body:");
  }
  let mut stdout = tokio::io::stdout();
  let mut total_bytes = 0_usize;
  let mut stream = body.into_data_stream();
  while let Some(chunk) = stream.next().await {
    let chunk = chunk.context("read v2 smoke response stream")?;
    total_bytes += chunk.len();
    stdout.write_all(&chunk).await.context("write smoke response stream")?;
    stdout.flush().await.ok();
  }
  if format == OutputFormat::Text {
    println!();
    println!("--- end of stream ({total_bytes} bytes) ---");
  }
  Ok(())
}

fn print_buffered_response(
  listener: &str,
  status: http::StatusCode,
  headers: &http::HeaderMap,
  body: &Bytes,
  snapshot: &CapturedSnapshot,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  let body_json = serde_json::from_slice::<Value>(body).ok();
  match format {
    OutputFormat::Json => {
      let report = serde_json::json!({
        "listener": listener,
        "request_id": snapshot.request_id,
        "account": snapshot.resolved.as_ref().map(|resolved| resolved.account_id.as_str()),
        "provider": snapshot.configured_provider,
        "driver": snapshot.resolved.as_ref().map(|resolved| resolved.provider_id.as_str()),
        "model": snapshot.resolved.as_ref().map(|resolved| resolved.model.as_str()),
        "upstream_model": snapshot.resolved.as_ref().map(|resolved| resolved.upstream_model.as_str()),
        "upstream_endpoint": snapshot.resolved.as_ref().and_then(|resolved| resolved.upstream_endpoint).map(|endpoint| endpoint.as_str()),
        "attempts": snapshot.attempts,
        "status": status.as_u16(),
        "headers": headers_json_value(headers, redact),
        "body": body_json.unwrap_or_else(|| Value::String(String::from_utf8_lossy(body).into_owned())),
      });
      println!("{}", serde_json::to_string_pretty(&report)?);
    }
    OutputFormat::Text => {
      println!();
      println!("--- response ---");
      if let Some(resolved) = snapshot.resolved.as_ref() {
        println!("account:  {}", resolved.account_id);
        if let Some(provider) = snapshot.configured_provider.as_deref() {
          println!("provider: {provider}");
        }
        println!("driver:   {}", resolved.provider_id);
        println!("model:    {} -> {}", resolved.model, resolved.upstream_model);
        if let Some(endpoint) = resolved.upstream_endpoint {
          println!("upstream: {}", endpoint.as_str());
        }
      }
      println!("status:   {status}");
      print_headers_text(headers, redact);
      println!("body:");
      match body_json {
        Some(body) => println!("{}", serde_json::to_string_pretty(&body)?),
        None => println!("{}", String::from_utf8_lossy(body)),
      }
    }
  }
  Ok(())
}

fn print_dry_run_response(
  listener: &str,
  snapshot: &CapturedSnapshot,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  let resolved = snapshot.resolved.as_ref();
  let headers = snapshot.built_headers.as_ref();
  let converted = snapshot.converted_request.as_ref();
  match format {
    OutputFormat::Json => {
      let report = serde_json::json!({
        "dry_run": true,
        "listener": listener,
        "request_id": snapshot.request_id,
        "account": resolved.map(|resolved| resolved.account_id.as_str()),
        "provider": snapshot.configured_provider,
        "driver": resolved.map(|resolved| resolved.provider_id.as_str()),
        "model": resolved.map(|resolved| resolved.model.as_str()),
        "upstream_model": resolved.map(|resolved| resolved.upstream_model.as_str()),
        "upstream_endpoint": resolved.and_then(|resolved| resolved.upstream_endpoint).map(Endpoint::as_str),
        "attempts": snapshot.attempts,
        "headers": headers.map(|headers| pipeline_headers_json(&headers.headers, redact)).unwrap_or(Value::Null),
        "body": converted.map(|converted| (*converted.upstream_body).clone()).unwrap_or(Value::Null),
        "content_encoding": converted.and_then(|converted| converted.content_encoding.as_deref()),
      });
      println!("{}", serde_json::to_string_pretty(&report)?);
    }
    OutputFormat::Text => {
      println!();
      println!("--- dry run ---");
      if let Some(resolved) = resolved {
        println!("account:  {}", resolved.account_id);
        if let Some(provider) = snapshot.configured_provider.as_deref() {
          println!("provider: {provider}");
        }
        println!("driver:   {}", resolved.provider_id);
        println!("model:    {} -> {}", resolved.model, resolved.upstream_model);
        if let Some(endpoint) = resolved.upstream_endpoint {
          println!("upstream: {}", endpoint.as_str());
        }
      }
      if let Some(headers) = headers {
        println!("headers:");
        for (name, value) in headers.headers.iter() {
          println!(
            "  {}: {}",
            name.as_str(),
            redact_header(name.as_str(), value.as_str(), redact)
          );
        }
      }
      if let Some(converted) = converted {
        if let Some(encoding) = converted.content_encoding.as_deref() {
          println!("content-encoding: {encoding}");
        }
        println!("body:");
        println!("{}", serde_json::to_string_pretty(&*converted.upstream_body)?);
      }
    }
  }
  Ok(())
}

#[derive(Default)]
struct Captured {
  inner: Mutex<CapturedSnapshot>,
  completed: tokio::sync::Notify,
}

#[derive(Clone, Default)]
struct CapturedSnapshot {
  request_id: Option<String>,
  configured_provider: Option<String>,
  resolved: Option<ResolvedSummary>,
  built_headers: Option<BuiltHeadersSummary>,
  converted_request: Option<ConvertedRequestSummary>,
  attempts: Option<u32>,
  stopped: bool,
  completed: bool,
}

impl Captured {
  fn install(events: &tokn_core::event::EventBus) -> Arc<Self> {
    let captured = Arc::new(Self::default());
    let sink = captured.clone();
    let mut receiver = events.subscribe();
    tokio::spawn(async move {
      loop {
        match receiver.recv().await {
          Ok(event) => {
            let CoreEvent::Requests(event) = &*event else {
              continue;
            };
            let mut snapshot = sink.inner.lock().unwrap();
            snapshot.request_id.get_or_insert_with(|| event.request_id.to_string());
            match &event.payload {
              RequestEventPayload::Stage(StageEvent::Resolve(resolved)) => snapshot.resolved = Some(resolved.clone()),
              RequestEventPayload::Stage(StageEvent::BuildHeaders(headers)) => {
                snapshot.built_headers = Some(headers.clone())
              }
              RequestEventPayload::Stage(StageEvent::ConvertRequest(converted)) => {
                snapshot.converted_request = Some(converted.clone())
              }
              RequestEventPayload::Stage(StageEvent::Error { stop, .. }) => snapshot.stopped = *stop,
              RequestEventPayload::Stage(StageEvent::Completed { attempts, .. }) => {
                snapshot.attempts = Some(*attempts);
                snapshot.completed = true;
                sink.completed.notify_waiters();
              }
              _ => {}
            }
          }
          Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
          Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
      }
    });
    captured
  }

  async fn snapshot_after_completion(&self) -> CapturedSnapshot {
    loop {
      let notified = self.completed.notified();
      let snapshot = self.inner.lock().unwrap().clone();
      if snapshot.completed {
        return snapshot;
      }
      if tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .is_err()
      {
        return self.inner.lock().unwrap().clone();
      }
    }
  }
}

fn subscribe_event_printer(events: &tokn_core::event::EventBus) {
  let mut receiver = events.subscribe();
  tokio::spawn(async move {
    loop {
      match receiver.recv().await {
        Ok(event) => {
          if let CoreEvent::Requests(event) = &*event {
            print_event(event);
          }
        }
        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
      }
    }
  });
}

fn print_event(event: &RequestEvent) {
  let RequestEventPayload::Stage(stage) = &event.payload else {
    return;
  };
  match stage {
    StageEvent::Started { request_endpoint } => println!("[started]          endpoint={request_endpoint}"),
    StageEvent::Extract(extracted) => println!(
      "[extract]          model={} stream={}",
      extracted.model, extracted.stream
    ),
    StageEvent::Resolve(resolved) => println!(
      "[resolve]          model={} -> {} account={} driver={} upstream_endpoint={}",
      resolved.model,
      resolved.upstream_model,
      resolved.account_id,
      resolved.provider_id,
      resolved.upstream_endpoint.map(Endpoint::as_str).unwrap_or("auto")
    ),
    StageEvent::BuildHeaders(_) => println!("[build_headers]    ok"),
    StageEvent::ConvertRequest(_) => println!("[convert_request]  ok"),
    StageEvent::Send(_) => println!("[send]             ok"),
    StageEvent::ConvertResponse(_) => println!("[convert_response] ok"),
    StageEvent::Error {
      stage,
      message,
      recoverable,
      stop,
    } => println!("[error]            stage={stage} recoverable={recoverable} stop={stop} message={message}"),
    StageEvent::Completed { success, attempts } => {
      println!("[completed]        success={success} attempts={attempts}")
    }
  }
}

fn parse_header_kv(raw: &str) -> std::result::Result<(String, String), String> {
  let (delimiter_index, delimiter) = raw
    .char_indices()
    .find(|(_, character)| matches!(character, '=' | ':'))
    .ok_or_else(|| format!("expected `name=value` or `name: value`, got `{raw}`"))?;
  let (name, value) = raw.split_at(delimiter_index);
  let value = &value[delimiter.len_utf8()..];
  let value = if delimiter == ':' { value.trim_start() } else { value };
  let name = name.trim();
  if name.is_empty() {
    return Err("header name must not be empty".into());
  }
  Ok((name.to_string(), value.trim().to_string()))
}

fn apply_headers(headers: &mut http::HeaderMap, overrides: &[(String, String)]) -> Result<()> {
  for (name, value) in overrides {
    let name =
      http::HeaderName::from_bytes(name.as_bytes()).with_context(|| format!("invalid header name '{name}'"))?;
    let value = http::HeaderValue::from_str(value).with_context(|| format!("invalid value for header '{name}'"))?;
    headers.insert(name, value);
  }
  Ok(())
}

fn endpoint_path(endpoint: Endpoint) -> &'static str {
  match endpoint {
    Endpoint::ChatCompletions => "/v1/chat/completions",
    Endpoint::Responses => "/v1/responses",
    Endpoint::Messages => "/v1/messages",
  }
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

fn load_body_file(path: &std::path::Path) -> Result<Value> {
  use std::io::Read;
  let raw = if path == std::path::Path::new("-") {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer).context("read stdin")?;
    buffer
  } else {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
  };
  let body = extract_body_section(&raw).unwrap_or_else(|| raw.trim_start());
  serde_json::from_str(body).context("parse body file as JSON")
}

fn extract_body_section(raw: &str) -> Option<&str> {
  let body_index = raw
    .lines()
    .scan(0_usize, |offset, line| {
      let start = *offset;
      *offset += line.len() + 1;
      Some((start, line))
    })
    .find_map(|(start, line)| line.trim().eq_ignore_ascii_case("body:").then_some(start + line.len()))?;
  Some(raw[body_index..].trim_start_matches(['\r', '\n']).trim_start())
}

fn print_headers_text(headers: &http::HeaderMap, redact: bool) {
  println!("headers:");
  for (name, value) in headers {
    let value = value.to_str().unwrap_or("<non-utf8>");
    println!("  {name}: {}", redact_header(name.as_str(), value, redact));
  }
}

fn headers_json_value(headers: &http::HeaderMap, redact: bool) -> Value {
  let mut map = serde_json::Map::new();
  for (name, value) in headers {
    let value = Value::String(redact_header(
      name.as_str(),
      value.to_str().unwrap_or("<non-utf8>"),
      redact,
    ));
    match map.get_mut(name.as_str()) {
      Some(Value::Array(values)) => values.push(value),
      Some(_) => unreachable!("header JSON values are arrays"),
      None => {
        map.insert(name.to_string(), Value::Array(vec![value]));
      }
    }
  }
  Value::Object(map)
}

fn pipeline_headers_json(headers: &tokn_headers::HeaderMap, redact: bool) -> Value {
  let mut map = serde_json::Map::new();
  for (name, value) in headers.iter() {
    let value = Value::String(redact_header(name.as_str(), value.as_str(), redact));
    match map.get_mut(name.as_str()) {
      Some(Value::Array(values)) => values.push(value),
      Some(_) => unreachable!("header JSON values are arrays"),
      None => {
        map.insert(name.as_str().to_string(), Value::Array(vec![value]));
      }
    }
  }
  Value::Object(map)
}

fn redact_header(name: &str, value: &str, redact: bool) -> String {
  if !redact || value.is_empty() || value == "<missing>" {
    return value.to_string();
  }
  match name.to_ascii_lowercase().as_str() {
    "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" => "<redacted>".into(),
    _ => value.to_string(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn builds_endpoint_specific_request_bodies() {
    let messages = build_request_body(Endpoint::Messages, "claude", "hi", false);
    assert_eq!(messages["max_tokens"], 32_000);
    assert_eq!(messages["messages"][0]["content"], "hi");

    let chat = build_request_body(Endpoint::ChatCompletions, "gpt-4.1", "hi", false);
    assert!(chat.get("max_tokens").is_none());
  }

  #[test]
  fn extracts_body_from_capture_or_plain_json() {
    let captured = "HEADERS:\n{\"accept\":\"*/*\"}\n\nBODY:\n{\"model\":\"glm-5.1\"}\n";
    assert_eq!(extract_body_section(captured), Some("{\"model\":\"glm-5.1\"}\n"));
    assert_eq!(extract_body_section("{\"model\":\"glm-5.1\"}"), None);
  }

  #[test]
  fn header_parser_uses_first_supported_delimiter() {
    assert_eq!(
      parse_header_kv(" x-trace: a=b ").unwrap(),
      ("x-trace".into(), "a=b".into())
    );
    assert_eq!(
      parse_header_kv("x-url=https://example.test").unwrap(),
      ("x-url".into(), "https://example.test".into())
    );
  }

  #[test]
  fn header_json_preserves_duplicate_values() {
    let mut headers = http::HeaderMap::new();
    headers.append("set-cookie", "a=1".parse().unwrap());
    headers.append("set-cookie", "b=2".parse().unwrap());

    assert_eq!(
      headers_json_value(&headers, false),
      serde_json::json!({"set-cookie": ["a=1", "b=2"]})
    );
  }
}
