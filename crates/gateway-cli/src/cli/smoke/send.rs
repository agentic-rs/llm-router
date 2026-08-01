//! `gateway smoke send` — execute one listener-free managed profile.

use super::OutputFormat;
use crate::provider::Endpoint;
use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use futures_util::StreamExt;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokn_auth::AuthStore;
use tokn_policy::{ProfileId, RouteKind};
use tokn_requests::execution::{ManagedClientBody, ManagedClientResponse};
use tokn_router::runtime::{
  link_builtin_gateway_runtime_with_profile_roots, EmbeddedProfileRoots, ManagedGatewayError, ManagedGatewayExecutor,
  ManagedGatewayOutcome, ManagedGatewayRequest, ManagedProfileSite, ManagedSelectionSummary,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
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
  /// Managed profile to execute. Profile selection is never request-derived.
  #[arg(long)]
  pub profile: String,

  /// Model to use. Required unless --body-file contains a string `model` field.
  #[arg(long)]
  pub model: Option<String>,

  /// Client-facing API operation to test.
  #[arg(long, value_enum, default_value_t = EndpointArg::ChatCompletions)]
  pub endpoint: EndpointArg,

  /// Request and forward a live SSE response without buffering it.
  #[arg(long)]
  pub stream: bool,

  /// Output format. JSON is available only for buffered responses.
  #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
  pub format: OutputFormat,

  /// Print response headers verbatim instead of redacting sensitive values.
  #[arg(long)]
  pub no_redact: bool,

  /// Read a JSON request body from a file, or `-` for stdin.
  #[arg(long)]
  pub body_file: Option<PathBuf>,

  /// Add a semantic request header (`name=value` or `name: value`). Repeatable; last wins.
  #[arg(long = "header", value_parser = parse_header_kv)]
  pub headers: Vec<(String, String)>,

  /// Message to send. Required unless --body-file is used.
  pub message: Option<String>,
}

struct ManagedSmokeRuntime {
  profile: ProfileId,
  executor: ManagedGatewayExecutor,
}

struct PreparedRequest {
  body: Value,
  model: String,
  stream: bool,
  headers: HeaderMap,
  request_id: String,
}

pub async fn run(config_path: Option<PathBuf>, args: SendArgs) -> Result<()> {
  let config_path = tokn_config::paths::resolve_config_path(config_path.as_deref())
    .context("resolve the default gateway config path")?;
  let runtime = load_runtime(&config_path, &args.profile)?;
  let prepared = prepare_request(&args)?;

  if prepared.stream && args.format == OutputFormat::Json {
    bail!("streaming smoke requests emit raw SSE; --format json requires a buffered request");
  }
  if args.no_redact {
    eprintln!("warning: --no-redact prints response headers verbatim; do not paste sensitive output into bug reports");
  }

  let PreparedRequest {
    body,
    model,
    stream: _,
    headers,
    request_id,
  } = prepared;
  let request = ManagedGatewayRequest::new(args.endpoint.into(), body).with_headers(headers);
  let outcome = match runtime.executor.execute(&runtime.profile, request).await {
    Ok(outcome) => outcome,
    Err(error) => {
      print_execution_error(&error, &runtime.profile, &request_id, args.format)?;
      return Err(anyhow!(error).context("managed smoke request failed"));
    }
  };

  match outcome {
    ManagedGatewayOutcome::Response {
      site,
      selection,
      response,
    } => print_response(&site, &selection, &request_id, response, args.format, !args.no_redact).await,
    ManagedGatewayOutcome::CoolingDown { site, retry_at } => {
      print_unavailable(
        &site,
        &request_id,
        &model,
        "cooling_down",
        Some(retry_after_ms(retry_at)),
        args.format,
      )?;
      bail!("{site} has no selectable account until its cooldown expires")
    }
    ManagedGatewayOutcome::NoEligible { site, reason } => {
      print_unavailable(
        &site,
        &request_id,
        &model,
        &format!("no_eligible: {reason}"),
        None,
        args.format,
      )?;
      bail!("{site} has no eligible account: {reason}")
    }
  }
}

fn load_runtime(config_path: &Path, profile: &str) -> Result<ManagedSmokeRuntime> {
  let profile = ProfileId::new(profile).with_context(|| format!("invalid managed profile id '{profile}'"))?;
  let compiled = tokn_config::v2::load(config_path)
    .with_context(|| format!("load compiled gateway config `{}`", config_path.display()))?;
  let profile_plan = compiled
    .gateway()
    .profile(&profile)
    .with_context(|| format!("compiled config has no profile named '{profile}'"))?;
  let route = compiled.gateway().route(profile_plan.route()).with_context(|| {
    format!(
      "profile '{profile}' references missing route '{}'",
      profile_plan.route()
    )
  })?;
  if route.kind() != RouteKind::Managed {
    bail!(
      "profile '{profile}' uses {} route '{}'; smoke send requires a managed profile",
      route_kind_name(route.kind()),
      profile_plan.route()
    );
  }

  let accounts = AuthStore::load(None, Some(config_path))
    .context("load gateway credentials")?
    .accounts;
  let roots = EmbeddedProfileRoots::one(profile.clone());
  let linked = link_builtin_gateway_runtime_with_profile_roots(compiled.gateway(), &accounts, &roots)
    .context("link managed smoke runtime")?;
  let http_options = compiled.service().outbound().to_http_client_options();
  let executor =
    ManagedGatewayExecutor::build(Arc::new(linked), &http_options).context("build managed smoke executor")?;
  Ok(ManagedSmokeRuntime { profile, executor })
}

fn prepare_request(args: &SendArgs) -> Result<PreparedRequest> {
  let custom_body = args.body_file.as_deref().map(load_body_file).transpose()?;
  let (body, model, stream) = prepare_body(
    args.endpoint.into(),
    args.model.as_deref(),
    custom_body,
    args.message.as_deref(),
    args.stream,
  )?;
  let (headers, request_id) = build_semantic_headers(&args.headers, stream)?;
  Ok(PreparedRequest {
    body,
    model,
    stream,
    headers,
    request_id,
  })
}

fn prepare_body(
  endpoint: Endpoint,
  explicit_model: Option<&str>,
  custom_body: Option<Value>,
  message: Option<&str>,
  force_stream: bool,
) -> Result<(Value, String, bool)> {
  let mut body = match custom_body {
    Some(body) => body,
    None => {
      let model = explicit_model.ok_or_else(|| anyhow!("missing model: pass --model or provide it in --body-file"))?;
      let message = message.ok_or_else(|| anyhow!("missing message: pass a positional message or --body-file"))?;
      build_request_body(endpoint, model, message, force_stream)
    }
  };
  let object = body
    .as_object_mut()
    .ok_or_else(|| anyhow!("smoke request body must be a JSON object"))?;
  if let Some(model) = explicit_model {
    object.insert("model".into(), Value::String(model.to_owned()));
  }
  let body_stream = object
    .get("stream")
    .map(|value| {
      value
        .as_bool()
        .ok_or_else(|| anyhow!("request body field `stream` must be a boolean"))
    })
    .transpose()?
    .unwrap_or(false);
  let stream = force_stream || body_stream;
  object.insert("stream".into(), Value::Bool(stream));
  let model = object
    .get("model")
    .and_then(Value::as_str)
    .ok_or_else(|| anyhow!("request body does not contain a string `model` field; pass --model"))?
    .to_owned();
  Ok((body, model, stream))
}

fn parse_header_kv(raw: &str) -> std::result::Result<(String, String), String> {
  let separator = match (raw.find('='), raw.find(':')) {
    (Some(equals), Some(colon)) => equals.min(colon),
    (Some(equals), None) => equals,
    (None, Some(colon)) => colon,
    (None, None) => return Err(format!("expected `name=value` or `name: value`, got `{raw}`")),
  };
  let (name, value) = raw.split_at(separator);
  let value = &value[1..];
  let name = name.trim();
  let value = value.trim();
  let parsed_name = name
    .parse::<HeaderName>()
    .map_err(|error| format!("invalid header name `{name}`: {error}"))?;
  value
    .parse::<HeaderValue>()
    .map_err(|error| format!("invalid value for header `{name}`: {error}"))?;
  Ok((parsed_name.as_str().to_owned(), value.to_owned()))
}

fn build_semantic_headers(overrides: &[(String, String)], stream: bool) -> Result<(HeaderMap, String)> {
  let request_id = uuid::Uuid::new_v4().to_string();
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  headers.insert(
    ACCEPT,
    HeaderValue::from_static(if stream {
      "text/event-stream"
    } else {
      "application/json"
    }),
  );
  headers.insert("x-request-id", HeaderValue::from_str(&request_id)?);
  for (name, value) in overrides {
    let name = name
      .parse::<HeaderName>()
      .with_context(|| format!("invalid header name `{name}`"))?;
    let value = value
      .parse::<HeaderValue>()
      .with_context(|| format!("invalid value for header `{name}`"))?;
    headers.insert(name, value);
  }
  let request_id = headers
    .get("x-request-id")
    .and_then(|value| value.to_str().ok())
    .unwrap_or(&request_id)
    .to_owned();
  Ok((headers, request_id))
}

async fn print_response(
  site: &ManagedProfileSite,
  selection: &ManagedSelectionSummary,
  request_id: &str,
  response: ManagedClientResponse,
  format: OutputFormat,
  redact: bool,
) -> Result<()> {
  let (status, headers, body) = response.into_parts();
  match body {
    ManagedClientBody::Buffered(body) => {
      match format {
        OutputFormat::Json => {
          let report = serde_json::json!({
            "success": status.is_success(),
            "request_id": request_id,
            "site": site_json(site),
            "selection": selection_json(selection),
            "response": {
              "status": status.as_u16(),
              "headers": headers_json_value(&headers, redact),
              "body": buffered_body_json(&body),
            },
          });
          println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => {
          print_selection_text(site, selection, request_id, false);
          println!("status:    {}", status.as_u16());
          print_headers_text(&headers, redact, false);
          println!("body:");
          println!("{}", buffered_body_text(&body));
        }
      }
      if status.is_success() {
        Ok(())
      } else {
        bail!("managed upstream returned HTTP {}", status.as_u16())
      }
    }
    ManagedClientBody::Stream(mut stream) => {
      if format == OutputFormat::Json {
        bail!("managed executor returned a stream for JSON output")
      }
      print_selection_text(site, selection, request_id, true);
      eprintln!("status:    {}", status.as_u16());
      print_headers_text(&headers, redact, true);
      let mut stdout = tokio::io::stdout();
      while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read managed SSE response")?;
        stdout.write_all(&chunk).await.context("write SSE response to stdout")?;
        stdout.flush().await.context("flush SSE response to stdout")?;
      }
      Ok(())
    }
  }
}

fn print_selection_text(
  site: &ManagedProfileSite,
  selection: &ManagedSelectionSummary,
  request_id: &str,
  stderr: bool,
) {
  let lines = [
    format!("profile:   {}", site.profile_id()),
    format!("route:     {}", site.route_id()),
    format!("request:   {request_id}"),
    format!("account:   {}", selection.account_id()),
    format!("provider:  {}", selection.provider_id()),
    format!("upstream:  {}", selection.upstream_id()),
    format!(
      "model:     {} -> {}",
      selection.requested_model(),
      selection.upstream_model()
    ),
    format!(
      "operation: {} -> {}",
      selection.requested_operation(),
      selection.upstream_operation()
    ),
  ];
  for line in lines {
    if stderr {
      eprintln!("{line}");
    } else {
      println!("{line}");
    }
  }
}

fn print_execution_error(
  error: &ManagedGatewayError,
  profile: &ProfileId,
  request_id: &str,
  format: OutputFormat,
) -> Result<()> {
  match format {
    OutputFormat::Json => {
      let report = execution_error_json(error, profile, request_id);
      println!("{}", serde_json::to_string_pretty(&report)?);
    }
    OutputFormat::Text => {
      eprintln!("profile: {profile}");
      eprintln!("request: {request_id}");
      if let Some(site) = error.site() {
        eprintln!("route:   {}", site.route_id());
      }
      if let Some(selection) = error.selection() {
        eprintln!("account: {}", selection.account_id());
        eprintln!("upstream: {}", selection.upstream_id());
      }
    }
  }
  Ok(())
}

fn execution_error_json(error: &ManagedGatewayError, profile: &ProfileId, request_id: &str) -> Value {
  serde_json::json!({
    "success": false,
    "request_id": request_id,
    "profile": profile.as_str(),
    "site": error.site().map(site_json).unwrap_or(Value::Null),
    "selection": error.selection().map(selection_json).unwrap_or(Value::Null),
    "error": error.to_string(),
  })
}

fn print_unavailable(
  site: &ManagedProfileSite,
  request_id: &str,
  model: &str,
  reason: &str,
  retry_after_ms: Option<u64>,
  format: OutputFormat,
) -> Result<()> {
  match format {
    OutputFormat::Json => {
      let report = serde_json::json!({
        "success": false,
        "request_id": request_id,
        "site": site_json(site),
        "model": model,
        "error": reason,
        "retry_after_ms": retry_after_ms,
      });
      println!("{}", serde_json::to_string_pretty(&report)?);
    }
    OutputFormat::Text => {
      eprintln!("profile: {}", site.profile_id());
      eprintln!("route:   {}", site.route_id());
      eprintln!("model:   {model}");
      eprintln!("reason:  {reason}");
      if let Some(retry_after_ms) = retry_after_ms {
        eprintln!("retry after: {retry_after_ms}ms");
      }
    }
  }
  Ok(())
}

fn site_json(site: &ManagedProfileSite) -> Value {
  serde_json::json!({
    "profile": site.profile_id().as_str(),
    "route": site.route_id().as_str(),
  })
}

fn selection_json(selection: &ManagedSelectionSummary) -> Value {
  serde_json::json!({
    "account": selection.account_id(),
    "provider": selection.provider_id().as_str(),
    "upstream": selection.upstream_id().as_str(),
    "requested_model": selection.requested_model(),
    "upstream_model": selection.upstream_model(),
    "requested_operation": selection.requested_operation().as_str(),
    "upstream_operation": selection.upstream_operation().as_str(),
    "wire_identity": selection.wire_identity().map(|identity| identity.as_str()),
  })
}

fn headers_json_value(headers: &HeaderMap, redact: bool) -> Value {
  let mut output = serde_json::Map::new();
  for name in headers.keys() {
    let values = headers
      .get_all(name)
      .iter()
      .map(|value| Value::String(render_header_value(name, value, redact)))
      .collect();
    output.insert(name.as_str().to_owned(), Value::Array(values));
  }
  Value::Object(output)
}

fn print_headers_text(headers: &HeaderMap, redact: bool, stderr: bool) {
  if stderr {
    eprintln!("headers:");
  } else {
    println!("headers:");
  }
  for name in headers.keys() {
    for value in headers.get_all(name) {
      let value = render_header_value(name, value, redact);
      if stderr {
        eprintln!("  {name}: {value}");
      } else {
        println!("  {name}: {value}");
      }
    }
  }
}

fn render_header_value(name: &HeaderName, value: &HeaderValue, redact: bool) -> String {
  if redact && (value.is_sensitive() || is_sensitive_header(name.as_str())) {
    return "<redacted>".to_owned();
  }
  value
    .to_str()
    .map(str::to_owned)
    .unwrap_or_else(|_| format!("<non-UTF-8 value: {} bytes>", value.as_bytes().len()))
}

fn is_sensitive_header(name: &str) -> bool {
  matches!(
    name,
    "authorization"
      | "proxy-authorization"
      | "cookie"
      | "set-cookie"
      | "api-key"
      | "x-api-key"
      | "x-goog-api-key"
      | "x-auth-token"
      | "x-access-token"
      | "ocp-apim-subscription-key"
  )
}

fn buffered_body_json(body: &[u8]) -> Value {
  serde_json::from_slice(body).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
}

fn buffered_body_text(body: &[u8]) -> String {
  match serde_json::from_slice::<Value>(body) {
    Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
    Err(_) => String::from_utf8_lossy(body).into_owned(),
  }
}

fn retry_after_ms(retry_at: Instant) -> u64 {
  retry_at
    .saturating_duration_since(Instant::now())
    .as_millis()
    .try_into()
    .unwrap_or(u64::MAX)
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
      "messages": [{"role": "user", "content": message}],
    }),
    Endpoint::Responses => serde_json::json!({
      "model": model,
      "stream": stream,
      "input": message,
    }),
  }
}

fn load_body_file(path: &Path) -> Result<Value> {
  use std::io::Read;

  let raw = if path == Path::new("-") {
    let mut buffer = String::new();
    std::io::stdin()
      .read_to_string(&mut buffer)
      .context("read smoke request body from stdin")?;
    buffer
  } else {
    std::fs::read_to_string(path).with_context(|| format!("read smoke request body `{}`", path.display()))?
  };
  let body = extract_body_section(&raw).unwrap_or_else(|| raw.trim_start());
  serde_json::from_str(body).context("parse smoke request body as JSON")
}

fn extract_body_section(raw: &str) -> Option<&str> {
  let mut offset = 0;
  for line_with_ending in raw.split_inclusive('\n') {
    let line = line_with_ending.strip_suffix('\n').unwrap_or(line_with_ending);
    let line = line.strip_suffix('\r').unwrap_or(line);
    offset += line_with_ending.len();
    if line.trim().eq_ignore_ascii_case("body:") {
      return Some(raw[offset..].trim_start());
    }
  }
  None
}

fn route_kind_name(kind: RouteKind) -> &'static str {
  match kind {
    RouteKind::Managed => "managed",
    RouteKind::Relay => "relay",
    RouteKind::Transparent => "transparent",
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn build_request_body_messages_leaves_route_defaults_to_managed_execution() {
    let body = build_request_body(Endpoint::Messages, "claude", "hi", false);
    assert!(body.get("max_tokens").is_none());
    assert_eq!(body["messages"][0]["content"], "hi");
  }

  #[test]
  fn prepare_body_requires_an_explicit_model_without_a_body_file() {
    let error = prepare_body(Endpoint::Responses, None, None, Some("hello"), false).unwrap_err();
    assert_eq!(
      error.to_string(),
      "missing model: pass --model or provide it in --body-file"
    );
  }

  #[test]
  fn explicit_flags_override_body_model_and_enable_streaming() {
    let (body, model, stream) = prepare_body(
      Endpoint::Responses,
      Some("provider/replacement"),
      Some(json!({"model": "provider/original", "input": "hello", "stream": false})),
      None,
      true,
    )
    .unwrap();

    assert_eq!(model, "provider/replacement");
    assert!(stream);
    assert_eq!(body["model"], "provider/replacement");
    assert_eq!(body["stream"], true);
  }

  #[test]
  fn body_file_stream_must_be_boolean_and_is_normalized_when_absent() {
    let error = prepare_body(
      Endpoint::Responses,
      None,
      Some(json!({"model": "provider/model", "stream": "yes"})),
      None,
      false,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "request body field `stream` must be a boolean");

    let (body, _, stream) = prepare_body(
      Endpoint::Responses,
      None,
      Some(json!({"model": "provider/model", "input": "hello"})),
      None,
      false,
    )
    .unwrap();
    assert!(!stream);
    assert_eq!(body["stream"], false);
  }

  #[test]
  fn generated_endpoint_bodies_use_the_requested_client_shape() {
    let chat = build_request_body(Endpoint::ChatCompletions, "provider/model", "hello", false);
    assert_eq!(chat["messages"][0]["content"], "hello");
    assert!(chat.get("input").is_none());

    let responses = build_request_body(Endpoint::Responses, "provider/model", "hello", false);
    assert_eq!(responses["input"], "hello");
    assert!(responses.get("messages").is_none());
  }

  #[test]
  fn header_parser_rejects_invalid_native_headers() {
    assert!(parse_header_kv("not a header=value").is_err());
    assert!(parse_header_kv("x-test=value\nsmuggled").is_err());
    assert_eq!(
      parse_header_kv("X-Session-Id: session").unwrap(),
      ("x-session-id".to_owned(), "session".to_owned())
    );
    assert_eq!(
      parse_header_kv("Cookie: session=abc==").unwrap(),
      ("cookie".to_owned(), "session=abc==".to_owned())
    );
    assert_eq!(
      parse_header_kv("x-callback=https://example.test/result?a=b").unwrap(),
      ("x-callback".to_owned(), "https://example.test/result?a=b".to_owned())
    );
  }

  #[test]
  fn semantic_header_overrides_are_last_wins() {
    let (headers, request_id) = build_semantic_headers(
      &[
        ("accept".to_owned(), "application/problem+json".to_owned()),
        ("x-request-id".to_owned(), "captured-request".to_owned()),
      ],
      true,
    )
    .unwrap();

    assert_eq!(headers.get(ACCEPT).unwrap(), "application/problem+json");
    assert_eq!(request_id, "captured-request");
  }

  #[test]
  fn headers_json_value_preserves_multi_values_and_redacts_secrets() {
    let mut headers = HeaderMap::new();
    headers.append("set-cookie", HeaderValue::from_static("a=1"));
    headers.append("x-test", HeaderValue::from_static("first"));
    headers.append("set-cookie", HeaderValue::from_static("b=2"));
    headers.append("api-key", HeaderValue::from_static("azure-secret"));
    headers.append("x-goog-api-key", HeaderValue::from_static("google-secret"));
    headers.append("x-auth-token", HeaderValue::from_static("provider-secret"));
    let mut marked_sensitive = HeaderValue::from_static("marked-secret");
    marked_sensitive.set_sensitive(true);
    headers.append("x-provider-secret", marked_sensitive);

    assert_eq!(
      headers_json_value(&headers, true),
      json!({
        "api-key": ["<redacted>"],
        "set-cookie": ["<redacted>", "<redacted>"],
        "x-auth-token": ["<redacted>"],
        "x-goog-api-key": ["<redacted>"],
        "x-provider-secret": ["<redacted>"],
        "x-test": ["first"],
      })
    );
    assert_eq!(
      headers_json_value(&headers, false)["x-provider-secret"],
      json!(["marked-secret"])
    );
  }

  #[test]
  fn extract_body_section_accepts_capture_format() {
    let raw = "HEADERS:\n{\"accept\":\"*/*\"}\n\nBODY:\n{\"model\":\"provider/model\"}\n";
    assert_eq!(
      extract_body_section(raw),
      Some("{\"model\":\"provider/model\"}\n".trim_start())
    );
  }

  #[test]
  fn extract_body_section_accepts_crlf_capture_format() {
    let raw = "HEADERS:\r\n{\"accept\":\"*/*\"}\r\n\r\nBODY:\r\n{\"model\":\"provider/model\"}\r\n";
    assert_eq!(extract_body_section(raw), Some("{\"model\":\"provider/model\"}\r\n"));
  }

  #[test]
  fn extract_body_section_returns_none_for_plain_json() {
    let raw = "{\"model\":\"provider/model\"}";
    assert_eq!(extract_body_section(raw), None);
    let parsed: Value = serde_json::from_str(extract_body_section(raw).unwrap_or(raw)).unwrap();
    assert_eq!(parsed, json!({"model": "provider/model"}));
  }

  #[test]
  fn execution_error_json_includes_request_id() {
    let profile = ProfileId::new("work").unwrap();
    let error = ManagedGatewayError::ProfileNotLinked {
      profile: profile.clone(),
    };

    let report = execution_error_json(&error, &profile, "request-123");

    assert_eq!(report["success"], false);
    assert_eq!(report["request_id"], "request-123");
    assert_eq!(report["profile"], "work");
  }
}
