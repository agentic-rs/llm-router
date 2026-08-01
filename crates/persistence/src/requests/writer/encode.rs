//! Encoding helpers for the unchanged request-database compatibility shape.

use super::{RequestWriteError, WriteResult};
use serde_json::{Map, Value};
use tokn_events::{
  is_sensitive_header_name, AttemptNo, AttemptOutcome, BodyResult, CapturedHeaderValue, CapturedHeaders, ConnectAction,
  EventFailure, HttpFamily, IngressKind, RequestFinished, RequestOutcome, RequestPhase, RequestSource, RequestStarted,
  TargetSelection, TokenUsage, UsageKind,
};

pub(super) fn day_key(timestamp_ms: i64) -> WriteResult<String> {
  time::OffsetDateTime::from_unix_timestamp(timestamp_ms.div_euclid(1_000))
    .map(|timestamp| timestamp.date().to_string())
    .map_err(|_| RequestWriteError::InvalidTimestamp(timestamp_ms))
}

pub(super) fn object_json(object: &Map<String, Value>) -> WriteResult<String> {
  Ok(serde_json::to_string(object)?)
}

pub(super) fn optional_object_json(object: &Map<String, Value>) -> WriteResult<Option<String>> {
  if object.is_empty() {
    Ok(None)
  } else {
    object_json(object).map(Some)
  }
}

pub(super) fn headers_json(headers: &CapturedHeaders) -> WriteResult<Vec<u8>> {
  let mut object = Map::new();
  for header in headers.iter() {
    let name = header.name().to_ascii_lowercase();
    let value = match header.captured_value() {
      _ if is_sensitive_header_name(&name) => "<redacted>".to_string(),
      CapturedHeaderValue::Value(value) => std::str::from_utf8(value).unwrap_or("<non-utf8>").to_string(),
      CapturedHeaderValue::Redacted => "<redacted>".to_string(),
    };
    object.insert(name, Value::String(value));
  }
  Ok(serde_json::to_vec(&object)?)
}

pub(super) fn usage_json(usage: &TokenUsage) -> WriteResult<Option<String>> {
  let mut object = Map::new();
  if let Some(kind) = usage.kind {
    object.insert("kind".to_string(), Value::String(usage_kind_name(kind).to_string()));
  }
  for (key, value) in [
    ("input", usage.input),
    ("output", usage.output),
    ("total", usage.total),
    ("cache_read", usage.cache_read),
    ("cache_write", usage.cache_write),
    ("reasoning", usage.reasoning),
  ] {
    if let Some(value) = value {
      object.insert(key.to_string(), Value::from(value));
    }
  }
  optional_object_json(&object)
}

fn usage_kind_name(kind: UsageKind) -> &'static str {
  match kind {
    UsageKind::ChatCompletions => "chat_completions",
    UsageKind::Responses => "responses",
    UsageKind::Messages => "messages",
    _ => "unknown",
  }
}

pub(super) fn started_context(started: &RequestStarted) -> Map<String, Value> {
  let mut context = Map::new();
  context.insert("body_present".to_string(), Value::Bool(started.body_present));
  insert_optional_string(&mut context, "http_version", started.http_version.as_ref());
  if started.target.is_redacted() {
    context.insert("inbound_target_redacted".to_string(), Value::Bool(true));
  }
  match &started.source {
    RequestSource::Listener {
      listener_id,
      ingress,
      local_addr,
      peer_addr,
    } => {
      insert_literal(&mut context, "request_source", "listener");
      insert_string(&mut context, "listener_id", listener_id);
      insert_literal(&mut context, "ingress", ingress_name(ingress));
      insert_literal(&mut context, "pipeline_id", ingress_name(ingress));
      if let IngressKind::InterceptedHttps { parent_connect_id } = ingress {
        insert_string(&mut context, "parent_connect_id", parent_connect_id);
      }
      if let Some(local_addr) = local_addr {
        insert_literal(&mut context, "local_addr", &local_addr.to_string());
      }
      if let Some(peer_addr) = peer_addr {
        insert_literal(&mut context, "peer_addr", &peer_addr.to_string());
      }
    }
    RequestSource::Embedded { profile_id } => {
      insert_literal(&mut context, "request_source", "embedded");
      insert_literal(&mut context, "pipeline_id", "embedded");
      insert_string(&mut context, "source_profile_id", profile_id);
    }
    _ => {
      insert_literal(&mut context, "request_source", "unknown");
      insert_literal(&mut context, "pipeline_id", "unknown");
    }
  }
  let correlation = &started.correlation;
  insert_optional_string(
    &mut context,
    "client_request_id",
    correlation.client_request_id.as_ref(),
  );
  insert_optional_string(&mut context, "thread_id", correlation.thread_id.as_ref());
  insert_optional_string(&mut context, "parent_thread_id", correlation.parent_thread_id.as_ref());
  insert_optional_string(
    &mut context,
    "parent_session_id",
    correlation.parent_session_id.as_ref(),
  );
  insert_optional_string(&mut context, "project_id", correlation.project_id.as_ref());
  insert_optional_string(&mut context, "turn_id", correlation.turn_id.as_ref());
  context
}

pub(super) fn insert_string(context: &mut Map<String, Value>, key: &str, value: &impl ToString) {
  insert_literal(context, key, &value.to_string());
}

pub(super) fn insert_optional_string<T: ToString>(context: &mut Map<String, Value>, key: &str, value: Option<&T>) {
  if let Some(value) = value {
    insert_string(context, key, value);
  }
}

pub(super) fn insert_literal(context: &mut Map<String, Value>, key: &str, value: &str) {
  context.insert(key.to_string(), Value::String(value.to_string()));
}

pub(super) fn insert_failure(context: &mut Map<String, Value>, key: &str, failure: &EventFailure) {
  let mut value = Map::new();
  insert_string(&mut value, "code", &failure.code);
  insert_string(&mut value, "message", &failure.message);
  context.insert(key.to_string(), Value::Object(value));
}

pub(super) fn format_failure(phase: RequestPhase, failure: &EventFailure) -> String {
  format!("{}: {}", request_phase_name(phase), failure.message)
}

pub(super) fn terminal_error(finished: &RequestFinished) -> Option<String> {
  if let Some(failure) = finished.failure.as_ref() {
    return Some(format_failure(finished.phase, failure));
  }
  match finished.outcome {
    RequestOutcome::Delivered => None,
    RequestOutcome::Rejected => Some(format!("{}: rejected", request_phase_name(finished.phase))),
    RequestOutcome::Failed => Some(format!("{}: failed", request_phase_name(finished.phase))),
    RequestOutcome::Cancelled => Some(format!("{}: cancelled", request_phase_name(finished.phase))),
    _ => Some(format!(
      "{}: request did not complete",
      request_phase_name(finished.phase)
    )),
  }
}

pub(super) fn http_family_name(family: HttpFamily) -> &'static str {
  match family {
    HttpFamily::Managed => "managed",
    HttpFamily::Relay => "relay",
    HttpFamily::Transparent => "transparent",
    _ => "unknown",
  }
}

pub(super) fn connect_action_name(action: ConnectAction) -> &'static str {
  match action {
    ConnectAction::Intercept => "intercept",
    ConnectAction::Tunnel => "tunnel",
    ConnectAction::Reject => "reject",
    _ => "unknown",
  }
}

pub(super) fn request_phase_name(phase: RequestPhase) -> &'static str {
  match phase {
    RequestPhase::Admission => "admission",
    RequestPhase::Authentication => "authentication",
    RequestPhase::Policy => "policy",
    RequestPhase::RequestBody => "request_body",
    RequestPhase::TargetSelection => "target_selection",
    RequestPhase::UpstreamRequest => "upstream_request",
    RequestPhase::UpstreamResponse => "upstream_response",
    RequestPhase::DownstreamResponse => "downstream_response",
    RequestPhase::Connect => "connect",
    RequestPhase::Complete => "complete",
    _ => "unknown",
  }
}

pub(super) fn request_outcome_name(outcome: RequestOutcome) -> &'static str {
  match outcome {
    RequestOutcome::Delivered => "delivered",
    RequestOutcome::Rejected => "rejected",
    RequestOutcome::Failed => "failed",
    RequestOutcome::Cancelled => "cancelled",
    _ => "unknown",
  }
}

pub(super) fn attempt_row_id(request_id: &str, attempt: AttemptNo) -> String {
  let suffix = attempt.get() - 1;
  if suffix == 0 {
    request_id.to_string()
  } else {
    format!("{request_id}:{suffix}")
  }
}

pub(super) fn insert_target_selection(context: &mut Map<String, Value>, target: &TargetSelection) {
  insert_literal(context, "http_family", http_family_name(target.family));
  insert_optional_string(context, "account_id", target.account_id.as_ref());
  insert_optional_string(context, "provider_id", target.provider_id.as_ref());
  insert_optional_string(context, "upstream_id", target.upstream_id.as_ref());
  insert_optional_string(context, "requested_model", target.requested_model.as_ref());
  insert_optional_string(context, "upstream_model", target.upstream_model.as_ref());
  insert_optional_string(context, "requested_operation", target.requested_operation.as_ref());
  insert_optional_string(context, "upstream_operation", target.upstream_operation.as_ref());
}

pub(super) fn attempt_outcome_name(outcome: AttemptOutcome) -> &'static str {
  match outcome {
    AttemptOutcome::Response => "response",
    AttemptOutcome::Failed => "failed",
    AttemptOutcome::Cancelled => "cancelled",
    _ => "unknown",
  }
}

pub(super) fn body_result_name(result: &BodyResult) -> &'static str {
  match result {
    BodyResult::Complete => "complete",
    BodyResult::Failed(_) => "failed",
    BodyResult::Cancelled => "cancelled",
    _ => "unknown",
  }
}

pub(super) fn body_result_error(phase: RequestPhase, result: &BodyResult) -> Option<String> {
  match result {
    BodyResult::Complete => None,
    BodyResult::Failed(failure) => Some(format_failure(phase, failure)),
    BodyResult::Cancelled => Some(format!("{}: cancelled", request_phase_name(phase))),
    _ => Some(format!("{}: body did not complete", request_phase_name(phase))),
  }
}

fn ingress_name(ingress: &IngressKind) -> &'static str {
  match ingress {
    IngressKind::LlmApi => "llm_api",
    IngressKind::ForwardProxy => "forward_proxy",
    IngressKind::InterceptedHttps { .. } => "intercepted_https",
    _ => "unknown",
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_events::CapturedHeader;

  #[test]
  fn durable_headers_redact_sensitive_names_even_when_the_event_value_did_not() {
    let encoded = headers_json(&CapturedHeaders::new([
      CapturedHeader::value("Authorization", "secret"),
      CapturedHeader::value("x-private-api-key", "also-secret"),
      CapturedHeader::value("x-safe", "visible"),
    ]))
    .unwrap();
    let value: Value = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(value["authorization"], "<redacted>");
    assert_eq!(value["x-private-api-key"], "<redacted>");
    assert_eq!(value["x-safe"], "visible");
  }

  #[test]
  fn durable_headers_mark_non_utf8_values_without_lossy_replacement() {
    let encoded = headers_json(&CapturedHeaders::new([CapturedHeader::value(
      "x-binary",
      bytes::Bytes::from_static(b"\xffvalue"),
    )]))
    .unwrap();
    let value: Value = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(value["x-binary"], "<non-utf8>");
  }

  #[test]
  fn usage_does_not_infer_total() {
    let usage = TokenUsage {
      input: Some(4),
      output: Some(2),
      ..TokenUsage::default()
    };
    let json: Value = serde_json::from_str(&usage_json(&usage).unwrap().unwrap()).unwrap();

    assert_eq!(json["input"], 4);
    assert_eq!(json["output"], 2);
    assert!(json.get("total").is_none());
  }

  #[test]
  fn one_based_attempts_keep_legacy_row_ids() {
    assert_eq!(attempt_row_id("request", AttemptNo::FIRST), "request");
    assert_eq!(attempt_row_id("request", AttemptNo::new(2).unwrap()), "request:1");
    assert_eq!(attempt_row_id("request", AttemptNo::new(3).unwrap()), "request:2");
  }
}
