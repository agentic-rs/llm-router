use super::error::ApiError;
use super::{AppState, LiveAppState, RequestPolicyRuntime};
use crate::pipeline::{request_header_extract, ChatParser, MessagesParser, RequestParser, ResponsesParser};
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::Value;
use smol_str::SmolStr;
use std::sync::Arc;
use tokn_access::AccessContext;
use tokn_accounts::routing::{route_mode_as_str, ResolveError};
use tokn_convert::value::messages::DEFAULT_MESSAGES_MAX_TOKENS;
use tokn_core::event::Event as CoreEvent;
use tokn_core::request_event::{RecordEvent, RequestEndpoint, RequestEvent, RequestEventPayload};
use tokn_requests::pipeline::error::RequestsError;
use tracing::instrument;

async fn handle(
  state: AppState,
  policy: Arc<RequestPolicyRuntime>,
  parser: &dyn RequestParser,
  access: &AccessContext,
  mut inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let hx = request_header_extract(&inbound);
  let local_addr = inbound
    .get("x-tokn-router-local-addr")
    .and_then(|v| v.to_str().ok())
    .map(str::to_string)
    .or_else(|| {
      inbound
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    });
  // Router-owned JSON endpoints run through tokn-requests and skip duplicate
  // lifecycle emission. The pipeline emits its own StageEvent/RecordEvent
  // stream which RequestEventHandler consumes; emitting a second bootstrap
  // event here would duplicate the request row before the pipeline begins.
  inbound.remove("x-route-mode");
  inbound.remove("x-tokn-router-agent-id");

  let mode = policy.route.resolve_mode(None).ok();

  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: SmolStr::new(&hx.request_id),
    attempt: 0,
    ts: tokn_core::util::now_unix_ms(),
    payload: RequestEventPayload::Record(RecordEvent::InboundConnection {
      user: access.key_name.clone().map(SmolStr::from),
      api_key_id: access.key_id.clone().map(SmolStr::from),
      local_addr: local_addr.clone().map(SmolStr::from),
      peer_addr: None,
      mode: SmolStr::new(request_record_mode(mode)),
      method: SmolStr::new("requests"),
      inbound_method: SmolStr::new("POST"),
      url: None,
    }),
  }));
  let mut decoded = super::codec::decode_json_request(&inbound, body)?;
  apply_endpoint_compat_defaults(parser.endpoint(), &inbound, &mut decoded)?;
  let raw = tokn_requests::RawInbound {
    request_endpoint: RequestEndpoint::from(parser.endpoint()),
    headers: (&inbound).into(),
    raw_body: decoded.raw_body.clone(),
    decoded_body: decoded.decoded_body.clone(),
    body_json: decoded.value.clone(),
    request_id: Some(SmolStr::new(&hx.request_id)),
  };
  let pipeline = match mode {
    Some(tokn_config::RouteMode::Passthrough) => &policy.passthrough_pipeline,
    Some(tokn_config::RouteMode::Switch) => &policy.switch_pipeline,
    _ => &policy.request_pipeline,
  };
  let mut run_config = tokn_requests::RunConfig::builder().with_agent_id_opt(policy.agent_id.clone());
  if let Some(providers) = access.providers.provider_ids() {
    run_config = run_config.with(
      tokn_requests::stages::ACCESS_ALLOWED_PROVIDERS_KEY,
      Value::Array(providers.iter().cloned().map(Value::String).collect()),
    );
  }
  let run_config = run_config.build();
  match pipeline.run_with(raw, run_config).await {
    Ok(converted) => Ok(super::response::converted_to_axum(converted)),
    Err(err) => Err(pipeline_error_to_api_error(err)),
  }
}

fn pipeline_error_to_api_error(err: tokn_requests::PipelineError) -> ApiError {
  match err.inner() {
    RequestsError::Resolve {
      source: ResolveError::InvalidRouteMode { .. },
    }
    | RequestsError::Resolve {
      source: ResolveError::InvalidExactModel { .. },
    } => ApiError::bad_request(err.message().into_owned()),
    RequestsError::SessionExpired { session_id } => ApiError::session_expired(session_id.to_string()),
    RequestsError::ProviderAccessDenied => ApiError::forbidden("API key does not allow the requested provider"),
    RequestsError::InvalidAccessPolicy => ApiError::internal("invalid API-key provider policy"),
    RequestsError::NoAccount { endpoint, model } => ApiError::not_implemented(endpoint.to_string(), model.to_string()),
    RequestsError::NoProviderAccount { provider_id } => ApiError::not_implemented("provider", provider_id.to_string()),
    RequestsError::UpstreamStatus { status, body } => match StatusCode::from_u16(*status) {
      Ok(status) => ApiError::upstream(status, body.clone()),
      Err(_) => ApiError::bad_gateway(body.clone()),
    },
    _ => ApiError::bad_gateway(err.message().into_owned()),
  }
}

fn request_record_mode(mode: Option<tokn_config::RouteMode>) -> &'static str {
  match mode {
    Some(mode) => route_mode_as_str(mode),
    None => "route",
  }
}

fn apply_endpoint_compat_defaults(
  endpoint: crate::provider::Endpoint,
  inbound: &HeaderMap,
  decoded: &mut super::codec::DecodedJsonRequest,
) -> Result<(), ApiError> {
  if endpoint != crate::provider::Endpoint::Messages {
    return Ok(());
  }

  let Some(obj) = decoded.value.as_object_mut() else {
    return Ok(());
  };
  if obj.contains_key("max_tokens") {
    return Ok(());
  }

  obj.insert(
    "max_tokens".into(),
    Value::Number(serde_json::Number::from(DEFAULT_MESSAGES_MAX_TOKENS)),
  );

  let normalized =
    serde_json::to_vec(&decoded.value).map_err(|e| ApiError::bad_request(format!("invalid JSON request body: {e}")))?;
  decoded.decoded_body = Bytes::from(normalized.clone());

  let encoding = super::codec::request_content_encoding(inbound)?;
  decoded.raw_body = super::codec::encode_body_bytes(&normalized, encoding).map_err(ApiError::bad_request)?;

  Ok(())
}

#[instrument(
  name = "chat_completions",
  skip_all,
  fields(
    endpoint = %crate::provider::Endpoint::ChatCompletions,
    model = tracing::field::Empty,
    stream = tracing::field::Empty,
    initiator = tracing::field::Empty,
  ),
)]
pub async fn chat_completions(
  State(state): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let state = state.current();
  let policy = state.default_policy.clone();
  handle(state, policy, &ChatParser, &access, inbound, body).await
}

#[instrument(
  name = "responses",
  skip_all,
  fields(
    endpoint = %crate::provider::Endpoint::Responses,
    model = tracing::field::Empty,
    stream = tracing::field::Empty,
    initiator = tracing::field::Empty,
  ),
)]
pub async fn responses(
  State(state): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let state = state.current();
  let policy = state.default_policy.clone();
  handle(state, policy, &ResponsesParser, &access, inbound, body).await
}

#[instrument(
  name = "messages",
  skip_all,
  fields(
    endpoint = %crate::provider::Endpoint::Messages,
    model = tracing::field::Empty,
    stream = tracing::field::Empty,
    initiator = tracing::field::Empty,
  ),
)]
pub async fn messages(
  State(state): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let state = state.current();
  let policy = state.default_policy.clone();
  handle(state, policy, &MessagesParser, &access, inbound, body).await
}

// --- Profile-prefixed variants ---

pub async fn chat_completions_with_profile(
  State(state): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  Path(profile): Path<String>,
  inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let state = state.current();
  let policy = profile_policy(&state, &profile)?;
  handle(state, policy, &ChatParser, &access, inbound, body).await
}

pub async fn responses_with_profile(
  State(state): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  Path(profile): Path<String>,
  inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let state = state.current();
  let policy = profile_policy(&state, &profile)?;
  handle(state, policy, &ResponsesParser, &access, inbound, body).await
}

pub async fn messages_with_profile(
  State(state): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  Path(profile): Path<String>,
  inbound: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  let state = state.current();
  let policy = profile_policy(&state, &profile)?;
  handle(state, policy, &MessagesParser, &access, inbound, body).await
}

fn profile_policy(state: &AppState, profile: &str) -> Result<Arc<RequestPolicyRuntime>, ApiError> {
  state
    .profiles
    .get(profile)
    .cloned()
    .ok_or_else(|| ApiError::bad_request(format!("unknown profile '{profile}'")))
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::http::header::CONTENT_ENCODING;
  use http::HeaderValue;

  #[test]
  fn messages_compat_sets_default_max_tokens_when_missing() {
    let mut decoded = super::super::codec::DecodedJsonRequest {
      raw_body: Bytes::from_static(br#"{"model":"claude","messages":[]}"#),
      decoded_body: Bytes::from_static(br#"{"model":"claude","messages":[]}"#),
      value: serde_json::json!({"model":"claude","messages":[]}),
    };

    apply_endpoint_compat_defaults(crate::provider::Endpoint::Messages, &HeaderMap::new(), &mut decoded).unwrap();

    assert_eq!(decoded.value["max_tokens"], DEFAULT_MESSAGES_MAX_TOKENS);
    let reparsed: Value = serde_json::from_slice(&decoded.decoded_body).unwrap();
    assert_eq!(reparsed["max_tokens"], DEFAULT_MESSAGES_MAX_TOKENS);
  }

  #[test]
  fn messages_compat_preserves_existing_max_tokens() {
    let body = serde_json::json!({"model":"claude","messages":[],"max_tokens":123});
    let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
    let mut decoded = super::super::codec::DecodedJsonRequest {
      raw_body: bytes.clone(),
      decoded_body: bytes,
      value: body,
    };

    apply_endpoint_compat_defaults(crate::provider::Endpoint::Messages, &HeaderMap::new(), &mut decoded).unwrap();

    assert_eq!(decoded.value["max_tokens"], 123);
  }

  #[test]
  fn messages_compat_reencodes_gzip_body_after_injecting_default() {
    let body = br#"{"model":"claude","messages":[]}"#;
    let raw_body =
      super::super::codec::encode_body_bytes(body, Some(super::super::codec::ContentEncodingKind::Gzip)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    let mut decoded = super::super::codec::DecodedJsonRequest {
      raw_body,
      decoded_body: Bytes::from_static(body),
      value: serde_json::json!({"model":"claude","messages":[]}),
    };

    apply_endpoint_compat_defaults(crate::provider::Endpoint::Messages, &headers, &mut decoded).unwrap();

    let round_trip = super::super::codec::decode_json_request(&headers, decoded.raw_body.clone()).unwrap();
    assert_eq!(round_trip.value["max_tokens"], DEFAULT_MESSAGES_MAX_TOKENS);
  }
}
