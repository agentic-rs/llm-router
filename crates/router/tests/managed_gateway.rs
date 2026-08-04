use futures_util::StreamExt;
use http::header::{HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH};
use http::HeaderMap;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokn_access::ProviderAccess;
use tokn_accounts::link::NoEligibleReason;
use tokn_core::account::{AccountConfig, Secret};
use tokn_core::generation::GenerationOptions;
use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
use tokn_core::util::http::HttpClientOptions;
use tokn_events::{
  AttemptOutcome, BodyCapture, BodyLeg, BodyOutcome, BodyResult, ConsumerResult, EventConsumer, EventSeq, GatewayEvent,
  HubBuilder, RequestOutcome, RequestPhase, RequestSource, TrafficEvent, TrafficEventKind,
};
use tokn_mock_server::{MockAuthConfig, MockEndpoint, MockLlmConfig, MockLlmServer, MockResponse, MockRoute};
use tokn_policy::ProfileId;
use tokn_requests::execution::ManagedClientBody;
use tokn_requests::RequestLifecycleEmitter;
use tokn_router::runtime::{
  link_builtin_gateway_runtime_with_profile_roots, EmbeddedProfileRoots, ManagedGatewayError, ManagedGatewayExecutor,
  ManagedGatewayOutcome, ManagedGatewayRequest, ManagedRequestBodyError,
};

const PROFILE: &str = "embedded";
const REQUESTED_MODEL: &str = "client-alias";
const UPSTREAM_MODEL: &str = "selected-backend-model";

struct CaptureConsumer {
  events: Arc<Mutex<Vec<GatewayEvent>>>,
}

impl EventConsumer<GatewayEvent> for CaptureConsumer {
  fn name(&self) -> &str {
    "embedded-managed-test"
  }

  fn handle(&mut self, _sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
    self.events.lock().unwrap().push(event.clone());
    Ok(())
  }
}

fn event_executor(
  runtime: Arc<tokn_router::runtime::LinkedGatewayRuntime>,
) -> (
  ManagedGatewayExecutor,
  Arc<Mutex<Vec<GatewayEvent>>>,
  tokn_events::EventHub<GatewayEvent>,
) {
  let events = Arc::new(Mutex::new(Vec::new()));
  let (publisher, hub) = HubBuilder::new()
    .consumer(CaptureConsumer {
      events: Arc::clone(&events),
    })
    .start()
    .unwrap();
  let gateway = ManagedGatewayExecutor::build_with_events(
    runtime,
    &HttpClientOptions::default(),
    RequestLifecycleEmitter::new(publisher),
    128,
  )
  .unwrap();
  (gateway, events, hub)
}

fn traffic(events: &[GatewayEvent]) -> Vec<&TrafficEvent> {
  events
    .iter()
    .filter_map(|event| match event {
      GatewayEvent::Traffic(event) => Some(event),
      _ => None,
    })
    .collect()
}

#[tokio::test]
async fn embedded_gateway_executes_one_v2_profile_without_a_listener() {
  let server = MockLlmServer::start(
    MockLlmConfig {
      routes: vec![MockRoute::chat_completions()],
      ..Default::default()
    }
    .with_auth(MockAuthConfig::bearer(["selected-key"])),
  )
  .await;
  let (profile, runtime) = runtime(server.base_url());
  assert!(runtime.listeners().is_empty());
  let gateway = ManagedGatewayExecutor::build(runtime, &HttpClientOptions::default()).unwrap();
  let mut headers = HeaderMap::new();
  headers.insert("x-session-id", HeaderValue::from_static("stale-header-session"));
  headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("999"));
  let request = ManagedGatewayRequest::new(
    Endpoint::Responses,
    json!({
      "model": REQUESTED_MODEL,
      "input": [{
        "role": "user",
        "content": [{"type": "input_text", "text": "hello from embedded"}]
      }],
      "stream": false
    }),
  )
  .with_headers(headers)
  .with_session_id("explicit-session")
  .with_generation_options(GenerationOptions::new().with_top_k(40));

  let outcome = gateway.execute(&profile, request).await.unwrap();
  let ManagedGatewayOutcome::Response {
    site,
    selection,
    response,
  } = outcome
  else {
    panic!("expected one managed response")
  };
  assert_eq!(site.profile_id(), &profile);
  assert_eq!(site.route_id().as_str(), "managed");
  assert_eq!(selection.account_id(), "selected-account");
  assert_eq!(selection.provider_id().as_str(), ID_LLAMA_CPP);
  assert_eq!(selection.upstream_id().as_str(), "selected");
  assert_eq!(selection.requested_model(), REQUESTED_MODEL);
  assert_eq!(selection.upstream_model(), UPSTREAM_MODEL);
  assert_eq!(selection.requested_operation(), Endpoint::Responses);
  assert_eq!(selection.upstream_operation(), Endpoint::ChatCompletions);

  let (status, _, body) = response.into_parts();
  assert_eq!(status, http::StatusCode::OK);
  let ManagedClientBody::Buffered(body) = body else {
    panic!("expected a buffered converted response")
  };
  let response_json: Value = serde_json::from_slice(&body).unwrap();
  assert_eq!(response_json["object"], "response");
  assert!(response_json["output"].is_array());

  let requests = server.requests();
  assert_eq!(requests.len(), 1);
  let captured = &requests[0];
  assert_eq!(captured.path, "/chat/completions");
  assert_eq!(captured.header("authorization"), Some("Bearer selected-key"));
  assert_eq!(captured.header("x-session-affinity"), Some("explicit-session"));
  assert_eq!(captured.header("content-encoding"), None);
  let upstream_json: Value = serde_json::from_slice(&captured.body).unwrap();
  assert_eq!(upstream_json["model"], UPSTREAM_MODEL);
  assert_eq!(upstream_json["messages"][0]["content"], "hello from embedded");
  assert_eq!(upstream_json["top_k"], 40);
  assert!(upstream_json.get("input").is_none());
}

#[tokio::test]
async fn embedded_gateway_keeps_lookup_validation_and_eligibility_distinct() {
  let (profile, runtime) = runtime("http://127.0.0.1:9");
  let gateway = ManagedGatewayExecutor::build(runtime, &HttpClientOptions::default()).unwrap();

  let unknown = ProfileId::new("unknown").unwrap();
  let error = gateway
    .execute(
      &unknown,
      ManagedGatewayRequest::new(Endpoint::Responses, json!({"model": REQUESTED_MODEL})),
    )
    .await
    .unwrap_err();
  assert!(matches!(
    error,
    ManagedGatewayError::ProfileNotLinked { profile: actual } if actual == unknown
  ));

  let error = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(Endpoint::Responses, json!({"model": " "})),
    )
    .await
    .unwrap_err();
  assert!(matches!(
    error,
    ManagedGatewayError::InvalidBody {
      site,
      source: ManagedRequestBodyError::ModelEmpty,
    } if site.profile_id() == &profile
  ));

  let denied = ProviderAccess::from_provider_ids(vec!["openai".to_owned()]).unwrap();
  let outcome = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(Endpoint::Responses, json!({"model": REQUESTED_MODEL})).with_provider_access(denied),
    )
    .await
    .unwrap();
  assert!(matches!(
    outcome,
    ManagedGatewayOutcome::NoEligible {
      site,
      reason: NoEligibleReason::ProviderAccessDenied,
    } if site.profile_id() == &profile
  ));
}

#[tokio::test]
async fn embedded_invalid_body_has_a_complete_zero_attempt_lifecycle_and_separate_correlation_id() {
  let (profile, runtime) = runtime("http://127.0.0.1:9");
  let (gateway, events, hub) = event_executor(runtime);
  let mut headers = HeaderMap::new();
  headers.insert("x-client-request-id", HeaderValue::from_static("client-request-42"));
  headers.insert("authorization", HeaderValue::from_static("Bearer do-not-disclose"));
  let error = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(
        Endpoint::Responses,
        json!({
          "model": " ",
          "stream": true,
          "input": "hello"
        }),
      )
      .with_headers(headers)
      .with_session_id("explicit-session"),
    )
    .await
    .unwrap_err();
  assert!(matches!(error, ManagedGatewayError::InvalidBody { .. }));
  drop(gateway);
  hub.shutdown().await.unwrap();

  let events = events.lock().unwrap();
  let traffic = traffic(&events);
  assert_eq!(
    traffic.iter().map(|event| event.sequence).collect::<Vec<_>>(),
    [1, 2, 3, 4, 5]
  );
  assert!(matches!(
    &traffic[0].kind,
    TrafficEventKind::Started(started)
      if matches!(&started.source, RequestSource::Embedded { profile_id } if profile_id == PROFILE)
        && started.method == "POST"
        && started.target.as_str() == "/v1/responses"
        && started.http_version.is_none()
        && started.body_present
        && started.correlation.client_request_id.as_deref() == Some("client-request-42")
        && started.correlation.session_id.as_deref() == Some("explicit-session")
  ));
  let TrafficEventKind::Started(started) = &traffic[0].kind else {
    unreachable!()
  };
  let authorization = started
    .headers
    .iter()
    .find(|header| header.name() == "authorization")
    .unwrap();
  assert!(authorization.captured_value().is_redacted());
  assert_ne!(traffic[0].request_id.as_str(), "client-request-42");
  assert!(matches!(traffic[1].kind, TrafficEventKind::Authenticated(_)));
  assert!(matches!(traffic[2].kind, TrafficEventKind::PolicySelected(_)));
  assert!(matches!(
    &traffic[3].kind,
    TrafficEventKind::RequestBody(body)
      if body.wire == BodyCapture::Absent
        && matches!(&body.outcome, BodyOutcome::Rejected(_))
        && body.requested_model.as_deref() == Some(" ")
        && body.stream == Some(true)
  ));
  assert!(matches!(
    traffic[4].kind,
    TrafficEventKind::Finished(ref finished)
      if finished.outcome == RequestOutcome::Rejected && finished.attempt_count == 0
  ));
  assert!(!traffic.iter().any(|event| matches!(
    event.kind,
    TrafficEventKind::Admitted(_) | TrafficEventKind::AttemptStarted(_)
  )));
}

#[tokio::test]
async fn embedded_buffered_success_finishes_upstream_and_downstream_before_return() {
  let server = MockLlmServer::start(MockLlmConfig {
    routes: vec![MockRoute::chat_completions()],
    ..Default::default()
  })
  .await;
  let (profile, runtime) = runtime(server.base_url());
  let (gateway, events, hub) = event_executor(runtime);
  let outcome = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(
        Endpoint::Responses,
        json!({
          "model": REQUESTED_MODEL,
          "input": "hello",
          "stream": false
        }),
      ),
    )
    .await
    .unwrap();
  let ManagedGatewayOutcome::Response { response, .. } = outcome else {
    panic!("expected buffered response")
  };
  assert!(matches!(response.body(), ManagedClientBody::Buffered(_)));
  drop(gateway);
  hub.shutdown().await.unwrap();

  let events = events.lock().unwrap();
  let traffic = traffic(&events);
  let position = |predicate: fn(&TrafficEventKind) -> bool| {
    traffic
      .iter()
      .position(|event| predicate(&event.kind))
      .expect("expected lifecycle event")
  };
  let attempt_head = position(|kind| matches!(kind, TrafficEventKind::AttemptResponseHead(_)));
  let upstream_finished = position(
    |kind| matches!(kind, TrafficEventKind::BodyFinished(body) if matches!(body.leg, BodyLeg::Upstream { .. })),
  );
  let attempt_finished = position(|kind| matches!(kind, TrafficEventKind::AttemptFinished(_)));
  let downstream_head = position(|kind| matches!(kind, TrafficEventKind::DownstreamResponseHead(_)));
  let downstream_finished =
    position(|kind| matches!(kind, TrafficEventKind::BodyFinished(body) if body.leg == BodyLeg::Downstream));
  let finished = position(|kind| matches!(kind, TrafficEventKind::Finished(_)));
  assert!(attempt_head < upstream_finished);
  assert!(upstream_finished < attempt_finished);
  assert!(attempt_finished < downstream_head);
  assert!(downstream_head < downstream_finished);
  assert!(downstream_finished < finished);
  assert!(matches!(
    &traffic[finished].kind,
    TrafficEventKind::Finished(event)
      if event.outcome == RequestOutcome::Delivered && event.attempt_count == 1
  ));
  assert!(traffic.iter().any(|event| matches!(
    &event.kind,
    TrafficEventKind::AttemptFinished(event) if event.outcome == AttemptOutcome::Response
  )));
}

#[tokio::test]
async fn embedded_streaming_protocol_mismatch_is_an_upstream_response_failure() {
  let server = MockLlmServer::start(MockLlmConfig {
    // The route deliberately returns JSON even though the translated request
    // asks for a stream.
    routes: vec![MockRoute::chat_completions()],
    ..Default::default()
  })
  .await;
  let (profile, runtime) = runtime(server.base_url());
  let (gateway, events, hub) = event_executor(runtime);

  let error = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(
        Endpoint::Responses,
        json!({
          "model": REQUESTED_MODEL,
          "input": "hello",
          "stream": true
        }),
      ),
    )
    .await
    .unwrap_err();
  assert!(matches!(error, ManagedGatewayError::Response { .. }));
  drop(gateway);
  hub.shutdown().await.unwrap();

  let events = events.lock().unwrap();
  let traffic = traffic(&events);
  assert!(traffic.iter().any(|event| matches!(
    &event.kind,
    TrafficEventKind::BodyFinished(body)
      if matches!(
        &body.result,
        BodyResult::Failed(failure) if failure.code == "invalid_upstream_response"
      ) && matches!(body.leg, BodyLeg::Upstream { .. })
  )));
  assert!(traffic.iter().any(|event| matches!(
    &event.kind,
    TrafficEventKind::AttemptFinished(attempt)
      if attempt.outcome == AttemptOutcome::Failed
        && attempt.phase == RequestPhase::UpstreamResponse
        && attempt.upstream_status == Some(200)
        && matches!(
          &attempt.failure,
          Some(failure) if failure.code == "invalid_upstream_response"
        )
  )));
  assert!(traffic.iter().any(|event| matches!(
    &event.kind,
    TrafficEventKind::Finished(finished)
      if finished.outcome == RequestOutcome::Failed
        && finished.phase == RequestPhase::UpstreamResponse
        && finished.attempt_count == 1
        && matches!(
          &finished.failure,
          Some(failure) if failure.code == "invalid_upstream_response"
        )
  )));
  assert!(!traffic.iter().any(|event| matches!(
    event.kind,
    TrafficEventKind::AttemptFinished(ref attempt) if attempt.outcome == AttemptOutcome::Cancelled
  )));
}

#[tokio::test]
async fn embedded_json_adaptation_failure_after_eof_keeps_the_transfer_complete() {
  let server = MockLlmServer::start(MockLlmConfig {
    routes: vec![MockRoute::new(
      MockEndpoint::ChatCompletions,
      MockResponse {
        status: http::StatusCode::OK,
        headers: vec![("content-type".into(), "application/json".into())],
        body: "{".into(),
      },
    )],
    ..Default::default()
  })
  .await;
  let (profile, runtime) = runtime(server.base_url());
  let (gateway, events, hub) = event_executor(runtime);

  let error = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(
        Endpoint::Responses,
        json!({
          "model": REQUESTED_MODEL,
          "input": "hello",
          "stream": false
        }),
      ),
    )
    .await
    .unwrap_err();
  assert!(matches!(error, ManagedGatewayError::Response { .. }));
  drop(gateway);
  hub.shutdown().await.unwrap();

  let events = events.lock().unwrap();
  let traffic = traffic(&events);
  assert!(traffic.iter().any(|event| matches!(
    &event.kind,
    TrafficEventKind::BodyFinished(body)
      if body.result == BodyResult::Complete && matches!(body.leg, BodyLeg::Upstream { .. })
  )));
  assert!(traffic.iter().any(|event| matches!(
    &event.kind,
    TrafficEventKind::AttemptFinished(attempt)
      if attempt.outcome == AttemptOutcome::Failed
        && matches!(
          &attempt.failure,
          Some(failure) if failure.code == "invalid_upstream_response"
        )
  )));
}

#[tokio::test]
async fn embedded_live_stream_owns_completion_through_eof_and_drop() {
  for consume in [true, false] {
    let server = MockLlmServer::start(MockLlmConfig {
      routes: vec![MockRoute::chat_completions_stream()],
      ..Default::default()
    })
    .await;
    let (profile, runtime) = runtime(server.base_url());
    let (gateway, events, hub) = event_executor(runtime);
    let outcome = gateway
      .execute(
        &profile,
        ManagedGatewayRequest::new(
          Endpoint::Responses,
          json!({
            "model": REQUESTED_MODEL,
            "input": "hello",
            "stream": true
          }),
        ),
      )
      .await
      .unwrap();
    let ManagedGatewayOutcome::Response { response, .. } = outcome else {
      panic!("expected streaming response")
    };
    let (_, _, body) = response.into_parts();
    let ManagedClientBody::Stream(mut stream) = body else {
      panic!("expected managed stream")
    };
    if consume {
      let mut received = Vec::new();
      while let Some(chunk) = stream.next().await {
        received.extend_from_slice(&chunk.unwrap());
      }
      assert!(!received.is_empty());
    }
    drop(stream);
    drop(gateway);
    hub.shutdown().await.unwrap();

    let events = events.lock().unwrap();
    let traffic = traffic(&events);
    let attempt = traffic.iter().find_map(|event| match &event.kind {
      TrafficEventKind::AttemptFinished(event) => Some(event),
      _ => None,
    });
    let downstream = traffic.iter().find_map(|event| match &event.kind {
      TrafficEventKind::BodyFinished(event) if event.leg == BodyLeg::Downstream => Some(event),
      _ => None,
    });
    let finished = traffic.iter().find_map(|event| match &event.kind {
      TrafficEventKind::Finished(event) => Some(event),
      _ => None,
    });
    if consume {
      assert!(matches!(attempt, Some(event) if event.outcome == AttemptOutcome::Response));
      assert!(matches!(downstream, Some(event) if event.result == BodyResult::Complete));
      assert!(matches!(finished, Some(event) if event.outcome == RequestOutcome::Delivered));
      assert!(traffic
        .iter()
        .any(|event| matches!(event.kind, TrafficEventKind::AttemptUsage(_))));
    } else {
      assert!(matches!(attempt, Some(event) if event.outcome == AttemptOutcome::Cancelled));
      assert!(matches!(downstream, Some(event) if event.result == BodyResult::Cancelled));
      assert!(matches!(finished, Some(event) if event.outcome == RequestOutcome::Cancelled));
    }
  }
}

fn runtime(base_url: &str) -> (ProfileId, Arc<tokn_router::runtime::LinkedGatewayRuntime>) {
  let config = format!(
    r#"
schema_version = 2

[profiles.{PROFILE}]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "fixed", upstream = "selected" }}
model = {{ kind = "fallback", selector = {{ kind = "fixed", group = "fixture" }} }}
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["*"]
strategy = "round_robin"

[upstreams.selected]
provider = "llama-cpp"
base_url = "{base_url}"
accounts = ["selected-account"]

[[model_groups.fixture]]
model = "{UPSTREAM_MODEL}"
upstream = "selected"
"#,
  );
  let compiled = tokn_config::v2::parse(&config, Path::new("embedded-managed.toml")).unwrap();
  let profile = ProfileId::new(PROFILE).unwrap();
  let runtime = link_builtin_gateway_runtime_with_profile_roots(
    compiled.gateway(),
    &[llama_account("selected-account", "selected-key")],
    &EmbeddedProfileRoots::one(profile.clone()),
  )
  .unwrap();
  (profile, Arc::new(runtime))
}

fn llama_account(id: &str, api_key: &str) -> AccountConfig {
  AccountConfig {
    id: id.to_owned(),
    provider: ID_LLAMA_CPP.to_owned(),
    enabled: true,
    tier: Default::default(),
    tags: Vec::new(),
    label: None,
    base_url: None,
    headers: Default::default(),
    auth_type: None,
    username: None,
    api_key: Some(Secret::new(api_key.to_owned())),
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  }
}
