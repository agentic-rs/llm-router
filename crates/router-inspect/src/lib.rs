//! Standalone, loopback-only inspector for persisted requests and semantic sessions.
//!
//! The inspector intentionally stays out of the main API router. Its request
//! data can include prompts and responses, so it gets a separate local listener
//! and reads existing databases without changing them.

use axum::extract::{Query, State};
use axum::http::header::{
  CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokn_persistence::viewer::{
  get_request_llm_message, get_request_llm_summary, get_request_llm_tool_definition, get_request_payload,
  RequestCursor, RequestPayloadField,
};
use tokn_persistence::{
  get_request, get_session_from_db, get_session_node_from_db, get_session_usage, is_valid_request_day,
  list_latest_requests, list_request_days, list_request_url_paths, list_requests, list_sessions_from_db,
  RequestListOptions,
};

const INDEX_HTML: &str = include_str!("../web/dist/index.html");
const VIEWER_JS: &str = include_str!("../web/dist/viewer.js");
const VIEWER_CSS: &str = include_str!("../web/dist/viewer.css");
const CONTENT_SECURITY_POLICY_VALUE: &str =
  "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone)]
struct InspectState {
  requests_dir: PathBuf,
  sessions_db: PathBuf,
  usage_db: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RequestsQuery {
  day: Option<String>,
  limit: Option<usize>,
  cursor: Option<String>,
  session_id: Option<String>,
  provider_id: Option<String>,
  url_path: Option<String>,
  status: Option<u16>,
  #[serde(default)]
  errors_only: bool,
  query: Option<String>,
}

impl From<RequestsQuery> for RequestListOptions {
  fn from(query: RequestsQuery) -> Self {
    Self {
      day: query.day,
      limit: query.limit,
      cursor: None,
      session_id: query.session_id,
      provider_id: query.provider_id,
      url_path: query.url_path,
      status: query.status,
      errors_only: query.errors_only,
      query: query.query,
    }
  }
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
  limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RequestPageQuery {
  limit: Option<usize>,
  cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RequestDayQuery {
  day: String,
}

#[derive(Debug, Deserialize)]
struct RequestDetailQuery {
  day: String,
  request_id: String,
  row_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RequestPayloadQuery {
  day: String,
  request_id: String,
  row_id: Option<i64>,
  field: String,
}

#[derive(Debug, Deserialize)]
struct RequestLlmItemQuery {
  day: String,
  request_id: String,
  row_id: Option<i64>,
  index: usize,
}

#[derive(Debug, Deserialize)]
struct SessionDetailQuery {
  session_id: String,
  limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SessionNodeDetailQuery {
  session_id: String,
  node_id: String,
}

#[derive(Debug, Serialize)]
struct ViewerInfo {
  requests_dir: String,
  sessions_db: String,
  usage_db: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
  error: String,
}

struct ApiError {
  status: StatusCode,
  message: String,
}

impl ApiError {
  fn internal(error: impl std::fmt::Display) -> Self {
    Self {
      status: StatusCode::INTERNAL_SERVER_ERROR,
      message: error.to_string(),
    }
  }

  fn not_found(kind: &str) -> Self {
    Self {
      status: StatusCode::NOT_FOUND,
      message: format!("{kind} not found"),
    }
  }

  fn bad_request(message: &str) -> Self {
    Self {
      status: StatusCode::BAD_REQUEST,
      message: message.to_string(),
    }
  }

  fn unavailable(kind: &str) -> Self {
    Self {
      status: StatusCode::SERVICE_UNAVAILABLE,
      message: format!("{kind} unavailable"),
    }
  }

  fn unavailable_message(message: impl Into<String>) -> Self {
    Self {
      status: StatusCode::SERVICE_UNAVAILABLE,
      message: message.into(),
    }
  }
}

impl IntoResponse for ApiError {
  fn into_response(self) -> Response {
    json_response(self.status, ErrorResponse { error: self.message })
  }
}

/// Serve the viewer on a separate loopback listener until a shutdown signal.
pub async fn serve(requests_dir: PathBuf, sessions_db: PathBuf, usage_db: PathBuf, port: u16) -> anyhow::Result<()> {
  let shutdown = tokn_core::util::shutdown::ShutdownSignal::new()?;
  let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
  let address = listener.local_addr()?;
  println!("Inspect viewer: http://{address}");
  println!("Request history may contain sensitive prompts and responses. Press Ctrl-C to stop.");

  axum::serve(
    listener,
    router(InspectState {
      requests_dir,
      sessions_db,
      usage_db,
    }),
  )
  .with_graceful_shutdown(async {
    if let Err(error) = shutdown.wait().await {
      tracing::error!(%error, "shutdown signal handler failed");
    }
  })
  .await?;
  Ok(())
}

fn router(state: InspectState) -> Router {
  Router::new()
    .route("/", get(index))
    .route("/assets/viewer.js", get(viewer_js))
    .route("/assets/viewer.css", get(viewer_css))
    .route("/api/info", get(info))
    .route("/api/request-days", get(request_days))
    .route("/api/request-url-paths", get(request_url_paths))
    .route("/api/requests", get(requests))
    .route("/api/requests/latest", get(latest_requests))
    .route("/api/request", get(request_detail))
    .route("/api/request-llm-summary", get(request_llm_summary))
    .route("/api/request-llm-message", get(request_llm_message))
    .route("/api/request-llm-tool-definition", get(request_llm_tool_definition))
    .route("/api/request-payload", get(request_payload))
    .route("/api/sessions", get(sessions))
    .route("/api/session", get(session_detail))
    .route("/api/session-usage", get(session_usage))
    .route("/api/session-node", get(session_node_detail))
    .with_state(state)
}

async fn index() -> Response {
  text_response("text/html; charset=utf-8", INDEX_HTML)
}

async fn viewer_js() -> Response {
  text_response("application/javascript; charset=utf-8", VIEWER_JS)
}

async fn viewer_css() -> Response {
  text_response("text/css; charset=utf-8", VIEWER_CSS)
}

async fn info(State(state): State<InspectState>) -> Response {
  json_response(
    StatusCode::OK,
    ViewerInfo {
      requests_dir: state.requests_dir.display().to_string(),
      sessions_db: state.sessions_db.display().to_string(),
      usage_db: state.usage_db.display().to_string(),
    },
  )
}

async fn request_days(State(state): State<InspectState>) -> Result<Response, ApiError> {
  let requests_dir = state.requests_dir;
  let days = tokio::task::spawn_blocking(move || list_request_days(&requests_dir))
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
  Ok(json_response(StatusCode::OK, days))
}

async fn request_url_paths(
  State(state): State<InspectState>,
  Query(query): Query<RequestDayQuery>,
) -> Result<Response, ApiError> {
  validate_request_day(&query.day)?;
  let requests_dir = state.requests_dir;
  let day = query.day;
  let paths = tokio::task::spawn_blocking(move || list_request_url_paths(&requests_dir, &day))
    .await
    .map_err(ApiError::internal)?
    .map_err(|_| ApiError::unavailable("request day"))?;
  Ok(json_response(StatusCode::OK, paths))
}

async fn requests(State(state): State<InspectState>, Query(query): Query<RequestsQuery>) -> Result<Response, ApiError> {
  if let Some(day) = query.day.as_deref() {
    validate_request_day(day)?;
  }
  let cursor = parse_request_cursor(query.cursor.as_deref())?;
  if let (Some(day), Some(cursor)) = (query.day.as_deref(), cursor.as_ref()) {
    if cursor.day() != day {
      return Err(ApiError::bad_request("cursor does not belong to the selected day"));
    }
  }
  let selected_day = query.day.is_some();
  let requests_dir = state.requests_dir;
  let mut options: RequestListOptions = query.into();
  options.cursor = cursor;
  let requests = tokio::task::spawn_blocking(move || list_requests(&requests_dir, &options))
    .await
    .map_err(ApiError::internal)?;
  let requests = requests.map_err(|error| {
    if selected_day {
      ApiError::unavailable("request day")
    } else {
      ApiError::internal(error)
    }
  })?;
  Ok(json_response(StatusCode::OK, requests))
}

async fn latest_requests(
  State(state): State<InspectState>,
  Query(query): Query<RequestPageQuery>,
) -> Result<Response, ApiError> {
  let requests_dir = state.requests_dir;
  let limit = query.limit;
  let cursor = parse_request_cursor(query.cursor.as_deref())?;
  let requests = tokio::task::spawn_blocking(move || list_latest_requests(&requests_dir, limit, cursor))
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
  Ok(json_response(StatusCode::OK, requests))
}

fn parse_request_cursor(cursor: Option<&str>) -> Result<Option<RequestCursor>, ApiError> {
  cursor
    .map(RequestCursor::decode)
    .transpose()
    .map_err(|_| ApiError::bad_request("cursor is malformed or unsupported"))
}

async fn request_detail(
  State(state): State<InspectState>,
  Query(query): Query<RequestDetailQuery>,
) -> Result<Response, ApiError> {
  validate_request_day(&query.day)?;
  let requests_dir = state.requests_dir;
  let day = query.day;
  let request_id = query.request_id;
  let row_id = query.row_id;
  let request = tokio::task::spawn_blocking(move || get_request(&requests_dir, &day, &request_id, row_id))
    .await
    .map_err(ApiError::internal)?
    .map_err(|_| ApiError::unavailable("request day"))?;
  let request = request.ok_or_else(|| ApiError::not_found("request"))?;
  Ok(json_response(StatusCode::OK, request))
}

async fn request_payload(
  State(state): State<InspectState>,
  Query(query): Query<RequestPayloadQuery>,
) -> Result<Response, ApiError> {
  validate_request_day(&query.day)?;
  let field = query
    .field
    .parse::<RequestPayloadField>()
    .map_err(|_| ApiError::bad_request("field is not a supported request payload field"))?;
  let requests_dir = state.requests_dir;
  let day = query.day;
  let request_id = query.request_id;
  let row_id = query.row_id;
  let payload =
    tokio::task::spawn_blocking(move || get_request_payload(&requests_dir, &day, &request_id, row_id, field))
      .await
      .map_err(ApiError::internal)?
      .map_err(|_| ApiError::unavailable("request day"))?;
  let payload = payload.ok_or_else(|| ApiError::not_found("request payload"))?;
  Ok(json_response(StatusCode::OK, payload))
}

async fn request_llm_summary(
  State(state): State<InspectState>,
  Query(query): Query<RequestDetailQuery>,
) -> Result<Response, ApiError> {
  validate_request_day(&query.day)?;
  let requests_dir = state.requests_dir;
  let day = query.day;
  let request_id = query.request_id;
  let row_id = query.row_id;
  let summary = tokio::task::spawn_blocking(move || get_request_llm_summary(&requests_dir, &day, &request_id, row_id))
    .await
    .map_err(ApiError::internal)?
    .map_err(|_| ApiError::unavailable("request day"))?;
  let summary = summary.ok_or_else(|| ApiError::not_found("request LLM summary"))?;
  Ok(json_response(StatusCode::OK, summary))
}

async fn request_llm_message(
  State(state): State<InspectState>,
  Query(query): Query<RequestLlmItemQuery>,
) -> Result<Response, ApiError> {
  validate_request_day(&query.day)?;
  let requests_dir = state.requests_dir;
  let day = query.day;
  let request_id = query.request_id;
  let row_id = query.row_id;
  let index = query.index;
  let message =
    tokio::task::spawn_blocking(move || get_request_llm_message(&requests_dir, &day, &request_id, row_id, index))
      .await
      .map_err(ApiError::internal)?
      .map_err(|_| ApiError::unavailable("request day"))?;
  let message = message.ok_or_else(|| ApiError::not_found("request LLM message"))?;
  Ok(json_response(StatusCode::OK, message))
}

async fn request_llm_tool_definition(
  State(state): State<InspectState>,
  Query(query): Query<RequestLlmItemQuery>,
) -> Result<Response, ApiError> {
  validate_request_day(&query.day)?;
  let requests_dir = state.requests_dir;
  let day = query.day;
  let request_id = query.request_id;
  let row_id = query.row_id;
  let index = query.index;
  let definition = tokio::task::spawn_blocking(move || {
    get_request_llm_tool_definition(&requests_dir, &day, &request_id, row_id, index)
  })
  .await
  .map_err(ApiError::internal)?
  .map_err(|_| ApiError::unavailable("request day"))?;
  let definition = definition.ok_or_else(|| ApiError::not_found("request LLM tool definition"))?;
  Ok(json_response(StatusCode::OK, definition))
}

fn validate_request_day(day: &str) -> Result<(), ApiError> {
  if is_valid_request_day(day) {
    Ok(())
  } else {
    Err(ApiError::bad_request("day must be a UTC date in YYYY-MM-DD format"))
  }
}

async fn sessions(State(state): State<InspectState>, Query(query): Query<LimitQuery>) -> Result<Response, ApiError> {
  let sessions_db = state.sessions_db;
  let limit = query.limit;
  let sessions = tokio::task::spawn_blocking(move || list_sessions_from_db(&sessions_db, limit))
    .await
    .map_err(ApiError::internal)?
    .map_err(session_database_error)?;
  Ok(json_response(StatusCode::OK, sessions))
}

async fn session_detail(
  State(state): State<InspectState>,
  Query(query): Query<SessionDetailQuery>,
) -> Result<Response, ApiError> {
  let sessions_db = state.sessions_db;
  let session_id = query.session_id;
  let limit = query.limit;
  let session = tokio::task::spawn_blocking(move || get_session_from_db(&sessions_db, &session_id, limit))
    .await
    .map_err(ApiError::internal)?
    .map_err(session_database_error)?;
  let session = session.ok_or_else(|| ApiError::not_found("session"))?;
  Ok(json_response(StatusCode::OK, session))
}

async fn session_node_detail(
  State(state): State<InspectState>,
  Query(query): Query<SessionNodeDetailQuery>,
) -> Result<Response, ApiError> {
  let sessions_db = state.sessions_db;
  let session_id = query.session_id;
  let node_id = query.node_id;
  let node = tokio::task::spawn_blocking(move || get_session_node_from_db(&sessions_db, &session_id, &node_id))
    .await
    .map_err(ApiError::internal)?
    .map_err(session_database_error)?;
  let node = node.ok_or_else(|| ApiError::not_found("session node"))?;
  Ok(json_response(StatusCode::OK, node))
}

async fn session_usage(
  State(state): State<InspectState>,
  Query(query): Query<SessionDetailQuery>,
) -> Result<Response, ApiError> {
  let usage_db = state.usage_db;
  let session_id = query.session_id;
  let usage = tokio::task::spawn_blocking(move || get_session_usage(&usage_db, &session_id))
    .await
    .map_err(ApiError::internal)?
    .map_err(usage_database_error)?;
  Ok(json_response(StatusCode::OK, usage))
}

fn session_database_error(error: tokn_persistence::Error) -> ApiError {
  match error {
    tokn_persistence::Error::UnsupportedSessionSchema { .. } => ApiError::unavailable_message(
      "sessions database requires migration; migrate the selected database before opening the sessions view",
    ),
    _ => ApiError::unavailable("session database"),
  }
}

fn usage_database_error(error: tokn_persistence::Error) -> ApiError {
  match error {
    tokn_persistence::Error::UnsupportedUsageSchema { .. } => ApiError::unavailable_message(
      "usage database requires migration; migrate the selected database before opening session usage",
    ),
    _ => ApiError::unavailable("usage database"),
  }
}

fn text_response(content_type: &'static str, body: &'static str) -> Response {
  let mut response = body.into_response();
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
  add_security_headers(&mut response);
  response
}

fn json_response<T: Serialize>(status: StatusCode, body: T) -> Response {
  let mut response = (status, Json(body)).into_response();
  add_security_headers(&mut response);
  response
}

fn add_security_headers(response: &mut Response) {
  let headers = response.headers_mut();
  headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
  headers.insert(
    CONTENT_SECURITY_POLICY,
    HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE),
  );
  headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
  headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::Body;
  use axum::http::Request;
  use rusqlite::params;
  use tokn_persistence::requests::open_day_db;
  use tokn_persistence::sessions::{SessionsDb, TreeRequestRecord};
  use tokn_persistence::{MessageRecord, UsageDb};
  use tower::ServiceExt;

  fn write_request(dir: &std::path::Path, day: &str, request_id: &str, session_id: &str) {
    let conn = open_day_db(&dir.join(format!("{day}.db"))).unwrap();
    conn
      .execute(
        "INSERT INTO request_connection (request_id, ts, endpoint, status)
         VALUES (?1, 1784444800000, 'responses', 200)",
        params![request_id],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_metadata (request_id, session_id, account_id, provider_id, model)
         VALUES (?1, ?2, 'account-1', 'openai', 'gpt-test')",
        params![request_id, session_id],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_downstream (request_id, inbound_req_body) VALUES (?1, '{\"input\":\"hello\"}')",
        params![request_id],
      )
      .unwrap();
  }

  fn write_session(sessions_db: &std::path::Path, session_id: &str, request_id: &str) {
    let mut sessions = SessionsDb::open(sessions_db).unwrap();
    sessions
      .record_tree(&TreeRequestRecord {
        ts: 1_783_987_200_000,
        session_id: session_id.to_string(),
        thread_id: None,
        parent_thread_id: None,
        parent_session_id: None,
        request_id: request_id.to_string(),
        endpoint: "responses".to_string(),
        status: Some(200),
        account_id: Some("account-1".to_string()),
        provider_id: Some("openai".to_string()),
        model: Some("gpt-test".to_string()),
        request_messages: vec![MessageRecord {
          role: "user".to_string(),
          status: None,
          parts: Vec::new(),
        }],
        response_messages: Vec::new(),
      })
      .unwrap();
  }

  fn write_usage(usage_db: &std::path::Path, session_id: &str, request_id: &str, usage_json: &str) {
    drop(UsageDb::open(usage_db).unwrap());
    let conn = rusqlite::Connection::open(usage_db).unwrap();
    conn
      .execute(
        "INSERT INTO requests (ts, session_id, request_id, model, usage_json)
         VALUES (1784444800000, ?1, ?2, 'gpt-test', ?3)",
        params![session_id, request_id, usage_json],
      )
      .unwrap();
  }

  async fn get_response(requests_dir: &std::path::Path, sessions_db: &std::path::Path, uri: &str) -> Response {
    router(InspectState {
      requests_dir: requests_dir.to_path_buf(),
      sessions_db: sessions_db.to_path_buf(),
      usage_db: sessions_db.with_file_name("usage.db"),
    })
    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
    .await
    .unwrap()
  }

  async fn response_body(response: Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
  }

  fn json_string_field(body: &str, field: &str) -> Option<String> {
    let prefix = format!(r#""{field}":""#);
    let value = body.split_once(&prefix)?.1.split_once('"')?.0;
    Some(value.to_string())
  }

  #[tokio::test]
  async fn history_endpoints_preserve_success_and_not_found_statuses() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    write_request(tempdir.path(), "2026-07-14", "request/one", "session/one");
    write_request(tempdir.path(), "2026-07-13", "request/two", "session/two");
    drop(open_day_db(&tempdir.path().join("2026-07-15.db")).unwrap());
    std::fs::write(tempdir.path().join("2026-07-16.db"), b"not a sqlite database").unwrap();

    let requests_response = get_response(tempdir.path(), &sessions_db, "/api/requests").await;
    assert_eq!(requests_response.status(), StatusCode::OK);
    assert_eq!(requests_response.headers()[CACHE_CONTROL], "no-store");

    let day_requests_response = get_response(tempdir.path(), &sessions_db, "/api/requests?day=2026-07-14").await;
    assert_eq!(day_requests_response.status(), StatusCode::OK);
    let day_requests_body = response_body(day_requests_response).await;
    assert!(day_requests_body.contains("request/one"));
    assert!(!day_requests_body.contains("request/two"));

    let request_days_response = get_response(tempdir.path(), &sessions_db, "/api/request-days").await;
    assert_eq!(request_days_response.status(), StatusCode::OK);
    let request_days_body = response_body(request_days_response).await;
    assert!(request_days_body.contains(r#"{"day":"2026-07-14","state":"available"}"#));
    assert!(request_days_body.contains(r#"{"day":"2026-07-15","state":"empty"}"#));
    assert!(request_days_body.contains(r#"{"day":"2026-07-16","state":"unavailable"}"#));

    let latest_requests_response = get_response(tempdir.path(), &sessions_db, "/api/requests/latest?limit=1").await;
    assert_eq!(latest_requests_response.status(), StatusCode::OK);
    let latest_requests_body = response_body(latest_requests_response).await;
    assert!(latest_requests_body.contains("2026-07-14"));
    assert!(latest_requests_body.contains("request/one"));

    let request_response = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-07-14&request_id=request%2Fone",
    )
    .await;
    assert_eq!(request_response.status(), StatusCode::OK);
    assert!(!response_body(request_response).await.contains("inbound_req_body"));

    let sessions_response = get_response(tempdir.path(), &sessions_db, "/api/sessions").await;
    assert_eq!(sessions_response.status(), StatusCode::OK);
    assert_eq!(response_body(sessions_response).await, "[]");

    let session_response = get_response(tempdir.path(), &sessions_db, "/api/session?session_id=session%2Fone").await;
    assert_eq!(session_response.status(), StatusCode::NOT_FOUND);

    let missing_request_response = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-07-14&request_id=request%2Fmissing",
    )
    .await;
    assert_eq!(missing_request_response.status(), StatusCode::NOT_FOUND);

    let invalid_day_response = get_response(tempdir.path(), &sessions_db, "/api/requests?day=not-a-day").await;
    assert_eq!(invalid_day_response.status(), StatusCode::BAD_REQUEST);

    let unavailable_day_response = get_response(tempdir.path(), &sessions_db, "/api/requests?day=2026-07-16").await;
    assert_eq!(unavailable_day_response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let invalid_detail_day_response = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-02-30&request_id=request%2Fone",
    )
    .await;
    assert_eq!(invalid_detail_day_response.status(), StatusCode::BAD_REQUEST);

    let missing_session_response = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/session?session_id=session%2Fmissing",
    )
    .await;
    assert_eq!(missing_session_response.status(), StatusCode::NOT_FOUND);
  }

  #[tokio::test]
  async fn request_endpoints_page_without_duplicates_and_validate_cursors() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    for request_id in ["request-a", "request-b", "request-c"] {
      write_request(tempdir.path(), "2026-07-14", request_id, "session/one");
    }

    let first_response = get_response(tempdir.path(), &sessions_db, "/api/requests?day=2026-07-14&limit=2").await;
    assert_eq!(first_response.status(), StatusCode::OK);
    let first_body = response_body(first_response).await;
    assert!(first_body.starts_with(r#"{"requests":["#));
    assert!(first_body.contains("request-c"));
    assert!(first_body.contains("request-b"));
    assert!(!first_body.contains("request-a"));
    assert!(first_body.contains(r#""row_id":"3""#));
    let cursor = json_string_field(&first_body, "next_cursor").unwrap();

    let second_response = get_response(
      tempdir.path(),
      &sessions_db,
      &format!("/api/requests?day=2026-07-14&limit=2&cursor={cursor}"),
    )
    .await;
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = response_body(second_response).await;
    assert!(second_body.contains("request-a"));
    assert!(!second_body.contains("request-b"));
    assert!(!second_body.contains("request-c"));
    assert!(second_body.contains(r#""next_cursor":null"#));

    let latest_response = get_response(tempdir.path(), &sessions_db, "/api/requests/latest?limit=2").await;
    assert_eq!(latest_response.status(), StatusCode::OK);
    let latest_body = response_body(latest_response).await;
    assert!(latest_body.contains(r#""day":"2026-07-14""#));
    let latest_cursor = json_string_field(&latest_body, "next_cursor").unwrap();
    let latest_next_response = get_response(
      tempdir.path(),
      &sessions_db,
      &format!("/api/requests/latest?limit=2&cursor={latest_cursor}"),
    )
    .await;
    assert_eq!(latest_next_response.status(), StatusCode::OK);
    let latest_next_body = response_body(latest_next_response).await;
    assert!(latest_next_body.contains("request-a"));
    assert!(!latest_next_body.contains("request-b"));

    let malformed_response = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/requests?day=2026-07-14&cursor=not-a-cursor",
    )
    .await;
    assert_eq!(malformed_response.status(), StatusCode::BAD_REQUEST);

    let wrong_day_response = get_response(
      tempdir.path(),
      &sessions_db,
      &format!("/api/requests?day=2026-07-13&cursor={cursor}"),
    )
    .await;
    assert_eq!(wrong_day_response.status(), StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn request_payload_endpoint_is_lazy_strict_and_base64_safe() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    write_request(tempdir.path(), "2026-07-14", "request/one", "session/one");
    let conn = open_day_db(&tempdir.path().join("2026-07-14.db")).unwrap();
    conn
      .execute(
        "UPDATE request_downstream
         SET inbound_req_body = '{\"input\":[{\"role\":\"user\",\"content\":\"hello\"},{\"type\":\"function_call\",\"name\":\"lookup\",\"arguments\":\"{}\"}],\"tools\":[{\"type\":\"function\",\"name\":\"lookup\",\"description\":\"Find a record\",\"parameters\":{\"type\":\"object\"}}]}'
         WHERE request_id = ?1",
        params!["request/one"],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_upstream (request_id, outbound_resp_body) VALUES (?1, ?2)",
        params!["request/one", &[0xff_u8, 0x00]],
      )
      .unwrap();

    let overview = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-07-14&request_id=request%2Fone&row_id=1",
    )
    .await;
    assert_eq!(overview.status(), StatusCode::OK);
    let overview_body = response_body(overview).await;
    assert!(overview_body.contains("request/one"));
    assert!(overview_body.contains(r#""row_id":"1""#));
    assert!(!overview_body.contains("inbound_req_body"));
    assert!(!overview_body.contains("outbound_resp_body"));

    let json_payload = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-payload?day=2026-07-14&request_id=request%2Fone&row_id=1&field=inbound_req_body",
    )
    .await;
    assert_eq!(json_payload.status(), StatusCode::OK);
    let json_payload_body = response_body(json_payload).await;
    assert!(json_payload_body.contains(r#""field":"inbound_req_body""#));
    assert!(json_payload_body.contains(r#""role":"user""#));

    let llm_summary = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-llm-summary?day=2026-07-14&request_id=request%2Fone&row_id=1",
    )
    .await;
    assert_eq!(llm_summary.status(), StatusCode::OK);
    let llm_summary_body = response_body(llm_summary).await;
    assert!(llm_summary_body.contains(r#""messages":[{"index":0"#));
    assert!(llm_summary_body.contains(r#""kind":"function_call""#));
    assert!(llm_summary_body.contains(r#""tool_definitions":[{"index":0"#));
    assert!(llm_summary_body.contains(r#""name":"lookup""#));
    assert!(llm_summary_body.contains(r#""description":"Find a record""#));

    let llm_message = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-llm-message?day=2026-07-14&request_id=request%2Fone&row_id=1&index=0",
    )
    .await;
    assert_eq!(llm_message.status(), StatusCode::OK);
    assert!(response_body(llm_message).await.contains(r#""content":"hello""#));

    let llm_tool = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-llm-tool-definition?day=2026-07-14&request_id=request%2Fone&row_id=1&index=0",
    )
    .await;
    assert_eq!(llm_tool.status(), StatusCode::OK);
    assert!(response_body(llm_tool)
      .await
      .contains(r#""parameters":{"type":"object"}"#));

    let missing_llm_message = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-llm-message?day=2026-07-14&request_id=request%2Fone&row_id=1&index=2",
    )
    .await;
    assert_eq!(missing_llm_message.status(), StatusCode::NOT_FOUND);

    let binary_payload = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-payload?day=2026-07-14&request_id=request%2Fone&row_id=1&field=outbound_resp_body",
    )
    .await;
    assert_eq!(binary_payload.status(), StatusCode::OK);
    let binary_payload_body = response_body(binary_payload).await;
    assert!(binary_payload_body.contains(r#""encoding":"base64""#));
    assert!(binary_payload_body.contains(r#""data":"/wA=""#));

    let invalid_field = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-payload?day=2026-07-14&request_id=request%2Fone&field=endpoint",
    )
    .await;
    assert_eq!(invalid_field.status(), StatusCode::BAD_REQUEST);

    let missing_request = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-payload?day=2026-07-14&request_id=missing&field=inbound_req_body",
    )
    .await;
    assert_eq!(missing_request.status(), StatusCode::NOT_FOUND);

    let missing_llm_summary = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-llm-summary?day=2026-07-14&request_id=missing",
    )
    .await;
    assert_eq!(missing_llm_summary.status(), StatusCode::NOT_FOUND);

    let mismatched_identity = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-07-14&request_id=request%2Fone&row_id=2",
    )
    .await;
    assert_eq!(mismatched_identity.status(), StatusCode::NOT_FOUND);
  }

  #[tokio::test]
  async fn row_id_disambiguates_duplicate_legacy_request_ids() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    let requests_db = tempdir.path().join("2026-07-14.db");
    let conn = rusqlite::Connection::open(requests_db).unwrap();
    conn
      .execute_batch(
        "CREATE TABLE requests (
           id INTEGER PRIMARY KEY,
           ts INTEGER NOT NULL,
           request_id TEXT,
           model TEXT,
           inbound_req_body BLOB
         );
         CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_ts INTEGER NOT NULL
         );
         INSERT INTO schema_migrations (version, name, applied_ts) VALUES
           (1, 'initial', 0),
           (2, 'correlation_and_error', 0);
         INSERT INTO requests (id, ts, request_id, model, inbound_req_body) VALUES
           (11, 1784444800, 'duplicate', 'model-11', '{\"row_id\":11}'),
           (12, 1784444800, 'duplicate', 'model-12', '{\"row_id\":12}');",
      )
      .unwrap();
    drop(conn);

    let overview = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-07-14&request_id=duplicate&row_id=11",
    )
    .await;
    assert_eq!(overview.status(), StatusCode::OK);
    let overview_body = response_body(overview).await;
    assert!(overview_body.contains(r#""row_id":"11""#));
    assert!(overview_body.contains("model-11"));
    assert!(!overview_body.contains("model-12"));

    let payload = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request-payload?day=2026-07-14&request_id=duplicate&row_id=12&field=inbound_req_body",
    )
    .await;
    assert_eq!(payload.status(), StatusCode::OK);
    let payload_body = response_body(payload).await;
    assert!(payload_body.contains(r#""row_id":12"#));

    let fallback = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/request?day=2026-07-14&request_id=duplicate",
    )
    .await;
    assert_eq!(fallback.status(), StatusCode::OK);
  }

  #[tokio::test]
  async fn requests_endpoint_filters_errors_only() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    write_request(tempdir.path(), "2026-07-14", "healthy", "session/one");
    write_request(tempdir.path(), "2026-07-14", "failed", "session/one");
    let conn = open_day_db(&tempdir.path().join("2026-07-14.db")).unwrap();
    conn
      .execute(
        "UPDATE request_connection SET request_error = 'failed' WHERE request_id = 'failed'",
        [],
      )
      .unwrap();

    let response = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/requests?day=2026-07-14&errors_only=true",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("failed"));
    assert!(!body.contains("healthy"));
  }

  #[tokio::test]
  async fn request_url_paths_endpoint_drives_exact_path_filtering() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    write_request(tempdir.path(), "2026-07-14", "search", "session/one");
    write_request(tempdir.path(), "2026-07-14", "responses", "session/one");
    let conn = open_day_db(&tempdir.path().join("2026-07-14.db")).unwrap();
    conn
      .execute(
        "UPDATE request_downstream SET inbound_req_url = ?2 WHERE request_id = ?1",
        ["search", "/backend-api/codex/alpha/search?client_version=1"],
      )
      .unwrap();
    conn
      .execute(
        "UPDATE request_downstream SET inbound_req_url = ?2 WHERE request_id = ?1",
        ["responses", "/backend-api/codex/responses"],
      )
      .unwrap();

    let choices = get_response(tempdir.path(), &sessions_db, "/api/request-url-paths?day=2026-07-14").await;
    assert_eq!(choices.status(), StatusCode::OK);
    let choices = response_body(choices).await;
    assert!(choices.contains(r#"{"url_path":"/backend-api/codex/alpha/search","request_count":1}"#));
    assert!(choices.contains(r#"{"url_path":"/backend-api/codex/responses","request_count":1}"#));

    let filtered = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/requests?day=2026-07-14&url_path=%2Fbackend-api%2Fcodex%2Falpha%2Fsearch",
    )
    .await;
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered = response_body(filtered).await;
    assert!(filtered.contains(r#""request_id":"search""#));
    assert!(!filtered.contains(r#""request_id":"responses""#));
  }

  #[tokio::test]
  async fn sessions_endpoint_reads_only_the_sessions_database() {
    let tempdir = tempfile::tempdir().unwrap();
    let requests_dir = tempdir.path().join("requests");
    std::fs::create_dir(&requests_dir).unwrap();
    write_request(&requests_dir, "2026-07-14", "request-only", "request-only-session");
    let sessions_db = tempdir.path().join("sessions.db");
    write_session(&sessions_db, "stored-session", "stored-request");

    let response = get_response(&requests_dir, &sessions_db, "/api/sessions").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("stored-session"));
    assert!(!body.contains("request-only-session"));
  }

  #[tokio::test]
  async fn sessions_endpoint_succeeds_without_request_history() {
    let tempdir = tempfile::tempdir().unwrap();
    let requests_dir = tempdir.path().join("not-a-directory");
    std::fs::write(&requests_dir, b"session endpoints must not read this path").unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    write_session(&sessions_db, "stored-session", "stored-request");

    let response = get_response(&requests_dir, &sessions_db, "/api/sessions").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_body(response).await.contains("stored-session"));

    let detail = get_response(
      &requests_dir,
      &sessions_db,
      "/api/session?session_id=stored-session&limit=20",
    )
    .await;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail = response_body(detail).await;
    assert!(detail.contains(r#""head_node_id":"stored-request""#));
    assert!(detail.contains(r#""node_id":"stored-request""#));
    assert!(detail.contains(r#""nodes_truncated":false"#));

    let node = get_response(
      &requests_dir,
      &sessions_db,
      "/api/session-node?session_id=stored-session&node_id=stored-request",
    )
    .await;
    assert_eq!(node.status(), StatusCode::OK);
    let node = response_body(node).await;
    assert!(node.contains(r#""request_messages":[{"role":"user""#));
    assert!(node.contains(r#""response_messages":[]"#));
    assert!(node.contains(r#""parts_total":0"#));
    assert!(node.contains(r#""messages_total":1,"messages_returned":1"#));
    assert!(node.contains(r#""parts_omitted":0"#));
  }

  #[tokio::test]
  async fn session_usage_endpoint_reads_only_the_usage_database() {
    let tempdir = tempfile::tempdir().unwrap();
    let requests_dir = tempdir.path().join("not-a-directory");
    std::fs::write(&requests_dir, b"session usage must not read request history").unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    let usage_db = tempdir.path().join("usage.db");
    write_session(&sessions_db, "stored-session", "stored-request");
    write_usage(
      &usage_db,
      "stored-session",
      "stored-request",
      r#"{"input":120,"output":30,"total":150,"cache_read":80,"reasoning":5}"#,
    );

    let response = get_response(
      &requests_dir,
      &sessions_db,
      "/api/session-usage?session_id=stored-session",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains(r#""session_id":"stored-session""#));
    assert!(body.contains(r#""input_tokens":120"#));
    assert!(body.contains(r#""output_tokens":30"#));
    assert!(body.contains(r#""cache_read_tokens":80"#));
    assert!(body.contains(
      r#""requests":[{"request_id":"stored-request","context_tokens":120,"input_delta_tokens":40,"output_tokens":30}]"#
    ));

    let missing = get_response(&requests_dir, &sessions_db, "/api/session-usage?session_id=missing").await;
    assert_eq!(missing.status(), StatusCode::OK);
    assert_eq!(response_body(missing).await, "null");
  }

  #[tokio::test]
  async fn stored_session_endpoints_preserve_missing_session_and_node_statuses() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");

    let missing_database_session = get_response(tempdir.path(), &sessions_db, "/api/session?session_id=missing").await;
    assert_eq!(missing_database_session.status(), StatusCode::NOT_FOUND);
    let missing_database_node = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/session-node?session_id=missing&node_id=missing-node",
    )
    .await;
    assert_eq!(missing_database_node.status(), StatusCode::NOT_FOUND);
    assert!(!sessions_db.exists());

    write_session(&sessions_db, "stored-session", "stored-request");
    let missing_session = get_response(tempdir.path(), &sessions_db, "/api/session?session_id=missing").await;
    assert_eq!(missing_session.status(), StatusCode::NOT_FOUND);
    let missing_node = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/session-node?session_id=stored-session&node_id=missing-node",
    )
    .await;
    assert_eq!(missing_node.status(), StatusCode::NOT_FOUND);
    assert!(response_body(missing_node).await.contains("session node not found"));
  }

  #[tokio::test]
  async fn sessions_endpoint_reports_an_unavailable_sessions_database() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    std::fs::write(&sessions_db, b"not a sqlite database").unwrap();

    let response = get_response(tempdir.path(), &sessions_db, "/api/sessions").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let detail = get_response(tempdir.path(), &sessions_db, "/api/session?session_id=stored").await;
    assert_eq!(detail.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_body(detail).await.contains("session database unavailable"));
  }

  #[tokio::test]
  async fn sessions_endpoint_explains_when_the_database_needs_migration() {
    let tempdir = tempfile::tempdir().unwrap();
    let sessions_db = tempdir.path().join("sessions.db");
    let conn = rusqlite::Connection::open(&sessions_db).unwrap();
    conn
      .execute_batch(
        "CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_ts INTEGER NOT NULL
         );
         INSERT INTO schema_migrations (version, name, applied_ts) VALUES (1, 'initial', 0);",
      )
      .unwrap();
    drop(conn);

    let response = get_response(tempdir.path(), &sessions_db, "/api/sessions").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_body(response).await.contains("migration"));

    let detail = get_response(tempdir.path(), &sessions_db, "/api/session?session_id=stored").await;
    assert_eq!(detail.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_body(detail).await.contains("migration"));

    let node = get_response(
      tempdir.path(),
      &sessions_db,
      "/api/session-node?session_id=stored&node_id=node",
    )
    .await;
    assert_eq!(node.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_body(node).await.contains("migration"));
  }
}
