pub mod access;
pub mod archive;
pub mod migrate;
pub mod requests;
pub mod sessions;
pub mod usage;
pub mod viewer;

pub use access::{AccessDb, ApiKeyRecord, ApiKeySummaryRecord, NewApiKeyRecord};
pub use requests::{read_request_row, RequestEventHandler, RequestPersistenceOptions};
pub use sessions::SessionEventHandler;
pub use viewer::{
  get_request, get_request_llm_message, get_request_llm_summary, get_request_llm_tool_definition, get_session,
  get_session_from_db, get_session_node_from_db, get_session_usage, is_valid_request_day, list_latest_requests,
  list_request_days, list_request_url_paths, list_requests, list_sessions, list_sessions_from_db, LatestRequests,
  LlmItemDetail, LlmMessageSummary, LlmRequestContentSummary, LlmToolDefinitionSummary, RequestDay, RequestDayState,
  RequestListOptions, RequestUrlPath, SessionDetail, SessionMessage, SessionMessageTruncation, SessionNodeDetail,
  SessionNodeDetailTruncation, SessionNodeSummary, SessionPart, SessionPartContent, SessionPartEncoding,
  SessionPartOmissionReason, SessionRequestUsage, SessionSummary, SessionUsage, StoredSessionDetail,
};

use bytes::Bytes;
use snafu::Snafu;
pub use tokn_core::db::{DbPaths, HttpSnapshot, MessageRecord, PartRecord};
#[allow(unused_imports)]
pub(crate) use tokn_core::db::{Usage, UsageDetails};
pub use usage::{UsageDb, UsageEventHandler};

/// Serialise an HTTP header map to JSON bytes, redacting values whose name
/// is sensitive (`authorization`, `proxy-authorization`, `cookie`, anything
/// containing `api-key`). Public so both inbound (server::forward) and
/// outbound (db::requests) capture paths share the same redaction policy.
pub fn headers_json(headers: &tokn_headers::HeaderMap) -> Bytes {
  use serde_json::{Map, Value};
  let mut out = Map::new();
  for (name, value) in headers {
    let key = name.as_str().to_ascii_lowercase();
    let value = if is_sensitive_header(&key) {
      "<redacted>".to_string()
    } else {
      value.as_str().to_string()
    };
    out.insert(key, Value::String(value));
  }
  serde_json::to_vec(&Value::Object(out)).unwrap_or_default().into()
}

pub fn is_sensitive_header(name: &str) -> bool {
  matches!(name, "authorization" | "proxy-authorization" | "cookie") || name.contains("api-key")
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
  #[snafu(display("db io"))]
  Io { source: std::io::Error },

  #[snafu(display("sqlite"))]
  Sqlite { source: rusqlite::Error },

  #[snafu(display(
    "sessions database schema version {version} does not support session viewing; version 2 or newer is required"
  ))]
  UnsupportedSessionSchema { version: u32 },

  #[snafu(display(
    "usage database schema version {version} does not support session usage; version 2 or newer is required"
  ))]
  UnsupportedUsageSchema { version: u32 },

  #[snafu(display("session node lineage is invalid at {node_id}"))]
  InvalidSessionLineage { node_id: String },

  #[snafu(display("session message tree is invalid at {message_id}"))]
  InvalidMessageTree { message_id: String },

  #[snafu(display("db writer channel closed"))]
  ChannelClosed,
}

impl From<std::io::Error> for Error {
  fn from(source: std::io::Error) -> Self {
    Error::Io { source }
  }
}

impl From<rusqlite::Error> for Error {
  fn from(source: rusqlite::Error) -> Self {
    Error::Sqlite { source }
  }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
