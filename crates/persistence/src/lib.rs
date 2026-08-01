pub mod access;
pub mod archive;
pub mod migrate;
pub mod requests;
pub mod sessions;
pub mod usage;
pub mod viewer;

pub use access::{AccessDb, ApiKeyRecord, ApiKeySummaryRecord, NewApiKeyRecord};
pub use viewer::{
  get_request, get_request_llm_message, get_request_llm_summary, get_request_llm_tool_definition, get_session,
  get_session_from_db, get_session_node_from_db, get_session_usage, is_valid_request_day, list_latest_requests,
  list_request_days, list_request_url_paths, list_requests, list_sessions, list_sessions_from_db, LatestRequests,
  LlmItemDetail, LlmMessageSummary, LlmRequestContentSummary, LlmToolDefinitionSummary, RequestDay, RequestDayState,
  RequestListOptions, RequestUrlPath, SessionDetail, SessionMessage, SessionMessageTruncation, SessionNodeDetail,
  SessionNodeDetailTruncation, SessionNodeSummary, SessionPart, SessionPartContent, SessionPartEncoding,
  SessionPartOmissionReason, SessionRequestUsage, SessionSummary, SessionUsage, StoredSessionDetail,
};

pub use sessions::{MessageRecord, PartRecord};
use snafu::Snafu;
pub use tokn_core::db::{DbPaths, HttpSnapshot};
pub use usage::UsageDb;

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
