//! Requests database — per-day SQLite files, single connection cache.
//!
//! This module is the **sole owner** of the day-rotated `Connection`
//! cache and the `request_id → day` map. Both writer flavours (legacy
//! lifecycle in [`legacy`] and stage-event in [`stages`]) operate on
//! `&mut RequestsDb` and use the helpers exposed here.
//!
//! Shared helpers (`composite_request_id`, `day_key`, `now_unix`,
//! `open_day_db`, migration constants) live here so the handler
//! re-implements them.

use crate::migrate;
use rusqlite::{params, Connection};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use time::macros::format_description;

use crate::Result;

pub mod stages;

pub use stages::{RequestEventHandler, RequestPersistenceOptions};

const CACHE_CAP: usize = 3;
pub(crate) const BOOTSTRAP: &str = include_str!("../../schemas/snapshot/requests/v0.2.0.sql");
pub(crate) const MIGRATIONS: &[migrate::Migration] = &[
  migrate::Migration {
    version: 1,
    name: "initial",
    sql: include_str!("../../schemas/snapshot/requests/v0.0.0.sql"),
  },
  migrate::Migration {
    version: 2,
    name: "add_correlation_and_error",
    sql: include_str!("../../schemas/migrations/requests/0002_add_correlation_and_error.sql"),
  },
  migrate::Migration {
    version: 3,
    name: "add_usage_breakdown",
    sql: include_str!("../../schemas/migrations/requests/0003_add_usage_breakdown.sql"),
  },
  migrate::Migration {
    version: 4,
    name: "add_response_header_latency",
    sql: include_str!("../../schemas/migrations/requests/0004_add_response_header_latency.sql"),
  },
  migrate::Migration {
    version: 5,
    name: "add_source_and_method",
    sql: include_str!("../../schemas/migrations/requests/0005_add_source_and_method.sql"),
  },
  migrate::Migration {
    version: 6,
    name: "add_context_and_metrics",
    sql: include_str!("../../schemas/migrations/requests/0006_add_context_and_metrics.sql"),
  },
  migrate::Migration {
    version: 7,
    name: "split_requests",
    sql: include_str!("../../schemas/migrations/requests/0007_split_requests.sql"),
  },
  migrate::Migration {
    version: 8,
    name: "metadata_json",
    sql: include_str!("../../schemas/migrations/requests/0008_metadata_json.sql"),
  },
];

pub fn latest_version() -> u32 {
  migrate::latest_version(MIGRATIONS)
}

struct RequestMeta {
  day: String,
  started_at_ms: i64,
}

/// Day-rotated SQLite connection pool plus a `request_id → day` map.
///
/// Each instance keeps up to [`CACHE_CAP`] day connections open (LRU).
/// The `request_meta` map lets stage-event UPDATEs route to the day
/// where the row was originally INSERTed, even if subsequent events
/// arrive on the next calendar day, and carries the start timestamp
/// for latency computation.
pub struct RequestsDb {
  dir: PathBuf,
  conns: HashMap<String, DayConnection>,
  order: VecDeque<String>,
  request_meta: HashMap<String, RequestMeta>,
}

struct DayConnection {
  connection: Connection,
  identity: same_file::Handle,
}

impl RequestsDb {
  pub fn new(dir: PathBuf) -> Result<Self> {
    std::fs::create_dir_all(&dir)?;
    Ok(Self {
      dir,
      conns: HashMap::new(),
      order: VecDeque::new(),
      request_meta: HashMap::new(),
    })
  }

  /// Iterate every existing day file under `dir` (without opening them).
  pub fn day_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
      return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
      let entry = entry?;
      let path = entry.path();
      if path.extension().and_then(|s| s.to_str()) == Some("db") {
        out.push(path);
      }
    }
    Ok(out)
  }

  /// Borrow (or open) the day connection keyed by `ts`. Refreshes LRU.
  pub(crate) fn conn_for_ts(&mut self, ts: i64) -> Result<&mut Connection> {
    let key = day_key(ts);
    self.conn_for_day(&key)
  }

  /// Borrow (or open) the day connection keyed by `day` (e.g. `"2026-05-19"`).
  pub(crate) fn conn_for_day(&mut self, key: &str) -> Result<&mut Connection> {
    let path = self.dir.join(format!("{key}.db"));
    if self.conns.get(key).is_some_and(|cached| !cached.matches_path(&path)) {
      self.conns.remove(key);
      self.order.retain(|cached| cached != key);
    }
    if !self.conns.contains_key(key) {
      if self.order.len() >= CACHE_CAP {
        if let Some(old) = self.order.pop_front() {
          self.conns.remove(&old);
        }
      }
      let conn = DayConnection::open(&path)?;
      self.conns.insert(key.to_string(), conn);
    }
    self.order.retain(|k| k != key);
    self.order.push_back(key.to_string());
    Ok(&mut self.conns.get_mut(key).expect("opened requests db").connection)
  }

  /// Look up the connection a previously-pinned `request_id` was written to.
  /// Returns `None` if no INSERT has pinned this id yet.
  pub(crate) fn conn_for_request(&mut self, request_id: &str) -> Option<&mut Connection> {
    let key = self.request_meta.get(request_id)?.day.clone();
    self.conn_for_day(&key).ok()
  }

  pub(crate) fn contains_request(&self, request_id: &str) -> bool {
    self.request_meta.contains_key(request_id)
  }

  pub(crate) fn pin_request(&mut self, request_id: &str, ts: i64) {
    let key = day_key(ts);
    self.request_meta.insert(
      request_id.to_string(),
      RequestMeta {
        day: key,
        started_at_ms: ts,
      },
    );
  }

  pub(crate) fn latency_since_start(&self, request_id: &str, ts_now: i64) -> i64 {
    self
      .request_meta
      .get(request_id)
      .map(|m| ts_now - m.started_at_ms)
      .unwrap_or(0)
  }

  pub(crate) fn clear_request(&mut self, request_id: &str) {
    let Some(meta) = self.request_meta.remove(request_id) else {
      return;
    };
    if !self.request_meta.values().any(|other| other.day == meta.day) {
      self.conns.remove(&meta.day);
      self.order.retain(|day| day != &meta.day);
    }
  }

  pub(crate) fn dir(&self) -> &Path {
    &self.dir
  }
}

impl DayConnection {
  fn open(path: &Path) -> Result<Self> {
    let connection = open_day_db(path)?;
    let identity = same_file::Handle::from_path(path)?;
    Ok(Self { connection, identity })
  }

  fn matches_path(&self, path: &Path) -> bool {
    same_file::Handle::from_path(path).is_ok_and(|identity| identity == self.identity)
  }
}

/// Open a single day file (creating + migrating as needed).
pub fn open_day_db(path: &Path) -> Result<Connection> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
  }
  let mut conn = Connection::open(path)?;
  migrate::apply(
    &mut conn,
    path,
    "requests",
    migrate::Bootstrap { sql: BOOTSTRAP },
    MIGRATIONS,
  )?;
  Ok(conn)
}

/// Compose a row-level `request_id` from the base id and attempt number.
/// Attempt 0 keeps the bare id; retries append `:N`.
pub(crate) fn composite_request_id(request_id: &str, attempt: u32) -> String {
  if attempt == 0 {
    request_id.to_string()
  } else {
    format!("{request_id}:{attempt}")
  }
}

/// Convert a unix timestamp to a day key like `"2026-05-19"`.
/// Accepts both seconds and milliseconds: values > 10_000_000_000 are
/// treated as milliseconds (2026 in seconds ≈ 1.7B, in ms ≈ 1.7T).
pub(crate) fn day_key(ts: i64) -> String {
  let ts_secs = if ts > 10_000_000_000 { ts / 1_000 } else { ts };
  let dt = time::OffsetDateTime::from_unix_timestamp(ts_secs).unwrap_or_else(|_| time::OffsetDateTime::now_utc());
  dt.date()
    .format(format_description!("[year]-[month]-[day]"))
    .unwrap_or_else(|_| "1970-01-01".to_string())
}

#[allow(dead_code)]
pub(crate) fn now_unix() -> i64 {
  time::OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn now_unix_ms() -> i64 {
  let ns = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
  (ns / 1_000_000) as i64
}

// ---------------------------------------------------------------------------
// Readback helper
// ---------------------------------------------------------------------------

/// Read a single persisted request row by `request_id` from the per-day
/// `requests/<YYYY-MM-DD>.db` files. Searches today first (UTC), then
/// yesterday to cover day-boundary races where the row was written just
/// before midnight and the read happened just after.
///
/// Returns `Ok(None)` if no row matches. BLOB columns are decoded to a
/// UTF-8 string when valid; otherwise they are emitted as a JSON array of
/// bytes (`[u8, u8, ...]`). Headers/body BLOBs written by the requests
/// writer are always JSON, so the string branch is the common path.
pub fn read_request_row(
  requests_dir: &Path,
  request_id: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
  let now = now_unix_ms();
  let today = day_key(now);
  let yesterday = day_key(now - 86_400_000);
  for day in [today, yesterday] {
    let path = requests_dir.join(format!("{day}.db"));
    if !path.exists() {
      continue;
    }
    let conn = open_day_db(&path)?;
    if let Some(row) = select_row(&conn, request_id)? {
      return Ok(Some(row));
    }
  }
  Ok(None)
}

const JSON_TEXT_COLUMNS: &[&str] = &["ctx_json", "params_json", "usage_json"];

fn select_row(conn: &Connection, request_id: &str) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
  let mut stmt = conn.prepare("SELECT * FROM requests WHERE request_id = ? LIMIT 1")?;
  let col_count = stmt.column_count();
  let col_names: Vec<String> = (0..col_count)
    .map(|i| stmt.column_name(i).unwrap_or("").to_string())
    .collect();
  let mut rows = stmt.query(params![request_id])?;
  let Some(row) = rows.next()? else {
    return Ok(None);
  };
  let mut out = serde_json::Map::with_capacity(col_count);
  for (i, name) in col_names.iter().enumerate() {
    let val = row.get_ref(i)?;
    let json = match val {
      rusqlite::types::ValueRef::Null => serde_json::Value::Null,
      rusqlite::types::ValueRef::Integer(n) => serde_json::Value::Number(n.into()),
      rusqlite::types::ValueRef::Real(f) => serde_json::Number::from_f64(f)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null),
      rusqlite::types::ValueRef::Text(t) => match std::str::from_utf8(t) {
        Ok(s) if JSON_TEXT_COLUMNS.contains(&name.as_str()) => {
          serde_json::from_str::<serde_json::Value>(s).unwrap_or_else(|_| serde_json::Value::String(s.to_string()))
        }
        Ok(s) => serde_json::Value::String(s.to_string()),
        Err(_) => serde_json::Value::Array(t.iter().map(|b| serde_json::Value::from(*b)).collect()),
      },
      rusqlite::types::ValueRef::Blob(b) => match std::str::from_utf8(b) {
        Ok(s) => match serde_json::from_str::<serde_json::Value>(s) {
          Ok(v) => v,
          Err(_) => serde_json::Value::String(s.to_string()),
        },
        Err(_) => serde_json::Value::Array(b.iter().map(|b| serde_json::Value::from(*b)).collect()),
      },
    };
    out.insert(name.clone(), json);
  }
  Ok(Some(out))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn fresh_day_file_has_canonical_columns() {
    let dir = std::env::temp_dir().join(format!("tokn-router-req-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("2099-01-01.db");
    let conn = open_day_db(&path).unwrap();
    for (table, columns) in [
      (
        "request_connection",
        &[
          "request_id",
          "ts",
          "ver",
          "endpoint",
          "status",
          "request_error",
          "user",
          "ctx_json",
        ][..],
      ),
      (
        "request_metadata",
        &[
          "request_id",
          "session_id",
          "account_id",
          "provider_id",
          "model",
          "params_json",
          "usage_json",
        ][..],
      ),
      (
        "request_downstream",
        &[
          "request_id",
          "inbound_req_method",
          "inbound_req_url",
          "inbound_req_headers",
          "inbound_req_body",
          "inbound_resp_status",
          "inbound_resp_headers",
          "inbound_resp_body",
        ][..],
      ),
      (
        "request_upstream",
        &[
          "request_id",
          "outbound_req_method",
          "outbound_req_url",
          "outbound_req_headers",
          "outbound_req_body",
          "outbound_resp_status",
          "outbound_resp_headers",
          "outbound_resp_body",
        ][..],
      ),
    ] {
      let table_exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1")
        .unwrap()
        .exists(params![table])
        .unwrap();
      assert!(table_exists, "missing table {table}");
      for col in columns {
        let exists: bool = conn
          .prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2")
          .unwrap()
          .exists(params![table, col])
          .unwrap();
        assert!(exists, "missing column {table}.{col}");
      }
    }
    let requests_view_exists: bool = conn
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = 'requests'")
      .unwrap()
      .exists([])
      .unwrap();
    assert!(requests_view_exists, "missing requests compatibility view");
    let idx_exists: bool = conn
      .prepare("SELECT 1 FROM pragma_table_info('requests') WHERE name = 'idx'")
      .unwrap()
      .exists([])
      .unwrap();
    assert!(idx_exists, "missing requests.idx compatibility column");
    let metrics_exists: bool = conn
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metrics'")
      .unwrap()
      .exists([])
      .unwrap();
    assert!(!metrics_exists, "metrics table should be removed");
    let v: i64 = conn
      .prepare("SELECT MAX(version) FROM schema_migrations")
      .unwrap()
      .query_row([], |r| r.get(0))
      .unwrap();
    assert_eq!(v, 8);
  }

  #[test]
  fn read_request_row_only_json_decodes_known_text_columns() {
    let dir = std::env::temp_dir().join(format!("tokn-router-req-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("2099-01-01.db");
    let conn = open_day_db(&path).unwrap();
    conn
      .execute(
        "INSERT INTO request_connection (request_id, ts, endpoint, request_error, ctx_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params!["req-json-text", 1_i64, "null", "true", r#"{"mode":"route"}"#],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_metadata (request_id, model, params_json, usage_json)
         VALUES (?1, ?2, ?3, ?4)",
        params!["req-json-text", "model", r#"{"stream":true}"#, r#"{"input":1}"#],
      )
      .unwrap();

    let row = select_row(&conn, "req-json-text").unwrap().unwrap();

    assert_eq!(row["endpoint"], serde_json::Value::String("null".to_string()));
    assert_eq!(row["request_error"], serde_json::Value::String("true".to_string()));
    assert_eq!(row["ctx_json"], serde_json::json!({"mode": "route"}));
    assert_eq!(row["params_json"], serde_json::json!({"stream": true}));
    assert_eq!(row["usage_json"], serde_json::json!({"input": 1}));
  }
}
