//! Requests database schema, migration, and enumeration helpers for per-day
//! SQLite files.

mod writer;

pub use writer::{RequestPersistenceConsumer, RequestPersistenceOptions};

use crate::migrate;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

use crate::Result;

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

/// Iterate every existing request day file under `dir` without opening it.
pub fn day_files(dir: &Path) -> Result<Vec<PathBuf>> {
  let mut out = Vec::new();
  if !dir.exists() {
    return Ok(out);
  }
  for entry in std::fs::read_dir(dir)? {
    let entry = entry?;
    if !entry.file_type()?.is_file() {
      continue;
    }
    let path = entry.path();
    if path.extension().and_then(|s| s.to_str()) == Some("db") {
      out.push(path);
    }
  }
  out.sort();
  Ok(out)
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

#[cfg(test)]
mod tests {
  use super::*;
  use rusqlite::params;

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
  fn day_files_returns_only_database_files() {
    let dir = std::env::temp_dir().join(format!("tokn-router-req-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("2026-05-01.db"), []).unwrap();
    std::fs::write(dir.join("2026-05-02.db"), []).unwrap();
    std::fs::write(dir.join("notes.txt"), []).unwrap();
    std::fs::create_dir(dir.join("nested.db")).unwrap();

    let file_names = day_files(&dir)
      .unwrap()
      .into_iter()
      .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
      .collect::<Vec<_>>();

    assert_eq!(file_names, ["2026-05-01.db", "2026-05-02.db"]);
  }
}
