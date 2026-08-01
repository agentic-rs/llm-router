use super::{migrate, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use tokn_core::request_event::RequestEndpoint;

pub struct UsageRecord<'a> {
  pub ts: i64,
  pub session_id: Option<&'a str>,
  pub request_id: &'a str,
  pub project_id: Option<&'a str>,
  pub ver: Option<&'a str>,
  pub request_error: Option<&'a str>,
  pub user: Option<&'a str>,
  pub endpoint: &'a RequestEndpoint,
  pub account_id: Option<&'a str>,
  pub provider_id: Option<&'a str>,
  pub model: &'a str,
  pub params_json: Option<&'a str>,
  pub usage_json: Option<&'a str>,
  pub ctx_json: Option<&'a str>,
  pub status: Option<u16>,
}

const BOOTSTRAP: &str = include_str!("../schemas/snapshot/usage/v0.2.1.sql");
const MIGRATIONS: &[migrate::Migration] = &[
  migrate::Migration {
    version: 1,
    name: "initial",
    sql: include_str!("../schemas/snapshot/usage/v0.0.0.sql"),
  },
  migrate::Migration {
    version: 2,
    name: "add_correlation_ids",
    sql: include_str!("../schemas/migrations/usage/0002_add_correlation_ids.sql"),
  },
  migrate::Migration {
    version: 3,
    name: "lifecycle_columns",
    sql: include_str!("../schemas/migrations/usage/0003_lifecycle_columns.sql"),
  },
  migrate::Migration {
    version: 4,
    name: "add_usage_breakdown",
    sql: include_str!("../schemas/migrations/usage/0004_add_usage_breakdown.sql"),
  },
  migrate::Migration {
    version: 5,
    name: "request_metadata",
    sql: include_str!("../schemas/migrations/usage/0005_request_metadata.sql"),
  },
  migrate::Migration {
    version: 6,
    name: "add_user",
    sql: include_str!("../schemas/migrations/usage/0006_add_user.sql"),
  },
];

pub fn latest_version() -> u32 {
  migrate::latest_version(MIGRATIONS)
}

pub struct UsageDb {
  conn: Connection,
}

impl UsageDb {
  /// Open `usage.db` at `path`, applying any pending migrations. Pass the
  /// canonical filesystem path so `migrate::apply` can stage a `.bak`.
  pub fn open(path: &Path) -> Result<Self> {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }
    let mut conn = Connection::open(path)?;
    migrate::apply(
      &mut conn,
      path,
      "usage",
      migrate::Bootstrap { sql: BOOTSTRAP },
      MIGRATIONS,
    )?;
    Ok(Self { conn })
  }

  pub fn record(&mut self, r: &UsageRecord<'_>) -> Result<()> {
    self.conn.execute(
      "INSERT OR REPLACE INTO requests (
         ts,
         session_id,
         request_id,
         project_id,
         ver,
         request_error,
         user,
         endpoint,
         account_id,
         provider_id,
         model,
         params_json,
         usage_json,
         ctx_json,
         status
       )
       VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
       )",
      params![
        r.ts,
        r.session_id,
        r.request_id,
        r.project_id,
        r.ver,
        r.request_error,
        r.user,
        r.endpoint.as_str(),
        r.account_id,
        r.provider_id,
        r.model,
        r.params_json,
        r.usage_json,
        r.ctx_json,
        r.status.map(|v| v as i64),
      ],
    )?;
    Ok(())
  }

  pub fn summary(&self, since_ts: i64, account: Option<&str>, provider: Option<&str>) -> Result<Vec<RowSummary>> {
    let mut sql = String::from(
      "SELECT account_id, provider_id, model,
              json_extract(params_json, '$.initiator') AS initiator,
              COUNT(*) AS n,
              COALESCE(SUM(COALESCE(json_extract(usage_json, '$.input'), 0)),0),
              COALESCE(SUM(COALESCE(json_extract(usage_json, '$.output'), 0)),0),
              COALESCE(SUM(COALESCE(json_extract(usage_json, '$.cache_read'), 0)),0),
              COALESCE(SUM(COALESCE(json_extract(usage_json, '$.reasoning'), 0)),0),
              COALESCE(AVG(COALESCE(json_extract(ctx_json, '$.latency_ms'), 0)),0)
       FROM requests
       WHERE ts >= ?1",
    );
    let mut bind_account = false;
    let mut bind_provider = false;
    if account.is_some() {
      bind_account = true;
      sql.push_str(" AND account_id = ?2");
    }
    if provider.is_some() {
      bind_provider = true;
      sql.push_str(if bind_account {
        " AND provider_id = ?3"
      } else {
        " AND provider_id = ?2"
      });
    }
    sql.push_str(
      " GROUP BY account_id, provider_id, model,
               json_extract(params_json, '$.initiator')
        ORDER BY n DESC",
    );

    let mut stmt = self.conn.prepare(&sql)?;
    let map_row = |row: &rusqlite::Row<'_>| {
      Ok(RowSummary {
        account: row.get::<_, String>(0)?,
        provider: row.get::<_, String>(1)?,
        model: row.get::<_, String>(2)?,
        initiator: row.get::<_, Option<String>>(3)?,
        count: row.get::<_, i64>(4)? as u64,
        input_tokens: row.get::<_, i64>(5)? as u64,
        output_tokens: row.get::<_, i64>(6)? as u64,
        cached_tokens: row.get::<_, i64>(7)? as u64,
        reasoning_tokens: row.get::<_, i64>(8)? as u64,
        avg_latency_ms: row.get::<_, f64>(9)?,
      })
    };

    let rows = match (bind_account, bind_provider) {
      (true, true) => stmt
        .query_map(params![since_ts, account.unwrap(), provider.unwrap()], map_row)?
        .collect::<rusqlite::Result<_>>()?,
      (true, false) => stmt
        .query_map(params![since_ts, account.unwrap()], map_row)?
        .collect::<rusqlite::Result<_>>()?,
      (false, true) => stmt
        .query_map(params![since_ts, provider.unwrap()], map_row)?
        .collect::<rusqlite::Result<_>>()?,
      (false, false) => stmt
        .query_map(params![since_ts], map_row)?
        .collect::<rusqlite::Result<_>>()?,
    };
    Ok(rows)
  }
}

#[derive(Debug)]
pub struct RowSummary {
  pub account: String,
  pub provider: String,
  pub model: String,
  pub initiator: Option<String>,
  pub count: u64,
  pub input_tokens: u64,
  pub output_tokens: u64,
  pub cached_tokens: u64,
  pub reasoning_tokens: u64,
  pub avg_latency_ms: f64,
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::provider::Endpoint;

  #[test]
  fn fresh_usage_db_records_correlation_ids() {
    let dir = std::env::temp_dir().join(format!("tokn-router-usage-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("usage.db");
    let mut db = UsageDb::open(&path).unwrap();

    db.record(&UsageRecord {
      ts: 100,
      session_id: Some("session-1"),
      request_id: "request-1",
      project_id: Some("project-1"),
      ver: Some("v1"),
      request_error: None,
      user: Some("client-a"),
      endpoint: &Endpoint::ChatCompletions.into(),
      account_id: Some("account"),
      provider_id: Some("provider"),
      model: "model",
      params_json: Some("{\"initiator\":\"user\",\"stream\":false}"),
      usage_json: Some("{\"input\":1}"),
      ctx_json: Some("{\"latency_ms\":1}"),
      status: Some(200),
    })
    .unwrap();

    let row: (String, String, String) = db
      .conn
      .query_row("SELECT session_id, request_id, project_id FROM requests", [], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
      })
      .unwrap();
    assert_eq!(row, ("session-1".into(), "request-1".into(), "project-1".into()));
  }
}
