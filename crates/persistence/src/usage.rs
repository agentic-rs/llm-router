use super::{migrate, Result};
use rusqlite::{params, Connection};
use std::path::Path;

mod live;

pub use live::UsagePersistenceConsumer;

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

  fn record(&mut self, record: &UsageRecord<'_>) -> Result<()> {
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
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
       )",
      params![
        record.ts,
        record.session_id,
        record.request_id,
        record.project_id,
        record.version,
        record.request_error,
        record.user,
        record.endpoint,
        record.account_id,
        record.provider_id,
        record.model,
        record.params_json,
        record.usage_json,
        record.context_json,
        record.status.map(i64::from),
      ],
    )?;
    Ok(())
  }

  pub fn summary(&self, since_ts: i64, account: Option<&str>, provider: Option<&str>) -> Result<Vec<RowSummary>> {
    let mut sql = String::from(
      "SELECT COALESCE(account_id, 'unknown'), COALESCE(provider_id, 'unknown'), model,
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
      sql.push_str(" AND COALESCE(account_id, 'unknown') = ?2");
    }
    if provider.is_some() {
      bind_provider = true;
      sql.push_str(if bind_account {
        " AND COALESCE(provider_id, 'unknown') = ?3"
      } else {
        " AND COALESCE(provider_id, 'unknown') = ?2"
      });
    }
    sql.push_str(
      " GROUP BY COALESCE(account_id, 'unknown'), COALESCE(provider_id, 'unknown'), model,
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

struct UsageRecord<'a> {
  ts: i64,
  session_id: Option<&'a str>,
  request_id: &'a str,
  project_id: Option<&'a str>,
  version: &'a str,
  request_error: Option<&'a str>,
  user: Option<&'a str>,
  endpoint: Option<&'a str>,
  account_id: Option<&'a str>,
  provider_id: Option<&'a str>,
  model: &'a str,
  params_json: Option<&'a str>,
  usage_json: Option<&'a str>,
  context_json: Option<&'a str>,
  status: Option<u16>,
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

  #[test]
  fn summary_aggregates_usage_and_applies_account_provider_filters() {
    let dir = std::env::temp_dir().join(format!("tokn-router-usage-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("usage.db");
    let db = UsageDb::open(&path).unwrap();

    for row in [
      SummaryFixture {
        request_id: "old-request",
        ts: 99,
        account: "account-a",
        provider: "provider-x",
        model: "model-1",
        initiator: "user",
        usage_json: r#"{"input":1000,"output":1000,"cache_read":1000,"reasoning":1000}"#,
        latency_ms: 1_000,
      },
      SummaryFixture {
        request_id: "request-1",
        ts: 100,
        account: "account-a",
        provider: "provider-x",
        model: "model-1",
        initiator: "user",
        usage_json: r#"{"input":10,"output":4,"cache_read":2,"reasoning":1}"#,
        latency_ms: 100,
      },
      SummaryFixture {
        request_id: "request-2",
        ts: 110,
        account: "account-a",
        provider: "provider-x",
        model: "model-1",
        initiator: "user",
        usage_json: r#"{"input":5,"output":2,"reasoning":3}"#,
        latency_ms: 300,
      },
      SummaryFixture {
        request_id: "request-3",
        ts: 120,
        account: "account-a",
        provider: "provider-y",
        model: "model-1",
        initiator: "tool",
        usage_json: r#"{"input":7,"output":1,"cache_read":1}"#,
        latency_ms: 50,
      },
      SummaryFixture {
        request_id: "request-4",
        ts: 130,
        account: "account-b",
        provider: "provider-x",
        model: "model-2",
        initiator: "user",
        usage_json: r#"{"input":20,"output":10,"cache_read":5,"reasoning":6}"#,
        latency_ms: 400,
      },
    ] {
      insert_summary_fixture(&db, row);
    }

    let rows = db.summary(100, None, None).unwrap();
    assert_eq!(rows.len(), 3);
    let aggregate = find_summary(&rows, "account-a", "provider-x");
    assert_eq!(aggregate.model, "model-1");
    assert_eq!(aggregate.initiator.as_deref(), Some("user"));
    assert_eq!(aggregate.count, 2);
    assert_eq!(aggregate.input_tokens, 15);
    assert_eq!(aggregate.output_tokens, 6);
    assert_eq!(aggregate.cached_tokens, 2);
    assert_eq!(aggregate.reasoning_tokens, 4);
    assert_eq!(aggregate.avg_latency_ms, 200.0);

    let account_rows = db.summary(100, Some("account-a"), None).unwrap();
    assert_eq!(account_rows.len(), 2);
    assert!(account_rows.iter().all(|row| row.account == "account-a"));

    let provider_rows = db.summary(100, None, Some("provider-x")).unwrap();
    assert_eq!(provider_rows.len(), 2);
    assert!(provider_rows.iter().all(|row| row.provider == "provider-x"));

    let combined_rows = db.summary(100, Some("account-a"), Some("provider-x")).unwrap();
    assert_eq!(combined_rows.len(), 1);
    assert_eq!(combined_rows[0].count, 2);
  }

  struct SummaryFixture<'a> {
    request_id: &'a str,
    ts: i64,
    account: &'a str,
    provider: &'a str,
    model: &'a str,
    initiator: &'a str,
    usage_json: &'a str,
    latency_ms: u64,
  }

  fn insert_summary_fixture(db: &UsageDb, fixture: SummaryFixture<'_>) {
    let params_json = format!(r#"{{"initiator":"{}"}}"#, fixture.initiator);
    let ctx_json = format!(r#"{{"latency_ms":{}}}"#, fixture.latency_ms);
    db.conn
      .execute(
        "INSERT INTO requests (
           ts, request_id, account_id, provider_id, model, params_json, usage_json, ctx_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
          fixture.ts,
          fixture.request_id,
          fixture.account,
          fixture.provider,
          fixture.model,
          params_json,
          fixture.usage_json,
          ctx_json,
        ],
      )
      .unwrap();
  }

  fn find_summary<'a>(rows: &'a [RowSummary], account: &str, provider: &str) -> &'a RowSummary {
    rows
      .iter()
      .find(|row| row.account == account && row.provider == provider)
      .unwrap()
  }
}
