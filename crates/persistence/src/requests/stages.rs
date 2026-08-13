//! Requests stage-event persistence.
//!
//! Subscribes to `Event::Requests(RequestEvent { request_id, attempt, payload })`
//! and writes one row per `(request_id, attempt)` into the per-day
//! `requests/<YYYY-MM-DD>.db` files. Mirrors the incremental pattern of
//! the legacy lifecycle writer ([`super::legacy`]): a single INSERT in
//! [`RequestEventHandler::on_started`] and one UPDATE per subsequent stage.
//!
//! `RequestEventHandler` owns the stage-event persistence semantics while
//! [`RequestsDb`] stays the low-level day-rotated connection cache and
//! `request_id → day` index used to route updates to the correct file.

use super::{composite_request_id, RequestsDb};
use crate::{headers_json, Result};
use rusqlite::params;
use serde_json::{Map, Value};
use std::path::PathBuf;
use tokn_core::event::{Event, EventHandler};
use tokn_core::request_event::{RecordEvent, RequestEndpoint, RequestEventPayload, Stage, StageEvent};

/// `EventHandler` that persists requests stage events into the requests DB.
/// Construct once and register with `spawn_event_loop`; its dedicated worker
/// preserves event order while this handler maintains its per-day connection
/// cache.
pub struct RequestEventHandler {
  db: RequestsDb,
  options: RequestPersistenceOptions,
}

/// Independent safety policy for projecting event bodies into SQLite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestPersistenceOptions {
  pub record_request_bodies: bool,
  pub body_max_bytes: usize,
}

impl Default for RequestPersistenceOptions {
  fn default() -> Self {
    Self {
      record_request_bodies: true,
      body_max_bytes: 10 * 1024 * 1024,
    }
  }
}

pub struct InboundConnectionUpdate<'a> {
  user: Option<&'a str>,
  api_key_id: Option<&'a str>,
  local_addr: Option<&'a str>,
  peer_addr: Option<&'a str>,
  mode: &'a str,
  method: &'a str,
  inbound_method: &'a str,
  url: Option<&'a str>,
}

impl RequestEventHandler {
  pub fn new(requests_dir: PathBuf) -> Result<Self> {
    Self::with_options(requests_dir, RequestPersistenceOptions::default())
  }

  pub fn with_options(requests_dir: PathBuf, options: RequestPersistenceOptions) -> Result<Self> {
    Ok(Self {
      db: RequestsDb::new(requests_dir)?,
      options,
    })
  }
}

impl EventHandler for RequestEventHandler {
  fn handle(&mut self, event: &Event) {
    let Event::Requests(r2) = event else {
      return;
    };
    let request_id = r2.request_id.as_str();
    let attempt = r2.attempt;
    let result = match &r2.payload {
      RequestEventPayload::Custom(_) => return,
      RequestEventPayload::Stage(stage) => match stage {
        StageEvent::Started { request_endpoint } => self.on_started(request_id, attempt, r2.ts, Some(request_endpoint)),
        StageEvent::Extract(s) => self.on_extract(
          request_id,
          attempt,
          s.model.as_str(),
          s.stream,
          s.session_id.as_deref(),
          s.initiator.as_deref(),
          &s.headers,
          &s.raw_body,
        ),
        StageEvent::Resolve(s) => self.on_resolve(
          request_id,
          attempt,
          s.account_id.as_str(),
          s.provider_id.as_str(),
          s.upstream_endpoint.map(RequestEndpoint::from).as_ref(),
        ),
        StageEvent::BuildHeaders(s) => self.on_build_headers(request_id, attempt, &s.headers),
        StageEvent::ConvertRequest(s) => self.on_convert_request(request_id, attempt, &s.upstream_wire_body),
        StageEvent::Send(s) => self.on_send(request_id, attempt, r2.ts, s.status, &s.headers),
        StageEvent::ConvertResponse(s) => {
          let body_bytes = s
            .body
            .as_ref()
            .map(|v| bytes::Bytes::from(serde_json::to_vec(v.as_ref()).unwrap_or_default()))
            .unwrap_or_default();
          self.on_convert_response(request_id, attempt, s.status, &s.headers, &body_bytes)
        }
        StageEvent::Error { stage, message, .. } => self.on_error(request_id, attempt, *stage, message.as_str()),
        StageEvent::Completed { .. } => self.on_completed(request_id, attempt, r2.ts),
      },
      // Record events capture transport-adjacent facts that live alongside
      // the stage lifecycle. Some of them overlap with stage summaries, but
      // they may still be the only persistence signal on error paths.
      RequestEventPayload::Record(record) => {
        if let Err(e) = self.ensure_started_for_record(request_id, attempt, r2.ts) {
          tracing::warn!(error = %e, request_id, attempt, "requests record bootstrap failed");
          return;
        }
        match record {
          RecordEvent::InboundConnection {
            user,
            api_key_id,
            local_addr,
            peer_addr,
            mode,
            method,
            inbound_method,
            url,
          } => self.on_inbound_connection(
            request_id,
            attempt,
            InboundConnectionUpdate {
              user: user.as_deref(),
              api_key_id: api_key_id.as_deref(),
              local_addr: local_addr.as_deref(),
              peer_addr: peer_addr.as_deref(),
              mode: mode.as_str(),
              method: method.as_str(),
              inbound_method: inbound_method.as_str(),
              url: url.as_deref(),
            },
          ),
          RecordEvent::UpstreamReq {
            method,
            url,
            headers,
            body,
          } => self.on_upstream_req(request_id, attempt, method.as_str(), url.as_str(), headers, body),
          RecordEvent::UpstreamResp { status, headers } => {
            self.on_upstream_resp(request_id, attempt, r2.ts, *status, headers)
          }
          RecordEvent::UpstreamBody { body, .. } => self.on_upstream_body(request_id, attempt, body),
          RecordEvent::ConvertedBody { body, .. } => self.on_converted_body(request_id, attempt, body),
          RecordEvent::Usage(usage) => self.on_usage(request_id, attempt, usage),
        }
      }
    };
    if let Err(e) = result {
      tracing::warn!(error = %e, request_id, attempt, "requests persistence write failed");
    }
  }
}

impl RequestEventHandler {
  fn ensure_started_for_record(&mut self, request_id: &str, attempt: u32, ts: i64) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    if self.db.conn_for_request(&id).is_some() {
      return Ok(());
    }
    self.on_started(request_id, attempt, ts, None)
  }

  pub fn on_inbound_connection(
    &mut self,
    request_id: &str,
    attempt: u32,
    update: InboundConnectionUpdate<'_>,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests InboundConnection bootstrap failed");
      return Ok(());
    };
    let mut ctx = Map::new();
    if let Some(local_addr) = update.local_addr {
      ctx.insert("local_addr".to_string(), Value::String(local_addr.to_string()));
    }
    if let Some(peer_addr) = update.peer_addr {
      ctx.insert("peer_addr".to_string(), Value::String(peer_addr.to_string()));
    }
    if let Some(api_key_id) = update.api_key_id {
      ctx.insert("api_key_id".to_string(), Value::String(api_key_id.to_string()));
    }
    ctx.insert("mode".to_string(), Value::String(update.mode.to_string()));
    ctx.insert("pipeline_id".to_string(), Value::String(update.method.to_string()));
    patch_ctx_json(conn, &id, ctx)?;
    conn.execute(
      "UPDATE request_connection SET user = COALESCE(user, ?2) WHERE request_id = ?1",
      params![id, update.user],
    )?;
    conn.execute(
      "INSERT INTO request_downstream (request_id, inbound_req_method, inbound_req_url)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(request_id) DO UPDATE SET
         inbound_req_method = COALESCE(excluded.inbound_req_method, request_downstream.inbound_req_method),
         inbound_req_url = COALESCE(excluded.inbound_req_url, request_downstream.inbound_req_url)",
      params![id, update.inbound_method, update.url],
    )?;
    Ok(())
  }

  /// Single anchor INSERT for a fresh request. Later handlers lazily upsert
  /// metadata and wire payload rows as those facts become available.
  pub fn on_started(
    &mut self,
    request_id: &str,
    attempt: u32,
    ts: i64,
    endpoint: Option<&RequestEndpoint>,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let conn = self.db.conn_for_ts(ts)?;
    conn.execute(
      "INSERT INTO request_connection (request_id, ts, ver, endpoint)
       VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(request_id) DO UPDATE SET
         ver = COALESCE(request_connection.ver, excluded.ver),
         endpoint = CASE
           WHEN request_connection.endpoint IS NULL OR request_connection.endpoint = '' THEN excluded.endpoint
           ELSE request_connection.endpoint
         END",
      params![
        id,
        ts,
        tokn_core::util::version::full(),
        endpoint.map(RequestEndpoint::as_str)
      ],
    )?;
    self.db.pin_request(&id, ts);
    Ok(())
  }

  #[allow(clippy::too_many_arguments)]
  pub fn on_extract(
    &mut self,
    request_id: &str,
    attempt: u32,
    model: &str,
    stream: bool,
    session_id: Option<&str>,
    initiator: Option<&str>,
    inbound_req_headers: &tokn_headers::HeaderMap,
    inbound_req_body: &bytes::Bytes,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let hdr_json = headers_json(inbound_req_headers);
    let persisted_body = persisted_body(self.options, inbound_req_body);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests Extract without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_metadata (request_id, model, session_id)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(request_id) DO UPDATE SET
         model = excluded.model,
         session_id = COALESCE(excluded.session_id, request_metadata.session_id)",
      params![id, model, session_id],
    )?;
    patch_params_json(conn, &id, params_patch(initiator, stream))?;
    conn.execute(
      "INSERT INTO request_downstream (request_id, inbound_req_headers, inbound_req_body)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(request_id) DO UPDATE SET
         inbound_req_headers = excluded.inbound_req_headers,
         inbound_req_body = excluded.inbound_req_body",
      params![id, hdr_json.as_ref(), persisted_body],
    )?;
    Ok(())
  }

  pub fn on_resolve(
    &mut self,
    request_id: &str,
    attempt: u32,
    account_id: &str,
    provider_id: &str,
    _upstream_endpoint: Option<&RequestEndpoint>,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests Resolve without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_metadata (request_id, account_id, provider_id)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(request_id) DO UPDATE SET
         account_id = excluded.account_id,
         provider_id = excluded.provider_id",
      params![id, account_id, provider_id],
    )?;
    Ok(())
  }

  pub fn on_build_headers(
    &mut self,
    request_id: &str,
    attempt: u32,
    outbound_req_headers: &tokn_headers::HeaderMap,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let hdr_json = headers_json(outbound_req_headers);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests BuildHeaders without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_upstream (request_id, outbound_req_headers)
       VALUES (?1, ?2)
       ON CONFLICT(request_id) DO UPDATE SET
         outbound_req_headers = excluded.outbound_req_headers",
      params![id, hdr_json.as_ref()],
    )?;
    Ok(())
  }

  pub fn on_convert_request(&mut self, request_id: &str, attempt: u32, outbound_req_body: &bytes::Bytes) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let persisted_body = persisted_body(self.options, outbound_req_body);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests ConvertRequest without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_upstream (request_id, outbound_req_body)
       VALUES (?1, ?2)
       ON CONFLICT(request_id) DO UPDATE SET
         outbound_req_body = excluded.outbound_req_body",
      params![id, persisted_body],
    )?;
    Ok(())
  }

  pub fn on_send(
    &mut self,
    request_id: &str,
    attempt: u32,
    ts: i64,
    status: u16,
    outbound_resp_headers: &tokn_headers::HeaderMap,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let hdr_json = headers_json(outbound_resp_headers);
    let latency_header_ms = self.db.latency_since_start(&id, ts);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests Send without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_upstream (request_id, outbound_resp_status, outbound_resp_headers)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(request_id) DO UPDATE SET
         outbound_resp_status = excluded.outbound_resp_status,
         outbound_resp_headers = excluded.outbound_resp_headers",
      params![id, status as i64, hdr_json.as_ref()],
    )?;
    patch_ctx_json(conn, &id, one_i64("latency_header_ms", latency_header_ms))?;
    Ok(())
  }

  pub fn on_convert_response(
    &mut self,
    request_id: &str,
    attempt: u32,
    status: u16,
    inbound_resp_headers: &tokn_headers::HeaderMap,
    inbound_resp_body: &bytes::Bytes,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let hdr_json = headers_json(inbound_resp_headers);
    let persisted_body = persisted_body(self.options, inbound_resp_body);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests ConvertResponse without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_downstream (request_id, inbound_resp_status, inbound_resp_headers, inbound_resp_body)
       VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(request_id) DO UPDATE SET
         inbound_resp_status = excluded.inbound_resp_status,
         inbound_resp_headers = excluded.inbound_resp_headers,
         inbound_resp_body = excluded.inbound_resp_body",
      params![id, status as i64, hdr_json.as_ref(), persisted_body],
    )?;
    conn.execute(
      "UPDATE request_connection SET status = ?2 WHERE request_id = ?1",
      params![id, status as i64],
    )?;
    Ok(())
  }

  pub fn on_error(&mut self, request_id: &str, attempt: u32, stage: Stage, message: &str) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let formatted = format!("{}: {message}", stage.as_str());
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests Error without prior Started");
      return Ok(());
    };
    conn.execute(
      "UPDATE request_connection SET request_error = ?2 WHERE request_id = ?1",
      params![id, formatted],
    )?;
    Ok(())
  }

  pub fn on_completed(&mut self, request_id: &str, attempt: u32, ts: i64) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let latency_ms = self.db.latency_since_start(&id, ts);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests Completed without prior Started");
      return Ok(());
    };
    patch_ctx_json(conn, &id, one_i64("latency_ms", latency_ms))?;
    self.db.clear_request(&id);
    Ok(())
  }

  /// Wire-truth upstream-request record. Overwrites the intent-time values
  /// written by `on_build_headers` / `on_convert_request` with what
  /// actually went on the wire (post auth injection, post Host /
  /// Content-Length strip, post body-bytes finalization). Also fills the
  /// previously-empty `outbound_req_method` and `outbound_req_url`
  /// columns that no stage event populated before `Record::UpstreamReq`
  /// existed.
  pub fn on_upstream_req(
    &mut self,
    request_id: &str,
    attempt: u32,
    method: &str,
    url: &str,
    headers: &tokn_headers::HeaderMap,
    body: &bytes::Bytes,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let hdr_json = headers_json(headers);
    let persisted_body = persisted_body(self.options, body);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests UpstreamReq without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_upstream (
         request_id,
         outbound_req_method,
         outbound_req_url,
         outbound_req_headers,
         outbound_req_body
       )
       VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(request_id) DO UPDATE SET
         outbound_req_method = excluded.outbound_req_method,
         outbound_req_url = excluded.outbound_req_url,
         outbound_req_headers = excluded.outbound_req_headers,
         outbound_req_body = excluded.outbound_req_body",
      params![id, method, url, hdr_json.as_ref(), persisted_body],
    )?;
    Ok(())
  }

  /// Wire-truth upstream-response status + headers. This overlaps with
  /// `StageEvent::Send` on successful requests, but error responses can fail
  /// before the Send stage completes, making this record the only place where
  /// we still learn the upstream status line.
  pub fn on_upstream_resp(
    &mut self,
    request_id: &str,
    attempt: u32,
    ts: i64,
    status: u16,
    headers: &tokn_headers::HeaderMap,
  ) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let hdr_json = headers_json(headers);
    let latency_header_ms = self.db.latency_since_start(&id, ts);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests UpstreamResp without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_upstream (request_id, outbound_resp_status, outbound_resp_headers)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(request_id) DO UPDATE SET
         outbound_resp_status = excluded.outbound_resp_status,
         outbound_resp_headers = excluded.outbound_resp_headers",
      params![id, status as i64, hdr_json.as_ref()],
    )?;
    patch_ctx_json(conn, &id, one_i64("latency_header_ms", latency_header_ms))?;
    Ok(())
  }

  /// Wire-truth upstream-response body. Written by ConvertResponse for
  /// buffered flows; streaming responses are not captured here (the live
  /// SSE byte stream is single-shot and can't be cheaply tee'd, matching
  /// legacy behavior). The `Send` stage already wrote status + response
  /// headers, so this update touches only the body column.
  pub fn on_upstream_body(&mut self, request_id: &str, attempt: u32, body: &bytes::Bytes) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let persisted_body = persisted_body(self.options, body);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests UpstreamBody without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_upstream (request_id, outbound_resp_body)
       VALUES (?1, ?2)
       ON CONFLICT(request_id) DO UPDATE SET
         outbound_resp_body = excluded.outbound_resp_body",
      params![id, persisted_body],
    )?;
    Ok(())
  }

  /// Wire-truth client-facing response body after any stream translation.
  /// Buffered flows still write `inbound_resp_body` from `StageEvent::ConvertResponse`;
  /// this record backfills the same column for streaming flows once the full
  /// SSE output has been accumulated.
  pub fn on_converted_body(&mut self, request_id: &str, attempt: u32, body: &bytes::Bytes) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let persisted_body = persisted_body(self.options, body);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests ConvertedBody without prior Started");
      return Ok(());
    };
    conn.execute(
      "INSERT INTO request_downstream (request_id, inbound_resp_body)
       VALUES (?1, ?2)
       ON CONFLICT(request_id) DO UPDATE SET
         inbound_resp_body = excluded.inbound_resp_body",
      params![id, persisted_body],
    )?;
    Ok(())
  }

  pub fn on_usage(&mut self, request_id: &str, attempt: u32, usage: &tokn_core::db::Usage) -> Result<()> {
    let id = composite_request_id(request_id, attempt);
    let Some(conn) = self.db.conn_for_request(&id) else {
      tracing::warn!(request_id = %id, "requests Usage without prior Started");
      return Ok(());
    };
    let usage_json = usage_json(usage);
    conn.execute(
      "INSERT INTO request_metadata (request_id, usage_json)
       VALUES (?1, ?2)
       ON CONFLICT(request_id) DO UPDATE SET
         usage_json = excluded.usage_json",
      params![id, usage_json],
    )?;
    Ok(())
  }
}

fn persisted_body(options: RequestPersistenceOptions, body: &bytes::Bytes) -> Option<&[u8]> {
  options
    .record_request_bodies
    .then(|| &body[..body.len().min(options.body_max_bytes)])
}

fn params_patch(initiator: Option<&str>, stream: bool) -> Map<String, Value> {
  let mut out = Map::new();
  if let Some(initiator) = initiator {
    out.insert("initiator".to_string(), Value::String(initiator.to_string()));
  }
  out.insert("stream".to_string(), Value::Bool(stream));
  out
}

fn one_i64(key: &str, value: i64) -> Map<String, Value> {
  let mut out = Map::new();
  out.insert(key.to_string(), Value::from(value));
  out
}

fn patch_ctx_json(conn: &rusqlite::Connection, request_id: &str, patch: Map<String, Value>) -> Result<()> {
  patch_json_column(
    conn,
    request_id,
    patch,
    "UPDATE request_connection
     SET ctx_json = json_set(COALESCE(ctx_json, '{}'), ?2, json(?3))
     WHERE request_id = ?1",
  )
}

fn patch_params_json(conn: &rusqlite::Connection, request_id: &str, patch: Map<String, Value>) -> Result<()> {
  patch_json_column(
    conn,
    request_id,
    patch,
    "UPDATE request_metadata
     SET params_json = json_set(COALESCE(params_json, '{}'), ?2, json(?3))
     WHERE request_id = ?1",
  )
}

fn patch_json_column(
  conn: &rusqlite::Connection,
  request_id: &str,
  patch: Map<String, Value>,
  update_sql: &str,
) -> Result<()> {
  if patch.is_empty() {
    return Ok(());
  }
  for (key, value) in patch {
    let path = format!("$.{key}");
    conn.execute(update_sql, params![request_id, path, value.to_string()])?;
  }
  Ok(())
}

fn usage_json(usage: &tokn_core::db::Usage) -> Option<String> {
  let mut out = Map::new();
  if let Some(v) = usage.usage_type {
    out.insert("kind".to_string(), Value::from(v.as_str()));
  }
  if let Some(v) = usage.input_tokens {
    out.insert("input".to_string(), Value::from(v));
  }
  if let Some(v) = usage.output_tokens {
    out.insert("output".to_string(), Value::from(v));
  }
  if let Some(v) = usage.total_tokens {
    out.insert("total".to_string(), Value::from(v));
  }
  if let Some(v) = usage.details.cache_read {
    out.insert("cache_read".to_string(), Value::from(v));
  }
  if let Some(v) = usage.details.cache_write {
    out.insert("cache_write".to_string(), Value::from(v));
  }
  if let Some(v) = usage.details.reasoning {
    out.insert("reasoning".to_string(), Value::from(v));
  }
  (!out.is_empty()).then(|| Value::Object(out).to_string())
}
