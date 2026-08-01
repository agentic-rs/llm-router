use super::{migrate, Result};
#[cfg(test)]
use bytes::Bytes;
use flate2::read::GzDecoder;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokn_headers::inbound::{PARENT_THREAD_ID_HEADERS, THREAD_ID_HEADERS};
use tracing::debug;

mod records;
mod semantic;

pub use records::{MessageRecord, PartRecord};
use semantic::{request_messages_from_json, response_messages_from_body};

const BOOTSTRAP: &str = include_str!("../schemas/snapshot/sessions/v0.2.1.sql");
const REQUESTS_TS_MILLIS_SCHEMA_VERSION: u32 = 8;
const SESSION_SOURCE_HEADER: &str = "header";
const MIGRATIONS: &[migrate::Migration] = &[
  migrate::Migration {
    version: 1,
    name: "initial",
    sql: include_str!("../schemas/snapshot/sessions/v0.0.0.sql"),
  },
  migrate::Migration {
    version: 2,
    name: "tree_nodes",
    sql: include_str!("../schemas/migrations/sessions/0002_tree_nodes.sql"),
  },
  migrate::Migration {
    version: 3,
    name: "session_views",
    sql: include_str!("../schemas/migrations/sessions/0003_session_views.sql"),
  },
  migrate::Migration {
    version: 4,
    name: "thread_lineage",
    sql: include_str!("../schemas/migrations/sessions/0004_thread_lineage.sql"),
  },
  migrate::Migration {
    version: 5,
    name: "message_tree",
    sql: include_str!("../schemas/migrations/sessions/0005_message_tree.sql"),
  },
];

type MessageId = [u8; 32];

pub fn latest_version() -> u32 {
  migrate::latest_version(MIGRATIONS)
}

pub struct SessionsDb {
  conn: Connection,
}

#[derive(Debug, Clone)]
pub struct TreeRequestRecord {
  pub ts: i64,
  pub session_id: String,
  pub thread_id: Option<String>,
  pub parent_thread_id: Option<String>,
  pub parent_session_id: Option<String>,
  pub request_id: String,
  pub endpoint: String,
  pub status: Option<u16>,
  pub account_id: Option<String>,
  pub provider_id: Option<String>,
  pub model: Option<String>,
  pub request_messages: Vec<MessageRecord>,
  pub response_messages: Vec<MessageRecord>,
}

#[derive(Debug, Default)]
pub struct PlaybackReport {
  pub rows_seen: u64,
  pub rows_with_session: u64,
  pub rows_recorded: u64,
  pub rows_existing: u64,
  pub rows_skipped: u64,
  pub decode_errors: u64,
  pub reduction_mismatches: u64,
  pub latest_mismatches: Vec<LatestMismatch>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlaybackStats {
  pub rows_seen: u64,
  pub rows_with_session: u64,
  pub rows_recorded: u64,
  pub rows_existing: u64,
  pub rows_skipped: u64,
  pub decode_errors: u64,
  pub reduction_mismatches: u64,
}

impl PlaybackStats {
  fn from_report(report: &PlaybackReport) -> Self {
    Self {
      rows_seen: report.rows_seen,
      rows_with_session: report.rows_with_session,
      rows_recorded: report.rows_recorded,
      rows_existing: report.rows_existing,
      rows_skipped: report.rows_skipped,
      decode_errors: report.decode_errors,
      reduction_mismatches: report.reduction_mismatches,
    }
  }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlaybackOptions {
  pub force: bool,
}

#[derive(Debug, Clone)]
pub enum PlaybackProgressEvent {
  Started {
    files_total: usize,
    rows_total: u64,
  },
  FileStarted {
    path: PathBuf,
    file_index: usize,
    files_total: usize,
    rows_total: u64,
  },
  RowProcessed {
    path: PathBuf,
    file_index: usize,
    files_total: usize,
    rows_seen: u64,
    rows_total: u64,
    file_stats: PlaybackStats,
    global_stats: PlaybackStats,
  },
  FileFinished {
    path: PathBuf,
    file_index: usize,
    files_total: usize,
    file_stats: PlaybackStats,
    global_stats: PlaybackStats,
  },
  Finished {
    global_stats: PlaybackStats,
  },
}

#[derive(Debug, Clone)]
pub enum PlaybackSource {
  File(PathBuf),
  Dir(PathBuf),
}

#[derive(Debug)]
pub struct LatestMismatch {
  pub session_id: String,
  pub expected_request_id: String,
  pub actual_request_id: Option<String>,
}

impl SessionsDb {
  pub fn open(path: &Path) -> Result<Self> {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }
    let mut conn = Connection::open(path)?;
    migrate::apply(
      &mut conn,
      path,
      "sessions",
      migrate::Bootstrap { sql: BOOTSTRAP },
      MIGRATIONS,
    )?;
    Ok(Self { conn })
  }

  pub fn record_tree(&mut self, r: &TreeRequestRecord) -> Result<()> {
    if r.request_messages.is_empty() && r.response_messages.is_empty() {
      debug!(session_id = %r.session_id, request_id = %r.request_id, "sessions.record_tree: no messages, skipping");
      return Ok(());
    }

    let explicit_thread_id = r.thread_id.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let thread_id = explicit_thread_id.unwrap_or(&r.session_id);
    let parent_thread_id = r
      .parent_thread_id
      .as_deref()
      .map(str::trim)
      .filter(|parent| !parent.is_empty() && *parent != thread_id);
    let thread_source = if explicit_thread_id.is_some() {
      "thread-header"
    } else {
      "session-fallback"
    };

    let tx = self.conn.transaction()?;
    let input_path = insert_message_path(&tx, None, 0, &r.request_messages)?;
    let input_tip = input_path.ids.last().copied();
    let output_path = insert_message_path(&tx, input_tip, input_path.ids.len(), &r.response_messages)?;
    let message_id = output_path
      .ids
      .last()
      .or(input_path.ids.last())
      .copied()
      .expect("record_tree rejects an empty input and output");
    let request_message_count = input_path.ids.len().saturating_sub(input_path.reused_prefix_messages);

    tx.execute(
      "INSERT INTO sessions (id, first_seen_ts, last_seen_ts, source, account_id, provider_id, model)
       VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT(id) DO UPDATE SET
         last_seen_ts = excluded.last_seen_ts,
         account_id = COALESCE(excluded.account_id, sessions.account_id),
         provider_id = COALESCE(excluded.provider_id, sessions.provider_id),
         model = COALESCE(excluded.model, sessions.model)",
      params![
        r.session_id,
        r.ts,
        SESSION_SOURCE_HEADER,
        r.account_id.as_deref(),
        r.provider_id.as_deref(),
        r.model.as_deref(),
      ],
    )?;
    tx.execute(
      "INSERT INTO session_threads
         (session_id, thread_id, parent_thread_id, first_seen_ts, last_seen_ts, source)
       VALUES (?1, ?2, ?3, ?4, ?4, ?5)
       ON CONFLICT(session_id, thread_id) DO UPDATE SET
         parent_thread_id = COALESCE(session_threads.parent_thread_id, excluded.parent_thread_id),
         first_seen_ts = MIN(session_threads.first_seen_ts, excluded.first_seen_ts),
         last_seen_ts = MAX(session_threads.last_seen_ts, excluded.last_seen_ts),
         source = CASE
           WHEN excluded.source = 'thread-header' THEN excluded.source
           ELSE session_threads.source
         END",
      params![r.session_id, thread_id, parent_thread_id, r.ts, thread_source],
    )?;
    // The immutable message tree owns ancestry; each node bookmarks one tip and retains its creation-time reuse count.
    tx.execute(
      "INSERT INTO session_nodes
         (id, session_id, parent_id, request_id, ts, endpoint, status, account_id, provider_id, model,
          reduction_kind, parent_source, common_prefix_messages, request_message_count, response_message_count,
          thread_id, message_id, input_message_count, output_message_count)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'message_tree', ?11, ?12, ?13, ?14, ?15,
               ?16, ?17, ?18)
       ON CONFLICT(session_id, request_id) DO UPDATE SET
         parent_id = excluded.parent_id,
         status = excluded.status,
         account_id = COALESCE(excluded.account_id, session_nodes.account_id),
         provider_id = COALESCE(excluded.provider_id, session_nodes.provider_id),
         model = COALESCE(excluded.model, session_nodes.model),
         reduction_kind = excluded.reduction_kind,
         parent_source = excluded.parent_source,
         response_message_count = excluded.response_message_count,
         thread_id = excluded.thread_id,
         message_id = excluded.message_id,
         input_message_count = excluded.input_message_count,
         output_message_count = excluded.output_message_count",
      params![
        r.request_id,
        r.session_id,
        None::<&str>,
        r.request_id,
        r.ts,
        r.endpoint,
        r.status.map(i64::from),
        r.account_id.as_deref(),
        r.provider_id.as_deref(),
        r.model.as_deref(),
        "none",
        input_path.reused_prefix_messages as i64,
        request_message_count as i64,
        output_path.ids.len() as i64,
        thread_id,
        message_id.as_slice(),
        input_path.ids.len() as i64,
        output_path.ids.len() as i64,
      ],
    )?;
    tx.execute(
      "INSERT INTO session_heads (session_id, node_id, updated_ts)
       VALUES (?1, ?2, ?3)
       ON CONFLICT(session_id) DO UPDATE SET
         node_id = excluded.node_id,
         updated_ts = excluded.updated_ts
       WHERE excluded.updated_ts >= session_heads.updated_ts",
      params![r.session_id, r.request_id, r.ts],
    )?;
    if let Some(parent_session_id) = r.parent_session_id.as_deref() {
      tx.execute(
        "INSERT INTO session_relations
           (parent_session_id, child_session_id, relation_kind, first_seen_ts, last_seen_ts, source)
         VALUES (?1, ?2, 'subagent', ?3, ?3, 'x-parent-session-id')
         ON CONFLICT(parent_session_id, child_session_id, relation_kind) DO UPDATE SET
           last_seen_ts = excluded.last_seen_ts",
        params![parent_session_id, r.session_id, r.ts],
      )?;
    }
    tx.commit()?;
    Ok(())
  }

  fn node_exists(&self, session_id: &str, request_id: &str) -> Result<bool> {
    let exists = self.conn.query_row(
      "SELECT EXISTS(SELECT 1 FROM session_nodes WHERE session_id = ?1 AND request_id = ?2)",
      params![session_id, request_id],
      |r| r.get::<_, bool>(0),
    )?;
    Ok(exists)
  }

  #[cfg(test)]
  fn materialize_request_messages(&self, node_id: &str) -> Result<Vec<MessageRecord>> {
    if let Some((request, _)) = self.materialize_message_tree_node(node_id)? {
      return Ok(request);
    }
    self.materialize_legacy_request_messages(node_id)
  }

  #[cfg(test)]
  fn materialize_response_messages(&self, node_id: &str) -> Result<Vec<MessageRecord>> {
    if let Some((_, response)) = self.materialize_message_tree_node(node_id)? {
      return Ok(response);
    }
    select_node_messages(&self.conn, node_id, "response")
  }

  #[cfg(test)]
  fn materialize_message_tree_node(&self, node_id: &str) -> Result<Option<(Vec<MessageRecord>, Vec<MessageRecord>)>> {
    let storage = self.conn.query_row(
      "SELECT message_id, input_message_count, output_message_count
       FROM session_nodes
       WHERE id = ?1",
      params![node_id],
      |row| {
        Ok((
          row.get::<_, Option<Vec<u8>>>(0)?,
          row.get::<_, Option<i64>>(1)?,
          row.get::<_, Option<i64>>(2)?,
        ))
      },
    )?;
    let Some(message_id) = storage.0 else {
      return Ok(None);
    };
    let input_count = required_count(storage.1, node_id)?;
    let output_count = required_count(storage.2, node_id)?;
    let message_id = decode_message_id(&message_id)?;
    let mut path = select_message_path(&self.conn, message_id)?;
    if path.len() != input_count.saturating_add(output_count) {
      return Err(crate::Error::InvalidMessageTree {
        message_id: encode_message_id(&message_id),
      });
    }
    let response = path.split_off(input_count);
    Ok(Some((path, response)))
  }

  #[cfg(test)]
  fn materialize_legacy_request_messages(&self, node_id: &str) -> Result<Vec<MessageRecord>> {
    let mut lineage = self.materialization_lineage(node_id)?;
    lineage.reverse();
    let mut out = Vec::new();
    for (node, kind) in lineage {
      let messages = select_node_messages(&self.conn, &node, "request")?;
      if kind == "root_snapshot" || kind == "conflict_snapshot" {
        out = messages;
      } else {
        out.extend(messages);
      }
    }
    Ok(out)
  }

  #[cfg(test)]
  fn materialization_lineage(&self, node_id: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut current = Some(node_id.to_string());
    while let Some(id) = current {
      let (parent_id, reduction_kind) = self.conn.query_row(
        "SELECT parent_id, reduction_kind FROM session_nodes WHERE id = ?1",
        params![&id],
        |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?)),
      )?;
      let is_snapshot = reduction_kind == "root_snapshot" || reduction_kind == "conflict_snapshot";
      out.push((id, reduction_kind));
      if is_snapshot {
        break;
      }
      current = parent_id;
    }
    Ok(out)
  }
}

struct MessagePath {
  ids: Vec<MessageId>,
  reused_prefix_messages: usize,
}

fn insert_message_path(
  tx: &rusqlite::Transaction<'_>,
  mut parent_id: Option<MessageId>,
  parent_depth: usize,
  messages: &[MessageRecord],
) -> Result<MessagePath> {
  let mut ids = Vec::with_capacity(messages.len());
  let mut reused_prefix_messages = 0;
  for (offset, message) in messages.iter().enumerate() {
    let depth = parent_depth + offset + 1;
    let message_hash = hash_message(message);
    let message_id = hash_prefix(parent_id.as_ref(), &message_hash);
    let parent_param = parent_id.as_ref().map(|id| id.as_slice());
    let inserted = tx.execute(
      "INSERT OR IGNORE INTO message_tree (id, parent_id, depth, message_hash, role, status)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
      params![
        message_id.as_slice(),
        parent_param,
        depth as i64,
        message_hash.as_slice(),
        message.role,
        message.status.map(i64::from),
      ],
    )?;
    if inserted == 0 {
      validate_existing_message(tx, message_id, parent_id, depth, message_hash, message)?;
      if reused_prefix_messages == offset {
        reused_prefix_messages += 1;
      }
    } else {
      for (part_index, part) in message.parts.iter().enumerate() {
        let part_hash = hash_part(&part.part_type, part.content.as_ref());
        insert_or_validate_part_blob(tx, message_id, &part_hash, part)?;
        insert_or_validate_message_part(tx, message_id, part_index, &part_hash)?;
      }
      validate_message_parts(tx, message_id, message)?;
    }
    ids.push(message_id);
    parent_id = Some(message_id);
  }
  Ok(MessagePath {
    ids,
    reused_prefix_messages,
  })
}

fn validate_existing_message(
  conn: &Connection,
  message_id: MessageId,
  parent_id: Option<MessageId>,
  depth: usize,
  message_hash: MessageId,
  message: &MessageRecord,
) -> Result<()> {
  let stored = conn.query_row(
    "SELECT parent_id, depth, message_hash, role, status
     FROM message_tree
     WHERE id = ?1",
    params![message_id.as_slice()],
    |row| {
      Ok((
        row.get::<_, Option<Vec<u8>>>(0)?,
        row.get::<_, i64>(1)?,
        row.get::<_, Vec<u8>>(2)?,
        row.get::<_, String>(3)?,
        row.get::<_, Option<i64>>(4)?,
      ))
    },
  )?;
  let stored_parent = stored.0.as_deref().map(decode_message_id).transpose()?;
  let stored_hash = decode_message_id(&stored.2)?;
  let matches = stored_parent == parent_id
    && stored.1 == depth as i64
    && stored_hash == message_hash
    && stored.3 == message.role
    && stored.4 == message.status.map(i64::from);
  if !matches {
    return Err(crate::Error::InvalidMessageTree {
      message_id: encode_message_id(&message_id),
    });
  }
  validate_message_parts(conn, message_id, message)
}

fn validate_message_parts(conn: &Connection, message_id: MessageId, message: &MessageRecord) -> Result<()> {
  let mut stmt = conn.prepare(
    "SELECT part.part_index, part.part_hash, blob.part_type, blob.content
     FROM message_parts part
     LEFT JOIN part_blobs blob ON blob.hash = part.part_hash
     WHERE part.message_id = ?1
     ORDER BY part.part_index",
  )?;
  let stored_parts = stmt
    .query_map(params![message_id.as_slice()], |row| {
      Ok((
        row.get::<_, i64>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, Option<String>>(2)?,
        row.get::<_, Option<Vec<u8>>>(3)?,
      ))
    })?
    .collect::<rusqlite::Result<Vec<_>>>()?;
  let matches = stored_parts.len() == message.parts.len()
    && stored_parts.iter().zip(&message.parts).enumerate().all(
      |(part_index, ((stored_index, stored_hash, stored_type, stored_content), part))| {
        *stored_index == part_index as i64
          && *stored_hash == hash_part(&part.part_type, part.content.as_ref())
          && stored_type.as_deref() == Some(part.part_type.as_str())
          && stored_content.as_deref() == Some(part.content.as_ref())
      },
    );
  if !matches {
    return Err(crate::Error::InvalidMessageTree {
      message_id: encode_message_id(&message_id),
    });
  }
  Ok(())
}

#[cfg(test)]
fn select_message_path(conn: &Connection, tip_id: MessageId) -> Result<Vec<MessageRecord>> {
  let mut current = Some(tip_id);
  let mut reversed = Vec::new();
  while let Some(message_id) = current {
    let stored = conn
      .query_row(
        "SELECT parent_id, depth, message_hash, role, status
         FROM message_tree
         WHERE id = ?1",
        params![message_id.as_slice()],
        |row| {
          Ok((
            row.get::<_, Option<Vec<u8>>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<i64>>(4)?,
          ))
        },
      )
      .optional()?;
    let Some((parent, depth, message_hash, role, status)) = stored else {
      return Err(crate::Error::InvalidMessageTree {
        message_id: encode_message_id(&message_id),
      });
    };
    let parent = parent.as_deref().map(decode_message_id).transpose()?;
    let message_hash = decode_message_id(&message_hash)?;
    let message = MessageRecord {
      role,
      status: status.map(|value| value as u16),
      parts: select_tree_message_parts(conn, &message_id)?,
    };
    if depth <= 0 || hash_message(&message) != message_hash || hash_prefix(parent.as_ref(), &message_hash) != message_id
    {
      return Err(crate::Error::InvalidMessageTree {
        message_id: encode_message_id(&message_id),
      });
    }
    reversed.push((depth as usize, message));
    current = parent;
  }
  reversed.reverse();
  if reversed
    .iter()
    .enumerate()
    .any(|(index, (depth, _))| *depth != index + 1)
  {
    return Err(crate::Error::InvalidMessageTree {
      message_id: encode_message_id(&tip_id),
    });
  }
  Ok(reversed.into_iter().map(|(_, message)| message).collect())
}

#[cfg(test)]
fn select_tree_message_parts(conn: &Connection, message_id: &MessageId) -> Result<Vec<PartRecord>> {
  let mut stmt = conn.prepare(
    "SELECT blob.part_type, blob.content
     FROM message_parts part
     JOIN part_blobs blob ON blob.hash = part.part_hash
     WHERE part.message_id = ?1
     ORDER BY part.part_index",
  )?;
  let parts = stmt
    .query_map(params![message_id.as_slice()], |row| {
      Ok(PartRecord {
        part_type: row.get(0)?,
        content: Bytes::from(row.get::<_, Vec<u8>>(1)?),
      })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()?;
  Ok(parts)
}

#[cfg(test)]
fn required_count(value: Option<i64>, id: &str) -> Result<usize> {
  match value.and_then(|value| usize::try_from(value).ok()) {
    Some(value) => Ok(value),
    None => Err(crate::Error::InvalidMessageTree {
      message_id: id.to_string(),
    }),
  }
}

fn decode_message_id(value: &[u8]) -> Result<MessageId> {
  value.try_into().map_err(|_| crate::Error::InvalidMessageTree {
    message_id: encode_message_id(value),
  })
}

fn encode_message_id(value: &[u8]) -> String {
  let mut out = String::with_capacity(value.len() * 2);
  for byte in value {
    let _ = write!(&mut out, "{byte:02x}");
  }
  out
}

fn insert_or_validate_part_blob(
  conn: &Connection,
  message_id: MessageId,
  part_hash: &str,
  part: &PartRecord,
) -> Result<()> {
  let inserted = conn.execute(
    "INSERT OR IGNORE INTO part_blobs (hash, part_type, content) VALUES (?1, ?2, ?3)",
    params![part_hash, part.part_type, part.content.as_ref()],
  )?;
  if inserted == 0 {
    let stored = conn.query_row(
      "SELECT part_type, content FROM part_blobs WHERE hash = ?1",
      params![part_hash],
      |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    if stored.0 != part.part_type || stored.1.as_slice() != part.content.as_ref() {
      return Err(crate::Error::InvalidMessageTree {
        message_id: encode_message_id(&message_id),
      });
    }
  }
  Ok(())
}

fn insert_or_validate_message_part(
  conn: &Connection,
  message_id: MessageId,
  part_index: usize,
  part_hash: &str,
) -> Result<()> {
  let inserted = conn.execute(
    "INSERT OR IGNORE INTO message_parts (message_id, part_index, part_hash)
     VALUES (?1, ?2, ?3)",
    params![message_id.as_slice(), part_index as i64, part_hash],
  )?;
  if inserted == 0 {
    let stored_hash = conn.query_row(
      "SELECT part_hash FROM message_parts WHERE message_id = ?1 AND part_index = ?2",
      params![message_id.as_slice(), part_index as i64],
      |row| row.get::<_, String>(0),
    )?;
    if stored_hash != part_hash {
      return Err(crate::Error::InvalidMessageTree {
        message_id: encode_message_id(&message_id),
      });
    }
  }
  Ok(())
}

#[cfg(test)]
fn select_node_messages(conn: &Connection, node_id: &str, side: &str) -> Result<Vec<MessageRecord>> {
  let mut stmt = conn.prepare(
    "SELECT id, role, status
     FROM node_messages
     WHERE node_id = ?1 AND side = ?2
     ORDER BY message_seq",
  )?;
  let rows = stmt
    .query_map(params![node_id, side], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, String>(1)?,
        r.get::<_, Option<i64>>(2)?,
      ))
    })?
    .collect::<rusqlite::Result<Vec<_>>>()?;
  rows
    .into_iter()
    .map(|(message_id, role, status)| {
      Ok(MessageRecord {
        role,
        status: status.map(|v| v as u16),
        parts: select_message_parts(conn, &message_id)?,
      })
    })
    .collect()
}

#[cfg(test)]
fn select_message_parts(conn: &Connection, message_id: &str) -> Result<Vec<PartRecord>> {
  let mut stmt = conn.prepare(
    "SELECT b.part_type, b.content
     FROM node_parts p
     JOIN part_blobs b ON b.hash = p.part_hash
     WHERE p.message_id = ?1
     ORDER BY p.part_index",
  )?;
  let parts = stmt
    .query_map(params![message_id], |r| {
      Ok(PartRecord {
        part_type: r.get(0)?,
        content: Bytes::from(r.get::<_, Vec<u8>>(1)?),
      })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()?;
  Ok(parts)
}

pub fn playback_requests_into_sessions(requests_db: &Path, sessions_db: &Path) -> Result<PlaybackReport> {
  playback_requests_into_sessions_with_options(requests_db, sessions_db, PlaybackOptions::default())
}

pub fn playback_requests_into_sessions_with_options(
  requests_db: &Path,
  sessions_db: &Path,
  options: PlaybackOptions,
) -> Result<PlaybackReport> {
  playback_requests_source_into_sessions(PlaybackSource::File(requests_db.to_path_buf()), sessions_db, options)
}

pub fn playback_requests_source_into_sessions(
  source: PlaybackSource,
  sessions_db: &Path,
  options: PlaybackOptions,
) -> Result<PlaybackReport> {
  playback_requests_source_into_sessions_with_progress(source, sessions_db, options, |_| {})
}

pub fn playback_requests_source_into_sessions_with_progress(
  source: PlaybackSource,
  sessions_db: &Path,
  options: PlaybackOptions,
  mut progress: impl FnMut(PlaybackProgressEvent),
) -> Result<PlaybackReport> {
  let request_dbs = match source {
    PlaybackSource::File(path) => vec![path],
    PlaybackSource::Dir(dir) => request_db_files(&dir)?,
  };
  let files_total = request_dbs.len();
  let rows_total = count_request_rows(&request_dbs)?;
  let mut sessions = SessionsDb::open(sessions_db)?;
  let mut report = PlaybackReport::default();
  let mut expected_latest = HashMap::new();
  progress(PlaybackProgressEvent::Started {
    files_total,
    rows_total,
  });
  for (file_index, requests_db) in request_dbs.into_iter().enumerate() {
    let requests = Connection::open_with_flags(&requests_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let file_rows_total = count_request_rows_in_connection(&requests)?;
    progress(PlaybackProgressEvent::FileStarted {
      path: requests_db.clone(),
      file_index,
      files_total,
      rows_total: file_rows_total,
    });
    let file_start = PlaybackStats::from_report(&report);
    playback_request_connection(
      &requests,
      &mut sessions,
      options,
      &mut report,
      &mut expected_latest,
      PlaybackFileContext {
        requests_db: &requests_db,
        file_start,
        rows_total: file_rows_total,
        file_index,
        files_total,
      },
      &mut progress,
    )?;
    let file_stats = subtract_stats(PlaybackStats::from_report(&report), file_start);
    progress(PlaybackProgressEvent::FileFinished {
      path: requests_db,
      file_index,
      files_total,
      file_stats,
      global_stats: PlaybackStats::from_report(&report),
    });
  }
  report.latest_mismatches = check_latest_heads(&expected_latest, &sessions.conn)?;
  progress(PlaybackProgressEvent::Finished {
    global_stats: PlaybackStats::from_report(&report),
  });
  Ok(report)
}

#[derive(Debug, Clone, Copy)]
struct PlaybackFileContext<'a> {
  requests_db: &'a Path,
  file_start: PlaybackStats,
  rows_total: u64,
  file_index: usize,
  files_total: usize,
}

fn playback_request_connection(
  requests: &Connection,
  sessions: &mut SessionsDb,
  options: PlaybackOptions,
  report: &mut PlaybackReport,
  expected_latest: &mut HashMap<String, (i64, i64, String)>,
  ctx: PlaybackFileContext<'_>,
  progress: &mut impl FnMut(PlaybackProgressEvent),
) -> Result<()> {
  let order_index = request_order_index(requests)?;
  let playback_ts = if migrate::read_current_version(requests)? < REQUESTS_TS_MILLIS_SCHEMA_VERSION {
    "ts * 1000"
  } else {
    "ts"
  };
  let mut stmt = requests.prepare(&format!(
    "SELECT {playback_ts}, session_id, request_id, endpoint, account_id, provider_id, model, status,
            {order_index}
     FROM requests
     WHERE session_id IS NOT NULL
     ORDER BY {playback_ts}, {order_index}",
  ))?;
  let mut rows = stmt.query([])?;
  while let Some(row) = rows.next()? {
    report.rows_seen += 1;
    report.rows_with_session += 1;
    let ts: i64 = row.get(0)?;
    let session_id: String = row.get(1)?;
    let request_id: String = row.get(2)?;
    let endpoint: String = row.get(3)?;
    let request_order: i64 = row.get(8)?;
    if !options.force && sessions.node_exists(&session_id, &request_id)? {
      report.rows_existing += 1;
      update_expected_latest(expected_latest, &session_id, &request_id, ts, request_order);
      emit_playback_row_progress(progress, ctx, report);
      continue;
    }
    let (headers, body, response_body) = select_playback_payload(requests, &request_id)?;
    let header_json = parse_json_bytes(&headers).unwrap_or(Value::Null);
    let body_json = if body.is_empty() {
      if headers_expect_body(&header_json) {
        tracing::warn!(
          requests_db = %ctx.requests_db.display(),
          request_id = %request_id,
          "request playback body missing"
        );
        report.decode_errors += 1;
        report.rows_skipped += 1;
        emit_playback_row_progress(progress, ctx, report);
        continue;
      }
      Value::Null
    } else {
      let decoded = match decode_request_body(&header_json, &body) {
        Ok(decoded) => decoded,
        Err(e) => {
          tracing::warn!(
            requests_db = %ctx.requests_db.display(),
            request_id = %request_id,
            error = %e,
            "request playback decode failed"
          );
          report.decode_errors += 1;
          report.rows_skipped += 1;
          emit_playback_row_progress(progress, ctx, report);
          continue;
        }
      };
      match serde_json::from_slice::<Value>(&decoded) {
        Ok(value) => value,
        Err(e) => {
          tracing::warn!(
            requests_db = %ctx.requests_db.display(),
            request_id = %request_id,
            error = %e,
            "request playback json parse failed"
          );
          report.decode_errors += 1;
          report.rows_skipped += 1;
          emit_playback_row_progress(progress, ctx, report);
          continue;
        }
      }
    };
    let request_messages = request_messages_from_json(&endpoint, &body_json);
    let response_messages = response_messages_from_body(&response_body);
    if request_messages.is_empty() && response_messages.is_empty() {
      report.rows_skipped += 1;
      emit_playback_row_progress(progress, ctx, report);
      continue;
    }
    let record = TreeRequestRecord {
      ts,
      session_id,
      thread_id: first_header_str(&header_json, THREAD_ID_HEADERS).map(str::to_string),
      parent_thread_id: first_header_str(&header_json, PARENT_THREAD_ID_HEADERS).map(str::to_string),
      parent_session_id: header_str(&header_json, "x-parent-session-id").map(str::to_string),
      request_id,
      endpoint,
      status: row.get::<_, Option<i64>>(7)?.map(|v| v as u16),
      account_id: row.get(4)?,
      provider_id: row.get(5)?,
      model: row.get(6)?,
      request_messages,
      response_messages,
    };
    sessions.record_tree(&record)?;
    report.rows_recorded += 1;
    update_expected_latest(
      expected_latest,
      &record.session_id,
      &record.request_id,
      record.ts,
      request_order,
    );
    emit_playback_row_progress(progress, ctx, report);
  }
  Ok(())
}

fn request_db_files(dir: &Path) -> Result<Vec<PathBuf>> {
  let mut files = Vec::new();
  for entry in std::fs::read_dir(dir)? {
    let entry = entry?;
    let path = entry.path();
    if path.extension().and_then(|value| value.to_str()) == Some("db") {
      files.push(path);
    }
  }
  files.sort();
  Ok(files)
}

fn select_playback_payload(requests: &Connection, request_id: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
  requests
    .query_row(
      "SELECT inbound_req_headers, inbound_req_body, inbound_resp_body
       FROM requests
       WHERE request_id = ?1",
      params![request_id],
      |r| {
        Ok((
          r.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
          r.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
          r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
        ))
      },
    )
    .map_err(Into::into)
}

fn count_request_rows(paths: &[PathBuf]) -> Result<u64> {
  let mut total = 0;
  for path in paths {
    let requests = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    total += count_request_rows_in_connection(&requests)?;
  }
  Ok(total)
}

fn count_request_rows_in_connection(requests: &Connection) -> Result<u64> {
  let count = requests.query_row("SELECT COUNT(*) FROM requests WHERE session_id IS NOT NULL", [], |r| {
    r.get::<_, i64>(0)
  })?;
  Ok(count.max(0) as u64)
}

fn emit_playback_row_progress(
  progress: &mut impl FnMut(PlaybackProgressEvent),
  ctx: PlaybackFileContext<'_>,
  report: &PlaybackReport,
) {
  let global_stats = PlaybackStats::from_report(report);
  let file_stats = subtract_stats(global_stats, ctx.file_start);
  progress(PlaybackProgressEvent::RowProcessed {
    path: ctx.requests_db.to_path_buf(),
    file_index: ctx.file_index,
    files_total: ctx.files_total,
    rows_seen: file_stats.rows_seen,
    rows_total: ctx.rows_total,
    file_stats,
    global_stats,
  });
}

fn subtract_stats(after: PlaybackStats, before: PlaybackStats) -> PlaybackStats {
  PlaybackStats {
    rows_seen: after.rows_seen.saturating_sub(before.rows_seen),
    rows_with_session: after.rows_with_session.saturating_sub(before.rows_with_session),
    rows_recorded: after.rows_recorded.saturating_sub(before.rows_recorded),
    rows_existing: after.rows_existing.saturating_sub(before.rows_existing),
    rows_skipped: after.rows_skipped.saturating_sub(before.rows_skipped),
    decode_errors: after.decode_errors.saturating_sub(before.decode_errors),
    reduction_mismatches: after.reduction_mismatches.saturating_sub(before.reduction_mismatches),
  }
}

fn update_expected_latest(
  out: &mut HashMap<String, (i64, i64, String)>,
  session_id: &str,
  request_id: &str,
  ts: i64,
  idx: i64,
) {
  let update = out
    .get(session_id)
    .map(|(existing_ts, existing_idx, _)| (ts, idx) >= (*existing_ts, *existing_idx))
    .unwrap_or(true);
  if update {
    out.insert(session_id.to_string(), (ts, idx, request_id.to_string()));
  }
}

fn request_order_index(requests: &Connection) -> Result<&'static str> {
  if requests_column_exists(requests, "idx")? {
    Ok("idx")
  } else {
    Ok("rowid")
  }
}

fn requests_column_exists(requests: &Connection, name: &str) -> Result<bool> {
  Ok(
    requests
      .prepare("SELECT 1 FROM pragma_table_info('requests') WHERE name = ?1")?
      .exists(params![name])?,
  )
}

fn check_latest_heads(
  expected: &HashMap<String, (i64, i64, String)>,
  sessions: &Connection,
) -> Result<Vec<LatestMismatch>> {
  let mut out = Vec::new();
  let mut expected: Vec<_> = expected.iter().collect();
  expected.sort_by(|a, b| a.0.cmp(b.0));
  for (session_id, (_, _, expected_request_id)) in expected {
    let actual_request_id = sessions
      .query_row(
        "SELECT n.request_id
         FROM session_heads h
         JOIN session_nodes n ON n.id = h.node_id
         WHERE h.session_id = ?1",
        params![session_id],
        |r| r.get::<_, String>(0),
      )
      .optional()?;
    if actual_request_id.as_deref() != Some(expected_request_id.as_str()) {
      out.push(LatestMismatch {
        session_id: session_id.clone(),
        expected_request_id: expected_request_id.clone(),
        actual_request_id,
      });
    }
  }
  Ok(out)
}

fn decode_request_body(headers: &Value, body: &[u8]) -> std::result::Result<Vec<u8>, String> {
  match header_str(headers, "content-encoding").unwrap_or("identity") {
    "identity" | "" => Ok(body.to_vec()),
    "gzip" => {
      let mut decoder = GzDecoder::new(body);
      let mut out = Vec::new();
      if let Err(e) = decoder.read_to_end(&mut out) {
        return decode_raw_json_body(body).ok_or_else(|| format!("gzip decode failed: {e}"));
      }
      Ok(out)
    }
    "zstd" => zstd::stream::decode_all(body)
      .or_else(|e| decode_raw_json_body(body).ok_or_else(|| format!("zstd decode failed: {e}"))),
    other => Err(format!("unsupported content-encoding: {other}")),
  }
}

fn headers_expect_body(headers: &Value) -> bool {
  let has_encoding = header_str(headers, "content-encoding")
    .map(|value| {
      let value = value.trim();
      !value.is_empty() && !value.eq_ignore_ascii_case("identity")
    })
    .unwrap_or(false);
  let has_content_length = header_str(headers, "content-length")
    .and_then(|value| value.parse::<u64>().ok())
    .map(|value| value > 0)
    .unwrap_or(false);
  has_encoding || has_content_length
}

fn decode_raw_json_body(body: &[u8]) -> Option<Vec<u8>> {
  parse_json_bytes(body).map(|_| body.to_vec())
}

fn header_str<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
  headers
    .as_object()?
    .iter()
    .find(|(key, _)| key.eq_ignore_ascii_case(name))
    .and_then(|(_, value)| value.as_str())
}

fn first_header_str<'a>(headers: &'a Value, names: &[&str]) -> Option<&'a str> {
  names.iter().find_map(|name| {
    header_str(headers, name)
      .map(str::trim)
      .filter(|value| !value.is_empty())
  })
}

fn parse_json_bytes(bytes: &[u8]) -> Option<Value> {
  serde_json::from_slice(bytes).ok()
}

fn hash_part(part_type: &str, content: &[u8]) -> String {
  let mut h = Sha256::new();
  h.update(part_type.as_bytes());
  h.update([0u8]);
  h.update(content);
  h.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_message(message: &MessageRecord) -> MessageId {
  let mut hash = Sha256::new();
  hash.update(b"tokn:session-message:v1\0");
  hash_len_prefixed(&mut hash, message.role.as_bytes());
  match message.status {
    Some(status) => {
      hash.update([1]);
      hash.update(status.to_be_bytes());
    }
    None => hash.update([0]),
  }
  hash.update((message.parts.len() as u64).to_be_bytes());
  for part in &message.parts {
    hash_len_prefixed(&mut hash, part.part_type.as_bytes());
    hash_len_prefixed(&mut hash, part.content.as_ref());
  }
  hash.finalize().into()
}

fn hash_prefix(parent_id: Option<&MessageId>, message_hash: &MessageId) -> MessageId {
  let mut hash = Sha256::new();
  hash.update(b"tokn:session-prefix:v1\0");
  match parent_id {
    Some(parent_id) => {
      hash.update([1]);
      hash.update(parent_id);
    }
    None => hash.update([0]),
  }
  hash.update(message_hash);
  hash.finalize().into()
}

fn hash_len_prefixed(hash: &mut Sha256, value: &[u8]) {
  hash.update((value.len() as u64).to_be_bytes());
  hash.update(value);
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::Bytes;
  use rusqlite::params;
  use serde_json::json;

  #[test]
  fn record_tree_builds_message_prefixes_without_splitting_observations() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    let first = vec![msg("system", "instructions"), msg("user", "hello")];
    let second = vec![
      msg("system", "instructions"),
      msg("user", "hello"),
      msg("assistant", "hi"),
      msg("user", "again"),
    ];
    let conflict = vec![msg("system", "changed"), msg("user", "branch")];

    db.record_tree(&TreeRequestRecord {
      ts: 100,
      session_id: "sess-1".into(),
      thread_id: None,
      parent_thread_id: None,
      parent_session_id: Some("parent-sess".into()),
      request_id: "req-1".into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: Some("acct".into()),
      provider_id: Some("prov".into()),
      model: Some("model".into()),
      request_messages: first,
      response_messages: vec![msg("assistant", "hi")],
    })
    .unwrap();
    db.record_tree(&TreeRequestRecord {
      ts: 110,
      session_id: "sess-1".into(),
      thread_id: None,
      parent_thread_id: None,
      parent_session_id: None,
      request_id: "req-2".into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: Some("acct".into()),
      provider_id: Some("prov".into()),
      model: Some("model".into()),
      request_messages: second.clone(),
      response_messages: vec![msg("assistant", "again")],
    })
    .unwrap();
    db.record_tree(&TreeRequestRecord {
      ts: 120,
      session_id: "sess-1".into(),
      thread_id: None,
      parent_thread_id: None,
      parent_session_id: None,
      request_id: "req-3".into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: Some("acct".into()),
      provider_id: Some("prov".into()),
      model: Some("model".into()),
      request_messages: conflict,
      response_messages: Vec::new(),
    })
    .unwrap();

    let rows = db
      .conn
      .prepare(
        "SELECT request_id, parent_id, reduction_kind, common_prefix_messages, request_message_count,
                input_message_count, output_message_count
         FROM session_nodes
         ORDER BY ts",
      )
      .unwrap()
      .query_map([], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, Option<String>>(1)?,
          r.get::<_, String>(2)?,
          r.get::<_, i64>(3)?,
          r.get::<_, i64>(4)?,
          r.get::<_, i64>(5)?,
          r.get::<_, i64>(6)?,
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(rows[0], ("req-1".into(), None, "message_tree".into(), 0, 2, 2, 1));
    assert_eq!(rows[1], ("req-2".into(), None, "message_tree".into(), 3, 1, 4, 1,));
    assert_eq!(rows[2], ("req-3".into(), None, "message_tree".into(), 0, 2, 2, 0));
    assert_messages_eq(&db.materialize_request_messages("req-2").unwrap(), &second);
    assert_messages_eq(
      &db.materialize_response_messages("req-2").unwrap(),
      &[msg("assistant", "again")],
    );
    let head: String = db
      .conn
      .query_row(
        "SELECT node_id FROM session_heads WHERE session_id = 'sess-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(head, "req-3");

    db.record_tree(&TreeRequestRecord {
      ts: 90,
      session_id: "sess-1".into(),
      thread_id: None,
      parent_thread_id: None,
      parent_session_id: None,
      request_id: "req-old".into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: Some("acct".into()),
      provider_id: Some("prov".into()),
      model: Some("model".into()),
      request_messages: vec![msg("user", "old")],
      response_messages: Vec::new(),
    })
    .unwrap();
    let head_after_old_insert: String = db
      .conn
      .query_row(
        "SELECT node_id FROM session_heads WHERE session_id = 'sess-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(head_after_old_insert, "req-3");
    let old_node: (Option<String>, String, String) = db
      .conn
      .query_row(
        "SELECT parent_id, reduction_kind, thread_id FROM session_nodes WHERE request_id = 'req-old'",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
      )
      .unwrap();
    assert_eq!(old_node, (None, "message_tree".into(), "sess-1".into()));

    let storage_counts: (i64, i64) = db
      .conn
      .query_row(
        "SELECT (SELECT COUNT(*) FROM message_tree), (SELECT COUNT(*) FROM node_messages)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
      )
      .unwrap();
    assert_eq!(storage_counts, (8, 0));

    let relation_count: i64 = db
      .conn
      .query_row("SELECT COUNT(*) FROM session_relations", [], |r| r.get(0))
      .unwrap();
    assert_eq!(relation_count, 1);
  }

  #[test]
  fn record_tree_keeps_thread_metadata_without_node_lineage() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();

    db.record_tree(&thread_record(
      100,
      "thread-root",
      None,
      "req-root-1",
      vec![msg("developer", "root"), msg("user", "shared")],
    ))
    .unwrap();
    db.record_tree(&thread_record(
      110,
      "thread-child",
      Some("thread-root"),
      "req-child-1",
      vec![msg("developer", "child"), msg("user", "task")],
    ))
    .unwrap();
    db.record_tree(&thread_record(
      120,
      "thread-root",
      None,
      "req-root-2",
      vec![
        msg("developer", "root"),
        msg("user", "shared"),
        msg("assistant", "root result"),
      ],
    ))
    .unwrap();
    db.record_tree(&thread_record(
      130,
      "thread-child",
      Some("thread-root"),
      "req-child-2",
      vec![
        msg("developer", "child"),
        msg("user", "task"),
        msg("assistant", "child result"),
      ],
    ))
    .unwrap();

    let nodes = db
      .conn
      .prepare(
        "SELECT request_id, parent_id, reduction_kind, common_prefix_messages,
                request_message_count, thread_id
         FROM session_nodes
         ORDER BY ts",
      )
      .unwrap()
      .query_map([], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, Option<String>>(1)?,
          r.get::<_, String>(2)?,
          r.get::<_, i64>(3)?,
          r.get::<_, i64>(4)?,
          r.get::<_, String>(5)?,
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(
      nodes,
      vec![
        (
          "req-root-1".into(),
          None,
          "message_tree".into(),
          0,
          2,
          "thread-root".into(),
        ),
        (
          "req-child-1".into(),
          None,
          "message_tree".into(),
          0,
          2,
          "thread-child".into(),
        ),
        (
          "req-root-2".into(),
          None,
          "message_tree".into(),
          2,
          1,
          "thread-root".into(),
        ),
        (
          "req-child-2".into(),
          None,
          "message_tree".into(),
          2,
          1,
          "thread-child".into(),
        ),
      ]
    );

    let threads = db
      .conn
      .prepare(
        "SELECT thread_id, parent_thread_id, source FROM session_threads
         WHERE session_id = 'sess-1' ORDER BY thread_id",
      )
      .unwrap()
      .query_map([], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, Option<String>>(1)?,
          r.get::<_, String>(2)?,
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(
      threads,
      vec![
        (
          "thread-child".into(),
          Some("thread-root".into()),
          "thread-header".into(),
        ),
        ("thread-root".into(), None, "thread-header".into()),
      ]
    );
  }

  #[test]
  fn message_tree_shares_prefixes_and_branches_at_first_difference() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();

    let mut root = thread_record(100, "thread-root", None, "req-root", vec![msg("user", "root")]);
    root.response_messages = vec![msg("assistant", "first")];
    db.record_tree(&root).unwrap();

    let mut extension = thread_record(
      110,
      "thread-root",
      None,
      "req-extension",
      vec![msg("user", "root"), msg("assistant", "first"), msg("user", "next")],
    );
    extension.response_messages = vec![msg("assistant", "second")];
    db.record_tree(&extension).unwrap();

    let mut branch = thread_record(
      120,
      "thread-root",
      None,
      "req-branch",
      vec![msg("user", "root"), msg("assistant", "first"), msg("user", "alternate")],
    );
    branch.response_messages = vec![msg("assistant", "branch")];
    db.record_tree(&branch).unwrap();

    let nodes = db
      .conn
      .prepare(
        "SELECT id, parent_id, common_prefix_messages, request_message_count
         FROM session_nodes
         ORDER BY ts",
      )
      .unwrap()
      .query_map([], |row| {
        Ok((
          row.get::<_, String>(0)?,
          row.get::<_, Option<String>>(1)?,
          row.get::<_, i64>(2)?,
          row.get::<_, i64>(3)?,
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(
      nodes,
      vec![
        ("req-root".into(), None, 0, 1),
        ("req-extension".into(), None, 2, 1),
        ("req-branch".into(), None, 2, 1),
      ]
    );

    let tree_rows: i64 = db
      .conn
      .query_row("SELECT COUNT(*) FROM message_tree", [], |row| row.get(0))
      .unwrap();
    assert_eq!(tree_rows, 6);
    assert_messages_eq(
      &db.materialize_request_messages("req-branch").unwrap(),
      &branch.request_messages,
    );
    assert_messages_eq(
      &db.materialize_response_messages("req-extension").unwrap(),
      &extension.response_messages,
    );
  }

  #[test]
  fn message_tree_reuse_count_is_global_not_session_lineage() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    let shared = vec![msg("system", "instructions"), msg("user", "hello")];

    db.record_tree(&thread_record(100, "thread-first", None, "req-first", shared.clone()))
      .unwrap();
    let mut second = thread_record(
      110,
      "thread-second",
      None,
      "req-second",
      [shared, vec![msg("user", "continue")]].concat(),
    );
    second.session_id = "sess-2".into();
    db.record_tree(&second).unwrap();

    let node = db
      .conn
      .query_row(
        "SELECT parent_id, parent_source, common_prefix_messages, request_message_count,
                input_message_count
         FROM session_nodes
         WHERE id = 'req-second'",
        [],
        |row| {
          Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(node, (None, "none".into(), 2, 1, 3));
  }

  #[test]
  fn message_tree_reuses_canonical_response_items_in_the_next_request() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    let first_input = request_messages_from_json(
      "responses",
      &json!({
        "input": [{"role": "user", "content": "inspect the session"}]
      }),
    );
    let first_output = response_messages_from_body(
      concat!(
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":",
        "{\"id\":\"rs_1\",\"type\":\"reasoning\",\"content\":[],\"encrypted_content\":\"ciphertext\",",
        "\"summary\":[],\"internal_chat_message_metadata_passthrough\":{\"turn_id\":\"turn-1\"},",
        "\"metadata\":{\"turn_id\":\"turn-1\"}}}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":",
        "{\"id\":\"fc_1\",\"type\":\"function_call\",\"status\":\"completed\",",
        "\"call_id\":\"call_1\",\"name\":\"exec_command\",\"arguments\":\"{\\\"cmd\\\":\\\"pwd\\\"}\",",
        "\"namespace\":\"functions\",\"internal_chat_message_metadata_passthrough\":{\"turn_id\":\"turn-1\"},",
        "\"metadata\":{\"turn_id\":\"turn-1\"}}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n",
      )
      .as_bytes(),
    );
    let mut first = thread_record(100, "thread-root", None, "req-first", first_input);
    first.response_messages = first_output;
    db.record_tree(&first).unwrap();

    let next_input = request_messages_from_json(
      "responses",
      &json!({
        "input": [
          {"role": "user", "content": "inspect the session"},
          {
            "type": "reasoning",
            "encrypted_content": "ciphertext",
            "summary": [],
            "internal_chat_message_metadata_passthrough": {"turn_id": "turn-1"}
          },
          {
            "type": "function_call",
            "call_id": "call_1",
            "name": "exec_command",
            "arguments": "{\"cmd\":\"pwd\"}",
            "namespace": "functions",
            "internal_chat_message_metadata_passthrough": {"turn_id": "turn-1"}
          },
          {
            "type": "function_call_output",
            "call_id": "call_1",
            "output": "workspace"
          }
        ]
      }),
    );
    db.record_tree(&thread_record(110, "thread-root", None, "req-next", next_input))
      .unwrap();

    let next_node = db
      .conn
      .query_row(
        "SELECT next.parent_id, next.common_prefix_messages, next.request_message_count,
                first.message_id = tip.parent_id
         FROM session_nodes next
         JOIN session_nodes first ON first.id = 'req-first'
         JOIN message_tree tip ON tip.id = next.message_id
         WHERE next.id = 'req-next'",
        [],
        |row| {
          Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, bool>(3)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(next_node, (None, 3, 1, true));
  }

  #[test]
  fn nodes_bookmark_final_message_and_reuse_identical_paths() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();

    let mut first = thread_record(100, "thread-root", None, "req-first", vec![msg("user", "hello")]);
    first.response_messages = vec![msg("assistant", "thinking"), msg("assistant", "done")];
    db.record_tree(&first).unwrap();
    db.record_tree(&first).unwrap();

    let mut retry = first.clone();
    retry.ts = 110;
    retry.request_id = "req-retry".into();
    db.record_tree(&retry).unwrap();

    let no_output = thread_record(120, "thread-root", None, "req-no-output", vec![msg("user", "hello")]);
    db.record_tree(&no_output).unwrap();

    let nodes = db
      .conn
      .prepare(
        "SELECT id, message_id, common_prefix_messages, request_message_count,
                input_message_count, output_message_count
         FROM session_nodes
         ORDER BY ts",
      )
      .unwrap()
      .query_map([], |row| {
        Ok((
          row.get::<_, String>(0)?,
          row.get::<_, Vec<u8>>(1)?,
          row.get::<_, i64>(2)?,
          row.get::<_, i64>(3)?,
          row.get::<_, i64>(4)?,
          row.get::<_, i64>(5)?,
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!((nodes[0].2, nodes[0].3, nodes[0].4, nodes[0].5), (0, 1, 1, 2));
    assert_eq!((nodes[1].2, nodes[1].3, nodes[1].4, nodes[1].5), (1, 0, 1, 2));
    assert_eq!((nodes[2].2, nodes[2].3, nodes[2].4, nodes[2].5), (1, 0, 1, 0));
    assert_eq!(nodes[0].1, nodes[1].1);
    assert_ne!(nodes[0].1, nodes[2].1);

    let tree_rows: i64 = db
      .conn
      .query_row("SELECT COUNT(*) FROM message_tree", [], |row| row.get(0))
      .unwrap();
    assert_eq!(tree_rows, 3);
    assert_messages_eq(
      &db.materialize_response_messages("req-retry").unwrap(),
      &retry.response_messages,
    );
  }

  #[test]
  fn reused_message_paths_reject_missing_or_corrupt_parts() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    let record = thread_record(100, "thread-root", None, "req-first", vec![msg("user", "hello")]);
    db.record_tree(&record).unwrap();

    let message_id = db
      .conn
      .query_row(
        "SELECT message_id FROM session_nodes WHERE id = 'req-first'",
        [],
        |row| row.get::<_, Vec<u8>>(0),
      )
      .unwrap();
    let expected_hash = hash_part("text", b"hello");
    db.conn
      .execute(
        "DELETE FROM message_parts WHERE message_id = ?1",
        params![message_id.as_slice()],
      )
      .unwrap();

    let mut retry = record.clone();
    retry.ts = 110;
    retry.request_id = "req-missing-part".into();
    assert!(matches!(
      db.record_tree(&retry),
      Err(crate::Error::InvalidMessageTree { .. })
    ));
    let part_count: i64 = db
      .conn
      .query_row(
        "SELECT COUNT(*) FROM message_parts WHERE message_id = ?1",
        params![message_id.as_slice()],
        |row| row.get(0),
      )
      .unwrap();
    assert_eq!(part_count, 0, "recording must not repair an immutable message");

    let wrong_hash = hash_part("text", b"wrong");
    db.conn
      .execute(
        "INSERT INTO part_blobs (hash, part_type, content) VALUES (?1, 'text', ?2)",
        params![wrong_hash, b"wrong".as_slice()],
      )
      .unwrap();
    db.conn
      .execute(
        "INSERT INTO message_parts (message_id, part_index, part_hash) VALUES (?1, 0, ?2)",
        params![message_id.as_slice(), wrong_hash],
      )
      .unwrap();
    retry.ts = 120;
    retry.request_id = "req-wrong-mapping".into();
    assert!(matches!(
      db.record_tree(&retry),
      Err(crate::Error::InvalidMessageTree { .. })
    ));

    db.conn
      .execute(
        "UPDATE message_parts SET part_hash = ?1 WHERE message_id = ?2 AND part_index = 0",
        params![expected_hash, message_id.as_slice()],
      )
      .unwrap();
    db.conn
      .execute(
        "UPDATE part_blobs SET content = ?1 WHERE hash = ?2",
        params![b"tampered".as_slice(), expected_hash],
      )
      .unwrap();
    let conflicting_blob = thread_record(
      130,
      "thread-root",
      None,
      "req-corrupt-blob",
      vec![msg("assistant", "hello")],
    );
    assert!(matches!(
      db.record_tree(&conflicting_blob),
      Err(crate::Error::InvalidMessageTree { .. })
    ));
  }

  #[test]
  fn message_tree_branches_after_a_sixty_five_message_prefix() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    let shared = (0..65)
      .map(|index| msg("user", &format!("shared-{index}")))
      .collect::<Vec<_>>();
    let mut left_messages = shared.clone();
    left_messages.push(msg("user", "left"));
    let mut right_messages = shared;
    right_messages.push(msg("user", "right"));

    db.record_tree(&thread_record(
      100,
      "thread-root",
      None,
      "req-left",
      left_messages.clone(),
    ))
    .unwrap();
    db.record_tree(&thread_record(
      110,
      "thread-root",
      None,
      "req-right",
      right_messages.clone(),
    ))
    .unwrap();

    let depth_counts = db
      .conn
      .query_row(
        "SELECT
           (SELECT COUNT(*) FROM message_tree WHERE depth <= 65),
           (SELECT COUNT(*) FROM message_tree WHERE depth = 66),
           (SELECT COUNT(DISTINCT parent_id) FROM message_tree WHERE depth = 66)",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
      )
      .unwrap();
    assert_eq!(depth_counts, (65, 2, 1));
    assert_messages_eq(&db.materialize_request_messages("req-left").unwrap(), &left_messages);
    assert_messages_eq(&db.materialize_request_messages("req-right").unwrap(), &right_messages);
  }

  #[test]
  fn message_tree_migration_does_not_rewrite_existing_nodes() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let conn = Connection::open(&path).unwrap();
    conn
      .execute_batch(
        "CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_ts INTEGER NOT NULL
         );",
      )
      .unwrap();
    conn.execute_batch(MIGRATIONS[0].sql).unwrap();
    for migration in &MIGRATIONS[..3] {
      if migration.version > 1 {
        conn.execute_batch(migration.sql).unwrap();
      }
      conn
        .execute(
          "INSERT INTO schema_migrations (version, name, applied_ts) VALUES (?1, ?2, 0)",
          params![migration.version, migration.name],
        )
        .unwrap();
    }
    conn
      .execute(
        "INSERT INTO sessions
           (id, first_seen_ts, last_seen_ts, source, account_id, provider_id, model)
         VALUES ('sess-old', 100, 100, 'header', 'acct', 'prov', 'model')",
        [],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO session_nodes
           (id, session_id, parent_id, request_id, ts, endpoint, status, account_id, provider_id, model,
            reduction_kind, parent_source, common_prefix_messages, request_message_count, response_message_count)
         VALUES
           ('req-old', 'sess-old', NULL, 'req-old', 100, 'responses', 200, 'acct', 'prov', 'model',
            'root_snapshot', 'none', 0, 1, 1)",
        [],
      )
      .unwrap();
    drop(conn);

    #[derive(Debug, PartialEq)]
    struct StoredLegacyNode {
      thread_id: Option<String>,
      parent_source: String,
      reduction_kind: String,
      request_message_count: i64,
      response_message_count: i64,
      message_id: Option<Vec<u8>>,
      input_message_count: Option<i64>,
      output_message_count: Option<i64>,
    }

    let db = SessionsDb::open(&path).unwrap();
    let old_node = db
      .conn
      .query_row(
        "SELECT thread_id, parent_source, reduction_kind, request_message_count, response_message_count,
                message_id, input_message_count, output_message_count
         FROM session_nodes WHERE id = 'req-old'",
        [],
        |r| {
          Ok(StoredLegacyNode {
            thread_id: r.get(0)?,
            parent_source: r.get(1)?,
            reduction_kind: r.get(2)?,
            request_message_count: r.get(3)?,
            response_message_count: r.get(4)?,
            message_id: r.get(5)?,
            input_message_count: r.get(6)?,
            output_message_count: r.get(7)?,
          })
        },
      )
      .unwrap();
    assert_eq!(
      old_node,
      StoredLegacyNode {
        thread_id: None,
        parent_source: "none".into(),
        reduction_kind: "root_snapshot".into(),
        request_message_count: 1,
        response_message_count: 1,
        message_id: None,
        input_message_count: None,
        output_message_count: None,
      }
    );
    let thread_count: i64 = db
      .conn
      .query_row("SELECT COUNT(*) FROM session_threads", [], |r| r.get(0))
      .unwrap();
    assert_eq!(thread_count, 0);
    let message_count: i64 = db
      .conn
      .query_row("SELECT COUNT(*) FROM message_tree", [], |r| r.get(0))
      .unwrap();
    assert_eq!(message_count, 0);
    assert_eq!(migrate::read_current_version(&db.conn).unwrap(), latest_version());
  }

  #[test]
  fn playback_requests_decodes_zstd_builds_tree_and_verifies_latest_head() {
    let dir = tempdir();
    let requests_path = dir.join("2026-05-22.db");
    let sessions_path = dir.join("sessions.db");
    crate::requests::open_day_db(&requests_path).unwrap();
    let conn = Connection::open(&requests_path).unwrap();
    insert_request_row(
      &conn,
      100,
      "req-1",
      "sess-1",
      &json!({
        "instructions": "be useful",
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}]
      }),
      sse_completed("hi"),
    );
    insert_request_row(
      &conn,
      110,
      "req-2",
      "sess-1",
      &json!({
        "instructions": "be useful",
        "input": [
          {"role": "user", "content": [{"type": "input_text", "text": "hello"}]},
          {"role": "assistant", "content": [{"type": "output_text", "text": "hi"}]},
          {"role": "user", "content": [{"type": "input_text", "text": "again"}]}
        ]
      }),
      "event: response.output_text.delta\ndata: {\"delta\":\"partial\"}\n\n",
    );

    let report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(report.rows_seen, 2);
    assert_eq!(report.rows_recorded, 2);
    assert_eq!(report.rows_existing, 0);
    assert_eq!(report.decode_errors, 0);
    assert!(report.latest_mismatches.is_empty());

    let second_report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(second_report.rows_seen, 2);
    assert_eq!(second_report.rows_recorded, 0);
    assert_eq!(second_report.rows_existing, 2);
    assert!(second_report.latest_mismatches.is_empty());

    let forced_report =
      playback_requests_into_sessions_with_options(&requests_path, &sessions_path, PlaybackOptions { force: true })
        .unwrap();
    assert_eq!(forced_report.rows_seen, 2);
    assert_eq!(forced_report.rows_recorded, 2);
    assert_eq!(forced_report.rows_existing, 0);
    assert!(forced_report.latest_mismatches.is_empty());

    let sessions = Connection::open(&sessions_path).unwrap();
    let reduction: String = sessions
      .query_row(
        "SELECT reduction_kind FROM session_nodes WHERE request_id = 'req-2'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(reduction, "message_tree");
    let head: String = sessions
      .query_row(
        "SELECT n.request_id FROM session_heads h JOIN session_nodes n ON n.id = h.node_id WHERE h.session_id = 'sess-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(head, "req-2");
    let timestamps = sessions
      .query_row(
        "SELECT s.first_seen_ts, s.last_seen_ts, h.updated_ts, n.ts
         FROM sessions s
         JOIN session_heads h ON h.session_id = s.id
         JOIN session_nodes n ON n.id = h.node_id
         WHERE s.id = 'sess-1'",
        [],
        |r| {
          Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(timestamps, (100, 110, 110, 110));
    let response_messages: i64 = sessions
      .query_row("SELECT COUNT(*) FROM message_tree WHERE role = 'assistant'", [], |r| {
        r.get(0)
      })
      .unwrap();
    assert_eq!(response_messages, 2);
  }

  #[test]
  fn playback_keeps_codex_root_and_subagent_threads_separate() {
    let dir = tempdir();
    let requests_path = dir.join("2026-05-22.db");
    let sessions_path = dir.join("sessions.db");
    crate::requests::open_day_db(&requests_path).unwrap();
    let conn = Connection::open(&requests_path).unwrap();
    let root_headers = json!({
      "Content-Encoding": "zstd",
      "thread-id": "thread-root"
    });
    let child_headers = json!({
      "Content-Encoding": "zstd",
      "thread-id": "thread-child",
      "x-codex-parent-thread-id": "thread-root"
    });

    insert_request_row_with_headers(
      &conn,
      100,
      "req-root-1",
      "sess-1",
      &json!({"input": [{"role": "developer", "content": "root"}]}),
      &root_headers,
      "",
    );
    insert_request_row_with_headers(
      &conn,
      110,
      "req-child-1",
      "sess-1",
      &json!({"input": [{"role": "developer", "content": "child"}]}),
      &child_headers,
      "",
    );
    insert_request_row_with_headers(
      &conn,
      120,
      "req-root-2",
      "sess-1",
      &json!({
        "input": [
          {"role": "developer", "content": "root"},
          {"role": "assistant", "content": "root result"}
        ]
      }),
      &root_headers,
      "",
    );
    insert_request_row_with_headers(
      &conn,
      130,
      "req-child-2",
      "sess-1",
      &json!({
        "input": [
          {"role": "developer", "content": "child"},
          {"role": "assistant", "content": "child result"}
        ]
      }),
      &child_headers,
      "",
    );

    let report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(report.rows_recorded, 4);
    assert_eq!(report.reduction_mismatches, 0);

    let sessions = Connection::open(&sessions_path).unwrap();
    let continuations = sessions
      .prepare(
        "SELECT request_id, parent_id, reduction_kind, common_prefix_messages, request_message_count
         FROM session_nodes WHERE request_id IN ('req-root-2', 'req-child-2') ORDER BY request_id",
      )
      .unwrap()
      .query_map([], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, Option<String>>(1)?,
          r.get::<_, String>(2)?,
          r.get::<_, i64>(3)?,
          r.get::<_, i64>(4)?,
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(
      continuations,
      vec![
        ("req-child-2".into(), None, "message_tree".into(), 1, 1,),
        ("req-root-2".into(), None, "message_tree".into(), 1, 1,),
      ]
    );
    let child_parent: String = sessions
      .query_row(
        "SELECT parent_thread_id FROM session_threads
         WHERE session_id = 'sess-1' AND thread_id = 'thread-child'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(child_parent, "thread-root");
  }

  #[test]
  fn session_views_expose_current_head_and_message_parts() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    db.record_tree(&TreeRequestRecord {
      ts: 100,
      session_id: "sess-1".into(),
      thread_id: None,
      parent_thread_id: None,
      parent_session_id: None,
      request_id: "req-1".into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: Some("acct".into()),
      provider_id: Some("prov".into()),
      model: Some("model".into()),
      request_messages: vec![msg("user", "hello")],
      response_messages: vec![msg("assistant", "hi")],
    })
    .unwrap();

    let current = db
      .conn
      .query_row(
        "SELECT session_id, head_request_id, head_endpoint, head_status, account_id, provider_id, model,
                head_reduction_kind, head_request_message_count, head_response_message_count
         FROM session_current",
        [],
        |r| {
          Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, i64>(8)?,
            r.get::<_, i64>(9)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(
      current,
      (
        "sess-1".into(),
        "req-1".into(),
        "responses".into(),
        200,
        "acct".into(),
        "prov".into(),
        "model".into(),
        "message_tree".into(),
        1,
        1,
      )
    );
    let head_storage: (String, i64, i64) = db
      .conn
      .query_row(
        "SELECT head_message_id, head_input_message_count, head_output_message_count FROM session_current",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
      )
      .unwrap();
    let head_message_id = head_storage.0;
    assert_eq!(head_message_id.len(), 64);
    assert_eq!((head_storage.1, head_storage.2), (1, 1));

    let messages = db
      .conn
      .prepare(
        "SELECT session_id, node_id, request_id, is_head, side, message_seq, role, part_index, part_type, content
         FROM session_messages
         ORDER BY node_ts, side, message_seq, part_index",
      )
      .unwrap()
      .query_map([], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, String>(1)?,
          r.get::<_, String>(2)?,
          r.get::<_, bool>(3)?,
          r.get::<_, String>(4)?,
          r.get::<_, i64>(5)?,
          r.get::<_, String>(6)?,
          r.get::<_, i64>(7)?,
          r.get::<_, String>(8)?,
          String::from_utf8(r.get::<_, Vec<u8>>(9)?).unwrap(),
        ))
      })
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(
      messages,
      vec![
        (
          "sess-1".into(),
          "req-1".into(),
          "req-1".into(),
          true,
          "request".into(),
          0,
          "user".into(),
          0,
          "text".into(),
          "hello".into(),
        ),
        (
          "sess-1".into(),
          "req-1".into(),
          "req-1".into(),
          true,
          "response".into(),
          0,
          "assistant".into(),
          0,
          "text".into(),
          "hi".into(),
        ),
      ]
    );
  }

  #[test]
  fn session_messages_view_keeps_messages_without_parts() {
    let dir = tempdir();
    let path = dir.join("sessions.db");
    let mut db = SessionsDb::open(&path).unwrap();
    db.record_tree(&TreeRequestRecord {
      ts: 100,
      session_id: "sess-empty".into(),
      thread_id: None,
      parent_thread_id: None,
      parent_session_id: None,
      request_id: "req-empty".into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: None,
      provider_id: None,
      model: None,
      request_messages: vec![MessageRecord {
        role: "user".into(),
        status: None,
        parts: Vec::new(),
      }],
      response_messages: Vec::new(),
    })
    .unwrap();

    let row = db
      .conn
      .query_row(
        "SELECT side, message_seq, role, part_index, part_hash, part_type, content
         FROM session_messages
         WHERE node_id = 'req-empty'",
        [],
        |row| {
          Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<Vec<u8>>>(6)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(row, ("request".into(), 0, "user".into(), None, None, None, None));
  }

  #[test]
  fn playback_requests_dir_sorts_files_and_verifies_latest_across_all_days() {
    let dir = tempdir();
    let requests_dir = dir.join("requests");
    std::fs::create_dir_all(&requests_dir).unwrap();
    let first_day = requests_dir.join("2026-05-21.db");
    let second_day = requests_dir.join("2026-05-22.db");
    std::fs::write(requests_dir.join("2026-05-23.db.bak"), b"not sqlite").unwrap();
    crate::requests::open_day_db(&second_day).unwrap();
    crate::requests::open_day_db(&first_day).unwrap();
    let first_conn = Connection::open(&first_day).unwrap();
    let second_conn = Connection::open(&second_day).unwrap();
    insert_request_row(
      &second_conn,
      200,
      "req-new",
      "sess-1",
      &json!({
        "input": [
          {"role": "user", "content": [{"type": "input_text", "text": "hello"}]},
          {"role": "assistant", "content": [{"type": "output_text", "text": "old"}]},
          {"role": "user", "content": [{"type": "input_text", "text": "new"}]}
        ]
      }),
      sse_completed("new"),
    );
    insert_request_row(
      &first_conn,
      100,
      "req-old",
      "sess-1",
      &json!({
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}]
      }),
      sse_completed("old"),
    );

    let sessions_path = dir.join("sessions.db");
    let report = playback_requests_source_into_sessions(
      PlaybackSource::Dir(requests_dir),
      &sessions_path,
      PlaybackOptions::default(),
    )
    .unwrap();
    assert_eq!(report.rows_seen, 2);
    assert_eq!(report.rows_recorded, 2);
    assert!(report.latest_mismatches.is_empty());

    let sessions = Connection::open(&sessions_path).unwrap();
    let head: String = sessions
      .query_row(
        "SELECT n.request_id FROM session_heads h JOIN session_nodes n ON n.id = h.node_id WHERE h.session_id = 'sess-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(head, "req-new");
    let parent: Option<String> = sessions
      .query_row(
        "SELECT parent_id FROM session_nodes WHERE request_id = 'req-new'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(parent, None);
  }

  #[test]
  fn playback_requests_accepts_legacy_requests_table_without_idx() {
    let dir = tempdir();
    let requests_path = dir.join("legacy.db");
    let sessions_path = dir.join("sessions.db");
    let conn = Connection::open(&requests_path).unwrap();
    create_legacy_requests_table(&conn);
    insert_legacy_request_row(
      &conn,
      100,
      "req-1",
      "sess-1",
      &json!({
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}]
      }),
      sse_completed("old"),
    );

    let report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(report.rows_seen, 1);
    assert_eq!(report.rows_recorded, 1);
    assert!(report.latest_mismatches.is_empty());

    let sessions = Connection::open(&sessions_path).unwrap();
    let head: String = sessions
      .query_row(
        "SELECT n.request_id FROM session_heads h JOIN session_nodes n ON n.id = h.node_id WHERE h.session_id = 'sess-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(head, "req-1");
    let node_ts: i64 = sessions
      .query_row("SELECT ts FROM session_nodes WHERE request_id = 'req-1'", [], |r| {
        r.get(0)
      })
      .unwrap();
    assert_eq!(node_ts, 100_000);
  }

  #[test]
  fn playback_requests_accepts_raw_json_when_encoding_header_is_stale() {
    let dir = tempdir();
    let requests_path = dir.join("2026-05-22.db");
    let sessions_path = dir.join("sessions.db");
    crate::requests::open_day_db(&requests_path).unwrap();
    let conn = Connection::open(&requests_path).unwrap();
    insert_request_row_with_raw_body(
      &conn,
      100,
      "req-1",
      "sess-1",
      &json!({
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}]
      }),
      sse_completed("ok"),
    );

    let report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(report.rows_seen, 1);
    assert_eq!(report.rows_recorded, 1);
    assert_eq!(report.decode_errors, 0);
    assert!(report.latest_mismatches.is_empty());
  }

  #[test]
  fn playback_requests_rejects_missing_request_body_with_encoded_header() {
    let dir = tempdir();
    let requests_path = dir.join("2026-05-22.db");
    let sessions_path = dir.join("sessions.db");
    crate::requests::open_day_db(&requests_path).unwrap();
    let conn = Connection::open(&requests_path).unwrap();
    insert_request_row_with_missing_encoded_body(&conn, 100, "req-1", "sess-1", sse_completed("ok"));

    let report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(report.rows_seen, 1);
    assert_eq!(report.rows_recorded, 0);
    assert_eq!(report.rows_skipped, 1);
    assert_eq!(report.decode_errors, 1);
    assert!(report.latest_mismatches.is_empty());

    let sessions = Connection::open(&sessions_path).unwrap();
    let node_count: i64 = sessions
      .query_row(
        "SELECT COUNT(*) FROM session_nodes WHERE request_id = 'req-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(node_count, 0);
  }

  #[test]
  fn playback_latest_head_ignores_rows_without_messages() {
    let dir = tempdir();
    let requests_path = dir.join("2026-05-22.db");
    let sessions_path = dir.join("sessions.db");
    crate::requests::open_day_db(&requests_path).unwrap();
    let conn = Connection::open(&requests_path).unwrap();
    insert_request_row(
      &conn,
      100,
      "req-recorded",
      "sess-1",
      &json!({
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}]
      }),
      sse_completed("ok"),
    );
    insert_request_row_with_empty_identity_body_and_status(&conn, 110, "req-empty", "sess-1", 400, "");

    let report = playback_requests_into_sessions(&requests_path, &sessions_path).unwrap();
    assert_eq!(report.rows_seen, 2);
    assert_eq!(report.rows_recorded, 1);
    assert_eq!(report.rows_skipped, 1);
    assert!(report.latest_mismatches.is_empty());

    let sessions = Connection::open(&sessions_path).unwrap();
    let head: String = sessions
      .query_row(
        "SELECT n.request_id FROM session_heads h JOIN session_nodes n ON n.id = h.node_id WHERE h.session_id = 'sess-1'",
        [],
        |r| r.get(0),
      )
      .unwrap();
    assert_eq!(head, "req-recorded");
  }

  fn assert_messages_eq(actual: &[MessageRecord], expected: &[MessageRecord]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
      assert_eq!(actual.role, expected.role);
      assert_eq!(actual.status, expected.status);
      assert_eq!(actual.parts.len(), expected.parts.len());
      for (actual, expected) in actual.parts.iter().zip(&expected.parts) {
        assert_eq!(actual.part_type, expected.part_type);
        assert_eq!(actual.content, expected.content);
      }
    }
  }

  fn msg(role: &str, text: &str) -> MessageRecord {
    MessageRecord {
      role: role.into(),
      status: None,
      parts: vec![PartRecord {
        part_type: "text".into(),
        content: Bytes::from(text.to_string()),
      }],
    }
  }

  fn thread_record(
    ts: i64,
    thread_id: &str,
    parent_thread_id: Option<&str>,
    request_id: &str,
    request_messages: Vec<MessageRecord>,
  ) -> TreeRequestRecord {
    TreeRequestRecord {
      ts,
      session_id: "sess-1".into(),
      thread_id: Some(thread_id.into()),
      parent_thread_id: parent_thread_id.map(str::to_string),
      parent_session_id: None,
      request_id: request_id.into(),
      endpoint: "responses".into(),
      status: Some(200),
      account_id: Some("acct".into()),
      provider_id: Some("prov".into()),
      model: Some("model".into()),
      request_messages,
      response_messages: Vec::new(),
    }
  }

  fn insert_request_row(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    body: &Value,
    response_body: impl AsRef<[u8]>,
  ) {
    insert_request_row_with_headers(
      conn,
      ts,
      request_id,
      session_id,
      body,
      &json!({
        "Content-Encoding": "zstd",
        "X-Parent-Session-Id": "parent-session"
      }),
      response_body,
    );
  }

  fn insert_request_row_with_headers(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    body: &Value,
    headers: &Value,
    response_body: impl AsRef<[u8]>,
  ) {
    let raw_body = serde_json::to_vec(body).unwrap();
    let encoded_body = zstd::stream::encode_all(raw_body.as_slice(), 0).unwrap();
    let headers = serde_json::to_vec(headers).unwrap();
    conn
      .execute(
        "INSERT INTO request_connection (request_id, ts, ver, endpoint, status)
         VALUES (?1, ?2, 'test', 'responses', 200)",
        params![request_id, ts],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_metadata (request_id, session_id, account_id, provider_id, model)
         VALUES (?1, ?2, 'acct', 'prov', 'model')",
        params![request_id, session_id],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_downstream (request_id, inbound_req_headers, inbound_req_body, inbound_resp_body)
         VALUES (?1, ?2, ?3, ?4)",
        params![request_id, headers, encoded_body, response_body.as_ref()],
      )
      .unwrap();
  }

  fn insert_request_row_with_missing_encoded_body(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    response_body: impl AsRef<[u8]>,
  ) {
    let headers = json!({
      "Content-Encoding": "zstd",
      "Content-Length": "81104"
    });
    insert_request_row_with_empty_body_and_status(conn, ts, request_id, session_id, 200, &headers, response_body);
  }

  fn insert_request_row_with_empty_identity_body_and_status(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    status: u16,
    response_body: impl AsRef<[u8]>,
  ) {
    insert_request_row_with_empty_body_and_status(conn, ts, request_id, session_id, status, &json!({}), response_body);
  }

  fn insert_request_row_with_empty_body_and_status(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    status: u16,
    headers: &Value,
    response_body: impl AsRef<[u8]>,
  ) {
    let headers = serde_json::to_vec(headers).unwrap();
    conn
      .execute(
        "INSERT INTO request_connection (request_id, ts, ver, endpoint, status)
         VALUES (?1, ?2, 'test', 'responses', ?3)",
        params![request_id, ts, status],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_metadata (request_id, session_id, account_id, provider_id, model)
         VALUES (?1, ?2, 'acct', 'prov', 'model')",
        params![request_id, session_id],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_downstream (request_id, inbound_req_headers, inbound_req_body, inbound_resp_body)
         VALUES (?1, ?2, X'', ?3)",
        params![request_id, headers, response_body.as_ref()],
      )
      .unwrap();
  }

  fn insert_request_row_with_raw_body(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    body: &Value,
    response_body: impl AsRef<[u8]>,
  ) {
    let raw_body = serde_json::to_vec(body).unwrap();
    let headers = serde_json::to_vec(&json!({ "Content-Encoding": "zstd" })).unwrap();
    conn
      .execute(
        "INSERT INTO request_connection (request_id, ts, ver, endpoint, status)
         VALUES (?1, ?2, 'test', 'responses', 200)",
        params![request_id, ts],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_metadata (request_id, session_id, account_id, provider_id, model)
         VALUES (?1, ?2, 'acct', 'prov', 'model')",
        params![request_id, session_id],
      )
      .unwrap();
    conn
      .execute(
        "INSERT INTO request_downstream (request_id, inbound_req_headers, inbound_req_body, inbound_resp_body)
         VALUES (?1, ?2, ?3, ?4)",
        params![request_id, headers, raw_body, response_body.as_ref()],
      )
      .unwrap();
  }

  fn create_legacy_requests_table(conn: &Connection) {
    conn
      .execute_batch(
        "CREATE TABLE requests (
          id INTEGER PRIMARY KEY,
          ts INTEGER NOT NULL,
          session_id TEXT,
          request_id TEXT,
          endpoint TEXT NOT NULL,
          account_id TEXT,
          provider_id TEXT,
          model TEXT,
          status INTEGER,
          inbound_req_headers BLOB,
          inbound_req_body BLOB,
          inbound_resp_body BLOB
        );",
      )
      .unwrap();
  }

  fn insert_legacy_request_row(
    conn: &Connection,
    ts: i64,
    request_id: &str,
    session_id: &str,
    body: &Value,
    response_body: impl AsRef<[u8]>,
  ) {
    let body = serde_json::to_vec(body).unwrap();
    let headers = serde_json::to_vec(&json!({})).unwrap();
    conn
      .execute(
        "INSERT INTO requests (
          ts, session_id, request_id, endpoint, account_id, provider_id, model, status,
          inbound_req_headers, inbound_req_body, inbound_resp_body
         )
         VALUES (?1, ?2, ?3, 'responses', 'acct', 'prov', 'model', 200, ?4, ?5, ?6)",
        params![ts, session_id, request_id, headers, body, response_body.as_ref()],
      )
      .unwrap();
  }

  fn sse_completed(text: &str) -> String {
    format!(
      "event: response.completed\ndata: {{\"response\":{{\"output\":[{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"{text}\"}}]}}]}}}}\n\n"
    )
  }

  fn tempdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("tokn-router-sessions-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&p).unwrap();
    p
  }
}
