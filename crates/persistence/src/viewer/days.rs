use rusqlite::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::macros::format_description;

use super::database::open_readonly_with_timeout;
use super::schema::RequestSchema;
use crate::Result;

const DAY_PROBE_BUSY_TIMEOUT: Duration = Duration::from_millis(100);

/// The availability of a request history database for one UTC day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestDayState {
  Available,
  Empty,
  Unavailable,
}

/// A request history day and the state of its backing database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestDay {
  pub day: String,
  pub state: RequestDayState,
}

#[derive(Debug, Clone)]
pub(super) struct DayFile {
  pub(super) day: String,
  pub(super) path: PathBuf,
}

/// Return whether `day` is a canonical UTC request-history day (`YYYY-MM-DD`).
pub fn is_valid_request_day(day: &str) -> bool {
  let bytes = day.as_bytes();
  if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
    return false;
  }
  if !bytes
    .iter()
    .enumerate()
    .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
  {
    return false;
  }
  time::Date::parse(day, format_description!("[year]-[month]-[day]")).is_ok()
}

/// List all request-day databases from newest to oldest with their availability.
pub fn list_request_days(requests_dir: &Path) -> Result<Vec<RequestDay>> {
  Ok(
    request_day_files(requests_dir)?
      .into_iter()
      .map(|day_file| RequestDay {
        state: probe_request_day_state_best_effort(&day_file),
        day: day_file.day,
      })
      .collect(),
  )
}

pub(super) fn request_day_files(requests_dir: &Path) -> Result<Vec<DayFile>> {
  if !requests_dir.exists() {
    return Ok(Vec::new());
  }

  let mut files = Vec::new();
  for entry in std::fs::read_dir(requests_dir)? {
    let entry = entry?;
    if !entry.file_type()?.is_file() {
      continue;
    }
    let path = entry.path();
    if path.extension().and_then(|value| value.to_str()) != Some("db") {
      continue;
    }
    let Some(day) = path.file_stem().and_then(|value| value.to_str()) else {
      continue;
    };
    if !is_valid_request_day(day) {
      continue;
    }
    files.push(DayFile {
      day: day.to_string(),
      path,
    });
  }
  files.sort_by(|left, right| right.day.cmp(&left.day));
  Ok(files)
}

/// Convert a Unix timestamp in seconds or milliseconds to a UTC request day.
pub(super) fn request_day_from_timestamp(timestamp: i64) -> String {
  let timestamp_seconds = if timestamp > 10_000_000_000 {
    timestamp / 1_000
  } else {
    timestamp
  };
  time::OffsetDateTime::from_unix_timestamp(timestamp_seconds)
    .ok()
    .and_then(|datetime| datetime.date().format(format_description!("[year]-[month]-[day]")).ok())
    .unwrap_or_else(|| "1970-01-01".to_string())
}

fn probe_request_day_state_best_effort(day_file: &DayFile) -> RequestDayState {
  let result = (|| -> Result<RequestDayState> {
    let Some(conn) = open_readonly_with_timeout(&day_file.path, DAY_PROBE_BUSY_TIMEOUT)? else {
      tracing::warn!(
        path = %day_file.path.display(),
        "request history database disappeared while checking its availability"
      );
      return Ok(RequestDayState::Unavailable);
    };
    let state = if day_has_requests(&conn)? {
      RequestDayState::Available
    } else {
      RequestDayState::Empty
    };
    Ok(state)
  })();

  match result {
    Ok(state) => state,
    Err(error) => {
      tracing::warn!(
        path = %day_file.path.display(),
        error = %error,
        "marking request history database unavailable after read failure"
      );
      RequestDayState::Unavailable
    }
  }
}

fn day_has_requests(conn: &Connection) -> Result<bool> {
  let sql = if RequestSchema::read(conn)?.is_split() {
    "SELECT EXISTS(SELECT 1 FROM request_connection)"
  } else {
    "SELECT EXISTS(SELECT 1 FROM requests)"
  };
  let has_requests = conn.query_row(sql, [], |row| row.get::<_, i64>(0))?;
  Ok(has_requests != 0)
}

#[cfg(test)]
mod tests {
  use super::request_day_from_timestamp;

  #[test]
  fn request_day_conversion_accepts_seconds_and_milliseconds() {
    assert_eq!(request_day_from_timestamp(0), "1970-01-01");
    assert_eq!(request_day_from_timestamp(1_767_225_600), "2026-01-01");
    assert_eq!(request_day_from_timestamp(1_767_225_600_000), "2026-01-01");
    assert_eq!(request_day_from_timestamp(i64::MAX), "1970-01-01");
  }
}
