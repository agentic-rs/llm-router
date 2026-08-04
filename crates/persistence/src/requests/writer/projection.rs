//! Independent safety projection from rich event captures to bounded DB blobs.

use super::RequestPersistenceOptions;
use bytes::Bytes;
use serde_json::{Map, Value};
use tokn_events::{BodyCapture, CaptureOmission};

pub(super) fn project_body(
  context: &mut Map<String, Value>,
  key: &str,
  capture: &BodyCapture,
  options: RequestPersistenceOptions,
) -> Option<Bytes> {
  match capture {
    BodyCapture::Absent => None,
    BodyCapture::Omitted { reason, bytes_seen } => {
      annotate_omitted(context, key, *reason, *bytes_seen);
      None
    }
    capture if !options.record_request_bodies => {
      annotate_omitted(context, key, CaptureOmission::Disabled, capture.bytes_seen());
      None
    }
    BodyCapture::Complete(bytes) => {
      if bytes.len() <= options.body_max_bytes {
        Some(bytes.clone())
      } else {
        let prefix = bytes.slice(..options.body_max_bytes);
        annotate_truncated(
          context,
          key,
          bytes.len() as u64,
          prefix.len(),
          options.body_max_bytes,
          "persistence",
        );
        Some(prefix)
      }
    }
    BodyCapture::Truncated { prefix, bytes_seen } => {
      let stored_len = prefix.len().min(options.body_max_bytes);
      let (limit, source) = if stored_len < prefix.len() {
        (options.body_max_bytes, "event_and_persistence")
      } else {
        (prefix.len(), "event")
      };
      annotate_truncated(context, key, *bytes_seen, stored_len, limit, source);
      Some(prefix.slice(..stored_len))
    }
    _ => {
      let mut detail = Map::new();
      insert_string(&mut detail, "state", "unknown");
      detail.insert("bytes_seen".to_string(), Value::from(capture.bytes_seen()));
      context.insert(key.to_string(), Value::Object(detail));
      None
    }
  }
}

/// Record event-side omission/truncation for captures that have no DB body
/// column (currently the decoded inbound observation).
pub(super) fn annotate_event_capture(context: &mut Map<String, Value>, key: &str, capture: &BodyCapture) {
  match capture {
    BodyCapture::Omitted { reason, bytes_seen } => annotate_omitted(context, key, *reason, *bytes_seen),
    BodyCapture::Truncated { prefix, bytes_seen } => {
      annotate_truncated(context, key, *bytes_seen, prefix.len(), prefix.len(), "event");
    }
    BodyCapture::Absent | BodyCapture::Complete(_) => {}
    _ => {
      let mut detail = Map::new();
      insert_string(&mut detail, "state", "unknown");
      detail.insert("bytes_seen".to_string(), Value::from(capture.bytes_seen()));
      context.insert(key.to_string(), Value::Object(detail));
    }
  }
}

fn annotate_omitted(context: &mut Map<String, Value>, key: &str, reason: CaptureOmission, bytes_seen: u64) {
  let mut detail = Map::new();
  insert_string(&mut detail, "state", "omitted");
  insert_string(&mut detail, "reason", omission_name(reason));
  detail.insert("bytes_seen".to_string(), Value::from(bytes_seen));
  context.insert(key.to_string(), Value::Object(detail));
}

fn annotate_truncated(
  context: &mut Map<String, Value>,
  key: &str,
  bytes_seen: u64,
  bytes_captured: usize,
  limit: usize,
  source: &str,
) {
  let mut detail = Map::new();
  insert_string(&mut detail, "state", "truncated");
  insert_string(&mut detail, "source", source);
  detail.insert("bytes_seen".to_string(), Value::from(bytes_seen));
  detail.insert("bytes_captured".to_string(), Value::from(bytes_captured as u64));
  detail.insert("limit_bytes".to_string(), Value::from(limit as u64));
  context.insert(key.to_string(), Value::Object(detail));
}

fn omission_name(reason: CaptureOmission) -> &'static str {
  match reason {
    CaptureOmission::Disabled => "disabled",
    CaptureOmission::Sensitive => "sensitive",
    CaptureOmission::Unavailable => "unavailable",
    _ => "unknown",
  }
}

fn insert_string(object: &mut Map<String, Value>, key: &str, value: &str) {
  object.insert(key.to_string(), Value::String(value.to_string()));
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn projection_disables_and_bounds_complete_captures() {
    let capture = BodyCapture::Complete(Bytes::from_static(b"abcdef"));
    let mut disabled_context = Map::new();
    let disabled = project_body(
      &mut disabled_context,
      "capture",
      &capture,
      RequestPersistenceOptions {
        record_request_bodies: false,
        body_max_bytes: usize::MAX,
      },
    );
    assert!(disabled.is_none());
    assert_eq!(disabled_context["capture"]["reason"], "disabled");

    let mut bounded_context = Map::new();
    let bounded = project_body(
      &mut bounded_context,
      "capture",
      &capture,
      RequestPersistenceOptions {
        record_request_bodies: true,
        body_max_bytes: 3,
      },
    );
    assert_eq!(bounded.as_deref(), Some(b"abc".as_slice()));
    assert_eq!(bounded_context["capture"]["state"], "truncated");
    assert_eq!(bounded_context["capture"]["bytes_seen"], 6);
    assert_eq!(bounded_context["capture"]["bytes_captured"], 3);
    assert_eq!(bounded_context["capture"]["source"], "persistence");
  }

  #[test]
  fn projection_preserves_event_omission_and_truncation_truth() {
    let mut sensitive_context = Map::new();
    let sensitive = project_body(
      &mut sensitive_context,
      "capture",
      &BodyCapture::Omitted {
        reason: CaptureOmission::Sensitive,
        bytes_seen: 7,
      },
      RequestPersistenceOptions {
        record_request_bodies: false,
        body_max_bytes: 2,
      },
    );
    assert!(sensitive.is_none());
    assert_eq!(sensitive_context["capture"]["reason"], "sensitive");

    let mut event_context = Map::new();
    let event_prefix = project_body(
      &mut event_context,
      "capture",
      &BodyCapture::Truncated {
        prefix: Bytes::from_static(b"abc"),
        bytes_seen: 9,
      },
      RequestPersistenceOptions {
        record_request_bodies: true,
        body_max_bytes: 8,
      },
    );
    assert_eq!(event_prefix.as_deref(), Some(b"abc".as_slice()));
    assert_eq!(event_context["capture"]["limit_bytes"], 3);
    assert_eq!(event_context["capture"]["source"], "event");
  }
}
