//! Folder-driven golden snapshot tests for chat → responses SSE translation.
//!
//! Each subdirectory of `tests/golden/chat_to_responses/` is a case:
//!
//! * `input.sse`    – raw chat-completions SSE captured from a provider
//! * `expected.sse` – expected Responses-API SSE (normalized)
//!
//! Run with `UPDATE_GOLDEN=1` to overwrite `expected.sse` with the current
//! (normalized) actual output. Useful for bootstrapping a new case.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tokn_convert::sse::{EndpointTranslator, EventTransformer, SseEvent};
use tokn_endpoint_core::Endpoint;

const CASES_DIR: &str = "tests/golden/chat_to_responses";

#[test]
fn chat_to_responses_golden_cases() {
  let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CASES_DIR);
  assert!(root.is_dir(), "golden cases dir missing: {}", root.display());

  let update = std::env::var("UPDATE_GOLDEN").map(|v| v == "1").unwrap_or(false);
  let mut failures = Vec::new();

  for entry in fs::read_dir(&root).expect("read golden dir") {
    let entry = entry.expect("dir entry");
    if !entry.file_type().expect("file type").is_dir() {
      continue;
    }
    let case_dir = entry.path();
    let case_name = case_dir.file_name().unwrap().to_string_lossy().to_string();

    if let Err(e) = run_case(&case_dir, update) {
      failures.push(format!("[{case_name}] {e}"));
    }
  }

  assert!(failures.is_empty(), "golden case failures:\n{}", failures.join("\n\n"));
}

fn run_case(dir: &Path, update: bool) -> Result<(), String> {
  let input_path = dir.join("input.sse");
  let expected_path = dir.join("expected.sse");

  let input_text = fs::read_to_string(&input_path).map_err(|e| format!("read input.sse: {e}"))?;
  let input_events = parse_sse_text(&input_text);

  let mut translator = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
  let mut produced: Vec<SseEvent> = Vec::new();
  for ev in input_events {
    let outs = translator.transform(ev).map_err(|e| format!("transform: {e}"))?;
    produced.extend(outs);
  }
  let finals = translator.finish().map_err(|e| format!("finish: {e}"))?;
  produced.extend(finals);

  let actual = normalize_sse(&serialize_sse(&produced));

  if update {
    fs::write(&expected_path, &actual).map_err(|e| format!("write expected.sse: {e}"))?;
    return Ok(());
  }

  let expected = fs::read_to_string(&expected_path)
    .map_err(|e| format!("read expected.sse: {e} (run with UPDATE_GOLDEN=1 to bootstrap)"))?;
  let expected = normalize_sse(&expected);

  if actual != expected {
    let diff = simple_diff(&expected, &actual);
    return Err(format!("expected.sse mismatch\n{diff}"));
  }
  Ok(())
}

/// Minimal SSE text parser: reads `event:` and `data:` lines, dispatches
/// on blank-line boundaries. Only supports a single `data:` line per event
/// (sufficient for our captures).
fn parse_sse_text(text: &str) -> Vec<SseEvent> {
  let mut out = Vec::new();
  let mut event: Option<String> = None;
  let mut data: Option<String> = None;

  for line in text.lines() {
    if line.is_empty() {
      if let Some(d) = data.take() {
        out.push(SseEvent::raw(event.take(), d));
      } else {
        event = None;
      }
      continue;
    }
    if let Some(rest) = line.strip_prefix("event:") {
      event = Some(rest.trim().to_string());
    } else if let Some(rest) = line.strip_prefix("data:") {
      let chunk = rest.strip_prefix(' ').unwrap_or(rest);
      data = Some(match data.take() {
        Some(prev) => format!("{prev}\n{chunk}"),
        None => chunk.to_string(),
      });
    }
  }
  if let Some(d) = data {
    out.push(SseEvent::raw(event, d));
  }
  out
}

fn serialize_sse(events: &[SseEvent]) -> String {
  let mut out = String::new();
  for ev in events {
    if let Some(name) = &ev.event {
      out.push_str("event: ");
      out.push_str(name);
      out.push('\n');
    }
    out.push_str("data: ");
    out.push_str(&ev.data);
    out.push_str("\n\n");
  }
  out
}

/// Normalise a Responses SSE stream so snapshot comparison is stable:
///
/// * pretty-print each `data:` JSON for readable diffs
/// * strip / replace volatile fields:
///   - `sequence_number`  → removed
///   - `created_at`       → 0
///   - `id` matching `^(msg|fc|rs|resp)_<digits>$` → `<id-kind-N>` per kind, deterministic counters
///   - `item_id` references rewritten consistently with the id table
fn normalize_sse(raw: &str) -> String {
  let parsed = parse_sse_text(raw);
  let mut id_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
  let mut counters: std::collections::HashMap<&'static str, usize> = std::collections::HashMap::new();
  let kind_for = |id: &str| -> Option<&'static str> {
    let prefix = id.split('_').next()?;
    match prefix {
      "msg" => Some("msg"),
      "fc" => Some("fc"),
      "rs" => Some("rs"),
      "resp" => Some("resp"),
      _ => None,
    }
  };

  let mut rewrite_id = |id: &str| -> String {
    if let Some(stable) = id_map.get(id) {
      return stable.clone();
    }
    let kind = match kind_for(id) {
      Some(k) => k,
      None => return id.to_string(),
    };
    let n = counters.entry(kind).or_insert(0);
    let stable = format!("<{kind}-{n}>");
    *n += 1;
    id_map.insert(id.to_string(), stable.clone());
    stable
  };

  let mut out = String::new();
  for ev in parsed {
    if let Some(name) = &ev.event {
      out.push_str("event: ");
      out.push_str(name);
      out.push('\n');
    }
    if ev.is_done() {
      out.push_str("data: [DONE]\n\n");
      continue;
    }
    let value: Value = match serde_json::from_str(&ev.data) {
      Ok(v) => v,
      Err(_) => {
        out.push_str("data: ");
        out.push_str(&ev.data);
        out.push_str("\n\n");
        continue;
      }
    };
    let mut value = value;
    walk_normalize(&mut value, &mut rewrite_id);
    let compact = serde_json::to_string(&value).unwrap();
    out.push_str("data: ");
    out.push_str(&compact);
    out.push_str("\n\n");
  }
  out
}

fn walk_normalize<F: FnMut(&str) -> String>(v: &mut Value, rewrite_id: &mut F) {
  match v {
    Value::Object(map) => {
      // strip volatile fields
      map.remove("sequence_number");
      for ts_key in ["created_at", "completed_at"] {
        if let Some(ts) = map.get_mut(ts_key) {
          *ts = Value::from(0);
        }
      }
      // rewrite known id-bearing fields
      for key in ["id", "item_id", "response_id"] {
        if let Some(Value::String(s)) = map.get_mut(key) {
          let new = rewrite_id(s);
          *s = new;
        }
      }
      for (_, val) in map.iter_mut() {
        walk_normalize(val, rewrite_id);
      }
    }
    Value::Array(arr) => {
      for item in arr {
        walk_normalize(item, rewrite_id);
      }
    }
    _ => {}
  }
}

fn simple_diff(expected: &str, actual: &str) -> String {
  let exp: Vec<&str> = expected.lines().collect();
  let act: Vec<&str> = actual.lines().collect();
  let n = exp.len().max(act.len());
  let mut out = String::new();
  for i in 0..n {
    let e = exp.get(i).copied().unwrap_or("<eof>");
    let a = act.get(i).copied().unwrap_or("<eof>");
    if e == a {
      continue;
    }
    out.push_str(&format!("L{:>4} expected: {}\n", i + 1, e));
    out.push_str(&format!("L{:>4}   actual: {}\n", i + 1, a));
    if out.lines().count() > 80 {
      out.push_str("... (diff truncated)\n");
      break;
    }
  }
  if out.is_empty() {
    out.push_str("(no per-line diff; whitespace only?)\n");
  }
  out
}
