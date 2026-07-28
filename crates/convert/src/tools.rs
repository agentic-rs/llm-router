//! Cross-API tool definition normalisation.
//!
//! The three OpenAI-shape APIs (Chat Completions, Responses, Anthropic
//! Messages) each ship the *same* function-calling concept in three subtly
//! different envelopes:
//!
//! - **Chat Completions**: `{ "type": "function", "function": { "name", "description", "parameters", "strict"? } }`
//! - **Responses**:        `{ "type": "function", "name", "description", "parameters", "strict"? }`
//! - **Anthropic Messages**: `{ "name", "description", "input_schema" }`
//!
//! When tokn-router translates a request between endpoints (e.g. a client hits
//! `/v1/responses` but the selected account only supports
//! `/chat/completions`), tool entries that pass through unchanged confuse the
//! upstream and produce errors like
//! `"Invalid 'tools[0].function.name': empty string"`.
//!
//! This module canonicalises tool entries to the **chat shape** inside the IR
//! (`{type:"function", function:{...}}`) and provides converters back to the
//! Responses and Messages shapes. Non-function tool entries (e.g.
//! `{"type":"web_search"}` and friends) are passed through unchanged so we do
//! not silently drop provider-specific surfaces we don't understand.

use serde_json::{json, Map, Value};

/// Normalise a tool definition into the canonical chat-shape used inside the
/// IR. Inputs may be in chat, responses, or messages shape; unknown shapes
/// are returned untouched.
pub fn normalise_tool(value: &Value) -> Value {
  let Some(obj) = value.as_object() else {
    return value.clone();
  };

  // Already chat-shape.
  if obj.get("function").and_then(Value::as_object).is_some() {
    return value.clone();
  }

  // Responses-shape: `{type:"function", name, description?, parameters?, strict?}`.
  if obj.get("type").and_then(Value::as_str) == Some("function") && obj.contains_key("name") {
    return wrap_function(obj);
  }

  // Anthropic Messages-shape: `{name, description?, input_schema}`.
  if obj.contains_key("input_schema") && obj.contains_key("name") {
    let mut inner = Map::new();
    insert_str(&mut inner, "name", obj.get("name"));
    insert_str(&mut inner, "description", obj.get("description"));
    if let Some(schema) = obj.get("input_schema") {
      inner.insert("parameters".into(), schema.clone());
    }
    return json!({ "type": "function", "function": Value::Object(inner) });
  }

  // Bare-name function definition (some clients send
  // `{name, description?, parameters?}` with no envelope at all).
  if obj.contains_key("name") && (obj.contains_key("parameters") || obj.contains_key("description")) {
    return wrap_function(obj);
  }

  value.clone()
}

fn wrap_function(obj: &Map<String, Value>) -> Value {
  let mut inner = Map::new();
  insert_str(&mut inner, "name", obj.get("name"));
  insert_str(&mut inner, "description", obj.get("description"));
  if let Some(params) = obj.get("parameters") {
    inner.insert("parameters".into(), params.clone());
  }
  if let Some(strict) = obj.get("strict") {
    inner.insert("strict".into(), strict.clone());
  }
  json!({ "type": "function", "function": Value::Object(inner) })
}

fn insert_str(out: &mut Map<String, Value>, key: &str, src: Option<&Value>) {
  if let Some(s) = src.and_then(Value::as_str) {
    out.insert(key.into(), Value::String(s.to_string()));
  }
}

/// Normalise every entry in a tools array. Returns an empty Vec for empty input.
pub fn normalise_tools(tools: &[Value]) -> Vec<Value> {
  tools.iter().map(normalise_tool).collect()
}

/// Normalize a tool choice to the Chat Completions representation used by the
/// IR: string modes or `{type:"function", function:{name}}`.
pub fn normalise_tool_choice(value: &Value) -> Value {
  if let Some(mode) = value.as_str() {
    return Value::String(mode.to_string());
  }
  let Some(object) = value.as_object() else {
    return value.clone();
  };
  match object.get("type").and_then(Value::as_str) {
    Some("auto") if has_only_keys(object, &["type"]) => Value::String("auto".into()),
    Some("none") if has_only_keys(object, &["type"]) => Value::String("none".into()),
    Some("any" | "required") if has_only_keys(object, &["type"]) => Value::String("required".into()),
    Some("tool") if has_only_keys(object, &["type", "name"]) => object
      .get("name")
      .and_then(Value::as_str)
      .map(named_tool_choice)
      .unwrap_or_else(|| value.clone()),
    Some("function") => {
      if object.get("function").and_then(Value::as_object).is_some() {
        value.clone()
      } else if has_only_keys(object, &["type", "name"]) {
        object
          .get("name")
          .and_then(Value::as_str)
          .map(named_tool_choice)
          .unwrap_or_else(|| value.clone())
      } else {
        value.clone()
      }
    }
    _ => value.clone(),
  }
}

fn has_only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
  object.keys().all(|key| allowed.contains(&key.as_str()))
}

fn named_tool_choice(name: &str) -> Value {
  json!({"type": "function", "function": {"name": name}})
}

fn named_tool_choice_name(value: &Value) -> Option<&str> {
  value
    .get("function")
    .and_then(Value::as_object)
    .and_then(|function| function.get("name"))
    .and_then(Value::as_str)
}

pub fn tool_choice_to_chat(value: &Value) -> Value {
  normalise_tool_choice(value)
}

pub fn tool_choice_to_responses(value: &Value) -> Value {
  let choice = normalise_tool_choice(value);
  named_tool_choice_name(&choice)
    .map(|name| json!({"type": "function", "name": name}))
    .unwrap_or(choice)
}

pub fn tool_choice_to_messages(value: &Value) -> Value {
  let choice = normalise_tool_choice(value);
  if let Some(name) = named_tool_choice_name(&choice) {
    return json!({"type": "tool", "name": name});
  }
  match choice.as_str() {
    Some("auto") => json!({"type": "auto"}),
    Some("none") => json!({"type": "none"}),
    Some("required") => json!({"type": "any"}),
    _ => choice,
  }
}

/// Convert a canonical (chat-shape) tool entry to Responses shape:
/// `{type:"function", name, description?, parameters?, strict?}`. Non-function
/// entries are returned untouched.
pub fn tool_to_responses(value: &Value) -> Value {
  let Some(obj) = value.as_object() else {
    return value.clone();
  };
  let Some(func) = obj.get("function").and_then(Value::as_object) else {
    return value.clone();
  };
  let mut out = Map::new();
  out.insert("type".into(), Value::String("function".into()));
  insert_str(&mut out, "name", func.get("name"));
  insert_str(&mut out, "description", func.get("description"));
  if let Some(params) = func.get("parameters") {
    out.insert("parameters".into(), params.clone());
  }
  if let Some(strict) = func.get("strict") {
    out.insert("strict".into(), strict.clone());
  }
  Value::Object(out)
}

/// Convert a canonical (chat-shape) tool entry to Anthropic Messages shape:
/// `{name, description?, input_schema}`. Non-function entries are returned
/// untouched.
pub fn tool_to_messages(value: &Value) -> Value {
  let Some(obj) = value.as_object() else {
    return value.clone();
  };
  let Some(func) = obj.get("function").and_then(Value::as_object) else {
    return value.clone();
  };
  let mut out = Map::new();
  insert_str(&mut out, "name", func.get("name"));
  insert_str(&mut out, "description", func.get("description"));
  let schema = func
    .get("parameters")
    .cloned()
    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
  out.insert("input_schema".into(), schema);
  Value::Object(out)
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn responses_shape_is_normalised_to_chat() {
    let input = json!({
      "type": "function",
      "name": "exec_command",
      "description": "Run a command.",
      "parameters": { "type": "object", "properties": {} },
      "strict": false,
    });
    let n = normalise_tool(&input);
    assert_eq!(n["type"], "function");
    assert_eq!(n["function"]["name"], "exec_command");
    assert_eq!(n["function"]["description"], "Run a command.");
    assert_eq!(n["function"]["strict"], false);
    assert!(n["function"]["parameters"].is_object());
  }

  #[test]
  fn chat_shape_is_left_untouched() {
    let input = json!({
      "type": "function",
      "function": { "name": "foo", "description": "bar", "parameters": {} },
    });
    assert_eq!(normalise_tool(&input), input);
  }

  #[test]
  fn messages_shape_is_normalised_to_chat() {
    let input = json!({
      "name": "search",
      "description": "Search the web.",
      "input_schema": { "type": "object" },
    });
    let n = normalise_tool(&input);
    assert_eq!(n["function"]["name"], "search");
    assert_eq!(n["function"]["parameters"], json!({"type": "object"}));
  }

  #[test]
  fn unknown_shape_passes_through() {
    let input = json!({ "type": "web_search", "max_results": 5 });
    assert_eq!(normalise_tool(&input), input);
  }

  #[test]
  fn chat_to_responses_drops_function_envelope() {
    let chat = json!({
      "type": "function",
      "function": { "name": "foo", "description": "bar", "parameters": { "type": "object" } },
    });
    let resp = tool_to_responses(&chat);
    assert_eq!(resp["type"], "function");
    assert_eq!(resp["name"], "foo");
    assert_eq!(resp["description"], "bar");
    assert_eq!(resp["parameters"], json!({ "type": "object" }));
  }

  #[test]
  fn chat_to_messages_uses_input_schema() {
    let chat = json!({
      "type": "function",
      "function": { "name": "foo", "parameters": { "type": "object" } },
    });
    let m = tool_to_messages(&chat);
    assert_eq!(m["name"], "foo");
    assert_eq!(m["input_schema"], json!({ "type": "object" }));
    assert!(m.get("type").is_none());
  }

  #[test]
  fn tool_choice_round_trips_across_dialects() {
    let canonical = normalise_tool_choice(&json!({"type": "tool", "name": "lookup"}));
    assert_eq!(canonical, json!({"type": "function", "function": {"name": "lookup"}}));
    assert_eq!(
      tool_choice_to_responses(&canonical),
      json!({"type": "function", "name": "lookup"})
    );
    assert_eq!(
      tool_choice_to_messages(&canonical),
      json!({"type": "tool", "name": "lookup"})
    );
    assert_eq!(tool_choice_to_messages(&json!("required")), json!({"type": "any"}));
  }

  #[test]
  fn tool_choice_normalization_preserves_extension_fields() {
    for choice in [
      json!({"type": "auto", "disable_parallel_tool_use": true}),
      json!({"type": "tool", "name": "lookup", "provider_extension": "keep"}),
      json!({"type": "function", "name": "lookup", "provider_extension": "keep"}),
    ] {
      assert_eq!(normalise_tool_choice(&choice), choice);
    }
  }
}
