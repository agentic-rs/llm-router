//! Presentation-only compaction of the validated migration projection.
//!
//! Keep the raw schema's serializer unchanged: expanded output and other
//! callers still need the full representation. Resource identities and rule
//! order are never changed here, including resources with all-default fields.

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use tokn_config::v2::{
  RawAccountPool, RawConfig, RawCors, RawListener, RawProvider, RawRoute, RawRouteRetry, RawService, RawWireIdentity,
  DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES,
};
use toml_edit::visit_mut::{self, VisitMut};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

const INLINE_WIDTH: usize = 120;

pub(super) fn render(raw: &RawConfig, expanded: bool) -> Result<String> {
  let source = toml::to_string_pretty(raw).context("render generated version 2 config")?;
  let mut document: DocumentMut = source.parse().context("parse generated config for rendering")?;
  if !expanded {
    compact(&mut document, raw)?;
  }
  TwoSpaceArrayIndent.visit_document_mut(&mut document);

  let rendered = document.to_string();
  let decoded: RawConfig = toml::from_str(&rendered).context("decode rendered migration output")?;
  ensure!(
    decoded == *raw,
    "rendered migration output changed projected config settings"
  );
  Ok(rendered)
}

fn compact(document: &mut DocumentMut, raw: &RawConfig) -> Result<()> {
  omit_defaults(table_at(document, &["service"])?, &raw.service, &RawService::default())?;

  for (id, listener) in &raw.listeners {
    let table = table_at(document, &["listeners", id])?;
    match listener {
      RawListener::LlmApi {
        cors,
        allow_insecure_public,
        ..
      } => {
        if !allow_insecure_public {
          table.remove("allow_insecure_public");
        }
        let cors_table = table
          .get_mut("cors")
          .and_then(Item::as_table_mut)
          .context("generated API listener has no CORS table")?;
        omit_defaults(cors_table, cors, &RawCors::default())?;
        if cors_table.is_empty() {
          table.remove("cors");
        }
      }
      RawListener::ForwardProxy {
        allow_insecure_public,
        request_body_max_bytes,
        ..
      } => {
        if !allow_insecure_public {
          table.remove("allow_insecure_public");
        }
        if *request_body_max_bytes == DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES {
          table.remove("request_body_max_bytes");
        }
      }
    }
    inline_small_fields(table, &["default_http_action"]);
  }

  for (id, profile) in &raw.profiles {
    let table = table_at(document, &["profiles", id])?;
    if profile.wire_identity == RawWireIdentity::default() {
      table.remove("wire_identity");
    }
    if let Some(pool) = &profile.account_pool {
      let pool_table = table
        .get_mut("account_pool")
        .and_then(Item::as_table_mut)
        .context("generated profile has no account-pool table")?;
      omit_defaults(pool_table, pool, &RawAccountPool::default())?;
    }
    inline_small_fields(table, &["wire_identity", "account_pool", "binding"]);
  }
  for (id, route) in &raw.routes {
    let table = table_at(document, &["routes", id])?;
    let (RawRoute::Managed { retry, .. } | RawRoute::Relay { retry, .. }) = route;
    if retry == &RawRouteRetry::default() {
      table.remove("retry");
    }
    inline_small_fields(table, &["provider", "model", "destination", "credentials", "retry"]);
  }

  // RawProvider has no Default impl. Decode its serde defaults rather than
  // copying provider flags into the presentation layer.
  let provider_defaults: RawProvider = toml::from_str("").context("read provider schema defaults")?;
  for (id, provider) in &raw.providers {
    omit_defaults(table_at(document, &["providers", id])?, provider, &provider_defaults)?;
  }

  for (section, matchers) in [
    ("bindings", &["hosts", "path_prefixes", "methods", "operations"][..]),
    ("connect_rules", &["hosts", "ports"][..]),
  ] {
    if let Some(rules) = document.get_mut(section).and_then(Item::as_array_of_tables_mut) {
      for rule in rules.iter_mut() {
        for field in matchers {
          if rule
            .get(field)
            .and_then(Item::as_array)
            .is_some_and(|array| array.is_empty())
          {
            rule.remove(field);
          }
        }
        inline_small_fields(rule, &["action"]);
      }
    }
  }

  // Only prune empty top-level containers. An empty named pool/provider is
  // still a declaration and must survive to preserve references and intent.
  document.as_table_mut().retain(|_, item| {
    !item.as_table().is_some_and(Table::is_empty) && !item.as_array().is_some_and(|array| array.is_empty())
  });
  Ok(())
}

struct TwoSpaceArrayIndent;

impl VisitMut for TwoSpaceArrayIndent {
  fn visit_array_mut(&mut self, array: &mut Array) {
    visit_mut::visit_array_mut(self, array);
    for value in array.iter_mut() {
      // Change syntax whitespace only. Replacing indentation in the rendered
      // text could corrupt multiline strings or other literal content.
      if value
        .decor()
        .prefix()
        .and_then(|prefix| prefix.as_str())
        .is_some_and(|prefix| prefix.contains('\n'))
      {
        value.decor_mut().set_prefix("\n  ");
      }
    }
  }
}

fn table_at<'a>(document: &'a mut DocumentMut, path: &[&str]) -> Result<&'a mut Table> {
  let mut table = document.as_table_mut();
  for segment in path {
    table = table
      .get_mut(segment)
      .and_then(Item::as_table_mut)
      .with_context(|| format!("generated config has no table at {}", path.join(".")))?;
  }
  Ok(table)
}

fn omit_defaults<T: Serialize>(table: &mut Table, actual: &T, defaults: &T) -> Result<()> {
  let actual = toml::Table::try_from(actual).context("serialize projected settings")?;
  let defaults = toml::Table::try_from(defaults).context("serialize schema defaults")?;
  omit_matching_fields(table, &actual, &defaults);
  Ok(())
}

fn omit_matching_fields(table: &mut Table, actual: &toml::Table, defaults: &toml::Table) {
  for (key, default) in defaults {
    let Some(value) = actual.get(key) else {
      continue;
    };
    if value == default {
      table.remove(key);
    } else if let (Some(child), Some(actual), Some(defaults)) = (
      table.get_mut(key).and_then(Item::as_table_mut),
      value.as_table(),
      default.as_table(),
    ) {
      omit_matching_fields(child, actual, defaults);
    }
  }
}

fn inline_small_fields(table: &mut Table, fields: &[&str]) {
  for field in fields {
    let Some(item) = table.get_mut(field) else {
      continue;
    };
    let Some(child) = item.as_table() else {
      continue;
    };
    // Keep family maps and other nested policies expanded for editing. Long
    // scalar policies also retain their readable multi-line representation.
    if !child.iter().all(|(_, value)| value.is_value()) {
      continue;
    }
    let inline = child.clone().into_inline_table();
    if field.len() + 3 + inline.to_string().chars().count() <= INLINE_WIDTH {
      *item = Item::Value(Value::InlineTable(inline));
      // A former table header's key has no value-assignment spacing.
      if let Some(mut key) = table.key_mut(field) {
        key.leaf_decor_mut().set_suffix(" ");
      }
    }
  }
}

#[cfg(test)]
mod tests;
