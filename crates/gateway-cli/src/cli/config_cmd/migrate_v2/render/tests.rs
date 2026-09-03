use super::*;
use std::collections::BTreeMap;
use std::path::Path;
use tokn_config::v2::{self, RawModelSelector, RawProviderSelector};
use tokn_config::{Config, ModelFamily, ProfileConfig, RouteMode};
use tokn_core::account::AccountConfig;
use tokn_router_legacy_config::v2::{project_v2_config, V2ForwardProxyProjectionOptions, V2ProjectionOptions};

fn source_path() -> &'static Path {
  Path::new("migration-test/config.toml")
}

fn native_config() -> RawConfig {
  v2::decode(crate::cli::config_cmd::V2_EXPLICIT_TEST_CONFIG, source_path()).unwrap()
}

fn account() -> AccountConfig {
  toml::from_str("id = 'primary'\nprovider = 'openai'\napi_key = 'not-a-real-secret'\nenabled = true").unwrap()
}

fn assert_equivalent(raw: &RawConfig) -> (String, String) {
  let compact = render(raw, false).unwrap();
  let expanded = render(raw, true).unwrap();
  // Expanded output keeps every serialized field, including defaults.
  assert_eq!(
    toml::from_str::<toml::Value>(&expanded).unwrap(),
    toml::Value::try_from(raw).unwrap()
  );
  assert_eq!(v2::decode(&compact, source_path()).unwrap(), *raw);
  assert_eq!(v2::decode(&expanded, source_path()).unwrap(), *raw);
  let expected = v2::compile_config(raw, source_path()).unwrap();
  assert_eq!(v2::parse_config(&compact, source_path()).unwrap(), expected);
  assert_eq!(v2::parse_config(&expanded, source_path()).unwrap(), expected);
  assert_eq!(
    render(&v2::decode(&compact, source_path()).unwrap(), false).unwrap(),
    compact
  );
  (compact, expanded)
}

#[test]
fn default_migration_is_compact_and_retains_an_empty_named_pool() {
  let projection = project_v2_config(&Config::default(), &[account()], V2ProjectionOptions::default()).unwrap();
  let (compact, expanded) = assert_equivalent(projection.raw_config());
  assert_eq!(compact, include_str!("fixtures/default.toml").replace("\r\n", "\n"));
  assert!(compact.lines().count() < expanded.lines().count() / 2);
  assert!(!compact.contains("[service"));
  assert!(!compact.contains("hosts = []"));
  assert!(!compact.contains("connect_rules = []"));
  assert!(!compact.contains("session_ttl_secs"));
  assert!(!compact.contains("wire_identity"));
  assert!(compact.contains("[account_pools.default]"));
  assert!(
    compact.contains("default_http_action = { kind = \"reject\" }"),
    "{compact}"
  );
  assert!(compact.contains("action = { kind = \"route\", profile = \"default\" }"));
  assert!(compact.contains("provider = { kind = \"any\" }"));
  assert!(compact.contains("model = { kind = \"capability\" }"));
  assert!(compact.contains("retry = { kind = \"recoverable\", policy = \"legacy-recoverable\" }"));
  assert!(!compact.contains("not-a-real-secret"));
}

#[test]
fn multiline_arrays_use_two_spaces_in_both_output_modes() {
  let mut raw = native_config();
  raw.service.outbound =
    toml::from_str("proxy_url = 'http://127.0.0.1:7890'\nno_proxy = ['localhost', 'example.com']").unwrap();
  raw.bindings.push(
    toml::from_str(
      r#"
id = "multi-host"
listener = "api"
hosts = ["api.example.com", "other.example.com"]
action = { kind = "route", profile = "default" }
"#,
    )
    .unwrap(),
  );
  let RawRoute::Managed { model, .. } = raw.routes.get_mut("default").unwrap() else {
    panic!("managed route");
  };
  *model = RawModelSelector::Family {
    families: BTreeMap::from([("coding".into(), vec!["gpt-5".into(), "gpt-5-mini".into()])]),
  };

  let (compact, expanded) = assert_equivalent(&raw);
  for output in [&compact, &expanded] {
    for expected in [
      "no_proxy = [\n  \"localhost\",\n  \"example.com\",\n]",
      "hosts = [\n  \"api.example.com\",\n  \"other.example.com\",\n]",
      "coding = [\n  \"gpt-5\",\n  \"gpt-5-mini\",\n]",
      "accounts = [\"*\"]",
      "[listeners.api]\nkind = \"llm_api\"",
    ] {
      assert!(output.contains(expected), "missing {expected:?} in {output}");
    }
    assert!(!output.lines().any(|line| line.starts_with("    ")));
  }
  assert!(expanded.contains("allowed_origins = []"));
}

#[test]
fn array_indentation_preserves_string_contents_and_inline_values() {
  let source = r#"single = ["some"]
empty = []
inline = { values = ["some", "another"] }
multiline = [
    "    leading spaces",
    '''first
    second''',
]
"#;
  let expected = r#"single = ["some"]
empty = []
inline = { values = ["some", "another"] }
multiline = [
  "    leading spaces",
  '''first
    second''',
]
"#;
  let mut document: DocumentMut = source.parse().unwrap();
  TwoSpaceArrayIndent.visit_document_mut(&mut document);
  assert_eq!(document.to_string(), expected);
  assert_eq!(
    toml::from_str::<toml::Value>(&document.to_string()).unwrap(),
    toml::from_str::<toml::Value>(source).unwrap()
  );
}

#[test]
fn expanded_output_is_unchanged_without_multiline_arrays() {
  let raw = native_config();
  assert_eq!(render(&raw, true).unwrap(), toml::to_string_pretty(&raw).unwrap());
}

#[test]
fn all_default_service_and_provider_fields_can_be_omitted_without_removing_resources() {
  let mut raw = native_config();
  raw.providers.insert("openai".into(), toml::from_str("").unwrap());
  let (compact, _) = assert_equivalent(&raw);
  assert!(compact.contains("[providers.openai]"));
  assert!(!compact.contains("enable = true"));
  assert!(!compact.contains("allow_insecure_http = false"));
  assert!(!compact.contains("[service"));
  // Explicit wildcard selectors are retained, rather than rewritten to None.
  assert!(compact.contains("accounts = [\"*\"]"));
  assert!(compact.contains("providers = [\"*\"]"));
}

#[test]
fn service_customizations_and_disabled_features_remain_explicit() {
  let mut raw = native_config();
  raw.service.logging = toml::from_str(
    "level = 'warn'\nformat = 'json'\ntarget = 'file'\ndir = 'logs/custom'\nansi = false\ninclude_spans = true",
  )
  .unwrap();
  raw.service.outbound = toml::from_str("proxy_url = 'http://127.0.0.1:7890'\nno_proxy = ['localhost']").unwrap();
  raw.service.request_limits.max_wire_bytes = 12345;
  raw.service.persistence = toml::from_str(
    r#"
enabled = false
usage_db_path = "state/usage.db"
sessions_db_path = "state/sessions.db"
requests_dir = "state/requests"
record_sessions = false
record_request_bodies = false
body_max_bytes = 12345
write_queue_capacity = 512
archive_extension = "db.zstd"
archive_after_days = 2
prune_after_days = 3
"#,
  )
  .unwrap();
  let (compact, _) = assert_equivalent(&raw);
  for expected in [
    "level = \"warn\"",
    "ansi = false",
    "include_spans = true",
    "enabled = false",
    "record_sessions = false",
    "record_request_bodies = false",
    "body_max_bytes = 12345",
    "write_queue_capacity = 512",
    "max_wire_bytes = 12345",
  ] {
    assert!(compact.contains(expected), "{expected}");
  }
  assert!(!compact.contains("max_decoded_bytes"));
  assert!(!compact.contains("use_system_proxy = false"));
}

#[test]
fn pool_ttl_cooldown_and_retention_are_preserved_including_zero() {
  for (ttl, retention) in [(1800, 5400), (0, 0)] {
    let mut raw = native_config();
    let pool = raw.account_pools.get_mut("default").unwrap();
    pool.session_ttl_secs = ttl;
    pool.session_expired_retention_secs = retention;
    pool.failure_cooldown_secs = 19;
    let (compact, _) = assert_equivalent(&raw);
    assert!(compact.contains(&format!("session_ttl_secs = {ttl}")));
    assert!(compact.contains("failure_cooldown_secs = 19"));
    if retention != 0 {
      assert!(compact.contains("session_expired_retention_secs = 5400"));
    }
  }
}

#[test]
fn cors_permissions_survive_even_when_disabled() {
  for enabled in [true, false] {
    let mut raw = native_config();
    let RawListener::LlmApi { cors, .. } = raw.listeners.get_mut("api").unwrap() else {
      panic!("API listener");
    };
    *cors = RawCors {
      enabled,
      allow_localhost: true,
      allowed_origins: vec!["https://APP.example:443/".into()],
    };
    let (compact, _) = assert_equivalent(&raw);
    assert!(compact.contains("allow_localhost = true"));
    assert!(compact.contains("https://APP.example:443/"));
    assert!(compact.contains("[listeners.api.cors]"));
  }
}

#[test]
fn security_opt_ins_and_disabled_providers_remain_explicit() {
  let mut raw = native_config();
  let RawListener::LlmApi {
    bind,
    client_auth,
    allow_insecure_public,
    ..
  } = raw.listeners.get_mut("api").unwrap()
  else {
    panic!("API listener");
  };
  *bind = "0.0.0.0:4141".into();
  *client_auth = v2::RawClientAuth::LocalKeys;
  *allow_insecure_public = true;
  raw.providers.insert(
    "openai".into(),
    toml::from_str("base_url = 'http://upstream.example/v1'\nallow_insecure_http = true").unwrap(),
  );
  raw
    .providers
    .insert("zai".into(), toml::from_str("enable = false").unwrap());
  let (compact, _) = assert_equivalent(&raw);
  for expected in [
    "bind = \"0.0.0.0:4141\"",
    "client_auth = \"local_keys\"",
    "allow_insecure_public = true",
    "allow_insecure_http = true",
    "enable = false",
  ] {
    assert!(compact.contains(expected), "{expected}");
  }
}

#[test]
fn projection_modes_profiles_and_proxy_order_round_trip() {
  for mode in [RouteMode::Route, RouteMode::Exact, RouteMode::Fuzzy, RouteMode::Switch] {
    let mut legacy = Config::default();
    legacy.defaults.mode = mode;
    legacy.defaults.default_provider_id = Some("openai".into());
    legacy.defaults.model_families = vec![ModelFamily {
      name: "coding family".into(),
      members: vec!["gpt-5".into(), "gpt-5-mini".into()],
    }];
    legacy.defaults.agent_id = Some(tokn_config::AgentId::CodexCli);
    legacy.profiles.insert("team blue".into(), ProfileConfig::default());
    legacy.profiles.insert("default".into(), ProfileConfig::default());
    legacy.proxy_mode.intercept_hosts = vec!["api.openai.com".into()];
    legacy.proxy_mode.passthrough_hosts = vec!["other.example".into()];
    legacy.proxy_mode.ca_dir = Some("certs/proxy".into());
    for proxy_mode in [RouteMode::Passthrough, RouteMode::Switch, mode] {
      let projection = project_v2_config(
        &legacy,
        &[account()],
        V2ProjectionOptions {
          forward_proxy: Some(V2ForwardProxyProjectionOptions {
            route_mode: proxy_mode,
            default_intercept_hosts: vec!["chatgpt.com".into()],
            provider_hosts: BTreeMap::new(),
          }),
          ..Default::default()
        },
      )
      .unwrap();
      let raw = projection.raw_config();
      let (compact, _) = assert_equivalent(raw);
      assert!(
        compact.contains("wire_identity = { named = \"codex-cli\" }"),
        "{compact}"
      );
      assert!(compact.contains("ca_dir = \"certs/proxy\""));
      assert!(compact.contains("default_connect ="));
      assert!(!compact.contains("request_body_max_bytes"));
      let decoded = v2::decode(&compact, source_path()).unwrap();
      assert_eq!(decoded.bindings, raw.bindings);
      assert_eq!(decoded.connect_rules, raw.connect_rules);
      assert_eq!(
        decoded.account_pools.keys().collect::<Vec<_>>(),
        raw.account_pools.keys().collect::<Vec<_>>()
      );
    }
  }
}

#[test]
fn large_and_nested_policy_tables_stay_expanded() {
  let mut raw = native_config();
  let long_name = "p".repeat(100);
  raw
    .providers
    .insert(long_name.clone(), toml::from_str("driver = 'openai'").unwrap());
  let RawRoute::Managed { provider, model, .. } = raw.routes.get_mut("default").unwrap() else {
    panic!("managed route");
  };
  *provider = RawProviderSelector::Fixed { provider: long_name };
  *model = RawModelSelector::Family {
    families: BTreeMap::from([("team \"alpha\"".into(), vec!["gpt-5".into(), "gpt-5-mini".into()])]),
  };
  let (compact, _) = assert_equivalent(&raw);
  assert!(compact.contains("[routes.default.provider]"));
  assert!(compact.contains("[routes.default.model.families]"));
  assert!(!compact.contains("model = {"));
}

#[test]
fn explicit_proxy_limits_security_flags_and_rule_matchers_are_preserved() {
  let mut raw = native_config();
  raw.listeners.insert(
    "proxy".into(),
    toml::from_str(
      r#"
kind = "forward_proxy"
bind = "0.0.0.0:4142"
client_auth = "local_keys"
allow_insecure_public = true
request_body_max_bytes = 123456
default_http_action = { kind = "reject" }
default_connect = "reject"
"#,
    )
    .unwrap(),
  );
  raw.connect_rules.push(v2::RawConnectRule {
    id: "first".into(),
    listener: "proxy".into(),
    action: v2::RawConnectAction::Tunnel,
    hosts: vec!["api.example.com".into(), "other.example.com".into()],
    ports: vec![443, 8443],
  });
  let (compact, expanded) = assert_equivalent(&raw);
  assert!(compact.contains("request_body_max_bytes = 123456"));
  assert!(compact.contains("allow_insecure_public = true"));
  for output in [&compact, &expanded] {
    assert!(output.contains("hosts = [\n  \"api.example.com\",\n  \"other.example.com\",\n]"));
    assert!(output.contains("ports = [\n  443,\n  8443,\n]"));
  }
  assert!(compact.contains("default_connect = \"reject\""));
}

#[test]
fn omitted_retry_and_nondefault_wire_identities_are_preserved() {
  for identity in [RawWireIdentity::None, RawWireIdentity::ProviderDefault] {
    let mut raw = native_config();
    raw.profiles.get_mut("default").unwrap().wire_identity = identity;
    let RawRoute::Managed { retry, .. } = raw.routes.get_mut("default").unwrap() else {
      panic!("managed route");
    };
    *retry = RawRouteRetry::default();
    let (compact, _) = assert_equivalent(&raw);
    assert!(!compact.contains("retry ="));
    assert!(!compact.contains("[routes.default.retry]"));
    assert!(compact.contains("wire_identity ="));
    assert!(compact.contains("[retry_policies.standard]"));
  }
}
