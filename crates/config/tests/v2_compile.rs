use std::path::Path;
use tokn_config::v2::{
  compile, decode, load, parse, parse_config, CompileError, Error, DEFAULT_ARCHIVE_AFTER_DAYS, DEFAULT_BODY_MAX_BYTES,
  DEFAULT_MAX_DECODED_BYTES, DEFAULT_MAX_WIRE_BYTES, DEFAULT_PRUNE_AFTER_DAYS, DEFAULT_WRITE_QUEUE_CAPACITY,
};
use tokn_policy::{ConnectAction, HttpAction, ListenerPlan, RouteKind};

const MINIMAL_MANAGED: &str = r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "default" }

[profiles.default]
route = "default"

[routes.default]
kind = "managed"
account_pool = "default"
provider = { kind = "any" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.default]
accounts = ["*"]
providers = ["*"]

[providers.default]
driver = "openai"
"#;

fn unwrap_compile_error(error: Error) -> Box<CompileError> {
  let Error::Compile { source, .. } = error else {
    panic!("expected a compile error");
  };
  source
}

#[test]
fn minimal_managed_llm_listener_compiles() {
  let plan = parse(MINIMAL_MANAGED, Path::new("config.toml")).unwrap();

  let listener = plan.listeners().get("api").unwrap();
  assert!(matches!(listener, ListenerPlan::LlmApi(_)));
  assert!(matches!(
    listener.default_http_action(),
    HttpAction::Route(profile) if profile.as_str() == "default"
  ));
  assert_eq!(plan.routes().get("default").unwrap().kind(), RouteKind::Managed);
  assert_eq!(plan.account_pools().len(), 1);
}

#[test]
fn service_defaults_match_v2_operational_defaults() {
  let compiled = parse_config(MINIMAL_MANAGED, Path::new("config.toml")).unwrap();
  let service = compiled.service();

  assert_eq!(service.outbound().proxy_url(), None);
  assert!(service.outbound().no_proxy().is_empty());
  assert!(!service.outbound().use_system_proxy());
  assert_eq!(
    service.request_limits().max_wire_bytes(),
    DEFAULT_MAX_WIRE_BYTES as usize
  );
  assert_eq!(
    service.request_limits().max_decoded_bytes(),
    DEFAULT_MAX_DECODED_BYTES as usize
  );
  let persistence = service.persistence();
  assert!(persistence.enabled());
  assert!(persistence.record_sessions());
  assert!(persistence.record_request_bodies());
  assert_eq!(persistence.body_max_bytes(), DEFAULT_BODY_MAX_BYTES as usize);
  assert_eq!(
    persistence.write_queue_capacity(),
    DEFAULT_WRITE_QUEUE_CAPACITY as usize
  );
  assert_eq!(persistence.archive_extension(), None);
  assert_eq!(persistence.archive_after_days(), DEFAULT_ARCHIVE_AFTER_DAYS as i64);
  assert_eq!(persistence.prune_after_days(), DEFAULT_PRUNE_AFTER_DAYS as i64);
}

#[test]
fn service_settings_compile_and_normalize() {
  let config = MINIMAL_MANAGED.replacen(
    "[listeners.api]",
    r#"[service.outbound]
proxy_url = "socks5h://proxy.example:1080"
no_proxy = [" localhost ", "localhost", "", " 10.0.0.0/8 "]

[service.request_limits]
max_wire_bytes = 1048576
max_decoded_bytes = 4194304

[service.persistence]
usage_db_path = "state/custom-usage.db"
sessions_db_path = "state/custom-sessions.db"
requests_dir = "state/custom-requests"
record_sessions = false
record_request_bodies = false
body_max_bytes = 12345
write_queue_capacity = 17
archive_extension = "db.zstd"
archive_after_days = 5
prune_after_days = 12

[listeners.api]"#,
    1,
  );

  let compiled = parse_config(&config, Path::new("config.toml")).unwrap();
  let service = compiled.service();
  assert_eq!(service.outbound().proxy_url(), Some("socks5h://proxy.example:1080"));
  assert_eq!(service.outbound().no_proxy(), ["localhost", "10.0.0.0/8"]);
  assert_eq!(service.request_limits().max_wire_bytes(), 1_048_576);
  assert_eq!(service.request_limits().max_decoded_bytes(), 4_194_304);

  let persistence = service.persistence();
  assert!(!persistence.record_sessions());
  assert!(!persistence.record_request_bodies());
  assert_eq!(persistence.body_max_bytes(), 12_345);
  assert_eq!(persistence.write_queue_capacity(), 256);
  assert_eq!(persistence.archive_extension(), Some("db.zstd"));
  assert_eq!(persistence.archive_after_days(), 5);
  assert_eq!(persistence.prune_after_days(), 12);
  let paths = persistence.resolve_paths().unwrap();
  assert_eq!(paths.usage_db, Path::new("state/custom-usage.db"));
  assert_eq!(paths.sessions_db, Path::new("state/custom-sessions.db"));
  assert_eq!(paths.requests_dir, Path::new("state/custom-requests"));
}

#[test]
fn service_rejects_invalid_persistence_ages() {
  for (settings, location) in [
    (
      "archive_after_days = 0\nprune_after_days = 10",
      "service.persistence.archive_after_days",
    ),
    (
      "archive_after_days = 7\nprune_after_days = 0",
      "service.persistence.prune_after_days",
    ),
    (
      "archive_after_days = 7\nprune_after_days = 7",
      "service.persistence.prune_after_days",
    ),
    (
      "archive_after_days = 10\nprune_after_days = 7",
      "service.persistence.prune_after_days",
    ),
    (
      "archive_after_days = 106751991167301\nprune_after_days = 106751991167302",
      "service.persistence.archive_after_days",
    ),
  ] {
    let config = MINIMAL_MANAGED.replacen(
      "[listeners.api]",
      &format!("[service.persistence]\n{settings}\n\n[listeners.api]"),
      1,
    );
    let error = unwrap_compile_error(parse_config(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(
      *error,
      CompileError::InvalidValue { location: actual, .. } if actual == location
    ));
  }
}

#[test]
fn service_rejects_invalid_proxy_and_request_limits() {
  for (settings, location) in [
    ("proxy_url = \"ftp://proxy.example\"", "service.outbound.proxy_url"),
    (
      "proxy_url = \"http://proxy.example\"\nuse_system_proxy = true",
      "service.outbound",
    ),
    ("no_proxy = [\"localhost\"]", "service.outbound.no_proxy"),
  ] {
    let config = MINIMAL_MANAGED.replacen(
      "[listeners.api]",
      &format!("[service.outbound]\n{settings}\n\n[listeners.api]"),
      1,
    );
    let error = unwrap_compile_error(parse_config(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(
      *error,
      CompileError::InvalidValue { location: actual, .. } if actual == location
    ));
  }

  for field in ["max_wire_bytes", "max_decoded_bytes"] {
    let config = MINIMAL_MANAGED.replacen(
      "[listeners.api]",
      &format!("[service.request_limits]\n{field} = 0\n\n[listeners.api]"),
      1,
    );
    let error = unwrap_compile_error(parse_config(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(
      *error,
      CompileError::InvalidValue { location, .. }
        if location == format!("service.request_limits.{field}")
    ));
  }
}

#[test]
fn load_preserves_proxy_rule_order_and_resolves_relative_ca_dir() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("gateway.toml");
  std::fs::write(
    &path,
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "reject"
ca_dir = "certificates"

[[bindings]]
id = "http-first"
listener = "proxy"
action = { kind = "reject" }
hosts = ["api.example.com"]

[[bindings]]
id = "http-second"
listener = "proxy"
action = { kind = "reject" }
path_prefixes = ["/v1"]

[[connect_rules]]
id = "connect-first"
listener = "proxy"
action = "tunnel"
hosts = ["private.example.com"]

[[connect_rules]]
id = "connect-second"
listener = "proxy"
action = "intercept"
ports = [443]
"#,
  )
  .unwrap();

  let plan = load(&path).unwrap();
  let ListenerPlan::ForwardProxy(proxy) = plan.listeners().get("proxy").unwrap() else {
    panic!("expected a forward proxy listener");
  };

  let http_ids = proxy
    .http_bindings()
    .iter()
    .map(|binding| binding.id().as_str())
    .collect::<Vec<_>>();
  assert_eq!(http_ids, ["http-first", "http-second"]);

  let connect_ids = proxy
    .connect_rules()
    .iter()
    .map(|rule| rule.id().as_str())
    .collect::<Vec<_>>();
  assert_eq!(connect_ids, ["connect-first", "connect-second"]);
  assert_eq!(proxy.connect_rules()[1].action(), ConnectAction::Intercept);

  let expected_ca_dir = directory.path().join("certificates");
  assert_eq!(proxy.tls().unwrap().ca_dir(), expected_ca_dir.as_path());
}

#[test]
fn compile_reports_unresolved_profile_references() {
  let source = Path::new("config.toml");
  let raw = decode(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "missing" }
"#,
    source,
  )
  .unwrap();

  let error = unwrap_compile_error(compile(&raw, source).unwrap_err());
  assert!(matches!(
    *error,
    CompileError::UnresolvedReference { target, .. } if target == "missing"
  ));
}

#[test]
fn parse_rejects_unknown_fields() {
  let config = MINIMAL_MANAGED.replacen("schema_version = 2", "schema_version = 2\nunknown = true", 1);

  assert!(matches!(
    parse(&config, Path::new("config.toml")),
    Err(Error::Parse { .. })
  ));

  for section in [
    "service",
    "service.outbound",
    "service.request_limits",
    "service.persistence",
  ] {
    let config = MINIMAL_MANAGED.replacen(
      "[listeners.api]",
      &format!("[{section}]\nunknown = true\n\n[listeners.api]"),
      1,
    );
    assert!(matches!(
      parse_config(&config, Path::new("config.toml")),
      Err(Error::Parse { .. })
    ));
  }
}

#[test]
fn unauthenticated_listener_must_bind_to_loopback() {
  let error = unwrap_compile_error(
    parse(
      r#"
schema_version = 2

[listeners.public]
kind = "llm_api"
bind = "0.0.0.0:4141"
client_auth = "none"
default_http_action = { kind = "reject" }
"#,
      Path::new("config.toml"),
    )
    .unwrap_err(),
  );

  assert!(matches!(*error, CompileError::InvalidValue { .. }));
}

#[test]
fn tunnel_and_reject_only_proxy_needs_no_resource_registries() {
  let plan = parse(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"

[[bindings]]
id = "reject-health"
listener = "proxy"
action = { kind = "reject" }
path_prefixes = ["/health"]

[[connect_rules]]
id = "reject-private"
listener = "proxy"
action = "reject"
hosts = ["*.internal.example"]
"#,
    Path::new("config.toml"),
  )
  .unwrap();

  assert!(plan.profiles().is_empty());
  assert!(plan.routes().is_empty());
  assert!(plan.account_pools().is_empty());
  assert_eq!(
    plan.providers().len(),
    tokn_core::provider::OFFICIAL_PROVIDER_PRESETS.len()
  );

  let ListenerPlan::ForwardProxy(proxy) = plan.listeners().get("proxy").unwrap() else {
    panic!("expected a forward proxy listener");
  };
  assert_eq!(proxy.default_connect_action(), ConnectAction::Tunnel);
  assert!(proxy.tls().is_none());
}

#[test]
fn llm_listener_rejects_routes_that_need_an_original_destination() {
  for config in [client_origin_relay_llm_config(), account_origin_relay_llm_config()] {
    let error = unwrap_compile_error(parse(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(*error, CompileError::InvalidValue { .. }));
  }
}

fn client_origin_relay_llm_config() -> String {
  r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "default" }

[profiles.default]
route = "default"

[routes.default]
kind = "relay"
destination = { kind = "original" }
credentials = { kind = "client" }
"#
  .into()
}

fn account_origin_relay_llm_config() -> String {
  r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "default" }

[profiles.default]
route = "default"

[routes.default]
kind = "relay"
destination = { kind = "original" }
credentials = { kind = "account_pool", account_pool = "default" }

[account_pools.default]
providers = ["openai"]

[providers.openai]
driver = "openai"
origins = ["https://api.example.com"]
"#
  .into()
}
