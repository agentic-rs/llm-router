use std::path::Path;
use tokn_config::v2::{
  compile, decode, load, parse, CompileError, Error, DEFAULT_BODY_MAX_BYTES, DEFAULT_MAX_DECODED_BYTES,
  DEFAULT_MAX_WIRE_BYTES, DEFAULT_WRITE_QUEUE_CAPACITY,
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
upstream = { kind = "any" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["*"]

[upstreams.default]
provider = "openai"
"#;

fn unwrap_compile_error(error: Error) -> Box<CompileError> {
  let Error::Compile { source, .. } = error else {
    panic!("expected a compile error");
  };
  source
}

#[test]
fn minimal_managed_llm_listener_compiles() {
  let compiled = parse(MINIMAL_MANAGED, Path::new("config.toml")).unwrap();
  let plan = compiled.gateway();

  let listener = plan.listeners().get("api").unwrap();
  assert!(matches!(listener, ListenerPlan::LlmApi(_)));
  assert!(matches!(
    listener.default_http_action(),
    HttpAction::Route(profile) if profile.as_str() == "default"
  ));
  assert_eq!(plan.routes().get("default").unwrap().kind(), RouteKind::Managed);
  assert_eq!(plan.account_pools().len(), 1);
  assert_eq!(compiled.service().outbound().proxy_url(), None);
  assert!(compiled.service().outbound().no_proxy().is_empty());
  assert!(!compiled.service().outbound().use_system_proxy());
  assert_eq!(
    compiled.service().request_limits().max_wire_bytes(),
    DEFAULT_MAX_WIRE_BYTES as usize
  );
  assert_eq!(
    compiled.service().request_limits().max_decoded_bytes(),
    DEFAULT_MAX_DECODED_BYTES as usize
  );
  let persistence = compiled.service().persistence();
  assert!(persistence.enabled());
  assert!(persistence.record_sessions());
  assert!(persistence.record_request_bodies());
  assert_eq!(persistence.body_max_bytes(), DEFAULT_BODY_MAX_BYTES as usize);
  assert_eq!(
    persistence.write_queue_capacity(),
    DEFAULT_WRITE_QUEUE_CAPACITY as usize
  );
  assert_eq!(persistence.archive_extension(), None);
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
paths = [{ kind = "prefix", path = "/v1" }]

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

  let compiled = load(&path).unwrap();
  let plan = compiled.gateway();
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
fn service_settings_compile_and_normalize_no_proxy_entries() {
  let config = MINIMAL_MANAGED.replacen(
    "[listeners.api]",
    r#"[service.outbound]
proxy_url = "socks5h://proxy.example:1080"
no_proxy = [" localhost ", "localhost", "", " 10.0.0.0/8 "]

[service.request_limits]
max_wire_bytes = 1048576
max_decoded_bytes = 4194304

[listeners.api]"#,
    1,
  );

  let compiled = parse(&config, Path::new("config.toml")).unwrap();
  let outbound = compiled.service().outbound();

  assert_eq!(outbound.proxy_url(), Some("socks5h://proxy.example:1080"));
  assert_eq!(outbound.no_proxy(), ["localhost", "10.0.0.0/8"]);
  assert!(!outbound.use_system_proxy());
  assert_eq!(compiled.service().request_limits().max_wire_bytes(), 1_048_576);
  assert_eq!(compiled.service().request_limits().max_decoded_bytes(), 4_194_304);
}

#[test]
fn service_accepts_system_proxy_without_explicit_proxy_settings() {
  let config = MINIMAL_MANAGED.replacen(
    "[listeners.api]",
    "[service.outbound]\nuse_system_proxy = true\n\n[listeners.api]",
    1,
  );

  let compiled = parse(&config, Path::new("config.toml")).unwrap();
  let outbound = compiled.service().outbound();
  let options = outbound.to_http_client_options();

  assert_eq!(outbound.proxy_url(), None);
  assert!(outbound.no_proxy().is_empty());
  assert!(outbound.use_system_proxy());
  assert_eq!(options.url, None);
  assert!(options.no_proxy.is_empty());
  assert!(options.system);
}

#[test]
fn service_persistence_preserves_existing_paths_and_runtime_controls() {
  let config = MINIMAL_MANAGED.replacen(
    "[listeners.api]",
    r#"[service.persistence]
enabled = true
usage_db_path = "state/custom-usage.db"
sessions_db_path = "state/custom-sessions.db"
requests_dir = "state/custom-requests"
record_sessions = false
record_request_bodies = false
body_max_bytes = 12345
write_queue_capacity = 17
archive_extension = "db.zstd"

[listeners.api]"#,
    1,
  );

  let compiled = parse(&config, Path::new("config.toml")).unwrap();
  let persistence = compiled.service().persistence();
  assert!(persistence.enabled());
  assert!(!persistence.record_sessions());
  assert!(!persistence.record_request_bodies());
  assert_eq!(persistence.body_max_bytes(), 12_345);
  assert_eq!(persistence.write_queue_capacity(), 256);
  assert_eq!(persistence.archive_extension(), Some("db.zstd"));
  let paths = persistence.resolve_paths().unwrap();
  assert_eq!(paths.usage_db, Path::new("state/custom-usage.db"));
  assert_eq!(paths.sessions_db, Path::new("state/custom-sessions.db"));
  assert_eq!(paths.requests_dir, Path::new("state/custom-requests"));
}

#[test]
fn service_outbound_rejects_unsupported_or_conflicting_proxy_settings() {
  for (settings, location) in [
    ("proxy_url = \"ftp://proxy.example\"", "service.outbound.proxy_url"),
    (
      "proxy_url = \"http://proxy.example/path\"",
      "service.outbound.proxy_url",
    ),
    (
      "proxy_url = \"http://proxy.example?mode=connect\"",
      "service.outbound.proxy_url",
    ),
    (
      "proxy_url = \"http://proxy.example#fragment\"",
      "service.outbound.proxy_url",
    ),
    ("proxy_url = \"http://proxy.example:0\"", "service.outbound.proxy_url"),
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

    let error = unwrap_compile_error(parse(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(
      *error,
      CompileError::InvalidValue { location: actual, .. } if actual == location
    ));
  }
}

#[test]
fn service_request_limits_reject_zero() {
  for field in ["max_wire_bytes", "max_decoded_bytes"] {
    let config = MINIMAL_MANAGED.replacen(
      "[listeners.api]",
      &format!("[service.request_limits]\n{field} = 0\n\n[listeners.api]"),
      1,
    );

    let error = unwrap_compile_error(parse(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(
      *error,
      CompileError::InvalidValue { location, .. }
        if location == format!("service.request_limits.{field}")
    ));
  }
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
      parse(&config, Path::new("config.toml")),
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
  let compiled = parse(
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
paths = [{ kind = "prefix", path = "/health" }]

[[connect_rules]]
id = "reject-private"
listener = "proxy"
action = "reject"
hosts = ["*.internal.example"]
"#,
    Path::new("config.toml"),
  )
  .unwrap();
  let plan = compiled.gateway();

  assert!(plan.profiles().is_empty());
  assert!(plan.routes().is_empty());
  assert!(plan.account_pools().is_empty());
  assert!(plan.upstreams().is_empty());
  assert!(plan.model_groups().is_empty());

  let ListenerPlan::ForwardProxy(proxy) = plan.listeners().get("proxy").unwrap() else {
    panic!("expected a forward proxy listener");
  };
  assert_eq!(proxy.default_connect_action(), ConnectAction::Tunnel);
  assert!(proxy.tls().is_none());
}

#[test]
fn llm_listener_rejects_routes_that_need_an_original_destination() {
  for config in [transparent_llm_config(), origin_relay_llm_config()] {
    let error = unwrap_compile_error(parse(&config, Path::new("config.toml")).unwrap_err());
    assert!(matches!(*error, CompileError::InvalidValue { .. }));
  }
}

fn transparent_llm_config() -> String {
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
kind = "transparent"
"#
  .into()
}

fn origin_relay_llm_config() -> String {
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
target = { kind = "upstream_from_origin", account_pool = "default" }

[account_pools.default]
providers = ["openai"]

[upstreams.openai]
provider = "openai"
origins = ["https://api.example.com"]
"#
  .into()
}
