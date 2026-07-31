use std::path::Path;
use tokn_config::v2::{compile, decode, load, parse, CompileError, Error};
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
accounts = ["*"]
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
