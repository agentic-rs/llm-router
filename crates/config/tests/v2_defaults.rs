use std::path::Path;

use tokn_config::v2::{self, CompileError, Error, RawDefaultPolicy};
use tokn_policy::{ConnectAction, HttpAction, ListenerPlan, ManagedRetry, RoutePlan};

const LISTENER: &str = r#"
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
"#;

const EXPLICIT_POLICY: &str = r#"
[profiles.default]
route = "default"

[routes.default]
kind = "managed"
provider = { kind = "any" }
model = { kind = "capability" }
operation = "translate_compatible"

[profiles.default.account_pool]
"#;

fn source() -> &'static Path {
  Path::new("config.toml")
}

fn shorthand(settings: &str) -> String {
  format!("schema_version = 2\n[defaults]\n{settings}\n{LISTENER}")
}

fn explicit(settings: &str) -> String {
  format!("schema_version = 2\n{LISTENER}\n{settings}")
}

fn assert_equivalent(short: &str, full: &str) {
  let raw = v2::decode(short, source()).unwrap();
  let before = raw.clone();
  let expected = v2::parse_config(full, source()).unwrap();
  assert_eq!(v2::compile_config(&raw, source()).unwrap(), expected);
  assert_eq!(v2::compile(&raw, source()).unwrap(), *expected.gateway());
  assert_eq!(v2::parse(short, source()).unwrap(), *expected.gateway());
  assert_eq!(raw, before);
  let rendered = toml::to_string_pretty(&raw).unwrap();
  assert_eq!(v2::decode(&rendered, source()).unwrap(), raw);
  assert_eq!(v2::parse_config(&rendered, source()).unwrap(), expected);
}

fn compile_error(config: &str) -> Box<CompileError> {
  let Error::Compile { source, .. } = v2::parse_config(config, source()).unwrap_err() else {
    panic!("expected a semantic error");
  };
  source
}

#[test]
fn empty_defaults_are_an_opt_in_equivalent_managed_policy() {
  let config = shorthand("");
  assert_equivalent(&config, &explicit(EXPLICIT_POLICY));
  let raw = v2::decode(&config, source()).unwrap();
  assert_eq!(raw.defaults, Some(RawDefaultPolicy::default()));
  assert!(raw.profiles.is_empty());
  assert!(raw.routes.is_empty());
  let plan = v2::parse(&config, source()).unwrap();
  let RoutePlan::Managed(route) = &plan.routes()["default"] else {
    panic!("managed default route");
  };
  assert_eq!(route.retry(), &ManagedRetry::Never);
  assert!(plan.retry_policies().is_empty());
}

#[test]
fn omitting_defaults_preserves_the_explicit_schema_and_serialization() {
  let config = explicit(EXPLICIT_POLICY);
  let raw = v2::decode(&config, source()).unwrap();
  assert!(raw.defaults.is_none());
  assert!(!toml::to_string_pretty(&raw).unwrap().contains("[defaults"));
  assert_equivalent(&config, &config);
  for required in [
    "provider = { kind = \"any\" }\n",
    "model = { kind = \"capability\" }\n",
    "operation = \"translate_compatible\"\n",
  ] {
    assert!(v2::decode(&config.replace(required, ""), source()).is_err());
  }
  let empty = v2::parse(&format!("schema_version = 2\n{LISTENER}"), source()).unwrap();
  assert!(empty.profiles().is_empty());
}

#[test]
fn customized_defaults_match_explicit_resources_and_service_settings() {
  let settings = r#"
providers = ["openai"]
provider = { kind = "fixed", provider = "openai" }
model = { kind = "qualified", namespace = "provider" }
operation = "preserve"
wire_identity = "none"
retry = { kind = "recoverable", policy = "standard" }

[defaults.account_pool]
accounts = ["work", "personal"]
session_ttl_secs = 1800
session_expired_retention_secs = 5400
failure_cooldown_secs = 19
"#;
  let policy = r#"
[profiles.default]
route = "default"
wire_identity = "none"

[routes.default]
kind = "managed"
providers = ["openai"]
provider = { kind = "fixed", provider = "openai" }
model = { kind = "qualified", namespace = "provider" }
operation = "preserve"
retry = { kind = "recoverable", policy = "standard" }

[profiles.default.account_pool]
accounts = ["work", "personal"]
session_ttl_secs = 1800
session_expired_retention_secs = 5400
failure_cooldown_secs = 19
"#;
  let shared = r#"
[retry_policies.standard]
max_retries = 2
initial_backoff_ms = 100

[service.logging]
level = "warn"
format = "json"

[service.persistence]
enabled = false
"#;
  assert_equivalent(
    &format!("{}{shared}", shorthand(settings)),
    &format!("{}{shared}", explicit(policy)),
  );
}

#[test]
fn model_families_and_named_wire_identity_use_existing_policy_types() {
  let model = "model = { kind = \"family\", families = { coding = [\"gpt-5\", \"gpt-5-mini\"] } }";
  let identity = "wire_identity = { named = \"codex-cli\" }";
  let short = shorthand(&format!("{model}\n{identity}"));
  let full = explicit(
    &EXPLICIT_POLICY
      .replace("model = { kind = \"capability\" }", model)
      .replace("route = \"default\"", &format!("route = \"default\"\n{identity}")),
  );
  assert_equivalent(&short, &full);
}

#[test]
fn shorthand_rejects_each_conflicting_resource_instead_of_overriding_it() {
  for declaration in [
    "[profiles.default]\nroute = 'other'",
    "[routes.default]\nkind = 'relay'\ndestination = { kind = 'original' }\ncredentials = { kind = 'client' }",
  ] {
    let error = compile_error(&format!("{}\n{declaration}", shorthand("")));
    assert!(matches!(
      error.as_ref(),
      CompileError::InvalidValue { location, .. } if location == "defaults"
    ));
    let header = declaration.lines().next().unwrap();
    assert!(error.to_string().contains(header), "{error}");
  }
}

#[test]
fn other_profiles_keep_independent_pools_and_do_not_inherit_defaults() {
  let other = EXPLICIT_POLICY.replace("default", "other");
  let original = v2::parse(
    &explicit(&other).replace("profile = \"default\"", "profile = \"other\""),
    source(),
  )
  .unwrap();
  let mut raw = v2::decode(
    &format!(
      "{}\n{other}",
      shorthand("[defaults.account_pool]\nsession_ttl_secs = 30")
    ),
    source(),
  )
  .unwrap();
  for ttl in [30, 60] {
    raw.defaults.as_mut().unwrap().account_pool.session_ttl_secs = ttl;
    let plan = v2::compile(&raw, source()).unwrap();
    assert_eq!(plan.profiles().len(), 2);
    assert_eq!(plan.routes().len(), 2);
    assert_eq!(plan.account_pools().len(), 2);
    assert_eq!(plan.profiles()["other"], original.profiles()["other"]);
    assert_eq!(plan.routes()["other"], original.routes()["other"]);
    assert_eq!(
      plan.account_pools()["profile.other"],
      original.account_pools()["profile.other"]
    );
    assert_eq!(
      plan.account_pools()["profile.default"]
        .session_affinity()
        .unwrap()
        .ttl()
        .as_secs(),
      ttl
    );
  }
}

#[test]
fn defaults_do_not_create_listeners_or_relax_public_listener_authentication() {
  assert!(matches!(
    *compile_error("schema_version = 2\n[defaults]"),
    CompileError::EmptyRegistry { resource: "listener" }
  ));
  let public = shorthand("").replace("127.0.0.1:4141", "0.0.0.0:4141");
  assert!(v2::parse(&public, source()).is_err());
  let unauthenticated = public.replace(
    "client_auth = \"none\"",
    "client_auth = \"none\"\nallow_insecure_public = true",
  );
  assert!(v2::parse(&unauthenticated, source()).is_err());
  let authenticated = public.replace(
    "client_auth = \"none\"",
    "client_auth = \"local_keys\"\nallow_insecure_public = true",
  );
  assert!(v2::parse(&authenticated, source()).is_ok());
  assert!(v2::decode(&shorthand("").replace("client_auth = \"none\"", ""), source()).is_err());
}

#[test]
fn bindings_and_proxy_connect_behavior_remain_explicit_and_ordered() {
  let extra = r#"
[[bindings]]
id = "first"
listener = "proxy"
hosts = ["blocked.example"]
action = { kind = "reject" }

[[bindings]]
id = "second"
listener = "proxy"
hosts = ["*.example"]
action = { kind = "route", profile = "default" }

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:4142"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "reject"

[[connect_rules]]
id = "denied"
listener = "proxy"
hosts = ["blocked.example"]
action = "reject"

[[connect_rules]]
id = "tunnel"
listener = "proxy"
hosts = ["*.example"]
action = "tunnel"
"#;
  let short = format!("{}{extra}", shorthand(""));
  assert_equivalent(&short, &format!("{}{extra}", explicit(EXPLICIT_POLICY)));
  let plan = v2::parse(&short, source()).unwrap();
  let ListenerPlan::ForwardProxy(proxy) = &plan.listeners()["proxy"] else {
    panic!("proxy listener");
  };
  assert_eq!(proxy.default_connect_action(), ConnectAction::Reject);
  assert_eq!(proxy.default_http_action(), &HttpAction::Reject);
  let missing_connect = short.replace("default_connect = \"reject\"", "");
  assert!(v2::decode(&missing_connect, source()).is_err());
}

#[test]
fn invalid_default_settings_pass_through_existing_semantic_validation() {
  for settings in [
    "retry = { kind = 'recoverable', policy = 'missing' }",
    "retry = { kind = 'safe_methods', policy = 'standard' }",
    "provider = { kind = 'fixed', provider = 'unknown' }",
    "model = { kind = 'family', families = { coding = [] } }",
    "[defaults.account_pool]\naccounts = []",
    "providers = ['*', 'openai']",
    "[defaults.account_pool]\nsession_ttl_secs = 0\nsession_expired_retention_secs = 1",
    "[defaults.account_pool]\nfailure_cooldown_secs = 86401",
  ] {
    assert!(
      matches!(v2::parse(&shorthand(settings), source()), Err(Error::Compile { .. })),
      "{settings}"
    );
  }
}

#[test]
fn invalid_values_point_to_authored_default_keys_without_changing_other_errors() {
  for (settings, expected) in [
    (
      "retry = { kind = 'safe_methods', policy = 'standard' }",
      "defaults.retry.kind",
    ),
    (
      "model = { kind = 'family', families = { coding = [] } }",
      "defaults.model.families.coding",
    ),
    (
      "[defaults.account_pool]\nsession_ttl_secs = 0\nsession_expired_retention_secs = 1",
      "defaults.account_pool.session_expired_retention_secs",
    ),
  ] {
    assert!(matches!(
      *compile_error(&shorthand(settings)),
      CompileError::InvalidValue { location, .. } if location == expected
    ));
  }
  for id in ["other", "default.other"] {
    let other = format!(
      "{}\n[profiles.\"{id}\"]\nroute = 'default'\n[profiles.\"{id}\".account_pool]\nfailure_cooldown_secs = 86401",
      shorthand("")
    );
    assert!(matches!(
      *compile_error(&other),
      CompileError::InvalidValue { location, .. } if location == format!("profiles.{id}.account_pool.failure_cooldown_secs")
    ));
  }
  let explicit_invalid = explicit(EXPLICIT_POLICY).replace(
    "[profiles.default.account_pool]",
    "[profiles.default.account_pool]\nfailure_cooldown_secs = 86401",
  );
  assert!(matches!(
    *compile_error(&explicit_invalid),
    CompileError::InvalidValue { location, .. } if location == "profiles.default.account_pool.failure_cooldown_secs"
  ));
}

#[test]
fn default_policy_has_no_legacy_agent_or_security_escape_fields() {
  for settings in [
    "mode = 'route'",
    "agent_id = 'codex-cli'",
    "kind = 'relay'",
    "allow_insecure_public = true",
    "allow_insecure_http = true",
    "client_auth = 'none'",
    "default_connect = 'intercept'",
    "provider = { kind = 'any', unknown = true }",
    "[defaults.account_pool]\nunknown = true",
  ] {
    assert!(
      matches!(v2::decode(&shorthand(settings), source()), Err(Error::Parse { .. })),
      "{settings}"
    );
  }
}

#[test]
fn reloading_shorthand_and_explicit_configs_produces_the_same_plan() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  std::fs::write(&path, shorthand("")).unwrap();
  let first = v2::load_config(&path).unwrap();
  std::fs::write(&path, explicit(EXPLICIT_POLICY)).unwrap();
  assert_eq!(v2::load_config(&path).unwrap(), first);
  std::fs::write(&path, shorthand("[defaults.account_pool]\nsession_ttl_secs = 1800")).unwrap();
  let updated = v2::load_config(&path).unwrap();
  assert_eq!(
    updated.gateway().account_pools()["profile.default"]
      .session_affinity()
      .unwrap()
      .ttl()
      .as_secs(),
    1800
  );
  assert_eq!(
    first.gateway().account_pools()["profile.default"]
      .session_affinity()
      .unwrap()
      .ttl()
      .as_secs(),
    18_000
  );
}
