use std::path::Path;
use tokn_config::v2::{self, RawBinding, RawProfileBinding, RawRoute};
use tokn_policy::ProviderId;

const CONFIG: &str = r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
[listeners.other]
kind = "llm_api"
bind = "127.0.0.1:4142"
client_auth = "none"
[profiles.default]
route = "shared"
[profiles.work]
route = "shared"
account_pool = { accounts = ["work"], session_ttl_secs = 60 }
[routes.shared]
kind = "managed"
providers = ["openai"]
provider = { kind = "any" }
model = { kind = "capability" }
operation = "translate_compatible"
"#;

fn raw() -> v2::RawConfig {
  v2::decode(CONFIG, Path::new("profiles.toml")).unwrap()
}

#[test]
fn shared_routes_use_private_profile_pools_and_global_default_mounts() {
  let raw = raw();
  let plan = v2::compile(&raw, Path::new("profiles.toml")).unwrap();
  assert!(raw.bindings.is_empty());
  assert_eq!(plan.routes().len(), 1);
  let default = &plan.profiles()["default"];
  let work = &plan.profiles()["work"];
  assert_ne!(default.account_pool(), work.account_pool());
  assert_eq!(default.api_binding().unwrap().path(), "/v1");
  assert_eq!(work.api_binding().unwrap().path(), "/work/v1");
  assert_eq!(work.api_binding().unwrap().endpoints().len(), 3);
  let pool = &plan.account_pools()[work.account_pool().unwrap()];
  assert_eq!(
    pool
      .selector()
      .accounts()
      .unwrap()
      .iter()
      .map(|id| id.as_str())
      .collect::<Vec<_>>(),
    ["work"]
  );
  assert_eq!(pool.session_affinity().unwrap().ttl().as_secs(), 60);
  let route = &plan.routes()["shared"];
  assert!(route.allows_provider(&ProviderId::new("openai").unwrap()));
  assert!(!route.allows_provider(&ProviderId::new("deepseek").unwrap()));
}

#[test]
fn custom_paths_and_generation_endpoint_lists_round_trip() {
  for endpoints in [
    vec![],
    vec!["responses".to_string()],
    vec!["chat_completions".into(), "messages".into()],
  ] {
    let mut raw = raw();
    raw.profiles.get_mut("work").unwrap().binding = Some(RawProfileBinding {
      path: Some("/custom/team%2fblue/api/".into()),
      endpoints: Some(endpoints.clone()),
    });
    let plan = v2::compile(&raw, Path::new("profiles.toml")).unwrap();
    let binding = plan.profiles()["work"].api_binding().unwrap();
    assert_eq!(binding.path(), "/custom/team%2Fblue/api");
    assert_eq!(binding.endpoints().len(), endpoints.len());
    let rendered = toml::to_string_pretty(&raw).unwrap();
    assert_eq!(v2::parse(&rendered, Path::new("profiles.toml")).unwrap(), plan);
  }
}

#[test]
fn rejects_ambiguous_unsafe_mounts_and_unknown_or_duplicate_endpoints() {
  for path in [
    "/v1", "/v1/", "/", "/admin", "/admin/x", "/healthz", "relative", "/x//y", "/x/../y", "/x/%2e/y", "/x?query",
    "/x/{id}", "/x/*rest",
  ] {
    let mut raw = raw();
    raw.profiles.get_mut("work").unwrap().binding = Some(RawProfileBinding {
      path: Some(path.into()),
      endpoints: None,
    });
    let error = v2::compile(&raw, Path::new("profiles.toml")).unwrap_err();
    assert!(
      error.to_string().contains("profiles.work.binding.path"),
      "{path}: {error}"
    );
  }
  for endpoints in [
    vec!["models"],
    vec!["providers"],
    vec!["unknown"],
    vec!["responses", "responses"],
  ] {
    let mut raw = raw();
    raw.profiles.get_mut("work").unwrap().binding = Some(RawProfileBinding {
      path: None,
      endpoints: Some(endpoints.into_iter().map(str::to_string).collect()),
    });
    assert!(v2::compile(&raw, Path::new("profiles.toml"))
      .unwrap_err()
      .to_string()
      .contains("profiles.work.binding.endpoints"));
  }
}

#[test]
fn retired_v2_fields_are_rejected_instead_of_silently_ignored() {
  for config in [
    format!("{CONFIG}\n[account_pools.legacy]"),
    "schema_version = 2\n[defaults.account_pool]\nproviders = ['openai']".to_string(),
    CONFIG.replace("[routes.shared]", "[routes.shared]\naccount_pool = 'legacy'"),
    CONFIG.replace("client_auth = \"none\"", "client_auth = \"none\"\ndefault_http_action = { kind = 'reject' }"),
    CONFIG.replace("accounts = [\"work\"]", "providers = ['openai'], accounts = [\"work\"]"),
    format!("{CONFIG}\n[routes.relay]\nkind = 'relay'\ndestination = {{ kind = 'original' }}\ncredentials = {{ kind = 'account_pool', account_pool = 'legacy' }}"),
  ] {
    let error = toml::from_str::<v2::RawConfig>(&config).unwrap_err();
    assert!(error.to_string().contains("unknown field"), "{error}");
  }
}

#[test]
fn api_rules_are_rejected_but_proxy_rules_can_select_profiles() {
  for prefix in [None, Some("/work/v1"), Some("/alias")] {
    let mut raw = raw();
    let mut rule: RawBinding =
      toml::from_str("id = 'legacy'\nlistener = 'api'\naction = { kind = 'route', profile = 'work' }").unwrap();
    rule.path_prefixes = prefix.into_iter().map(str::to_string).collect();
    raw.bindings.push(rule);
    assert!(v2::compile(&raw, Path::new("profiles.toml")).is_err());
  }
  let config = format!("{CONFIG}\n[listeners.proxy]\nkind = 'forward_proxy'\nbind = '127.0.0.1:4143'\nclient_auth = 'none'\ndefault_connect = 'reject'\ndefault_http_action = {{ kind = 'route', profile = 'work' }}\n[[bindings]]\nid = 'host'\nlistener = 'proxy'\nhosts = ['api.example.com']\naction = {{ kind = 'route', profile = 'default' }}");
  assert!(v2::parse(&config, Path::new("profiles.toml")).is_ok());
}

#[test]
fn validates_route_provider_filters() {
  for providers in [vec![], vec!["unknown"], vec!["openai", "openai"], vec!["*", "openai"]] {
    let mut raw = raw();
    let RawRoute::Managed { providers: field, .. } = raw.routes.get_mut("shared").unwrap() else {
      unreachable!()
    };
    *field = Some(providers.into_iter().map(str::to_string).collect());
    assert!(v2::compile(&raw, Path::new("profiles.toml")).is_err());
  }
}

#[test]
fn fixed_client_relays_mount_by_default_but_original_relays_remain_proxy_only() {
  let mut raw = raw();
  raw.profiles.remove("work");
  raw.routes.insert("shared".into(), toml::from_str("kind = 'relay'\ndestination = { kind = 'fixed_provider', provider = 'openai' }\ncredentials = { kind = 'client' }").unwrap());
  let plan = v2::compile(&raw, Path::new("profiles.toml")).unwrap();
  assert!(plan.profiles()["default"].account_pool().is_none());
  assert_eq!(plan.profiles()["default"].api_binding().unwrap().path(), "/v1");
  raw.profiles.get_mut("default").unwrap().account_pool = Some(Default::default());
  assert!(v2::compile(&raw, Path::new("profiles.toml"))
    .unwrap_err()
    .to_string()
    .contains("do not use an account pool"));
  raw.profiles.get_mut("default").unwrap().account_pool = None;
  let RawRoute::Relay { destination, .. } = raw.routes.get_mut("shared").unwrap() else {
    unreachable!()
  };
  *destination = v2::RawRelayDestination::Original {};
  raw.profiles.get_mut("default").unwrap().binding = Some(Default::default());
  assert!(v2::compile(&raw, Path::new("profiles.toml")).is_err());
  raw.profiles.get_mut("default").unwrap().binding = None;
  assert!(
    v2::compile(&raw, Path::new("profiles.toml")).unwrap().profiles()["default"]
      .api_binding()
      .is_none()
  );
}
