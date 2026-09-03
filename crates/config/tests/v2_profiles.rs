use std::path::Path;
use tokn_config::v2::{self, RawBinding, RawProfileBinding, RawRoute};
use tokn_policy::{HttpAction, ProviderId};

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
  assert!(raw.account_pools.is_empty());
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
  for listener in plan.listeners().values() {
    assert_eq!(listener.default_http_action(), &HttpAction::Reject);
    assert!(listener.http_bindings().is_empty());
  }
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
fn legacy_pool_references_keep_legacy_exposure_and_cannot_be_mixed_ambiguously() {
  let mut raw = raw();
  raw.profiles.get_mut("work").unwrap().account_pool = None;
  raw.account_pools.insert("legacy".into(), Default::default());
  let RawRoute::Managed { account_pool, .. } = raw.routes.get_mut("shared").unwrap() else {
    unreachable!()
  };
  *account_pool = Some("legacy".into());
  let plan = v2::compile(&raw, Path::new("profiles.toml")).unwrap();
  for profile in plan.profiles().values() {
    assert_eq!(profile.account_pool().unwrap().as_str(), "legacy");
    assert!(profile.api_binding().is_none());
  }
  raw.profiles.get_mut("work").unwrap().binding = Some(Default::default());
  let plan = v2::compile(&raw, Path::new("profiles.toml")).unwrap();
  assert_eq!(plan.profiles()["work"].account_pool().unwrap().as_str(), "profile.work");
  assert_eq!(plan.account_pools()["legacy"], plan.account_pools()["profile.work"]);
  raw.profiles.get_mut("work").unwrap().account_pool = Some(Default::default());
  assert!(v2::compile(&raw, Path::new("profiles.toml")).is_err());
}

#[test]
fn legacy_api_rules_cannot_override_or_alias_profile_mounts_but_proxy_rules_can_select_them() {
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
fn validates_provider_filters_and_profile_pool_intersection() {
  for providers in [vec![], vec!["unknown"], vec!["openai", "openai"], vec!["*", "openai"]] {
    let mut raw = raw();
    let RawRoute::Managed { providers: field, .. } = raw.routes.get_mut("shared").unwrap() else {
      unreachable!()
    };
    *field = Some(providers.into_iter().map(str::to_string).collect());
    assert!(v2::compile(&raw, Path::new("profiles.toml")).is_err());
  }
  let mut raw = raw();
  raw
    .profiles
    .get_mut("work")
    .unwrap()
    .account_pool
    .as_mut()
    .unwrap()
    .providers = Some(vec!["deepseek".into()]);
  assert!(v2::compile(&raw, Path::new("profiles.toml"))
    .unwrap_err()
    .to_string()
    .contains("no overlap"));
}

#[test]
fn fixed_client_relays_can_opt_into_mounts_but_original_relays_remain_proxy_only() {
  let mut raw = raw();
  raw.profiles.remove("work");
  raw.routes.insert("shared".into(), toml::from_str("kind = 'relay'\ndestination = { kind = 'fixed_provider', provider = 'openai' }\ncredentials = { kind = 'client' }").unwrap());
  raw.profiles.get_mut("default").unwrap().binding = Some(Default::default());
  let plan = v2::compile(&raw, Path::new("profiles.toml")).unwrap();
  assert!(plan.profiles()["default"].account_pool().is_none());
  assert_eq!(plan.profiles()["default"].api_binding().unwrap().path(), "/v1");
  let RawRoute::Relay { destination, .. } = raw.routes.get_mut("shared").unwrap() else {
    unreachable!()
  };
  *destination = v2::RawRelayDestination::Original {};
  assert!(v2::compile(&raw, Path::new("profiles.toml")).is_err());
  raw.profiles.get_mut("default").unwrap().binding = None;
  assert!(
    v2::compile(&raw, Path::new("profiles.toml")).unwrap().profiles()["default"]
      .api_binding()
      .is_none()
  );
}
