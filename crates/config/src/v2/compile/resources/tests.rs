use super::*;

fn parse_config(contents: &str) -> RawConfig {
  toml::from_str(contents).unwrap()
}

fn base_config(extra: &str) -> RawConfig {
  parse_config(&format!(
    r#"
schema_version = 2

[profiles.default]
route = "default"

[routes.default]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "any" }}
model = {{ kind = "capability" }}
operation = "translate_compatible"

[account_pools.default]
accounts = ["*"]
providers = ["*"]

[upstreams.default]
provider = "openai"

{extra}
"#
  ))
}

#[test]
fn transport_only_gateway_may_have_no_routing_resources() {
  let compiled = compile_resources(&parse_config("schema_version = 2\n")).unwrap();

  assert!(compiled.profiles.is_empty());
  assert!(compiled.routes.is_empty());
  assert!(compiled.account_pools.is_empty());
  assert!(compiled.upstreams.is_empty());
  assert!(compiled.model_groups.is_empty());
}

#[test]
fn compiles_wildcards_and_managed_auto_identity() {
  let compiled = compile_resources(&base_config("")).unwrap();
  let pool = &compiled.account_pools[&AccountPoolId::new("default").unwrap()];
  let profile = &compiled.profiles[&ProfileId::new("default").unwrap()];

  assert_eq!(pool.selector(), &AccountSelector::all());
  assert_eq!(profile.wire_identity(), &WireIdentity::ProviderDefault);
}

#[test]
fn shared_origin_is_allowed_when_no_origin_route_needs_unique_ownership() {
  let config = base_config(
    r#"
[upstreams.first]
provider = "openai"
base_url = "https://EXAMPLE.com:443/v1"

[upstreams.second]
provider = "openai"
origins = ["https://example.com"]
"#,
  );

  let compiled = compile_resources(&config).unwrap();
  assert!(compiled.upstreams.contains_key("first"));
  assert!(compiled.upstreams.contains_key("second"));
}

#[test]
fn origin_route_rejects_ambiguous_compatible_claimants() {
  let mut config = base_config(
    r#"
[upstreams.first]
provider = "openai"
base_url = "https://EXAMPLE.com:443/v1"

[upstreams.second]
provider = "openai"
origins = ["https://example.com"]
"#,
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Relay {
      target: RawRelayTarget::UpstreamFromOrigin {
        account_pool: "default".into(),
      },
    },
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::DuplicateOrigin { origin, .. }) if origin == "https://example.com"
  ));
}

#[test]
fn rejects_a_base_url_origin_repeated_by_the_same_upstream() {
  let config = base_config(
    r#"
[upstreams.public]
provider = "openai"
base_url = "https://api.openai.com/v1"
origins = ["https://API.OPENAI.com:443"]
"#,
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.public.origins"
  ));
}

#[test]
fn rejects_fixed_upstream_excluded_by_pool() {
  let mut config = base_config(
    r#"
[upstreams.public]
provider = "openai"
base_url = "https://api.openai.com/v1"
"#,
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      upstream: RawUpstreamSelector::Fixed {
        upstream: "public".into(),
      },
      model: RawModelSelector::Capability {},
      operation: RawOperationPolicy::Preserve,
    },
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn transparent_auto_is_none_but_explicit_identity_is_rejected() {
  let mut config = base_config("");
  config.routes.insert("default".into(), RawRoute::Transparent {});
  let compiled = compile_resources(&config.clone()).unwrap();
  assert_eq!(
    compiled.profiles[&ProfileId::new("default").unwrap()].wire_identity(),
    &WireIdentity::None
  );

  config.profiles.get_mut("default").unwrap().wire_identity = RawWireIdentity::ProviderDefault;
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn by_requested_fallback_is_nonempty_and_unique() {
  let mut config = base_config("");
  config.model_groups.insert(
    "coding".into(),
    vec![RawModelCandidate {
      model: "gpt-5".into(),
      upstream: None,
    }],
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      upstream: RawUpstreamSelector::Any {},
      model: RawModelSelector::Fallback {
        selector: RawFallbackSelector::ByRequested {
          groups: vec!["coding".into(), "coding".into()],
        },
      },
      operation: RawOperationPolicy::Preserve,
    },
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn origin_relay_requires_a_compatible_claimed_origin() {
  let mut config = base_config(
    r#"
[upstreams.public]
provider = "openai"
origins = ["https://api.openai.com"]
"#,
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Relay {
      target: RawRelayTarget::UpstreamFromOrigin {
        account_pool: "default".into(),
      },
    },
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn origin_relay_defers_provider_default_origin_resolution() {
  let mut config = base_config(
    r#"
[upstreams.default-provider]
provider = "openai"
"#,
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["openai".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Relay {
      target: RawRelayTarget::UpstreamFromOrigin {
        account_pool: "default".into(),
      },
    },
  );

  compile_resources(&config).unwrap();
}

#[test]
fn fallback_pins_must_match_the_route_pool_and_fixed_upstream() {
  let mut config = base_config(
    r#"
[upstreams.openai]
provider = "openai"

[upstreams.zai]
provider = "zai"

[[model_groups.coding]]
model = "gpt-5"
upstream = "openai"
"#,
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      upstream: RawUpstreamSelector::Fixed { upstream: "zai".into() },
      model: RawModelSelector::Fallback {
        selector: RawFallbackSelector::Fixed { group: "coding".into() },
      },
      operation: RawOperationPolicy::Preserve,
    },
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { .. })
  ));

  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      upstream: RawUpstreamSelector::Any {},
      model: RawModelSelector::Fallback {
        selector: RawFallbackSelector::Fixed { group: "coding".into() },
      },
      operation: RawOperationPolicy::Preserve,
    },
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn managed_any_requires_a_compatible_configured_upstream() {
  let mut config = base_config("");
  config.upstreams.clear();
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "routes.default.upstream"
  ));

  config.upstreams.insert(
    "default".into(),
    RawUpstream {
      provider: "openai".into(),
      accounts: None,
      base_url: None,
      origins: Vec::new(),
      allow_insecure_http: false,
    },
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "routes.default.upstream"
  ));
}

#[test]
fn upstream_account_filters_prevent_implicit_credential_cartesian_products() {
  let mut config = base_config("");
  config.upstreams.get_mut("default").unwrap().accounts = Some(vec!["work".into()]);
  let compiled = compile_resources(&config).unwrap();
  let upstream = &compiled.upstreams[&UpstreamId::new("default").unwrap()];
  assert!(upstream.permits_account("work"));
  assert!(!upstream.permits_account("personal"));

  config.upstreams.get_mut("default").unwrap().accounts = Some(vec!["*".into()]);
  assert!(
    compile_resources(&config).unwrap().upstreams[&UpstreamId::new("default").unwrap()].permits_account("personal")
  );

  for invalid in [
    Vec::new(),
    vec!["*".into(), "work".into()],
    vec!["work".into(), "work".into()],
  ] {
    config.upstreams.get_mut("default").unwrap().accounts = Some(invalid);
    assert!(matches!(
      compile_resources(&config),
      Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.default.accounts"
    ));
  }
}

#[test]
fn upstream_urls_reject_port_zero_and_normalize_base_prefixes() {
  let mut config = base_config("");
  config.upstreams.get_mut("default").unwrap().base_url = Some("https://api.example.com:0/v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.default.base_url"
  ));

  config.upstreams.get_mut("default").unwrap().base_url = Some("https://API.example.com:443/v1".into());
  let compiled = compile_resources(&config).unwrap();
  assert_eq!(
    compiled.upstreams[&UpstreamId::new("default").unwrap()].base_url(),
    Some("https://api.example.com/v1/")
  );

  config.upstreams.get_mut("default").unwrap().base_url = Some("http://api.example.com/v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.default.base_url"
  ));

  config.upstreams.get_mut("default").unwrap().allow_insecure_http = true;
  compile_resources(&config).unwrap();

  config.upstreams.get_mut("default").unwrap().allow_insecure_http = false;
  config.upstreams.get_mut("default").unwrap().base_url = Some("http://127.0.0.1:8080/v1".into());
  compile_resources(&config).unwrap();

  config.upstreams.get_mut("default").unwrap().base_url = Some("https://api.example.com./v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.default.base_url"
  ));

  for invalid in [
    " https://api.example.com/v1",
    "https://api.example.com/\n/v1",
    r"https:\api.example.com\v1",
    "https://api.example.com/a/../v1",
    "https://api.example.com/%2E%2e/v1",
    "https://127.1/v1",
    "https://example.0x10/v1",
    "https://example.123/v1",
  ] {
    config.upstreams.get_mut("default").unwrap().base_url = Some(invalid.into());
    assert!(matches!(
      compile_resources(&config),
      Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.default.base_url"
    ));
  }

  config.upstreams.get_mut("default").unwrap().base_url = Some("http://localhost:8080/v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "upstreams.default.base_url"
  ));

  config.upstreams.get_mut("default").unwrap().base_url = Some("http://[::1]:8080/v1".into());
  compile_resources(&config).unwrap();
}

#[test]
fn pool_durations_have_operational_bounds() {
  let mut config = base_config("");
  config.account_pools.get_mut("default").unwrap().failure_cooldown_secs = MAX_FAILURE_COOLDOWN_SECS + 1;
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. })
      if location == "account_pools.default.failure_cooldown_secs"
  ));

  config.account_pools.get_mut("default").unwrap().failure_cooldown_secs = 60;
  config.account_pools.get_mut("default").unwrap().session_ttl_secs = MAX_SESSION_DURATION_SECS + 1;
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "account_pools.default.session_ttl_secs"
  ));
}

#[test]
fn fixed_route_rejects_effectively_duplicate_fallback_candidates() {
  let mut config = base_config("");
  config.model_groups.insert(
    "coding".into(),
    vec![
      RawModelCandidate {
        model: "gpt-5".into(),
        upstream: None,
      },
      RawModelCandidate {
        model: "gpt-5".into(),
        upstream: Some("default".into()),
      },
    ],
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      upstream: RawUpstreamSelector::Fixed {
        upstream: "default".into(),
      },
      model: RawModelSelector::Fallback {
        selector: RawFallbackSelector::Fixed { group: "coding".into() },
      },
      operation: RawOperationPolicy::Preserve,
    },
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, message })
      if location == "routes.default.model" && message.contains("effective candidate")
  ));
}
