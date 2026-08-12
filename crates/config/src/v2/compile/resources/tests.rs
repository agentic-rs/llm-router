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
provider = {{ kind = "any" }}
model = {{ kind = "capability" }}
operation = "translate_compatible"

[account_pools.default]
accounts = ["*"]
providers = ["*"]

[providers.default]
driver = "openai"

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
  assert_eq!(
    compiled.providers.len(),
    tokn_core::provider::OFFICIAL_PROVIDER_PRESETS.len()
  );
  assert!(compiled.providers.contains_key("openai"));
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
[providers.first]
driver = "openai"
base_url = "https://EXAMPLE.com:443/v1"

[providers.second]
driver = "openai"
origins = ["https://example.com"]
"#,
  );

  let compiled = compile_resources(&config).unwrap();
  assert!(compiled.providers.contains_key("first"));
  assert!(compiled.providers.contains_key("second"));
}

#[test]
fn origin_route_rejects_ambiguous_compatible_claimants() {
  let mut config = base_config(
    r#"
[providers.first]
driver = "openai"
base_url = "https://EXAMPLE.com:443/v1"

[providers.second]
driver = "openai"
origins = ["https://example.com"]
"#,
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Relay {
      target: RawRelayTarget::ProviderFromOrigin {
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
fn rejects_a_base_url_origin_repeated_by_the_same_provider() {
  let config = base_config(
    r#"
[providers.public]
driver = "openai"
base_url = "https://api.openai.com/v1"
origins = ["https://API.OPENAI.com:443"]

[providers.zai]
driver = "zai"
"#,
  );

  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.public.origins"
  ));
}

#[test]
fn rejects_fixed_provider_excluded_by_pool() {
  let mut config = base_config(
    r#"
[providers.public]
driver = "openai"
base_url = "https://api.openai.com/v1"

[providers.zai]
driver = "zai"
"#,
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      provider: RawProviderSelector::Fixed {
        provider: "public".into(),
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
      provider: None,
    }],
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      provider: RawProviderSelector::Any {},
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
fn origin_relay_can_defer_to_the_selected_providers_driver_default() {
  let mut config = base_config(
    r#"
[providers.public]
driver = "openai"
origins = ["https://api.openai.com"]

[providers.zai]
driver = "zai"
"#,
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Relay {
      target: RawRelayTarget::ProviderFromOrigin {
        account_pool: "default".into(),
      },
    },
  );

  compile_resources(&config).unwrap();
}

#[test]
fn origin_relay_defers_provider_default_origin_resolution() {
  let mut config = base_config(
    r#"
[providers.default-provider]
driver = "openai"
"#,
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["default-provider".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Relay {
      target: RawRelayTarget::ProviderFromOrigin {
        account_pool: "default".into(),
      },
    },
  );

  compile_resources(&config).unwrap();
}

#[test]
fn fallback_pins_must_match_the_route_pool_and_fixed_provider() {
  let mut config = base_config(
    r#"
[providers.openai]
driver = "openai"

[providers.zai]
driver = "zai"

[[model_groups.coding]]
model = "gpt-5"
provider = "openai"
"#,
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      provider: RawProviderSelector::Fixed { provider: "zai".into() },
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
      provider: RawProviderSelector::Any {},
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
fn managed_any_uses_official_presets_and_validates_pool_references() {
  let mut config = base_config("");
  config.providers.clear();
  let compiled = compile_resources(&config).unwrap();
  assert!(compiled.providers.contains_key("openai"));

  config.providers.insert(
    "default".into(),
    RawProvider {
      enable: true,
      driver: Some("openai".into()),
      base_url: None,
      origins: Vec::new(),
      allow_insecure_http: false,
    },
  );
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["zai".into()]);
  assert!(compile_resources(&config).is_ok());

  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["not-installed".into()]);
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::UnresolvedReference { field: "providers", target, .. }) if target == "not-installed"
  ));
}

#[test]
fn official_provider_presets_are_implicit_and_overlayable() {
  let mut config = parse_config(
    r#"
schema_version = 2

[providers.openai]
base_url = "https://gateway.example/v1"
"#,
  );
  let compiled = compile_resources(&config).unwrap();
  let openai = &compiled.providers[&ProviderId::new("openai").unwrap()];
  assert_eq!(openai.driver().as_str(), "openai");
  assert_eq!(openai.base_url(), Some("https://gateway.example/v1/"));

  config.providers.get_mut("openai").unwrap().driver = Some("deepseek".into());
  let compiled = compile_resources(&config).unwrap();
  assert_eq!(
    compiled.providers[&ProviderId::new("openai").unwrap()]
      .driver()
      .as_str(),
    "deepseek"
  );
}

#[test]
fn fixed_routes_and_pools_can_reference_an_implicit_official_provider() {
  let mut config = base_config("");
  config.providers.clear();
  config.account_pools.get_mut("default").unwrap().providers = Some(vec!["openai".into()]);
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      provider: RawProviderSelector::Fixed {
        provider: "openai".into(),
      },
      model: RawModelSelector::Capability {},
      operation: RawOperationPolicy::Preserve,
    },
  );

  let compiled = compile_resources(&config).unwrap();
  assert!(compiled.providers.contains_key("openai"));
}

#[test]
fn official_destination_variants_defer_destinations_to_runtime_linking() {
  let compiled = compile_resources(&parse_config("schema_version = 2\n")).unwrap();
  for provider in ["zai-coding-plan", "zhipuai", "zhipuai-coding-plan"] {
    let provider = &compiled.providers[&ProviderId::new(provider).unwrap()];
    assert_eq!(provider.driver().as_str(), "zai");
    assert_eq!(provider.base_url(), None);
  }
}

#[test]
fn official_providers_can_be_disabled_without_discarding_their_settings() {
  let config = parse_config(
    r#"
schema_version = 2

[providers.openai]
enable = false
"#,
  );
  let compiled = compile_resources(&config).unwrap();
  assert!(!compiled.providers.contains_key("openai"));

  let mut referenced = base_config("");
  referenced.providers.clear();
  referenced
    .providers
    .insert("openai".into(), config.providers["openai"].clone());
  referenced.account_pools.get_mut("default").unwrap().providers = Some(vec!["openai".into()]);
  assert!(matches!(
    compile_resources(&referenced),
    Err(CompileError::UnresolvedReference { target, .. }) if target == "openai"
  ));

  let configured = parse_config(
    r#"
schema_version = 2
[providers.openai]
enable = false
driver = "openai"
base_url = "https://gateway.example/v1"
"#,
  );
  assert!(!compile_resources(&configured).unwrap().providers.contains_key("openai"));

  let custom = parse_config(
    r#"
schema_version = 2
[providers.custom]
enable = false
driver = "openai"
base_url = "https://gateway.example/v1"
"#,
  );
  assert!(matches!(
    compile_resources(&custom),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.custom.enable"
  ));
}

#[test]
fn custom_provider_still_requires_a_driver() {
  let missing = parse_config(
    r#"
schema_version = 2
[providers.company]
base_url = "https://gateway.example/v1"
"#,
  );
  assert!(matches!(
    compile_resources(&missing),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.company.driver"
  ));

  let configured = parse_config(
    r#"
schema_version = 2
[providers.company]
driver = "openai"
base_url = "https://gateway.example/v1"
"#,
  );
  assert_eq!(
    compile_resources(&configured).unwrap().providers[&ProviderId::new("company").unwrap()]
      .driver()
      .as_str(),
    "openai"
  );
}

#[test]
fn provider_urls_reject_port_zero_and_normalize_base_prefixes() {
  let mut config = base_config("");
  config.providers.get_mut("default").unwrap().base_url = Some("https://api.example.com:0/v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.default.base_url"
  ));

  config.providers.get_mut("default").unwrap().base_url = Some("https://API.example.com:443/v1".into());
  let compiled = compile_resources(&config).unwrap();
  assert_eq!(
    compiled.providers[&ProviderId::new("default").unwrap()].base_url(),
    Some("https://api.example.com/v1/")
  );

  config.providers.get_mut("default").unwrap().base_url = Some("http://api.example.com/v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.default.base_url"
  ));

  config.providers.get_mut("default").unwrap().allow_insecure_http = true;
  compile_resources(&config).unwrap();

  config.providers.get_mut("default").unwrap().allow_insecure_http = false;
  config.providers.get_mut("default").unwrap().base_url = Some("http://127.0.0.1:8080/v1".into());
  compile_resources(&config).unwrap();

  config.providers.get_mut("default").unwrap().base_url = Some("https://api.example.com./v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.default.base_url"
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
    config.providers.get_mut("default").unwrap().base_url = Some(invalid.into());
    assert!(matches!(
      compile_resources(&config),
      Err(CompileError::InvalidValue { location, .. }) if location == "providers.default.base_url"
    ));
  }

  config.providers.get_mut("default").unwrap().base_url = Some("http://localhost:8080/v1".into());
  assert!(matches!(
    compile_resources(&config),
    Err(CompileError::InvalidValue { location, .. }) if location == "providers.default.base_url"
  ));

  config.providers.get_mut("default").unwrap().base_url = Some("http://[::1]:8080/v1".into());
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
        provider: None,
      },
      RawModelCandidate {
        model: "gpt-5".into(),
        provider: Some("default".into()),
      },
    ],
  );
  config.routes.insert(
    "default".into(),
    RawRoute::Managed {
      account_pool: "default".into(),
      provider: RawProviderSelector::Fixed {
        provider: "default".into(),
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
