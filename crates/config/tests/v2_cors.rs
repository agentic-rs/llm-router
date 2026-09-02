use std::path::Path;
use tokn_config::v2::{decode, parse_config, RawListener};
use tokn_policy::{CorsPlan, ListenerPlan};

const API: &str = r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }
"#;

fn cors(source: &str) -> CorsPlan {
  let config = parse_config(source, Path::new("cors.toml")).unwrap();
  let ListenerPlan::LlmApi(listener) = &config.gateway().listeners()["api"] else {
    panic!("expected API listener");
  };
  listener.cors().clone()
}

#[test]
fn cors_is_disabled_by_default_and_does_not_activate_inert_permissions() {
  for settings in [
    "",
    "[listeners.api.cors]",
    "[listeners.api.cors]\nallow_localhost = true\nallowed_origins = ['https://app.example']",
  ] {
    assert_eq!(cors(&format!("{API}\n{settings}")), CorsPlan::default());
  }
}

#[test]
fn cors_round_trip_preserves_raw_permissions_and_compiles_canonical_origins() {
  let source = format!(
    "{API}\n[listeners.api.cors]\nenabled = true\nallow_localhost = true\n\
     allowed_origins = ['https://APP.example:443/', 'https://app.example', 'http://localhost:3000']"
  );
  let raw = decode(&source, Path::new("cors.toml")).unwrap();
  let rendered = toml::to_string_pretty(&raw).unwrap();
  assert_eq!(decode(&rendered, Path::new("cors.toml")).unwrap(), raw);
  let plan = cors(&rendered);
  assert!(plan.allow_localhost());
  assert_eq!(
    plan.allowed_origins().iter().map(String::as_str).collect::<Vec<_>>(),
    ["http://localhost:3000", "https://app.example"]
  );
  let RawListener::LlmApi { cors: raw_cors, .. } = &raw.listeners["api"] else {
    panic!("expected raw API listener");
  };
  assert_eq!(raw_cors.allowed_origins.len(), 3);
}

#[test]
fn cors_can_enable_only_localhost_permissions() {
  let plan = cors(&format!(
    "{API}\n[listeners.api.cors]\nenabled = true\nallow_localhost = true"
  ));
  assert!(plan.allow_localhost());
  assert!(plan.allowed_origins().is_empty());
}

#[test]
fn cors_rejects_invalid_permissions_even_when_disabled() {
  for origin in [
    "*",
    "null",
    "ftp://app.example",
    "https://user:password@app.example",
    "https://app.example/path",
    "https://app.example/?query=yes",
    "https://app.example/#fragment",
  ] {
    for enabled in [false, true] {
      let source = format!("{API}\n[listeners.api.cors]\nenabled = {enabled}\nallowed_origins = [{origin:?}]");
      let error = parse_config(&source, Path::new("cors.toml")).unwrap_err();
      assert!(error.to_string().contains("listeners.api.cors"), "{origin}: {error}");
    }
  }
  let error = parse_config(
    &format!("{API}\n[listeners.api.cors]\nenabled = true"),
    Path::new("cors.toml"),
  )
  .unwrap_err();
  assert!(error.to_string().contains("listeners.api.cors"));
}

#[test]
fn cors_syntax_is_strict_and_unavailable_on_forward_proxies() {
  for settings in ["allow_localhosts = true", "enabled = 'true'", "allowed_origins = '*'"] {
    assert!(decode(
      &format!("{API}\n[listeners.api.cors]\n{settings}"),
      Path::new("cors.toml")
    )
    .is_err());
  }
  let proxy = API.replace(
    "kind = \"llm_api\"",
    "kind = \"forward_proxy\"\ndefault_connect = \"reject\"",
  );
  assert!(decode(&format!("{proxy}\n[listeners.api.cors]"), Path::new("cors.toml")).is_err());
}
