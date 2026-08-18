use super::*;

fn exact_host(value: &str) -> HostPattern {
  HostPattern::exact(CanonicalHost::parse(value).unwrap())
}

fn subdomains_of(value: &str) -> HostPattern {
  HostPattern::subdomains_of(CanonicalHost::parse(value).unwrap()).unwrap()
}

fn parse_config(contents: &str) -> RawConfig {
  toml::from_str(contents).unwrap()
}

fn compile_config(raw: &RawConfig, source: &Path) -> Result<BTreeMap<ListenerId, ListenerPlan>, CompileError> {
  let resources = super::super::resources::compile_resources(raw).unwrap();
  compile_listeners(raw, source, &resources.profiles, &resources.routes)
}

fn assert_invalid_message(raw: &RawConfig, expected: &str) {
  match compile_config(raw, Path::new("config.toml")) {
    Err(CompileError::InvalidValue { message, .. }) => {
      assert!(message.contains(expected), "{message:?} does not contain {expected:?}");
    }
    _ => panic!("expected an invalid-value error containing {expected:?}"),
  }
}

#[test]
fn compiles_normalized_http_matchers_in_source_order() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "specific"
listener = "api"
action = { kind = "reject" }
hosts = ["API.Example.COM"]
methods = ["POST"]
operations = ["chat_completions"]

[[bindings]]
id = "fallback"
listener = "api"
action = { kind = "reject" }
path_prefixes = ["/v1"]
"#,
  );

  let listeners = compile_config(&raw, Path::new("config.toml")).unwrap();
  let ListenerPlan::LlmApi(listener) = &listeners["api"] else {
    panic!("expected LLM API listener");
  };
  assert_eq!(listener.http_bindings()[0].id().as_str(), "specific");
  assert_eq!(listener.http_bindings()[1].id().as_str(), "fallback");
  let matcher = listener.http_bindings()[0].matcher();
  assert_eq!(matcher.hosts(), &[exact_host("api.example.com")]);
  assert_eq!(matcher.methods()[0].as_str(), "POST");
  assert_eq!(matcher.operations()[0].as_str(), "chat_completions");
}

#[test]
fn host_patterns_are_strict_and_canonical() {
  assert_eq!(
    compile_host("*.API.Example.COM", "hosts").unwrap(),
    subdomains_of("api.example.com")
  );
  assert_eq!(
    compile_host("[2001:0db8::1]", "hosts").unwrap(),
    exact_host("2001:db8::1")
  );
  assert_eq!(compile_host("127.0.0.1", "hosts").unwrap(), exact_host("127.0.0.1"));

  for invalid in [
    "*",
    "api.example.com.",
    "https://api.example.com",
    "api.example.com:443",
    "api_example.com",
    "-api.example.com",
    "api..example.com",
    "*.127.0.0.1",
    "127.1",
    "2130706433",
    "0177.0.0.1",
    "0x7f000001",
    "*.127.1",
    " api.example.com",
  ] {
    assert!(
      compile_host(invalid, "hosts").is_err(),
      "{invalid:?} should be rejected"
    );
  }
}

#[test]
fn methods_must_already_be_canonical_case_sensitive_tokens() {
  assert_eq!(
    compile_methods(&["PROPFIND".into(), "M-SEARCH".into()], "extensions")
      .unwrap()
      .0,
    vec!["PROPFIND", "M-SEARCH"]
  );
  for method in ["post", "Post", "PROPFINDé"] {
    assert!(
      compile_methods(&[method.into()], "invalid").is_err(),
      "{method:?} should be rejected"
    );
  }
}

#[test]
fn rejects_empty_duplicate_and_equivalent_http_matchers() {
  let empty = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "empty"
listener = "api"
action = { kind = "reject" }
"#,
  );
  assert!(matches!(
    compile_config(&empty, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));

  let duplicate_value = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "duplicate"
listener = "api"
action = { kind = "reject" }
hosts = ["api.example.com", "API.EXAMPLE.COM"]
"#,
  );
  assert!(matches!(
    compile_config(&duplicate_value, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));

  let equivalent = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "first"
listener = "api"
action = { kind = "reject" }
hosts = ["a.example.com", "b.example.com"]
methods = ["GET", "POST"]

[[bindings]]
id = "second"
listener = "api"
action = { kind = "reject" }
hosts = ["B.EXAMPLE.COM", "A.EXAMPLE.COM"]
methods = ["POST", "GET"]
"#,
  );
  assert!(matches!(
    compile_config(&equivalent, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn rejects_http_matcher_shadowed_by_an_earlier_binding() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "broad"
listener = "api"
action = { kind = "reject" }
hosts = ["*.example.com"]
path_prefixes = ["/v1"]
methods = ["GET", "POST"]

[[bindings]]
id = "shadowed"
listener = "api"
action = { kind = "reject" }
hosts = ["api.example.com"]
path_prefixes = ["/v1/chat"]
methods = ["POST"]
operations = ["chat_completions"]
"#,
  );

  assert_invalid_message(&raw, "binding `broad` matches all of its requests");
}

#[test]
fn rejects_http_matcher_covered_by_the_union_of_earlier_bindings() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "get"
listener = "api"
action = { kind = "reject" }
methods = ["GET"]

[[bindings]]
id = "post"
listener = "api"
action = { kind = "reject" }
methods = ["POST"]

[[bindings]]
id = "get-or-post"
listener = "api"
action = { kind = "reject" }
methods = ["GET", "POST"]
"#,
  );

  assert_invalid_message(&raw, "earlier bindings collectively match all of its requests");
}

#[test]
fn preserves_http_matcher_with_an_atom_not_covered_by_earlier_bindings() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "get"
listener = "api"
action = { kind = "reject" }
methods = ["GET"]

[[bindings]]
id = "post"
listener = "api"
action = { kind = "reject" }
methods = ["POST"]

[[bindings]]
id = "includes-put"
listener = "api"
action = { kind = "reject" }
methods = ["GET", "POST", "PUT"]
"#,
  );

  let listeners = compile_config(&raw, Path::new("config.toml")).unwrap();
  let ListenerPlan::LlmApi(listener) = &listeners["api"] else {
    panic!("expected LLM API listener");
  };
  assert_eq!(listener.http_bindings().len(), 3);
}

#[test]
fn preserves_legitimate_partial_http_matcher_overlap() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "one-host"
listener = "api"
action = { kind = "reject" }
hosts = ["a.example.com"]
methods = ["GET"]

[[bindings]]
id = "two-hosts"
listener = "api"
action = { kind = "reject" }
hosts = ["a.example.com", "b.example.com"]
methods = ["GET"]
"#,
  );

  let listeners = compile_config(&raw, Path::new("config.toml")).unwrap();
  let ListenerPlan::LlmApi(listener) = &listeners["api"] else {
    panic!("expected LLM API listener");
  };
  assert_eq!(listener.http_bindings().len(), 2);
}

#[test]
fn rejects_redundant_alternatives_inside_an_http_matcher() {
  for selector in [
    r#"hosts = ["*.example.com", "api.example.com"]"#,
    r#"hosts = ["*.api.example.com", "*.example.com"]"#,
    r#"path_prefixes = ["/v1/chat", "/v1"]"#,
  ] {
    let raw = parse_config(&format!(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "reject" }}

[[bindings]]
id = "redundant"
listener = "api"
action = {{ kind = "reject" }}
{selector}
"#
    ));
    assert_invalid_message(&raw, "is redundant because");
  }
}

#[test]
fn rejects_root_path_prefix_as_an_unconstrained_matcher() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "all-paths"
listener = "api"
action = { kind = "reject" }
path_prefixes = ["/"]
"#,
  );

  assert_invalid_message(&raw, "`/` matches every path");
}

#[test]
fn canonicalizes_and_validates_raw_encoded_path_prefixes() {
  assert_eq!(
    compile_path_prefixes(&["/v1/%2fchat".into()], "encoded").unwrap().0,
    vec!["/v1/%2Fchat"]
  );

  for path in ["/café", "/%zz", "/%2", "/v1 path", "/v1[chat]"] {
    assert!(
      compile_path_prefixes(&[path.into()], "invalid").is_err(),
      "{path:?} should be rejected"
    );
  }

  assert!(matches!(
    compile_path_prefixes(&["/v1/%2f".into(), "/v1/%2F".into()], "duplicate"),
    Err(CompileError::InvalidValue { .. })
  ));
  assert!(compile_path_prefixes(&["/v1%2Fchat".into(), "/v1/chat".into()], "encoded-slash").is_ok());
}

#[test]
fn rejects_literal_and_percent_encoded_dot_segments() {
  for path in ["/./v1", "/../v1", "/%2e/v1", "/v1/%2E%2e", "/v1/.%2e/chat"] {
    assert!(
      compile_path_prefixes(&[path.into()], "dot-segment").is_err(),
      "{path:?} should be rejected"
    );
  }

  assert!(compile_path_prefixes(&["/v1/release..candidate".into()], "ordinary-dots").is_ok());
}

#[test]
fn allows_wildcard_and_apex_host_alternatives() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "apex-and-subdomains"
listener = "api"
action = { kind = "reject" }
hosts = ["*.example.com", "example.com"]
"#,
  );

  assert!(compile_config(&raw, Path::new("config.toml")).is_ok());
}

#[test]
fn rejects_shadowed_connect_matcher_and_preserves_partial_overlap() {
  let shadowed = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"

[[connect_rules]]
id = "broad"
listener = "proxy"
action = "tunnel"
hosts = ["*.example.com"]
ports = [443, 8443]

[[connect_rules]]
id = "shadowed"
listener = "proxy"
action = "reject"
hosts = ["api.example.com"]
ports = [443]
"#,
  );
  assert_invalid_message(&shadowed, "CONNECT rule `broad` matches all of its requests");

  let partial = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"

[[connect_rules]]
id = "one-port"
listener = "proxy"
action = "tunnel"
hosts = ["api.example.com"]
ports = [443]

[[connect_rules]]
id = "two-ports"
listener = "proxy"
action = "reject"
hosts = ["api.example.com"]
ports = [443, 8443]
"#,
  );
  let listeners = compile_config(&partial, Path::new("config.toml")).unwrap();
  let ListenerPlan::ForwardProxy(listener) = &listeners["proxy"] else {
    panic!("expected forward proxy listener");
  };
  assert_eq!(listener.connect_rules().len(), 2);
}

#[test]
fn rejects_connect_matcher_covered_by_split_host_and_port_rules() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"

[[connect_rules]]
id = "a-443"
listener = "proxy"
action = "tunnel"
hosts = ["a.example.com"]
ports = [443]

[[connect_rules]]
id = "a-8443"
listener = "proxy"
action = "tunnel"
hosts = ["a.example.com"]
ports = [8443]

[[connect_rules]]
id = "b-443"
listener = "proxy"
action = "tunnel"
hosts = ["b.example.com"]
ports = [443]

[[connect_rules]]
id = "b-8443"
listener = "proxy"
action = "tunnel"
hosts = ["b.example.com"]
ports = [8443]

[[connect_rules]]
id = "covered-product"
listener = "proxy"
action = "reject"
hosts = ["a.example.com", "b.example.com"]
ports = [443, 8443]
"#,
  );

  assert_invalid_message(&raw, "earlier CONNECT rules collectively match all of its requests");
}

#[test]
fn listener_binds_are_numeric_unique_and_secure_by_default() {
  for bind in ["localhost:4141", "127.0.0.1:0"] {
    let raw = parse_config(&format!(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "{bind}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
"#
    ));
    assert!(matches!(
      compile_config(&raw, Path::new("config.toml")),
      Err(CompileError::InvalidValue { .. })
    ));
  }

  let public_unauthenticated = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "0.0.0.0:4141"
client_auth = "none"
default_http_action = { kind = "reject" }
"#,
  );
  assert!(matches!(
    compile_config(&public_unauthenticated, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));

  let public_authenticated_without_acknowledgement = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "0.0.0.0:4141"
client_auth = "local_keys"
default_http_action = { kind = "reject" }
"#,
  );
  assert!(matches!(
    compile_config(
      &public_authenticated_without_acknowledgement,
      Path::new("config.toml")
    ),
    Err(CompileError::InvalidValue { location, .. })
      if location == "listeners.api.allow_insecure_public"
  ));

  let acknowledged_public_listener = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "0.0.0.0:4141"
client_auth = "local_keys"
allow_insecure_public = true
default_http_action = { kind = "reject" }
"#,
  );
  compile_config(&acknowledged_public_listener, Path::new("config.toml")).unwrap();

  let duplicate = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[listeners.proxy]
kind = "forward_proxy"
bind = "0.0.0.0:4141"
client_auth = "local_keys"
allow_insecure_public = true
default_http_action = { kind = "reject" }
default_connect = "tunnel"
"#,
  );
  assert!(matches!(
    compile_config(&duplicate, Path::new("config.toml")),
    Err(CompileError::DuplicateBind { .. })
  ));
}

#[test]
fn intercept_requires_tls_and_resolves_ca_dir_from_source() {
  let with_tls = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"
ca_dir = "certificates"

[[connect_rules]]
id = "intercept-api"
listener = "proxy"
action = "intercept"
hosts = ["api.example.com"]
"#,
  );
  let listeners = compile_config(&with_tls, Path::new("etc/gateway.toml")).unwrap();
  let ListenerPlan::ForwardProxy(listener) = &listeners["proxy"] else {
    panic!("expected forward proxy listener");
  };
  assert_eq!(listener.tls().unwrap().ca_dir(), Path::new("etc/certificates"));
  assert_eq!(listener.connect_rules()[0].action(), ConnectAction::Intercept);

  let without_tls = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "intercept"
"#,
  );
  assert!(matches!(
    compile_config(&without_tls, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn forward_proxy_request_body_limit_has_a_default_and_must_be_positive() {
  let defaulted = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "reject"
"#,
  );
  let listeners = compile_config(&defaulted, Path::new("config.toml")).unwrap();
  let ListenerPlan::ForwardProxy(listener) = &listeners["proxy"] else {
    panic!("expected forward proxy listener");
  };
  assert_eq!(
    listener.request_body_max_bytes(),
    crate::v2::raw::DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES
  );

  let configured = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
request_body_max_bytes = 4096
default_http_action = { kind = "reject" }
default_connect = "reject"
"#,
  );
  let listeners = compile_config(&configured, Path::new("config.toml")).unwrap();
  let ListenerPlan::ForwardProxy(listener) = &listeners["proxy"] else {
    panic!("expected forward proxy listener");
  };
  assert_eq!(listener.request_body_max_bytes(), 4096);

  let zero = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
request_body_max_bytes = 0
default_http_action = { kind = "reject" }
default_connect = "reject"
"#,
  );
  assert!(matches!(
    compile_config(&zero, Path::new("config.toml")),
    Err(CompileError::InvalidValue { location, .. })
      if location == "listeners.proxy.request_body_max_bytes"
  ));
}

#[test]
fn binding_ids_are_global_and_connect_rules_require_forward_proxy() {
  let duplicate_id = parse_config(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"

[[bindings]]
id = "shared"
listener = "proxy"
action = { kind = "reject" }
hosts = ["api.example.com"]

[[connect_rules]]
id = "shared"
listener = "proxy"
action = "tunnel"
ports = [443]
"#,
  );
  assert!(matches!(
    compile_config(&duplicate_id, Path::new("config.toml")),
    Err(CompileError::DuplicateId { .. })
  ));

  let llm_connect = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[connect_rules]]
id = "invalid"
listener = "api"
action = "tunnel"
ports = [443]
"#,
  );
  assert!(matches!(
    compile_config(&llm_connect, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));
}

#[test]
fn llm_bindings_reject_routes_that_need_an_original_destination() {
  let raw = parse_config(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "transparent"
listener = "api"
action = { kind = "route", profile = "transparent" }
path_prefixes = ["/v1"]

[profiles.transparent]
route = "transparent"

[routes.transparent]
kind = "relay"
destination = { kind = "original" }
credentials = { kind = "client" }
"#,
  );
  assert!(matches!(
    compile_config(&raw, Path::new("config.toml")),
    Err(CompileError::InvalidValue { .. })
  ));
}
