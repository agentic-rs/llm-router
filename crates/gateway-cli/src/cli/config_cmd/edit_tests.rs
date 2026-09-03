use super::*;

fn read_key(path: &Path, key: &str) -> String {
  let document = load_doc(path).unwrap();
  render_item(lookup(&document, &key_segments(None, key)).expect("existing config key"))
}

fn set_key(path: &Path, key: &str, value: &str, add: bool) -> Result<()> {
  cmd_set(
    path,
    SetArgs {
      key: key.into(),
      value: value.into(),
      add,
      account: None,
    },
  )
}

fn unset_key(path: &Path, key: &str) -> Result<()> {
  cmd_unset(
    path,
    UnsetArgs {
      key: key.into(),
      account: None,
    },
  )
}

#[test]
fn init_template_nested_values_can_be_read_and_updated() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  std::fs::write(
    &path,
    format!("{V2_INIT_TEMPLATE}\n[retry_policies.fast]\nmax_retries = 1\ninitial_backoff_ms = 50\n"),
  )
  .unwrap();

  for (key, expected) in [
    ("listeners.api.client_auth", "none"),
    ("defaults.retry.policy", "standard"),
  ] {
    cmd_get(
      &path,
      GetArgs {
        key: key.into(),
        account: None,
      },
    )
    .unwrap();
    assert_eq!(read_key(&path, key), expected);
  }

  set_key(&path, "defaults.retry.policy", "fast", false).unwrap();
  assert_eq!(read_key(&path, "defaults.retry.policy"), "fast");
  set_key(&path, "defaults.model.kind", "capability", false).unwrap();
  set_key(&path, "defaults.account_pool.session_ttl_secs", "1800", false).unwrap();
  set_key(&path, "defaults.account_pool.accounts", "primary", true).unwrap();
  let raw = tokn_config::v2::load_raw(&path).unwrap();
  let defaults = raw.defaults.unwrap();
  assert_eq!(defaults.account_pool.session_ttl_secs, 1800);
  assert_eq!(defaults.account_pool.accounts.unwrap(), ["primary"]);
  unset_key(&path, "defaults.account_pool.session_ttl_secs").unwrap();
  assert_eq!(
    tokn_config::v2::load_raw(&path)
      .unwrap()
      .defaults
      .unwrap()
      .account_pool
      .session_ttl_secs,
    tokn_config::DEFAULT_SESSION_TTL_SECS
  );
  tokn_config::v2::load_config(&path).unwrap();
}

#[test]
fn default_policy_edit_errors_leave_the_original_file_unchanged() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  std::fs::write(&path, V2_INIT_TEMPLATE).unwrap();
  cmd_list(&path).unwrap();
  for (key, value) in [
    ("defaults.account_pool.session_ttl_secs", "-1"),
    ("defaults.provider.kind", "unknown"),
    ("defaults.mode", "route"),
    ("profiles.default.route", "default"),
  ] {
    assert!(set_key(&path, key, value, false).is_err(), "{key}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), V2_INIT_TEMPLATE);
  }
  for key in ["defaults.retry.policy", "listeners.api.client_auth"] {
    assert!(unset_key(&path, key).is_err(), "{key}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), V2_INIT_TEMPLATE);
  }
  // Removing all profiles is valid: the listener then exposes no generation routes.
  unset_key(&path, "defaults").unwrap();
  assert!(tokn_config::v2::load_config(&path)
    .unwrap()
    .gateway()
    .profiles()
    .is_empty());
}

#[test]
fn nested_inline_edits_preserve_key_formatting_comments_and_siblings() {
  let source = "# header\n\"root\" = { \"nested\" = { \"leaf\"   = 'before', keep = 42 }, other = true } # tail\n";
  let mut document: DocumentMut = source.parse().unwrap();
  let key = key_segments(None, "root.nested.leaf");

  assert_eq!(render_item(lookup(&document, &key).unwrap()), "before");
  insert(&mut document, &key, value("after")).unwrap();
  assert_eq!(document.to_string(), source.replace("'before'", "\"after\""));

  assert!(remove(&mut document, &key));
  assert!(lookup(&document, &key).is_none());
  assert_eq!(
    lookup(&document, &key_segments(None, "root.nested.keep")).and_then(Item::as_integer),
    Some(42)
  );
  assert!(document.to_string().starts_with("# header\n"));
  assert!(document.to_string().ends_with(" # tail\n"));
  let reparsed: DocumentMut = document.to_string().parse().unwrap();
  assert_eq!(
    lookup(&reparsed, &key_segments(None, "root.other")).and_then(Item::as_bool),
    Some(true)
  );
}

#[test]
fn creating_nested_tables_respects_the_existing_representation() {
  for source in ["[root]\nkeep = true\n", "root = { keep = true }\n"] {
    let mut document: DocumentMut = source.parse().unwrap();
    let key = key_segments(None, "root.new.deep.leaf");
    insert(&mut document, &key, value(42)).unwrap();
    let rendered = document.to_string();
    let reparsed: DocumentMut = rendered.parse().unwrap();

    assert_eq!(lookup(&reparsed, &key).and_then(Item::as_integer), Some(42));
    assert_eq!(
      lookup(&reparsed, &key_segments(None, "root.keep")).and_then(Item::as_bool),
      Some(true)
    );
    assert_eq!(document["root"].is_inline_table(), source.starts_with("root ="));
    assert!(remove(&mut document, &key));
    assert!(!remove(&mut document, &key));
  }
}

#[test]
fn replacing_normal_table_values_preserves_comments_and_spacing() {
  let source = "# header\n[root]\n# leaf note\n\"leaf\"  = 42 # tail\nkeep = true\n";
  let mut document: DocumentMut = source.parse().unwrap();
  insert(&mut document, &key_segments(None, "root.leaf"), value(43)).unwrap();
  assert_eq!(document.to_string(), source.replace("42", "43"));
}

#[test]
fn inline_cors_arrays_support_append_replace_and_unset() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  let source = V2_INIT_TEMPLATE.replace(
    "client_auth = \"none\"",
    "client_auth = \"none\"\ncors = { enabled = true, allowed_origins = [\"https://first.example\"] } # browser access",
  );
  std::fs::write(&path, &source).unwrap();
  let key = "listeners.api.cors.allowed_origins";

  set_key(&path, key, "https://second.example", true).unwrap();
  let raw = tokn_config::v2::load_raw(&path).unwrap();
  let tokn_config::v2::RawListener::LlmApi { cors, .. } = &raw.listeners["api"] else {
    panic!("API listener");
  };
  assert_eq!(
    cors.allowed_origins,
    ["https://first.example", "https://second.example"]
  );

  set_key(&path, key, "https://third.example, https://fourth.example", false).unwrap();
  let document = load_doc(&path).unwrap();
  let origins = lookup(&document, &key_segments(None, key)).unwrap().as_array().unwrap();
  assert_eq!(
    origins.iter().map(|item| item.as_str().unwrap()).collect::<Vec<_>>(),
    ["https://third.example", "https://fourth.example"]
  );
  set_key(&path, "listeners.api.cors.allow_localhost", "true", false).unwrap();
  unset_key(&path, key).unwrap();
  assert_eq!(read_key(&path, "listeners.api.cors.allow_localhost"), "true");
  let edited = std::fs::read_to_string(&path).unwrap();
  assert!(edited.contains("# browser access"));
  assert!(edited.contains("cors = {"));
  assert!(!edited.contains("allowed_origins"));
  tokn_config::v2::load_config(&path).unwrap();
}

#[test]
fn inline_edit_errors_leave_the_original_file_unchanged() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  std::fs::write(&path, V2_EXPLICIT_TEST_CONFIG).unwrap();

  for (key, value, add, message) in [
    ("routes.default.retry.policy", "missing", false, "missing"),
    ("routes.default.retry.policy.child", "value", false, "not a table"),
    ("routes.default.retry.policy", "other", true, "not an array"),
    ("routes.default.model.unknown", "value", false, "validation failed"),
  ] {
    let error = set_key(&path, key, value, add).unwrap_err().to_string();
    assert!(error.contains(message), "{key}: {error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), V2_EXPLICIT_TEST_CONFIG);
  }
  for key in [
    "routes.default.retry.policy",
    "listeners.api.default_http_action.profile",
  ] {
    let error = unset_key(&path, key).unwrap_err().to_string();
    assert!(error.contains("validation failed"), "{key}: {error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), V2_EXPLICIT_TEST_CONFIG);
  }
}

#[test]
fn table_inline_and_mixed_v2_forms_support_the_same_edits() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  let mixed = V2_EXPLICIT_TEST_CONFIG.replace(
    "model = { kind = \"capability\" }",
    "model = { kind = \"family\", families = { coding = [\"gpt-5\"] } }",
  );
  let raw = tokn_config::v2::decode(&mixed, &path).unwrap();
  let expanded = toml::to_string_pretty(&raw).unwrap();
  let mut document: DocumentMut = mixed.parse().unwrap();
  for (_, item) in document.iter_mut() {
    if item.is_table() {
      item.make_value();
    }
  }
  let inline = document.to_string();

  for source in [mixed, expanded, inline] {
    std::fs::write(&path, &source).unwrap();
    tokn_config::v2::load_config(&path).unwrap();

    set_key(&path, "routes.default.model.families.coding", "gpt-5-mini", true).unwrap();
    set_key(&path, "routes.default.model.families.testing", "gpt-5", true).unwrap();
    assert_eq!(read_key(&path, "routes.default.model.kind"), "family");
    let document = load_doc(&path).unwrap();
    assert_eq!(
      lookup(&document, &key_segments(None, "routes.default.model.families.coding"))
        .unwrap()
        .as_array()
        .unwrap()
        .len(),
      2
    );
    unset_key(&path, "routes.default.model.families.testing").unwrap();
    set_key(&path, "listeners.api.cors.allow_localhost", "true", false).unwrap();
    set_key(&path, "listeners.api.cors.enabled", "true", false).unwrap();
    assert_eq!(read_key(&path, "listeners.api.cors.enabled"), "true");
    unset_key(&path, "listeners.api.cors.enabled").unwrap();
    tokn_config::v2::load_config(&path).unwrap();
  }
}

#[test]
fn legacy_account_selectors_traverse_inline_values_without_touching_other_accounts() {
  let source = r#"[[accounts]]
id = "personal"
metadata = { label = "Personal" }

[[accounts]]
id = "work.account"
metadata = { label = "Work", tags = ["one"] } # retain
"#;
  let mut document: DocumentMut = source.parse().unwrap();
  let key = key_segments(Some("work.account"), "metadata.label");
  assert_eq!(render_item(lookup(&document, &key).unwrap()), "Work");
  insert(&mut document, &key, value("Updated")).unwrap();
  append_array(
    &mut document,
    &key_segments(Some("work.account"), "metadata.tags"),
    "two",
  )
  .unwrap();
  assert!(remove(&mut document, &key));
  assert!(lookup(&document, &key).is_none());
  assert_eq!(
    render_item(lookup(&document, &key_segments(Some("personal"), "metadata.label")).unwrap()),
    "Personal"
  );
  assert!(document.to_string().contains("# retain"));
  assert_eq!(document["accounts"].as_array_of_tables().unwrap().len(), 2);

  let new_key = key_segments(Some("new.account"), "metadata.label");
  insert(&mut document, &new_key, value("New")).unwrap();
  assert_eq!(render_item(lookup(&document, &new_key).unwrap()), "New");
  assert_eq!(document["accounts"].as_array_of_tables().unwrap().len(), 3);
}

#[test]
fn missing_paths_and_scalar_collisions_do_not_mutate_documents() {
  for source in ["[root]\nleaf = 42\n", "root = { leaf = 42 }\n"] {
    let mut document: DocumentMut = source.parse().unwrap();
    for path in ["root.missing", "root.missing.child", "root.leaf.child"] {
      let key = key_segments(None, path);
      assert!(lookup(&document, &key).is_none());
      assert!(!remove(&mut document, &key));
      assert_eq!(document.to_string(), source);
    }
    let error = insert(&mut document, &key_segments(None, "root.leaf.child"), value("x"))
      .unwrap_err()
      .to_string();
    assert!(error.contains("not a table"));
    assert_eq!(document.to_string(), source);
  }
}

#[test]
fn dotted_toml_keys_keep_their_layout_during_inline_edits() {
  for source in [
    "root.nested.leaf = 42 # note\nroot.keep = true\n",
    "root = { nested.leaf = 42, keep = true } # note\n",
  ] {
    let mut document: DocumentMut = source.parse().unwrap();
    let key = key_segments(None, "root.nested.leaf");
    assert_eq!(lookup(&document, &key).and_then(Item::as_integer), Some(42));
    insert(&mut document, &key, value(43)).unwrap();
    assert_eq!(document.to_string(), source.replace("42", "43"));
    assert!(remove(&mut document, &key));
    let reparsed: DocumentMut = document.to_string().parse().unwrap();
    assert_eq!(
      lookup(&reparsed, &key_segments(None, "root.keep")).and_then(Item::as_bool),
      Some(true)
    );
  }
}
