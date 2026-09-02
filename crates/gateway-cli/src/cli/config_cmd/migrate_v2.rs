use super::MigrateV2Args;
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;
use tokn_auth::AuthStore;
use tokn_config::{Config, ConfigSchema};
use tokn_core::account::AccountConfig;
use tokn_router_legacy_config::v2::{project_v2_config, V2ProjectionOptions, V2ProjectionWarning};

struct PreparedMigration {
  rendered: String,
  warnings: Vec<V2ProjectionWarning>,
}

pub(super) fn run(config_path: &Path, args: &MigrateV2Args) -> Result<()> {
  let stdout = std::io::stdout();
  let stderr = std::io::stderr();
  execute(config_path, args, None, &mut stdout.lock(), &mut stderr.lock())
}

fn execute(
  config_path: &Path,
  args: &MigrateV2Args,
  auth_path: Option<&Path>,
  stdout: &mut dyn Write,
  stderr: &mut dyn Write,
) -> Result<()> {
  let prepared = prepare(config_path, args, auth_path)?;
  emit(&prepared, stdout, stderr)
}

fn prepare(config_path: &Path, args: &MigrateV2Args, auth_path: Option<&Path>) -> Result<PreparedMigration> {
  if tokn_config::detect_config_schema(config_path)? == ConfigSchema::V2 {
    bail!(
      "config at {} already uses schema_version = 2; migrate-v2 accepts only legacy configs",
      config_path.display()
    );
  }

  let loaded = Config::load_with_sources(Some(config_path))
    .with_context(|| format!("load effective legacy config at {}", config_path.display()))?;
  let accounts = load_authoritative_accounts(config_path, auth_path)?;
  let forward_proxy = args.with_proxy.then(|| {
    let route_mode = args
      .proxy_route_mode
      .map(Into::into)
      .unwrap_or(loaded.config.proxy_mode.route_mode);
    crate::cli::v2_projection::forward_proxy_options(route_mode)
  });
  let projection = project_v2_config(
    &loaded.config,
    &accounts,
    V2ProjectionOptions {
      allow_insecure_http: args.allow_insecure_http,
      allow_insecure_public_listener: args.insecure_allow_remote,
      forward_proxy,
    },
  )
  .context("project effective legacy config into version 2")?;

  let rendered = toml::to_string_pretty(projection.raw_config()).context("render generated version 2 config")?;
  validate_rendered(config_path, &rendered, projection.accounts())?;

  Ok(PreparedMigration {
    rendered,
    warnings: projection.warnings().to_vec(),
  })
}

fn load_authoritative_accounts(config_path: &Path, auth_path: Option<&Path>) -> Result<Vec<AccountConfig>> {
  let store = AuthStore::load(auth_path, Some(config_path)).context("load current auth store")?;
  if store.has_persisted_sources() {
    return Ok(store.accounts);
  }

  Ok(
    tokn_router_legacy_config::schema::load_legacy_accounts(config_path)
      .with_context(|| format!("load embedded accounts from legacy config at {}", config_path.display()))?
      .unwrap_or_default(),
  )
}

fn validate_rendered(config_path: &Path, rendered: &str, accounts: &[AccountConfig]) -> Result<()> {
  let compiled = tokn_config::v2::parse_config(rendered, config_path)
    .with_context(|| format!("validate rendered version 2 config for {}", config_path.display()))?;
  let registry = tokn_router::accounts::registry::Registry::builtin();
  let providers = tokn_router::accounts::link::link_provider_graph(compiled.gateway(), accounts, &registry)
    .context("link generated version 2 providers against current accounts")?;
  tokn_router::accounts::link::link_account_pools(compiled.gateway(), &providers)
    .context("link generated version 2 account pools")?;
  Ok(())
}

fn emit(prepared: &PreparedMigration, stdout: &mut dyn Write, stderr: &mut dyn Write) -> Result<()> {
  stdout
    .write_all(prepared.rendered.as_bytes())
    .context("write generated version 2 config to stdout")?;
  stdout.flush().context("flush generated version 2 config")?;
  for warning in &prepared.warnings {
    writeln!(stderr, "warning: {warning}").context("write migration warning to stderr")?;
  }
  stderr.flush().context("flush migration warnings")?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::{Cli, Cmd};
  use clap::Parser;
  use std::collections::BTreeMap;
  use std::fs;
  use std::path::{Path, PathBuf};

  fn args() -> MigrateV2Args {
    MigrateV2Args::default()
  }

  fn account(id: &str, provider: &str) -> AccountConfig {
    toml::from_str(&format!(
      "id = {id:?}\nprovider = {provider:?}\nenabled = true\napi_key = \"migration-secret\"\n"
    ))
    .unwrap()
  }

  fn write_auth(path: &Path, accounts: impl IntoIterator<Item = AccountConfig>) {
    let mut store = AuthStore::load(Some(path), None).unwrap();
    for account in accounts {
      store.upsert(account);
    }
    store.save().unwrap();
  }

  fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
      let mut entries = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
      entries.sort();
      for entry in entries {
        if entry.is_dir() {
          visit(root, &entry, snapshot);
        } else {
          snapshot.insert(
            entry.strip_prefix(root).unwrap().to_path_buf(),
            fs::read(entry).unwrap(),
          );
        }
      }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
  }

  #[test]
  fn clap_parses_read_only_preview_options() {
    let cli = Cli::try_parse_from([
      "tokn-router",
      "config",
      "migrate-v2",
      "--with-proxy",
      "--proxy-route-mode",
      "passthrough",
      "--insecure-allow-remote",
      "--allow-insecure-http",
    ])
    .unwrap();
    let Cmd::Config(config) = cli.cmd else {
      panic!("expected config command")
    };
    assert!(config.requires_pristine_startup());
    let super::super::ConfigCmd::MigrateV2(parsed) = config.cmd else {
      panic!("expected migrate-v2 command")
    };
    assert!(parsed.with_proxy);
    assert!(matches!(
      parsed.proxy_route_mode,
      Some(super::super::RouteModeArg::Passthrough)
    ));
    assert!(parsed.insecure_allow_remote);
    assert!(parsed.allow_insecure_http);

    let error =
      Cli::try_parse_from(["tokn-router", "config", "migrate-v2", "--proxy-route-mode", "route"]).unwrap_err();
    assert!(error.to_string().contains("--with-proxy"));
  }

  #[test]
  fn preview_merges_fragments_uses_auth_and_never_writes() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    fs::write(
      &config_path,
      r#"
[defaults]
accounts = ["primary"]

[server.cors]
enabled = true
allow_localhost = true
allowed_origins = ["https://APP.example:443/"]

[logging]
level = "warn,tokn_router=debug"
format = "json"
target = "file"
dir = "migration-test-logs"
ansi = false
include_spans = true

[pool]
session_ttl_secs = 1800
session_tombstone_secs = 7200
"#,
    )
    .unwrap();
    let fragment_path = tokn_config::paths::agent_config_fragment_path(&config_path, "opencode");
    fs::create_dir_all(fragment_path.parent().unwrap()).unwrap();
    fs::write(
      &fragment_path,
      r#"
[agents.opencode]
profile = "opencode"

[profiles.opencode]
agent_id = "opencode"
accounts = ["primary"]
"#,
    )
    .unwrap();
    write_auth(&auth_path, [account("primary", "openai")]);
    let before = snapshot_tree(directory.path());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    execute(&config_path, &args(), Some(&auth_path), &mut stdout, &mut stderr).unwrap();

    assert_eq!(snapshot_tree(directory.path()), before);
    let rendered = std::str::from_utf8(&stdout).unwrap();
    let raw = tokn_config::v2::decode(rendered, &config_path).unwrap();
    assert!(raw.profiles.contains_key("default"));
    assert!(raw.profiles.contains_key("opencode"));
    assert!(!rendered.contains("migration-secret"));
    let legacy = Config::load(Some(&config_path)).unwrap().0;
    let compiled = tokn_config::v2::parse_config(rendered, &config_path).unwrap();
    assert_eq!(compiled.service().logging(), &legacy.logging);
    let tokn_policy::ListenerPlan::LlmApi(listener) = &compiled.gateway().listeners()["api"] else {
      panic!("expected projected API listener");
    };
    assert!(listener.cors().allow_localhost());
    assert_eq!(
      listener.cors().allowed_origins(),
      &legacy.server.cors.canonical_allowed_origins().unwrap()
    );
    assert!(!String::from_utf8_lossy(&stderr).contains("CORS"));
    for pool in compiled.gateway().account_pools().values() {
      let affinity = pool.session_affinity().unwrap();
      assert_eq!(affinity.ttl().as_secs(), 1800);
      assert_eq!(affinity.expired_retention().as_secs(), 5400);
    }
    assert_eq!(
      rendered,
      toml::to_string_pretty(&tokn_config::v2::decode(rendered, &config_path).unwrap()).unwrap()
    );
    let diagnostics = std::str::from_utf8(&stderr).unwrap();
    assert!(diagnostics.lines().all(|line| line.starts_with("warning: ")));
    assert!(diagnostics.contains("legacy agent bindings"));
  }

  #[test]
  fn preview_can_include_the_legacy_forward_proxy() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    fs::write(&config_path, "[proxy_mode]\nroute_mode = \"route\"\n").unwrap();
    write_auth(&auth_path, [account("primary", "openai")]);
    let mut args = args();
    args.with_proxy = true;
    args.proxy_route_mode = Some(super::super::RouteModeArg::Passthrough);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    execute(&config_path, &args, Some(&auth_path), &mut stdout, &mut stderr).unwrap();

    let raw = tokn_config::v2::decode(std::str::from_utf8(&stdout).unwrap(), &config_path).unwrap();
    assert_eq!(raw.listeners.len(), 2);
    assert!(raw.listeners.contains_key("api"));
    assert!(raw.listeners.contains_key("proxy"));
  }

  #[test]
  fn embedded_accounts_are_previewed_only_when_modern_auth_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    fs::write(
      &config_path,
      r#"
[[accounts]]
id = "embedded"
provider = "openai"
enabled = true
api_key = "embedded-secret"
"#,
    )
    .unwrap();

    let accounts = load_authoritative_accounts(&config_path, Some(&auth_path)).unwrap();
    assert_eq!(
      accounts.iter().map(|account| account.id.as_str()).collect::<Vec<_>>(),
      ["embedded"]
    );

    fs::write(&auth_path, "version: 1\naccounts: []\n").unwrap();
    assert!(load_authoritative_accounts(&config_path, Some(&auth_path))
      .unwrap()
      .is_empty());
  }

  #[test]
  fn failure_emits_no_partial_preview() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    fs::write(&config_path, "schema_version = 2\n").unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = execute(&config_path, &args(), Some(&auth_path), &mut stdout, &mut stderr).unwrap_err();

    assert!(error.to_string().contains("already uses schema_version = 2"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
  }
}
