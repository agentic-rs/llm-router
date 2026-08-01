use super::{MigrateV2Args, V2ActivationArg};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use tokn_auth::AuthStore;
use tokn_core::account::AccountConfig;
use tokn_router_legacy_config::v2::{
  plan_v2_migration, V2BehaviorChange, V2ListenerSelection, V2MigrationOptions, V2MigrationWarning,
};

struct PreparedMigration {
  rendered: String,
  warnings: Vec<String>,
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
  let loaded = tokn_config::Config::load_with_sources(Some(config_path))
    .with_context(|| format!("load effective legacy config `{}`", config_path.display()))?;
  let accounts = load_authoritative_accounts(config_path, auth_path)?;
  let plan = plan_v2_migration(
    &loaded.config,
    &accounts,
    V2MigrationOptions {
      listener_selection: args.activate.listener_selection(),
      allow_insecure_upstreams: args.allow_insecure_upstreams,
    },
  )
  .context("plan version 2 config migration")?;

  let rendered = toml::to_string_pretty(plan.raw_config()).context("render generated version 2 config")?;
  let compiled = tokn_config::v2::parse(&rendered, config_path)
    .with_context(|| format!("parse generated version 2 config for `{}`", config_path.display()))?;
  tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &accounts)
    .context("link generated version 2 gateway runtime")?;

  Ok(PreparedMigration {
    rendered,
    warnings: plan.warnings().iter().map(render_warning).collect(),
  })
}

fn load_authoritative_accounts(config_path: &Path, auth_path: Option<&Path>) -> Result<Vec<AccountConfig>> {
  let store = AuthStore::load(auth_path, None).context("load modern credential sources")?;
  let has_modern_source = store
    .sources()
    .iter()
    .any(|source| store.source_sha256(source).is_some());
  if has_modern_source {
    return Ok(store.accounts);
  }

  Ok(
    tokn_router_legacy_config::schema::load_legacy_accounts(config_path)
      .with_context(|| format!("load embedded accounts from `{}`", config_path.display()))?
      .unwrap_or_default(),
  )
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

impl V2ActivationArg {
  fn listener_selection(self) -> V2ListenerSelection {
    match self {
      Self::Api => V2ListenerSelection::Api,
      Self::Proxy => V2ListenerSelection::Proxy,
      Self::Both => V2ListenerSelection::ApiAndProxy,
    }
  }
}

fn render_warning(warning: &V2MigrationWarning) -> String {
  match warning {
    V2MigrationWarning::BehaviorChange(change) => render_behavior_change(*change).to_string(),
    V2MigrationWarning::LegacyServerRouteModeUsed { mode } => {
      format!("legacy server.route_mode {mode:?} supplied the effective default route mode")
    }
    V2MigrationWarning::ProfileResourceRenamed { profile, resource_id } => {
      format!("legacy profile {profile:?} was assigned version 2 resource id {resource_id:?}")
    }
    V2MigrationWarning::CleartextUpstreamAllowed { accounts, base_url } => {
      format!("non-loopback cleartext upstream {base_url:?} was explicitly allowed for accounts {accounts:?}")
    }
    V2MigrationWarning::LegacyPoolStrategyIgnored { strategy } => {
      format!("legacy pool strategy {strategy:?} is not represented; generated pools use round_robin")
    }
    V2MigrationWarning::LegacySystemProxyShadowedByExplicitProxy => {
      "legacy proxy.system was ineffective because proxy.url was set; the generated config keeps the explicit proxy"
        .to_string()
    }
    V2MigrationWarning::LegacyNoProxyWithoutExplicitProxyIgnored => {
      "legacy proxy.no_proxy was ineffective without proxy.url and is omitted from the generated config".to_string()
    }
  }
}

fn render_behavior_change(change: V2BehaviorChange) -> &'static str {
  match change {
    V2BehaviorChange::AuxiliaryApiEndpoints => {
      "legacy model and provider discovery endpoints are not exposed by the generated version 2 listener"
    }
    V2BehaviorChange::ManagedSelectionOrder => {
      "managed account selection may differ because version 2 selects through explicit pool and upstream resources"
    }
    V2BehaviorChange::ManagedRetryPolicy => {
      "legacy request-pipeline retries are not represented by the generated managed routes"
    }
    V2BehaviorChange::OperationalSettings => {
      "legacy persistence and logging settings are not represented by the current version 2 service schema"
    }
    V2BehaviorChange::Cors => "legacy CORS settings are not represented by the generated version 2 listener",
    V2BehaviorChange::AgentBindings => {
      "legacy agent link-management metadata is not represented by the generated routing graph"
    }
    V2BehaviorChange::PercentDecodedProfileAliases => {
      "named profiles accept only their generated canonical encoded paths, not legacy percent-decoded aliases"
    }
    V2BehaviorChange::HttpRejectionBehavior => {
      "unmatched paths, methods, and operations use the version 2 rejection response contract"
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::{Cli, Cmd};
  use clap::Parser;
  use std::fs;

  fn args(activate: V2ActivationArg) -> MigrateV2Args {
    MigrateV2Args {
      activate,
      allow_insecure_upstreams: false,
    }
  }

  fn legacy_config(path: &Path) {
    fs::write(
      path,
      r#"
[[accounts]]
id = "embedded"
provider = "openai"
enabled = true
api_key = "migration-secret"
"#,
    )
    .unwrap();
  }

  #[test]
  fn clap_requires_activation_and_maps_every_selection() {
    assert!(Cli::try_parse_from(["tokn-router", "config", "migrate-v2"]).is_err());

    for (value, expected) in [
      ("api", V2ListenerSelection::Api),
      ("proxy", V2ListenerSelection::Proxy),
      ("both", V2ListenerSelection::ApiAndProxy),
    ] {
      let cli = Cli::try_parse_from([
        "tokn-router",
        "config",
        "migrate-v2",
        "--activate",
        value,
        "--allow-insecure-upstreams",
      ])
      .unwrap();
      let Cmd::Config(config) = cli.cmd else {
        panic!("expected config command")
      };
      assert!(config.requires_pristine_startup());
      let super::super::ConfigCmd::MigrateV2(ref parsed) = config.cmd else {
        panic!("expected migrate-v2 command")
      };
      assert_eq!(parsed.activate.listener_selection(), expected);
      assert!(parsed.allow_insecure_upstreams);
    }
  }

  #[test]
  fn modern_source_is_authoritative_even_when_empty() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);

    let embedded = load_authoritative_accounts(&config_path, Some(&auth_path)).unwrap();
    assert_eq!(
      embedded.iter().map(|account| account.id.as_str()).collect::<Vec<_>>(),
      ["embedded"]
    );

    fs::write(&auth_path, "version: 1\naccounts: []\n").unwrap();
    assert!(load_authoritative_accounts(&config_path, Some(&auth_path))
      .unwrap()
      .is_empty());
  }

  #[test]
  fn execution_keeps_streams_empty_until_preflight_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("missing-auth.yaml");
    legacy_config(&config_path);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = execute(
      &config_path,
      &args(V2ActivationArg::Proxy),
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("does not yet support"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
  }

  #[test]
  fn execution_rejects_proxy_credentials_without_disclosing_them() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("missing-auth.yaml");
    fs::write(
      &config_path,
      r#"
[[accounts]]
id = "embedded"
provider = "openai"
enabled = true

[proxy]
url = "http://user:sentinel-password@proxy.example"
"#,
    )
    .unwrap();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = execute(
      &config_path,
      &args(V2ActivationArg::Api),
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
    )
    .unwrap_err();

    assert!(!format!("{error:#}").contains("sentinel-password"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
  }

  #[test]
  fn execution_emits_exact_parseable_toml_and_human_warnings() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("missing-auth.yaml");
    legacy_config(&config_path);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    execute(
      &config_path,
      &args(V2ActivationArg::Api),
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
    )
    .unwrap();

    let rendered = std::str::from_utf8(&stdout).unwrap();
    tokn_config::v2::parse(rendered, &config_path).unwrap();
    assert_eq!(
      rendered,
      toml::to_string_pretty(&tokn_config::v2::decode(rendered, &config_path).unwrap()).unwrap()
    );
    assert!(!rendered.contains("migration-secret"));
    let diagnostics = std::str::from_utf8(&stderr).unwrap();
    assert!(diagnostics.lines().all(|line| line.starts_with("warning: ")));
    assert!(diagnostics.contains("persistence and logging"));
  }
}
