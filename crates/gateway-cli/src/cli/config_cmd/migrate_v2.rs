use super::{MigrateV2Args, V2ActivationArg};
use anyhow::{bail, Context, Result};
use inquire::Confirm;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokn_auth::{AuthSource, AuthStore};
use tokn_config::StableLoadedConfig;
use tokn_core::account::AccountConfig;
use tokn_router_legacy_config::v2::{
  plan_v2_migration, V2BehaviorChange, V2ListenerSelection, V2MigrationOptions, V2MigrationWarning,
};

mod apply;
mod backup;

struct PreparedMigration {
  output: PlannedOutput,
  legacy: StableLoadedConfig,
  auth_path: PathBuf,
  auth_preimage: AuthPreimage,
  embedded_accounts: Vec<AccountConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PlannedOutput {
  rendered: String,
  warnings: Vec<String>,
}

#[derive(Clone, Eq, PartialEq)]
struct AuthPreimage {
  sources: Vec<(AuthSource, Option<String>)>,
}

pub(super) fn run(config_path: &Path, args: &MigrateV2Args) -> Result<()> {
  let stdout = std::io::stdout();
  let stderr = std::io::stderr();
  let mut confirm = |prompt: &str| {
    Confirm::new(prompt)
      .with_default(false)
      .prompt()
      .context("version 2 migration confirmation cancelled")
  };
  execute_with_confirmation(
    config_path,
    args,
    None,
    &mut stdout.lock(),
    &mut stderr.lock(),
    &mut confirm,
  )
}

#[cfg(test)]
fn execute(
  config_path: &Path,
  args: &MigrateV2Args,
  auth_path: Option<&Path>,
  stdout: &mut dyn Write,
  stderr: &mut dyn Write,
) -> Result<()> {
  let mut unexpected_confirmation = |_: &str| bail!("unexpected migration confirmation");
  execute_with_confirmation(
    config_path,
    args,
    auth_path,
    stdout,
    stderr,
    &mut unexpected_confirmation,
  )
}

fn execute_with_confirmation(
  config_path: &Path,
  args: &MigrateV2Args,
  auth_path: Option<&Path>,
  stdout: &mut dyn Write,
  stderr: &mut dyn Write,
  confirm: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<()> {
  if validate_already_v2(config_path, auth_path)? {
    if !args.apply {
      bail!(
        "config `{}` already uses schema version 2; no migration preview is needed",
        config_path.display()
      );
    }
    writeln!(
      stderr,
      "version 2 config `{}` is already active and valid; no files changed",
      config_path.display()
    )
    .context("write already-active migration result")?;
    stderr.flush().context("flush already-active migration result")?;
    return Ok(());
  }

  let prepared = prepare(config_path, args, auth_path)?;
  if !args.apply {
    return emit_dry_run(&prepared.output, stdout, stderr);
  }

  let legacy_contents = prepared
    .legacy
    .snapshot
    .root_preimage()
    .ok_or_else(|| anyhow::anyhow!("cannot apply a migration without an existing legacy config root"))?;
  if !prepared.legacy.snapshot.fragments().is_empty() && !args.flatten_config_d {
    bail!(
      "the effective legacy config includes {} config.d fragment(s); inspect the preview and rerun with \
       --flatten-config-d to acknowledge that they will be retained but inactive under version 2",
      prepared.legacy.snapshot.fragments().len()
    );
  }
  let backup_path = backup::legacy_backup_path(prepared.legacy.snapshot.root())?;
  emit_apply_preview(&prepared, &backup_path, stderr)?;
  if !args.yes && !confirm("Back up the legacy config and activate version 2?")? {
    writeln!(stderr, "migration cancelled; no files changed").context("write migration cancellation")?;
    stderr.flush().context("flush migration cancellation")?;
    return Ok(());
  }

  let mut checkpoint = |_| Ok(());
  match apply::apply(&prepared, args, legacy_contents, &mut checkpoint) {
    Ok(report) => {
      writeln!(
        stderr,
        "activated version 2 config `{}`; {} legacy backup `{}`{}",
        report.config_path.display(),
        if report.backup_created { "created" } else { "reused" },
        report.backup_path.display(),
        if report.auth_created {
          "; embedded credentials were installed in modern auth"
        } else {
          ""
        }
      )
      .context("write migration success")?;
      stderr.flush().context("flush migration success")?;
      Ok(())
    }
    Err(failure) => {
      emit_apply_failure(&failure, stderr)?;
      Err(failure.into_error())
    }
  }
}

fn prepare(config_path: &Path, args: &MigrateV2Args, auth_path: Option<&Path>) -> Result<PreparedMigration> {
  let legacy = tokn_config::Config::load_stable(Some(config_path))
    .with_context(|| format!("load stable effective legacy config `{}`", config_path.display()))?;
  let (store, auth_preimage) = load_stable_auth(auth_path)?;
  let embedded_accounts = if auth_preimage.has_persisted_sources() {
    Vec::new()
  } else {
    legacy
      .snapshot
      .root_preimage()
      .map(|contents| tokn_router_legacy_config::schema::parse_legacy_accounts(contents, legacy.snapshot.root()))
      .transpose()
      .with_context(|| format!("load embedded accounts from `{}`", legacy.snapshot.root().display()))?
      .flatten()
      .unwrap_or_default()
  };
  let accounts = if auth_preimage.has_persisted_sources() {
    &store.accounts
  } else {
    &embedded_accounts
  };
  let output = plan_output(&legacy.config, accounts, config_path, args)?;

  Ok(PreparedMigration {
    output,
    legacy,
    auth_path: store.path().to_path_buf(),
    auth_preimage,
    embedded_accounts,
  })
}

fn plan_output(
  legacy: &tokn_config::Config,
  accounts: &[AccountConfig],
  config_path: &Path,
  args: &MigrateV2Args,
) -> Result<PlannedOutput> {
  let plan = plan_v2_migration(
    legacy,
    accounts,
    V2MigrationOptions {
      listener_selection: args.activate.listener_selection(),
      allow_insecure_upstreams: args.allow_insecure_upstreams,
    },
  )
  .context("plan version 2 config migration")?;

  let rendered = toml::to_string_pretty(plan.raw_config()).context("render generated version 2 config")?;
  let compiled = tokn_config::v2::parse(&rendered, config_path)
    .with_context(|| format!("parse generated version 2 config for `{}`", config_path.display()))?;
  tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), accounts)
    .context("link generated version 2 gateway runtime")?;

  Ok(PlannedOutput {
    rendered,
    warnings: plan.warnings().iter().map(render_warning).collect(),
  })
}

fn load_stable_auth(auth_path: Option<&Path>) -> Result<(AuthStore, AuthPreimage)> {
  let first = AuthStore::load(auth_path, None).context("load modern credential sources")?;
  let first_preimage = AuthPreimage::capture(&first);
  let second = AuthStore::load(auth_path, None).context("reload modern credential sources")?;
  let second_preimage = AuthPreimage::capture(&second);
  if first_preimage != second_preimage {
    bail!("modern credential sources changed while they were being loaded; retry the command");
  }
  Ok((second, second_preimage))
}

fn validate_already_v2(config_path: &Path, auth_path: Option<&Path>) -> Result<bool> {
  let snapshot = tokn_config::ConfigFileSnapshot::capture(config_path)
    .with_context(|| format!("capture config root `{}` for schema detection", config_path.display()))?;
  let Some(contents) = snapshot.contents() else {
    return Ok(false);
  };
  let contents = std::str::from_utf8(contents)
    .with_context(|| format!("read config `{}` as UTF-8 for schema detection", config_path.display()))?;
  let raw = match tokn_config::v2::decode(contents, config_path) {
    Ok(raw) => raw,
    Err(tokn_config::v2::Error::MissingSchemaVersion { .. }) => return Ok(false),
    Err(error) => return Err(error).context("validate existing version 2 config syntax"),
  };
  let compiled = tokn_config::v2::compile(&raw, config_path).context("compile existing version 2 config")?;
  let (store, auth_preimage) = load_stable_auth(auth_path)?;
  tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &store.accounts)
    .context("link existing version 2 gateway runtime")?;

  snapshot
    .validate()
    .context("revalidate existing version 2 config after runtime linking")?;
  let (_, final_auth_preimage) = load_stable_auth(auth_path)?;
  if final_auth_preimage != auth_preimage {
    bail!(
      "modern credential sources changed while the existing version 2 config was being validated; retry the command"
    );
  }
  snapshot
    .validate()
    .context("revalidate existing version 2 config after credential validation")?;
  Ok(true)
}

fn emit_dry_run(output: &PlannedOutput, stdout: &mut dyn Write, stderr: &mut dyn Write) -> Result<()> {
  stdout
    .write_all(output.rendered.as_bytes())
    .context("write generated version 2 config to stdout")?;
  stdout.flush().context("flush generated version 2 config")?;
  emit_warnings(output, stderr)?;
  stderr.flush().context("flush migration warnings")?;
  Ok(())
}

fn emit_warnings(output: &PlannedOutput, stderr: &mut dyn Write) -> Result<()> {
  for warning in &output.warnings {
    writeln!(stderr, "warning: {warning}").context("write migration warning to stderr")?;
  }
  Ok(())
}

fn emit_apply_preview(prepared: &PreparedMigration, backup_path: &Path, stderr: &mut dyn Write) -> Result<()> {
  emit_warnings(&prepared.output, stderr)?;
  writeln!(stderr, "config: {}", prepared.legacy.snapshot.root().display()).context("write migration target")?;
  writeln!(stderr, "legacy backup: {}", backup_path.display()).context("write migration backup target")?;
  if prepared.auth_preimage.has_persisted_sources() {
    writeln!(
      stderr,
      "auth: preserve authoritative modern sources rooted at {}",
      prepared.auth_path.display()
    )
    .context("write migration auth summary")?;
  } else {
    writeln!(
      stderr,
      "auth: install {} embedded account(s) at {} before activation",
      prepared.embedded_accounts.len(),
      prepared.auth_path.display()
    )
    .context("write migration auth summary")?;
  }
  if !prepared.legacy.snapshot.fragments().is_empty() {
    writeln!(
      stderr,
      "config.d: flatten {} effective fragment(s); retain their files unchanged but inactive",
      prepared.legacy.snapshot.fragments().len()
    )
    .context("write migration fragment summary")?;
  }
  stderr.flush().context("flush migration preview")?;
  Ok(())
}

fn emit_apply_failure(failure: &apply::ApplyFailure, stderr: &mut dyn Write) -> Result<()> {
  if failure.activation_may_have_completed() {
    writeln!(
      stderr,
      "warning: version 2 activation may already be complete at {}; do not restore automatically; inspect the active config before taking further action",
      failure.config_path().display()
    )
    .context("write post-activation failure guidance")?;
  } else if failure.auth_created() {
    writeln!(
      stderr,
      "warning: modern credentials are durable at {}, but the legacy config remains active; fix the error and rerun",
      failure.auth_path().display()
    )
    .context("write partial migration guidance")?;
  }
  stderr.flush().context("flush migration failure guidance")?;
  Ok(())
}

impl AuthPreimage {
  fn capture(store: &AuthStore) -> Self {
    Self {
      sources: store
        .sources()
        .into_iter()
        .map(|source| {
          let sha256 = store.source_sha256(&source);
          (source, sha256)
        })
        .collect(),
    }
  }

  fn has_persisted_sources(&self) -> bool {
    self.sources.iter().any(|(_, sha256)| sha256.is_some())
  }
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
      apply: false,
      yes: false,
      flatten_config_d: false,
    }
  }

  fn apply_args() -> MigrateV2Args {
    MigrateV2Args {
      apply: true,
      yes: true,
      ..args(V2ActivationArg::Api)
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
      assert!(!parsed.apply);
      assert!(!parsed.yes);
      assert!(!parsed.flatten_config_d);
    }

    for flag in ["--yes", "--flatten-config-d"] {
      assert!(Cli::try_parse_from(["tokn-router", "config", "migrate-v2", "--activate", "api", flag,]).is_err());
    }
  }

  #[test]
  fn modern_source_is_authoritative_even_when_empty() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);

    let (missing_store, missing_preimage) = load_stable_auth(Some(&auth_path)).unwrap();
    assert!(!missing_preimage.has_persisted_sources());
    assert!(missing_store.accounts.is_empty());
    let prepared = prepare(&config_path, &args(V2ActivationArg::Api), Some(&auth_path)).unwrap();
    assert_eq!(
      prepared
        .embedded_accounts
        .iter()
        .map(|account| account.id.as_str())
        .collect::<Vec<_>>(),
      ["embedded"]
    );

    fs::write(&auth_path, "version: 1\naccounts: []\n").unwrap();
    let (empty_store, empty_preimage) = load_stable_auth(Some(&auth_path)).unwrap();
    assert!(empty_preimage.has_persisted_sources());
    assert!(empty_store.accounts.is_empty());
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

  #[test]
  fn declined_apply_is_read_only_and_does_not_acquire_locks() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let original = fs::read(&config_path).unwrap();
    let mut args = apply_args();
    args.yes = false;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut confirmations = 0;
    let mut decline = |_: &str| {
      confirmations += 1;
      Ok(false)
    };

    execute_with_confirmation(
      &config_path,
      &args,
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
      &mut decline,
    )
    .unwrap();

    assert_eq!(confirmations, 1);
    assert!(stdout.is_empty());
    assert!(std::str::from_utf8(&stderr).unwrap().contains("no files changed"));
    assert!(!std::str::from_utf8(&stderr).unwrap().contains("migration-secret"));
    assert_eq!(fs::read(&config_path).unwrap(), original);
    assert!(!auth_path.exists());
    assert!(!backup::legacy_backup_path(&config_path).unwrap().exists());
    assert!(!directory.path().join(".config.toml.lock").exists());
    assert!(!directory.path().join(".auth.yaml.lock").exists());
  }

  #[test]
  fn apply_installs_credentials_before_activating_exact_v2_config() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let original = fs::read(&config_path).unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut unexpected_confirmation = |_: &str| -> Result<bool> { panic!("--yes must skip confirmation") };

    execute_with_confirmation(
      &config_path,
      &apply_args(),
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
      &mut unexpected_confirmation,
    )
    .unwrap();

    assert!(stdout.is_empty());
    let activated = fs::read_to_string(&config_path).unwrap();
    let compiled = tokn_config::v2::parse(&activated, &config_path).unwrap();
    let store = AuthStore::load(Some(&auth_path), None).unwrap();
    tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &store.accounts).unwrap();
    assert_eq!(store.accounts.len(), 1);
    assert_eq!(store.accounts[0].id, "embedded");
    assert!(!activated.contains("migration-secret"));
    let backup_path = backup::legacy_backup_path(&config_path).unwrap();
    assert_eq!(fs::read(&backup_path).unwrap(), original);
    let diagnostics = std::str::from_utf8(&stderr).unwrap();
    assert!(diagnostics.contains("activated version 2 config"));
    assert!(!diagnostics.contains("migration-secret"));
  }

  #[test]
  fn apply_requires_explicit_fragment_flattening_and_retains_fragment_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let fragment_path = tokn_config::paths::agent_config_fragment_path(&config_path, "opencode");
    fs::create_dir_all(fragment_path.parent().unwrap()).unwrap();
    let fragment = br#"
[agents.opencode]
profile = "opencode"

[profiles.opencode]
agent_id = "opencode"
mode = "route"
"#;
    fs::write(&fragment_path, fragment).unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut unexpected_confirmation = |_: &str| -> Result<bool> { panic!("preflight must not confirm") };

    let error = execute_with_confirmation(
      &config_path,
      &apply_args(),
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
      &mut unexpected_confirmation,
    )
    .unwrap_err();

    assert!(
      error.to_string().contains("--flatten-config-d"),
      "unexpected error: {error:#}"
    );
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(!backup::legacy_backup_path(&config_path).unwrap().exists());
    assert!(!auth_path.exists());

    let mut flattened = apply_args();
    flattened.flatten_config_d = true;
    execute_with_confirmation(
      &config_path,
      &flattened,
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
      &mut unexpected_confirmation,
    )
    .unwrap();

    tokn_config::v2::load(&config_path).unwrap();
    assert_eq!(fs::read(fragment_path).unwrap(), fragment);
  }

  #[test]
  fn interrupted_after_credentials_is_forward_retryable() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let original = fs::read(&config_path).unwrap();
    let prepared = prepare(&config_path, &apply_args(), Some(&auth_path)).unwrap();
    let legacy_contents = prepared.legacy.snapshot.root_preimage().unwrap().to_vec();
    let mut interrupt = |checkpoint| {
      if checkpoint == apply::ApplyCheckpoint::CredentialsDurable {
        bail!("injected interruption after credentials")
      }
      Ok(())
    };

    let failure = apply::apply(&prepared, &apply_args(), &legacy_contents, &mut interrupt).unwrap_err();

    assert!(!failure.activation_may_have_completed());
    assert!(failure.auth_created());
    assert!(format!("{:#}", failure.into_error()).contains("injected interruption"));
    assert_eq!(fs::read(&config_path).unwrap(), original);
    assert_eq!(
      fs::read(backup::legacy_backup_path(&config_path).unwrap()).unwrap(),
      original
    );
    assert_eq!(AuthStore::load(Some(&auth_path), None).unwrap().accounts.len(), 1);

    let retried = prepare(&config_path, &apply_args(), Some(&auth_path)).unwrap();
    let retry_contents = retried.legacy.snapshot.root_preimage().unwrap().to_vec();
    let mut uninterrupted = |_| Ok(());
    let report = apply::apply(&retried, &apply_args(), &retry_contents, &mut uninterrupted)
      .unwrap_or_else(|failure| panic!("retry failed: {:#}", failure.into_error()));

    assert!(!report.backup_created);
    assert!(!report.auth_created);
    let active = fs::read_to_string(&config_path).unwrap();
    let compiled = tokn_config::v2::parse(&active, &config_path).unwrap();
    let store = AuthStore::load(Some(&auth_path), None).unwrap();
    tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &store.accounts).unwrap();
  }

  #[test]
  fn credential_change_after_durable_checkpoint_prevents_activation() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let original = fs::read(&config_path).unwrap();
    let prepared = prepare(&config_path, &apply_args(), Some(&auth_path)).unwrap();
    let legacy_contents = prepared.legacy.snapshot.root_preimage().unwrap().to_vec();
    let mut mutate_auth = |checkpoint| {
      if checkpoint == apply::ApplyCheckpoint::CredentialsDurable {
        let current = fs::read_to_string(&auth_path).context("read durable auth in checkpoint")?;
        let changed = current.replace("migration-secret", "externally-changed-secret");
        assert_ne!(changed, current);
        fs::write(&auth_path, changed).context("mutate durable auth in checkpoint")?;
      }
      Ok(())
    };

    let failure = apply::apply(&prepared, &apply_args(), &legacy_contents, &mut mutate_auth).unwrap_err();

    assert!(!failure.activation_may_have_completed());
    assert!(failure.auth_created());
    assert!(format!("{:#}", failure.into_error()).contains("changed after loading the auth store"));
    assert_eq!(fs::read(&config_path).unwrap(), original);
  }

  #[test]
  fn config_change_at_activation_boundary_is_never_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let prepared = prepare(&config_path, &apply_args(), Some(&auth_path)).unwrap();
    let legacy_contents = prepared.legacy.snapshot.root_preimage().unwrap().to_vec();
    let external = b"externally replaced config\n";
    let mut mutate_config = |checkpoint| {
      if checkpoint == apply::ApplyCheckpoint::BeforeActivation {
        fs::write(&config_path, external).context("mutate config at activation boundary")?;
      }
      Ok(())
    };

    let failure = apply::apply(&prepared, &apply_args(), &legacy_contents, &mut mutate_config).unwrap_err();

    assert!(!failure.activation_may_have_completed());
    assert!(failure.auth_created());
    assert!(format!("{:#}", failure.into_error()).contains("revalidate legacy config at activation"));
    assert_eq!(fs::read(&config_path).unwrap(), external);
  }

  #[test]
  fn failure_after_activation_reports_ambiguous_active_state() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    legacy_config(&config_path);
    let prepared = prepare(&config_path, &apply_args(), Some(&auth_path)).unwrap();
    let legacy_contents = prepared.legacy.snapshot.root_preimage().unwrap().to_vec();
    let mut interrupt = |checkpoint| {
      if checkpoint == apply::ApplyCheckpoint::Activated {
        bail!("injected interruption after activation")
      }
      Ok(())
    };

    let failure = apply::apply(&prepared, &apply_args(), &legacy_contents, &mut interrupt).unwrap_err();

    assert!(failure.activation_may_have_completed());
    let mut diagnostics = Vec::new();
    emit_apply_failure(&failure, &mut diagnostics).unwrap();
    let diagnostics = std::str::from_utf8(&diagnostics).unwrap();
    assert!(diagnostics.contains("activation may already be complete"));
    assert!(diagnostics.contains("inspect the active config"));
    assert!(!diagnostics.contains("rerun"));
    tokn_config::v2::load(&config_path).unwrap();

    let active = fs::read(&config_path).unwrap();
    let durable_auth = fs::read(&auth_path).unwrap();
    let backup_path = backup::legacy_backup_path(&config_path).unwrap();
    fs::remove_file(&backup_path).unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut retry_args = apply_args();
    retry_args.yes = false;
    let mut unexpected_confirmation = |_: &str| -> Result<bool> { panic!("already-v2 apply must not confirm") };
    execute_with_confirmation(
      &config_path,
      &retry_args,
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
      &mut unexpected_confirmation,
    )
    .unwrap();

    assert!(stdout.is_empty());
    assert!(std::str::from_utf8(&stderr)
      .unwrap()
      .contains("already active and valid; no files changed"));
    assert_eq!(fs::read(&config_path).unwrap(), active);
    assert_eq!(fs::read(&auth_path).unwrap(), durable_auth);
    assert!(!backup_path.exists());

    stdout.clear();
    stderr.clear();
    let error = execute(
      &config_path,
      &args(V2ActivationArg::Api),
      Some(&auth_path),
      &mut stdout,
      &mut stderr,
    )
    .unwrap_err();
    assert!(error.to_string().contains("already uses schema version 2"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
  }
}
