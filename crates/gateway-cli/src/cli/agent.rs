//! CLI bindings for agent account import and binding commands.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use tokn_agent_migration::{
  apply_reconcile, import_accounts, list_agents, plan_reconcile, show_agent_with_config, unlink,
  unlink_with_legacy_root, AgentProfileLayout, AgentStatus, ImportRequest, ReconcilePlan, ReconcileRequest,
  UnlinkRequest,
};
use tokn_config::{AgentAccountSource, Config, RouteMode};
use tokn_core::AgentId;

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
  /// List supported agents and their current binding/import status.
  List,
  /// Show detailed status for one agent.
  Show(AgentTargetArgs),
  /// Import accounts from an agent without changing bindings or rewriting agent config.
  Import(AgentImportArgs),
  /// Bind an agent to the gateway and rewrite the agent's config to use it.
  Link(AgentLinkArgs),
  /// Reconcile agents from the `[agents.*]` source of truth.
  Sync(AgentSyncArgs),
  /// Restore files from the latest or specified bind manifest.
  Unlink(AgentUnlinkArgs),
}

#[derive(Args, Debug)]
pub struct AgentTargetArgs {
  #[arg(value_parser = parse_supported_agent)]
  pub agent: AgentId,
}

#[derive(Args, Debug)]
pub struct AgentImportArgs {
  #[command(flatten)]
  pub target: AgentTargetArgs,
  #[arg(long)]
  pub yes: bool,
}

#[derive(Args, Debug)]
pub struct AgentLinkArgs {
  #[command(flatten)]
  pub target: AgentTargetArgs,
  #[arg(long)]
  pub profile: Option<String>,
  /// Gateway routing mode. Fresh links default to `route`; relinks preserve
  /// their current mode when this option is omitted. `exact` requires an agent
  /// that can encode provider-qualified model IDs (currently OpenCode).
  #[arg(long, value_parser = parse_route_mode)]
  pub mode: Option<RouteMode>,
  /// Leave the agent's credentials untouched and use the gateway's existing
  /// main account pool instead of importing agent credentials.
  ///
  /// On an existing link, omitting this flag preserves the current account
  /// source. Unlink before linking again with a different source.
  #[arg(long)]
  pub use_main_accounts: bool,
  /// Limit a main-account passthrough or switch link to one provider.
  ///
  /// If omitted, the link publishes every enabled provider in the effective
  /// main account pool.
  #[arg(long, requires = "use_main_accounts", conflicts_with = "provider_filters")]
  pub provider: Option<String>,
  /// Limit main-account provider discovery to this provider ID.
  ///
  /// May be supplied more than once. If omitted, `agent link` discovers all
  /// enabled providers in the effective main account pool.
  #[arg(
    long = "provider-filter",
    requires = "use_main_accounts",
    conflicts_with = "provider",
    value_name = "ID"
  )]
  pub provider_filters: Vec<String>,
  #[arg(long)]
  pub yes: bool,
}

#[derive(Args, Debug)]
pub struct AgentSyncArgs {
  #[arg(value_parser = parse_supported_agent)]
  pub agent: Option<AgentId>,
  #[arg(long)]
  pub all: bool,
  #[arg(long)]
  pub yes: bool,
}

#[derive(Args, Debug)]
pub struct AgentUnlinkArgs {
  #[command(flatten)]
  pub target: AgentTargetArgs,
  /// Timestamp or full manifest path. Defaults to the latest manifest for the agent.
  #[arg(long)]
  pub backup_id: Option<String>,
  /// Original working directory used by a legacy link whose manifest contains
  /// relative paths. Modern manifests never require this option.
  #[arg(long)]
  pub legacy_root: Option<PathBuf>,
  /// Apply the unlink without an interactive confirmation.
  #[arg(long)]
  pub yes: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, cmd: AgentCmd) -> Result<()> {
  match cmd {
    AgentCmd::List => list(cfg_path),
    AgentCmd::Show(args) => show(cfg_path, args),
    AgentCmd::Import(args) => import(cfg_path, args),
    AgentCmd::Link(args) => link(cfg_path, args),
    AgentCmd::Sync(args) => sync(cfg_path, args),
    AgentCmd::Unlink(args) => unlink_cmd(args),
  }
}

fn list(cfg_path: Option<PathBuf>) -> Result<()> {
  let statuses = list_agents(cfg_path.as_deref(), None, None)?;
  for status in statuses {
    print_list_row(&status);
  }
  Ok(())
}

fn show(cfg_path: Option<PathBuf>, args: AgentTargetArgs) -> Result<()> {
  let (cfg, resolved_config_path) = Config::load(cfg_path.as_deref())?;
  let status = show_agent_with_config(&cfg, &resolved_config_path, None, None, args.agent)?;
  let displayed_config_path = cfg_path.as_ref().map(|_| resolved_config_path.as_path());
  print_status(&status, displayed_config_path, cfg.api_key.enabled);
  Ok(())
}

fn import(cfg_path: Option<PathBuf>, args: AgentImportArgs) -> Result<()> {
  if !args.yes && !confirm(&format!("Import accounts from {}?", args.target.agent))? {
    println!("Import cancelled.");
    return Ok(());
  }
  let report = import_accounts(ImportRequest {
    agent: args.target.agent,
    gateway_config_path: cfg_path,
    agent_home: None,
  })?;
  println!("Imported into {}", report.gateway_auth_path.display());
  print_string_list("imported_accounts", &report.imported_account_ids);
  print_string_list("disabled_missing_accounts", &report.disabled_account_ids);
  Ok(())
}

fn link(cfg_path: Option<PathBuf>, args: AgentLinkArgs) -> Result<()> {
  let yes = args.yes;
  let plan = plan_reconcile(link_reconcile_request(cfg_path, args))?;
  print_plan("link", &plan);
  if !yes && !confirm("Apply this agent link?")? {
    println!("Link cancelled.");
    return Ok(());
  }
  let report = apply_reconcile(plan)?;
  println!("Link complete. Manifest: {}", report.manifest_path.display());
  Ok(())
}

fn sync(cfg_path: Option<PathBuf>, args: AgentSyncArgs) -> Result<()> {
  let agents = resolve_sync_agents(cfg_path.as_deref(), &args)?;
  if agents.is_empty() {
    println!("No synced agents configured.");
    return Ok(());
  }
  println!(
    "Syncing: {}",
    agents.iter().map(AgentId::to_string).collect::<Vec<_>>().join(", ")
  );

  for (index, agent) in agents.into_iter().enumerate() {
    let plan = plan_reconcile(sync_reconcile_request(cfg_path.clone(), agent.clone()))?;
    print_plan("sync", &plan);
    if !args.yes && !confirm(&format!("Apply this sync plan for {agent}?"))? {
      if index == 0 {
        println!("Sync cancelled.");
      } else {
        println!("Sync stopped before {agent}; previously confirmed agents remain synchronized.");
      }
      return Ok(());
    }
    apply_sync_plan(plan)?;
  }
  Ok(())
}

fn apply_sync_plan(plan: ReconcilePlan) -> Result<()> {
  let agent = plan.agent.clone();
  let report = apply_reconcile(plan)?;
  println!("synced {} -> {}", agent, report.manifest_path.display());
  Ok(())
}

fn unlink_cmd(args: AgentUnlinkArgs) -> Result<()> {
  let AgentUnlinkArgs {
    target,
    backup_id,
    legacy_root,
    yes,
  } = args;
  let agent = target.agent;
  let backup = backup_id.as_deref().unwrap_or("latest active manifest");
  println!("Agent unlink request");
  println!("agent: {agent}");
  println!("backup: {backup}");
  if let Some(root) = &legacy_root {
    println!("legacy_root: {}", root.display());
  }
  if !yes && !confirm(&format!("Restore {agent} from {backup}?"))? {
    println!("Unlink cancelled.");
    return Ok(());
  }
  let request = UnlinkRequest {
    agent: agent.clone(),
    backup_id,
  };
  let report = match legacy_root.as_deref() {
    Some(root) => unlink_with_legacy_root(request, root)?,
    None => unlink(request)?,
  };
  println!("Rolling back {} from {}", agent, report.timestamp);
  for action in report.actions {
    match action {
      tokn_agent_migration::FileAction::Removed(path) => println!("removed {}", path.display()),
      tokn_agent_migration::FileAction::Restored { original, .. } => println!("restored {}", original.display()),
    }
  }
  Ok(())
}

fn parse_supported_agent(value: &str) -> Result<AgentId, String> {
  let Some(agent) = AgentId::from_slug(value) else {
    return Err(format!("unknown agent '{value}'"));
  };
  match agent {
    AgentId::Opencode | AgentId::CodexCli => Ok(agent),
    _ => Err(format!(
      "agent '{}' is recognized but not yet supported by `agent`; supported: opencode, codex-cli",
      agent.as_str()
    )),
  }
}

fn parse_route_mode(value: &str) -> Result<RouteMode, String> {
  match value.trim() {
    "passthrough" => Ok(RouteMode::Passthrough),
    "switch" => Ok(RouteMode::Switch),
    "exact" => Ok(RouteMode::Exact),
    "route" => Ok(RouteMode::Route),
    "fuzzy" => Ok(RouteMode::Fuzzy),
    _ => Err(format!("unknown route mode '{value}'")),
  }
}

fn resolve_sync_agents(cfg_path: Option<&std::path::Path>, args: &AgentSyncArgs) -> Result<Vec<AgentId>> {
  match (&args.agent, args.all) {
    (Some(agent), false) => Ok(vec![agent.clone()]),
    (None, true) => {
      let (cfg, _) = Config::load(cfg_path)?;
      let mut agents = cfg
        .agents
        .iter()
        .filter(|(_, binding)| binding.sync)
        .filter_map(|(name, _)| AgentId::from_slug(name))
        .collect::<Vec<_>>();
      agents.sort_by(|a, b| a.as_str().cmp(b.as_str()));
      Ok(agents)
    }
    (Some(_), true) => bail!("use either an agent or --all, not both"),
    (None, false) => bail!("sync requires either an <AGENT> or --all"),
  }
}

fn print_list_row(status: &AgentStatus) {
  let binding = status
    .binding
    .as_ref()
    .map(|binding| match binding.profile.as_deref() {
      Some(profile) => format!(
        "{} ({}; accounts={})",
        profile,
        route_mode_as_str(binding.mode),
        account_source_as_str(binding.account_source)
      ),
      None => format!(
        "defaults ({}; accounts={})",
        route_mode_as_str(binding.mode),
        account_source_as_str(binding.account_source)
      ),
    })
    .unwrap_or_else(|| "unbound".into());
  let detected = if status.detected { "detected" } else { "missing" };
  let sync = match (&status.binding, status.link_in_sync) {
    (None, _) => "unmanaged",
    (Some(_), true) => "ok",
    (Some(_), false) => "drifted",
  };
  println!(
    "{}\tdetected={}\tbinding={}\timported={}\tlink={}",
    status.agent,
    detected,
    binding,
    status.imported_account_ids.len(),
    sync
  );
}

fn print_status(status: &AgentStatus, gateway_config_path: Option<&Path>, api_key_enabled: bool) {
  println!("agent: {}", status.agent);
  println!("supported: {}", status.supported);
  println!("detected: {}", status.detected);
  println!("auth_path: {}", status.auth_path.display());
  println!("config_path: {}", status.config_path.display());
  match &status.binding {
    Some(binding) => {
      println!("binding:");
      println!("  profile: {}", binding.profile.as_deref().unwrap_or("(defaults)"));
      println!("  mode: {}", route_mode_as_str(binding.mode));
      println!("  account_source: {}", account_source_as_str(binding.account_source));
      println!(
        "  profile_layout: {}",
        profile_layout(binding.mode, binding.account_source, binding.provider.as_deref())
      );
      if let Some(provider) = binding.provider.as_deref() {
        println!("  provider: {provider}");
      }
      if binding.account_source == AgentAccountSource::Main && !binding.mode.is_verbatim() {
        println!(
          "  provider_filter: {}",
          binding
            .provider_filter
            .as_deref()
            .filter(|providers| !providers.is_empty())
            .map(|providers| providers.join(", "))
            .unwrap_or_else(|| "(all effective providers)".into())
        );
      }
      if let Some(source_providers) = binding.source_providers.as_deref() {
        println!(
          "  legacy_source_providers: {}",
          if source_providers.is_empty() {
            "(empty legacy value)".to_string()
          } else {
            source_providers.join(", ")
          }
        );
        println!("  migration: unlink this binding before linking again");
      }
      println!("  sync: {}", binding.sync);
    }
    None => println!("binding: (none)"),
  }
  println!("imported_accounts:");
  if status.imported_account_ids.is_empty() {
    println!("  (none)");
  } else {
    for id in &status.imported_account_ids {
      println!("  - {id}");
    }
  }
  println!("link_in_sync: {}", status.link_in_sync);
  if status.binding.is_some() && !status.link_in_sync {
    println!("{}", drift_hint(&status.agent, gateway_config_path, api_key_enabled));
  }
}

fn drift_hint(agent: &AgentId, gateway_config_path: Option<&Path>, api_key_enabled: bool) -> String {
  if api_key_enabled {
    return match gateway_config_path {
      Some(path) => format!(
        "hint: disable `[api_key].enabled` in {} before syncing; generated agent client keys are not supported yet",
        path.display()
      ),
      None => {
        "hint: disable `[api_key].enabled` before syncing; generated agent client keys are not supported yet".into()
      }
    };
  }
  match gateway_config_path {
    Some(path) => format!(
      "hint: run `tokn-gateway agent sync {agent}` with the global `--config` path set to {} to review and repair drift",
      path.display()
    ),
    None => format!("hint: run `tokn-gateway agent sync {agent}` to review and repair drift"),
  }
}

fn print_plan(kind: &str, plan: &ReconcilePlan) {
  println!("Agent {kind} plan");
  println!("agent: {}", plan.agent);
  println!("profile: {}", plan.binding_profile.as_deref().unwrap_or("(defaults)"));
  println!("mode: {}", route_mode_as_str(plan.binding_mode));
  println!("account_source: {}", account_source_as_str(plan.account_source));
  println!("profile_layout: {}", plan.profile_layout());
  if let Some(provider) = plan.provider.as_deref() {
    println!("provider: {provider}");
  }
  println!("target_base_url: {}", plan.target_base_url);
  println!("gateway_config: {}", plan.gateway_config_path.display());
  println!(
    "gateway_config_fragment: {}",
    plan.gateway_config_fragment_path.display()
  );
  if let Some(auth_shard) = &plan.gateway_auth_shard_path {
    println!("gateway_auth_root: unchanged");
    println!("gateway_auth_fragment: {}", auth_shard.display());
  } else {
    println!("gateway_auth: unchanged");
  }
  if let Some(agent_auth) = &plan.agent_auth_path {
    println!("agent_auth_source: {}", agent_auth.display());
  }
  if plan.account_source == AgentAccountSource::Main && !plan.binding_mode.is_verbatim() {
    println!(
      "provider_filter: {}",
      plan
        .provider_filter
        .as_deref()
        .filter(|providers| !providers.is_empty())
        .map(|providers| providers.join(", "))
        .unwrap_or_else(|| "(all effective providers)".into())
    );
  }
  print_string_list("gateway_provider_scope", &plan.gateway_provider_ids());
  print_string_list("injected_agent_providers", &plan.injected_provider_ids());
  if !plan.providers_without_models.is_empty() {
    println!(
      "warning: OpenCode has no static model catalogue for {}; existing custom selections are preserved when safe, but these providers will not add models to the picker",
      plan.providers_without_models.join(", ")
    );
  }
  if plan.agent == AgentId::Opencode && plan.account_source == AgentAccountSource::Agent {
    println!(
      "warning: project-local .opencode agent/command Markdown model references are not rewritten; update references to transferred providers so they use the generated tokn-router namespace"
    );
  }
  print_string_list(
    "imported_accounts",
    &plan
      .imported_accounts
      .iter()
      .map(|account| account.id.clone())
      .collect::<Vec<_>>(),
  );
  println!("edits:");
  for edit in &plan.edits {
    println!("  - {}", edit.path.display());
  }
}

fn print_string_list(label: &str, values: &[String]) {
  if values.is_empty() {
    println!("{label}: (none)");
    return;
  }
  println!("{label}:");
  for value in values {
    println!("  - {value}");
  }
}

fn route_mode_as_str(mode: RouteMode) -> &'static str {
  match mode {
    RouteMode::Passthrough => "passthrough",
    RouteMode::Switch => "switch",
    RouteMode::Exact => "exact",
    RouteMode::Route => "route",
    RouteMode::Fuzzy => "fuzzy",
  }
}

fn profile_layout(mode: RouteMode, account_source: AgentAccountSource, provider: Option<&str>) -> AgentProfileLayout {
  AgentProfileLayout::for_binding(mode, account_source, provider)
}

fn requested_account_source(use_main_accounts: bool) -> Option<AgentAccountSource> {
  use_main_accounts.then_some(AgentAccountSource::Main)
}

fn link_reconcile_request(cfg_path: Option<PathBuf>, args: AgentLinkArgs) -> ReconcileRequest {
  ReconcileRequest {
    agent: args.target.agent,
    profile: args.profile,
    mode: args.mode,
    account_source: requested_account_source(args.use_main_accounts),
    default_provider_id: args.provider,
    // An explicit link recomputes the published provider set. `Some([])` means
    // automatic discovery; `None` is reserved for sync's preserve semantics.
    provider_filter: Some(args.provider_filters),
    gateway_config_path: cfg_path,
    agent_home: None,
  }
}

fn sync_reconcile_request(cfg_path: Option<PathBuf>, agent: AgentId) -> ReconcileRequest {
  ReconcileRequest {
    agent,
    profile: None,
    mode: None,
    account_source: None,
    default_provider_id: None,
    provider_filter: None,
    gateway_config_path: cfg_path,
    agent_home: None,
  }
}

fn account_source_as_str(source: AgentAccountSource) -> &'static str {
  match source {
    AgentAccountSource::Agent => "agent",
    AgentAccountSource::Main => "main",
  }
}

fn confirm(prompt: &str) -> Result<bool> {
  inquire::Confirm::new(prompt)
    .with_default(false)
    .prompt()
    .context("confirmation prompt cancelled")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::{Cli, Cmd};
  use clap::Parser;

  fn link_args(provider_filters: Vec<String>) -> AgentLinkArgs {
    AgentLinkArgs {
      target: AgentTargetArgs {
        agent: AgentId::Opencode,
      },
      profile: None,
      mode: None,
      use_main_accounts: true,
      provider: None,
      provider_filters,
      yes: true,
    }
  }

  #[test]
  fn use_main_accounts_only_requests_a_source_when_present() {
    assert_eq!(requested_account_source(false), None);
    assert_eq!(requested_account_source(true), Some(AgentAccountSource::Main));
  }

  #[test]
  fn explicit_link_without_provider_filters_requests_automatic_discovery() {
    let request = link_reconcile_request(None, link_args(Vec::new()));

    assert_eq!(request.provider_filter, Some(Vec::new()));
  }

  #[test]
  fn explicit_link_forwards_provider_filters() {
    let request = link_reconcile_request(None, link_args(vec!["openai".into(), "deepseek".into()]));

    assert_eq!(request.provider_filter, Some(vec!["openai".into(), "deepseek".into()]));
  }

  #[test]
  fn explicit_link_forwards_the_raw_provider() {
    let mut args = link_args(Vec::new());
    args.mode = Some(RouteMode::Switch);
    args.provider = Some("openai".into());
    let request = link_reconcile_request(None, args);

    assert_eq!(request.default_provider_id.as_deref(), Some("openai"));
  }

  #[test]
  fn sync_defers_provider_resolution_to_the_existing_binding() {
    let request = sync_reconcile_request(None, AgentId::Opencode);

    assert_eq!(request.provider_filter, None);
  }

  #[test]
  fn provider_filter_uses_the_canonical_option_name() {
    let cli = Cli::try_parse_from([
      "tokn-router",
      "agent",
      "link",
      "opencode",
      "--use-main-accounts",
      "--provider-filter",
      "deepseek",
    ])
    .unwrap();
    let Cmd::Agent(AgentCmd::Link(args)) = cli.cmd else {
      panic!("expected agent link command");
    };

    assert_eq!(args.provider_filters, ["deepseek"]);
  }

  #[test]
  fn legacy_source_provider_option_is_rejected() {
    let err = Cli::try_parse_from([
      "tokn-router",
      "agent",
      "link",
      "opencode",
      "--use-main-accounts",
      "--source-provider",
      "openai",
    ])
    .expect_err("legacy source-provider option must not be accepted");

    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
  }

  #[test]
  fn provider_and_provider_filter_are_mutually_exclusive() {
    let err = Cli::try_parse_from([
      "tokn-router",
      "agent",
      "link",
      "opencode",
      "--use-main-accounts",
      "--mode",
      "switch",
      "--provider",
      "openai",
      "--provider-filter",
      "deepseek",
    ])
    .expect_err("raw provider and normalized filter must conflict");

    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
  }

  #[test]
  fn unlink_accepts_non_interactive_confirmation() {
    let cli = Cli::try_parse_from(["tokn-router", "agent", "unlink", "opencode", "--yes"]).unwrap();
    let Cmd::Agent(AgentCmd::Unlink(args)) = cli.cmd else {
      panic!("expected agent unlink command");
    };

    assert!(args.yes);
  }

  #[test]
  fn unlink_accepts_an_explicit_legacy_manifest_root() {
    let cli = Cli::try_parse_from([
      "tokn-router",
      "agent",
      "unlink",
      "opencode",
      "--legacy-root",
      "/original/link/root",
      "--yes",
    ])
    .unwrap();
    let Cmd::Agent(AgentCmd::Unlink(args)) = cli.cmd else {
      panic!("expected agent unlink command");
    };

    assert_eq!(args.legacy_root.as_deref(), Some(Path::new("/original/link/root")));
  }

  #[test]
  fn drift_hint_preserves_custom_config_scope_without_shell_specific_quoting() {
    assert_eq!(
      drift_hint(
        &AgentId::Opencode,
        Some(Path::new("/tmp/router config/user's.toml")),
        false
      ),
      "hint: run `tokn-gateway agent sync opencode` with the global `--config` path set to /tmp/router config/user's.toml to review and repair drift"
    );
    assert_eq!(
      drift_hint(&AgentId::Opencode, None, false),
      "hint: run `tokn-gateway agent sync opencode` to review and repair drift"
    );
  }

  #[test]
  fn drift_hint_explains_when_api_key_enforcement_blocks_sync() {
    assert_eq!(
      drift_hint(
        &AgentId::Opencode,
        Some(Path::new("/tmp/router/config.toml")),
        true
      ),
      "hint: disable `[api_key].enabled` in /tmp/router/config.toml before syncing; generated agent client keys are not supported yet"
    );
  }

  #[test]
  fn profile_layout_is_derived_from_mode_and_account_source() {
    for mode in [RouteMode::Route, RouteMode::Fuzzy, RouteMode::Exact] {
      for source in [AgentAccountSource::Agent, AgentAccountSource::Main] {
        assert_eq!(profile_layout(mode, source, None), AgentProfileLayout::Single);
      }
    }
    for mode in [RouteMode::Switch, RouteMode::Passthrough] {
      assert_eq!(
        profile_layout(mode, AgentAccountSource::Main, None),
        AgentProfileLayout::PerProvider
      );
      assert_eq!(
        profile_layout(mode, AgentAccountSource::Main, Some("deepseek")),
        AgentProfileLayout::SinglePinned
      );
      assert_eq!(
        profile_layout(mode, AgentAccountSource::Agent, None),
        AgentProfileLayout::PerProvider
      );
    }
  }
}
