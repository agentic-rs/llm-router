//! `tokn-router config` subcommand — git-style key/value access. Comment-
//! preserving edits via `toml_edit`.

use crate::cli::config_context::{ConfigContext, ResolvedProviderAuth};
use crate::config::{paths, Config, ConfigSchema, DEFAULT_HOST, DEFAULT_PORT};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use inquire::{Confirm, Text};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokn_auth::AuthStore;
use tokn_config::RouteMode;
use toml_edit::{value, Array, DocumentMut, Item, Value as EditValue};

mod document;
mod migrate_v2;

use document::{insert, lookup, remove};

#[cfg(test)]
mod edit_tests;

#[derive(Args, Debug)]
pub struct ConfigArgs {
  #[command(subcommand)]
  pub cmd: ConfigCmd,
}

impl ConfigArgs {
  pub(super) fn requires_pristine_startup(&self) -> bool {
    matches!(self.cmd, ConfigCmd::MigrateV2(_))
  }
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
  /// Print the value of a primary-config key (e.g. `copilot.user_agent`)
  Get(GetArgs),
  /// Set a primary-config key (e.g. `copilot.user_agent "vscode/<version>"`)
  Set(SetArgs),
  /// Remove a primary-config key
  Unset(UnsetArgs),
  /// Print normalized config as TOML
  List,
  /// Open the primary config file in $EDITOR; validates after save
  Edit,
  /// Print the path to the config file
  Path,
  /// Initialize a new version 2 config with the onboarding wizard
  Init(InitArgs),
  /// Render a validated version 2 config without modifying any files
  #[command(name = "migrate-v2")]
  MigrateV2(MigrateV2Args),
}

#[derive(Args, Debug, Default)]
pub struct MigrateV2Args {
  /// Include all default values and expanded policy tables instead of compact output
  #[arg(long)]
  pub expanded: bool,
  /// Include a forward-proxy listener projected from legacy [proxy_mode]
  #[arg(long)]
  pub with_proxy: bool,
  /// Override the projected forward-proxy listener's static route mode
  #[arg(long, value_enum, requires = "with_proxy")]
  pub proxy_route_mode: Option<RouteModeArg>,
  /// Permit reviewed non-loopback listener binds
  #[arg(long)]
  pub insecure_allow_remote: bool,
  /// Permit account credentials to use reviewed non-loopback cleartext HTTP providers
  #[arg(long)]
  pub allow_insecure_http: bool,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum RouteModeArg {
  Passthrough,
  Switch,
  Exact,
  Route,
  Fuzzy,
}

impl From<RouteModeArg> for RouteMode {
  fn from(value: RouteModeArg) -> Self {
    match value {
      RouteModeArg::Passthrough => RouteMode::Passthrough,
      RouteModeArg::Switch => RouteMode::Switch,
      RouteModeArg::Exact => RouteMode::Exact,
      RouteModeArg::Route => RouteMode::Route,
      RouteModeArg::Fuzzy => RouteMode::Fuzzy,
    }
  }
}

#[derive(Args, Debug, Default)]
pub struct InitArgs {
  /// Non-interactive mode.
  #[arg(long)]
  pub yes: bool,
  /// Legacy-only option; unsupported by version 2 initialization.
  #[arg(long, value_enum, hide = true)]
  pub route_mode: Option<RouteModeArg>,
  /// Numeric loopback IP for the llm_api listener.
  #[arg(long)]
  pub host: Option<String>,
  /// Port for the llm_api listener.
  #[arg(long)]
  pub port: Option<u16>,
  /// Legacy-only option; unsupported by version 2 initialization.
  #[arg(long, hide = true)]
  pub proxy_host: Option<String>,
  /// Legacy-only option; unsupported by version 2 initialization.
  #[arg(long, hide = true)]
  pub proxy_port: Option<u16>,
  /// Legacy-only option; unsupported by version 2 initialization.
  #[arg(long, value_enum, hide = true)]
  pub proxy_route_mode: Option<RouteModeArg>,
  /// Non-interactive repeatable account specs:
  /// id=...,provider=...,from=...[,env_var=...]
  #[arg(long = "account", requires = "yes")]
  pub accounts: Vec<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
  pub key: String,
  /// Operate inside a legacy [[accounts]] entry
  #[arg(long)]
  pub account: Option<String>,
}

#[derive(Args, Debug)]
pub struct SetArgs {
  pub key: String,
  pub value: String,
  /// Append to an array instead of replacing
  #[arg(long)]
  pub add: bool,
  /// Operate inside a legacy [[accounts]] entry
  #[arg(long)]
  pub account: Option<String>,
}

#[derive(Args, Debug)]
pub struct UnsetArgs {
  pub key: String,
  /// Operate inside a legacy [[accounts]] entry
  #[arg(long)]
  pub account: Option<String>,
}

pub async fn run(cfg_path: Option<PathBuf>, args: ConfigArgs) -> Result<()> {
  let path = match cfg_path {
    Some(p) => p,
    None => paths::config_path()?,
  };

  match args.cmd {
    ConfigCmd::Get(a) => cmd_get(&path, a),
    ConfigCmd::Set(a) => cmd_set(&path, a),
    ConfigCmd::Unset(a) => cmd_unset(&path, a),
    ConfigCmd::List => cmd_list(&path),
    ConfigCmd::Edit => cmd_edit(&path),
    ConfigCmd::Path => cmd_path(&path),
    ConfigCmd::Init(a) => cmd_init(&path, a).await,
    ConfigCmd::MigrateV2(a) => migrate_v2::run(&path, &a),
  }
}

// --- get ---------------------------------------------------------------

fn cmd_get(path: &std::path::Path, args: GetArgs) -> Result<()> {
  let schema = crate::config::detect_config_schema(path)?;
  reject_v2_account_selector(schema, args.account.as_deref())?;
  let segments = key_segments(args.account.as_deref(), &args.key);
  ensure_root_key_is_not_fragment_managed(path, schema, &segments)?;
  let doc = load_doc(path)?;
  match lookup(&doc, &segments) {
    Some(item) => {
      print!("{}", render_item(item));
      if !render_item(item).ends_with('\n') {
        println!();
      }
      Ok(())
    }
    None => Err(anyhow!("key not found: {}", args.key)),
  }
}

fn render_item(item: &Item) -> String {
  match item {
    Item::Value(v) => match v {
      EditValue::String(s) => s.value().to_string(),
      EditValue::Integer(i) => i.value().to_string(),
      EditValue::Float(f) => f.value().to_string(),
      EditValue::Boolean(b) => b.value().to_string(),
      EditValue::Datetime(d) => d.value().to_string(),
      EditValue::Array(a) => a.to_string(),
      EditValue::InlineTable(t) => t.to_string(),
    },
    Item::Table(t) => t.to_string(),
    Item::ArrayOfTables(a) => format!("{} table(s)", a.len()),
    Item::None => String::new(),
  }
}

// --- set ---------------------------------------------------------------

fn cmd_set(path: &std::path::Path, args: SetArgs) -> Result<()> {
  let schema = crate::config::detect_config_schema(path)?;
  reject_v2_account_selector(schema, args.account.as_deref())?;
  let segments = key_segments(args.account.as_deref(), &args.key);
  ensure_root_key_is_not_fragment_managed(path, schema, &segments)?;
  #[allow(clippy::result_large_err)]
  crate::config::edit_primary_in_place(path, |doc| {
    if args.add {
      append_array(doc, &segments, &args.value)?;
    } else {
      let existing = lookup(doc, &segments).cloned();
      let new = coerce(&args.value, existing.as_ref());
      insert(doc, &segments, new)?;
    }
    Ok(())
  })?;
  tracing::info!(key = %args.key, account = ?args.account, add = args.add, "config set");
  println!("set {}", args.key);
  Ok(())
}

fn coerce(raw: &str, prior: Option<&Item>) -> Item {
  // Honour the existing type if present.
  if let Some(Item::Value(v)) = prior {
    match v {
      EditValue::Boolean(_) => {
        if let Ok(b) = raw.parse::<bool>() {
          return value(b);
        }
      }
      EditValue::Integer(_) => {
        if let Ok(n) = raw.parse::<i64>() {
          return value(n);
        }
      }
      EditValue::Float(_) => {
        if let Ok(n) = raw.parse::<f64>() {
          return value(n);
        }
      }
      EditValue::Array(_) => {
        let arr: Array = raw.split(',').map(|s| s.trim().to_string()).collect();
        return value(arr);
      }
      _ => {}
    }
  }
  // Heuristic fallback
  if let Ok(b) = raw.parse::<bool>() {
    return value(b);
  }
  if let Ok(n) = raw.parse::<i64>() {
    return value(n);
  }
  value(raw)
}

fn append_array(doc: &mut DocumentMut, segments: &[String], raw: &str) -> Result<()> {
  let existing = lookup(doc, segments).cloned();
  let mut arr = match existing {
    Some(Item::Value(EditValue::Array(a))) => a,
    Some(_) => bail!("--add: existing value is not an array"),
    None => Array::new(),
  };
  arr.push(raw);
  insert(doc, segments, value(arr))
}

// --- unset -------------------------------------------------------------

fn cmd_unset(path: &std::path::Path, args: UnsetArgs) -> Result<()> {
  let schema = crate::config::detect_config_schema(path)?;
  reject_v2_account_selector(schema, args.account.as_deref())?;
  let segments = key_segments(args.account.as_deref(), &args.key);
  ensure_root_key_is_not_fragment_managed(path, schema, &segments)?;
  #[allow(clippy::result_large_err)]
  crate::config::edit_primary_in_place(path, |doc| {
    if !remove(doc, &segments) {
      return Err(anyhow::anyhow!("key not found: {}", args.key).into());
    }
    Ok(())
  })?;
  tracing::info!(key = %args.key, account = ?args.account, "config unset");
  println!("unset {}", args.key);
  Ok(())
}

// --- list / edit / path ------------------------------------------------

fn cmd_list(path: &std::path::Path) -> Result<()> {
  let s = match crate::config::detect_config_schema(path)? {
    ConfigSchema::Legacy => {
      let (cfg, _) = Config::load(Some(path))?;
      toml::to_string_pretty(&cfg)?
    }
    ConfigSchema::V2 => {
      let raw = crate::config::v2::load_raw(path)?;
      crate::config::v2::compile_config(&raw, path)?;
      toml::to_string_pretty(&raw)?
    }
  };
  print!("{s}");
  Ok(())
}

fn cmd_edit(path: &std::path::Path) -> Result<()> {
  let schema = crate::config::detect_config_schema(path)?;
  if schema == ConfigSchema::Legacy {
    print_fragment_editor_note(path);
  }
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).ok();
  }
  open_in_editor(path)?;
  validate_config_path(path, schema).context("validation failed after edit")?;
  println!("ok");
  Ok(())
}

fn print_fragment_editor_note(path: &std::path::Path) {
  let fragment_dir = paths::config_fragment_dir(path);
  if !fragment_dir.is_dir() {
    return;
  }
  let has_fragments = std::fs::read_dir(&fragment_dir)
    .ok()
    .into_iter()
    .flatten()
    .filter_map(Result::ok)
    .map(|entry| entry.path())
    .any(|entry| entry.is_file() && entry.extension().is_some_and(|extension| extension == "toml"));
  if has_fragments {
    eprintln!(
      "note: linked-agent state is managed separately under {}; this editor changes only {}",
      fragment_dir.display(),
      path.display()
    );
  }
}

fn validate_config_path(path: &std::path::Path, expected_schema: ConfigSchema) -> Result<()> {
  let actual_schema = crate::config::detect_config_schema(path)?;
  if actual_schema != expected_schema {
    bail!(
      "config editing cannot change schemas; use an explicit migration instead (expected {}, found {})",
      schema_name(expected_schema),
      schema_name(actual_schema)
    );
  }
  match actual_schema {
    ConfigSchema::Legacy => Config::load_primary(Some(path)).map(drop).map_err(Into::into),
    ConfigSchema::V2 => crate::config::v2::load_config(path).map(drop).map_err(Into::into),
  }
}

fn schema_name(schema: ConfigSchema) -> &'static str {
  match schema {
    ConfigSchema::Legacy => "legacy",
    ConfigSchema::V2 => "version 2",
  }
}

fn cmd_path(path: &std::path::Path) -> Result<()> {
  println!("{}", path.display());
  Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountSpec {
  id: String,
  provider: String,
  /// `env` (default), `string`, `file`, `stdin`, `login`, or any
  /// provider-defined custom key (e.g. `gh`, `copilot-plugin`).
  from: String,
  /// Env var name when `from=env`; defaults to provider-derived.
  env_var: Option<String>,
  /// Literal credential bytes when `from=string`.
  credential: Option<String>,
  /// File path when `from=file`.
  file: Option<String>,
  /// Force `RefreshToken` flavor (overrides provider default).
  refresh_token: bool,
  /// Force `ApiKey` flavor (overrides provider default).
  api_key: bool,
}

async fn cmd_init(path: &std::path::Path, args: InitArgs) -> Result<()> {
  println!("Config path: {}", path.display());
  ensure_init_target_missing(path)?;
  reject_legacy_init_options(&args)?;

  let bind = if args.yes {
    init_listener_bind(args.host.as_deref(), args.port)?
  } else {
    interactive_listener_bind(args.host.as_deref(), args.port)?
  };
  let (contents, compiled) = build_v2_init_config(path, bind)?;
  if args.yes && args.accounts.is_empty() {
    create_v2_config(path, &contents)?;
    println!("Initialized version 2 config with no accounts.");
    println!("Next: tokn-router account import ...  # then tokn-router serve");
    return Ok(());
  }

  let context = ConfigContext::from_v2(path.to_path_buf(), compiled);
  let mut store = AuthStore::load(None, Some(path))?;
  let client = context.build_http_client(false)?;

  if args.yes {
    for raw in &args.accounts {
      let spec = parse_account_spec(raw)?;
      let provider = context.resolve_provider(&spec.provider)?;
      let source = account_source_from_spec(&spec, &provider, false)?;
      let account = crate::cli::onboarding::resolve_account(&client, &provider, Some(spec.id.clone()), source).await?;
      store.upsert_in_main(account)?;
    }
    create_v2_config(path, &contents)?;
    store.save()?;
    println!(
      "Initialized version 2 config and upserted {} account(s).",
      args.accounts.len()
    );
    return Ok(());
  }

  let mut upserted = 0usize;
  let provider_ids = context.provider_ids();
  loop {
    let provider_id = crate::cli::onboarding::pick_provider(&provider_ids)?;
    let provider = context.resolve_provider(&provider_id)?;
    let account = crate::cli::onboarding::interactive_add_account(&client, &provider, None).await?;
    store.upsert_in_main(account)?;
    upserted += 1;
    let more = Confirm::new("Add another account?")
      .with_default(false)
      .prompt()
      .context("account loop cancelled")?;
    if !more {
      break;
    }
  }

  create_v2_config(path, &contents)?;
  store.save()?;
  println!("Initialized version 2 config and upserted {upserted} account(s).");
  println!("Next: tokn-router serve");
  Ok(())
}

fn ensure_init_target_missing(path: &Path) -> Result<()> {
  if path.exists() {
    bail!(
      "config already exists at {}; `config init` only creates new version 2 configs and never overwrites or migrates existing files",
      path.display()
    );
  }
  Ok(())
}

fn reject_legacy_init_options(args: &InitArgs) -> Result<()> {
  let mut options = Vec::new();
  if args.route_mode.is_some() {
    options.push("--route-mode");
  }
  if args.proxy_host.is_some() {
    options.push("--proxy-host");
  }
  if args.proxy_port.is_some() {
    options.push("--proxy-port");
  }
  if args.proxy_route_mode.is_some() {
    options.push("--proxy-route-mode");
  }
  if !options.is_empty() {
    bail!(
      "{} are legacy-only and unsupported by version 2 config initialization; configure routes or a forward_proxy listener explicitly after initialization",
      options.join(", ")
    );
  }
  Ok(())
}

fn interactive_listener_bind(host: Option<&str>, port: Option<u16>) -> Result<SocketAddr> {
  let default = init_listener_bind(host, port)?;
  if host.is_some() || port.is_some() {
    return Ok(default);
  }
  if !Confirm::new("Set llm_api listener IP/port?")
    .with_default(false)
    .prompt()
    .context("listener IP/port prompt cancelled")?
  {
    return Ok(default);
  }

  let host = Text::new("Listener IP:")
    .with_initial_value(&default.ip().to_string())
    .prompt()
    .context("listener IP prompt cancelled")?;
  let port = Text::new("Listener port:")
    .with_initial_value(&default.port().to_string())
    .prompt()
    .context("listener port prompt cancelled")?
    .parse()
    .context("listener port must be a valid u16")?;
  init_listener_bind(Some(&host), Some(port))
}

fn init_listener_bind(host: Option<&str>, port: Option<u16>) -> Result<SocketAddr> {
  let ip = host
    .unwrap_or(DEFAULT_HOST)
    .parse::<IpAddr>()
    .context("version 2 listener host must be a numeric IP address")?;
  if !ip.is_loopback() {
    bail!(
      "version 2 config init only creates an unauthenticated loopback listener; configure local_keys and allow_insecure_public explicitly for a non-loopback listener"
    );
  }
  Ok(SocketAddr::new(ip, port.unwrap_or(DEFAULT_PORT)))
}

const V2_INIT_TEMPLATE: &str = r#"schema_version = 2

[defaults]
retry = { kind = "recoverable", policy = "standard" }

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"

[retry_policies.standard]
max_retries = 2
initial_backoff_ms = 100
"#;

// Keep explicit-resource regressions independent of the changing init format.
#[cfg(test)]
const V2_EXPLICIT_TEST_CONFIG: &str = include_str!("config_cmd/fixtures/explicit_v2.toml");

fn build_v2_init_config(path: &Path, bind: SocketAddr) -> Result<(String, tokn_config::v2::CompiledConfig)> {
  let mut document = V2_INIT_TEMPLATE
    .parse::<DocumentMut>()
    .context("invalid built-in version 2 config template")?;
  insert(
    &mut document,
    &["listeners".into(), "api".into(), "bind".into()],
    value(bind.to_string()),
  )?;
  let contents = document.to_string();
  let compiled = tokn_config::v2::parse_config(&contents, path)?;
  Ok((contents, compiled))
}

fn create_v2_config(path: &Path, contents: &str) -> Result<()> {
  tokn_config::replace_contents_if_unchanged(path, None, contents.as_bytes())
    .map_err(anyhow::Error::from)
    .with_context(|| format!("create version 2 config at {}", path.display()))
}

fn parse_account_spec(raw: &str) -> Result<AccountSpec> {
  let mut id: Option<String> = None;
  let mut provider: Option<String> = None;
  let mut from: Option<String> = None;
  let mut env_var: Option<String> = None;
  let mut credential: Option<String> = None;
  let mut file: Option<String> = None;
  let mut refresh_token = false;
  let mut api_key = false;

  for part in raw.split(',') {
    let (k, v) = part
      .split_once('=')
      .ok_or_else(|| anyhow!("invalid account spec segment '{part}', expected key=value"))?;
    let key = k.trim();
    let val = v.trim();
    if val.is_empty() {
      bail!("account spec key '{key}' cannot be empty");
    }
    match key {
      "id" => id = Some(val.to_string()),
      "provider" => provider = Some(val.to_string()),
      "from" => from = Some(val.to_string()),
      "env_var" => env_var = Some(val.to_string()),
      "credential" => credential = Some(val.to_string()),
      "file" => file = Some(val.to_string()),
      "refresh_token" => refresh_token = parse_bool(key, val)?,
      "api_key" => api_key = parse_bool(key, val)?,
      _ => bail!("unknown account spec key '{key}'"),
    }
  }
  if refresh_token && api_key {
    bail!("account spec cannot set both refresh_token=true and api_key=true");
  }

  let spec = AccountSpec {
    id: id.ok_or_else(|| anyhow!("account spec missing required key 'id'"))?,
    provider: provider.ok_or_else(|| anyhow!("account spec missing required key 'provider'"))?,
    from: from.unwrap_or_else(|| "env".to_string()),
    env_var,
    credential,
    file,
    refresh_token,
    api_key,
  };
  crate::cli::onboarding::validate_provider(&spec.provider)?;
  Ok(spec)
}

fn parse_bool(key: &str, val: &str) -> Result<bool> {
  match val.to_ascii_lowercase().as_str() {
    "true" | "1" | "yes" => Ok(true),
    "false" | "0" | "no" => Ok(false),
    _ => Err(anyhow!("account spec key '{key}' must be true/false, got '{val}'")),
  }
}

fn account_source_from_spec(
  spec: &AccountSpec,
  provider: &ResolvedProviderAuth,
  allow_login: bool,
) -> Result<crate::cli::onboarding::CredentialSource> {
  if spec.from == "login" {
    if !allow_login {
      bail!("from=login is interactive-only; use env/string/file/stdin (or a provider-specific source like gh / copilot-plugin) in --yes mode");
    }
    return Ok(crate::cli::onboarding::CredentialSource::Login);
  }
  // Reuse the import command's source builder — same semantics for
  // CLI flags and `--yes` account specs.
  let args = crate::cli::import::ImportArgs {
    from: spec.from.clone(),
    provider: spec.provider.clone(),
    env_var: spec.env_var.clone(),
    credential: spec.credential.clone(),
    file: spec.file.clone().map(std::path::PathBuf::from),
    refresh_token: spec.refresh_token,
    api_key: spec.api_key,
    id: Some(spec.id.clone()),
  };
  let source = crate::cli::import::build_source(&args, provider)?;
  crate::cli::onboarding::validate_provider_source(provider, &source)?;
  Ok(source)
}

fn open_in_editor(path: &std::path::Path) -> Result<()> {
  let editor = std::env::var("VISUAL")
    .or_else(|_| std::env::var("EDITOR"))
    .unwrap_or_else(|_| "vi".into());
  let status = std::process::Command::new(&editor)
    .arg(path)
    .status()
    .with_context(|| format!("spawn editor `{editor}`"))?;
  if !status.success() {
    bail!("editor exited with status {status}");
  }
  Ok(())
}

// --- key plumbing ------------------------------------------------------

fn key_segments(account: Option<&str>, key: &str) -> Vec<String> {
  let mut out = Vec::new();
  if let Some(id) = account {
    out.push("accounts".into());
    out.push(id.into());
  }
  for s in key.split('.') {
    out.push(s.to_string());
  }
  out
}

fn reject_v2_account_selector(schema: ConfigSchema, account: Option<&str>) -> Result<()> {
  if schema == ConfigSchema::V2 && account.is_some() {
    bail!("`--account` addresses legacy inline accounts; v2 accounts are managed by `tokn-router account`");
  }
  Ok(())
}

/// The generic config editor operates on the primary TOML source. Agent
/// overlays are deliberately separate and must be changed through `agent
/// link`, `agent sync`, or `agent unlink`; silently editing their shadowed
/// root keys would report a change that has no runtime effect.
fn ensure_root_key_is_not_fragment_managed(
  path: &std::path::Path,
  schema: ConfigSchema,
  segments: &[String],
) -> Result<()> {
  if schema == ConfigSchema::V2 {
    return Ok(());
  }
  let [section, name, ..] = segments else {
    return Ok(());
  };
  if section != "agents" && section != "profiles" {
    return Ok(());
  }
  let loaded = Config::load_with_sources(Some(path))?;
  for fragment_path in &loaded.sources.fragments {
    let fragment = load_doc(fragment_path)?;
    let managed = fragment
      .get(section)
      .and_then(Item::as_table_like)
      .and_then(|items| items.get(name))
      .is_some();
    if managed {
      bail!(
        "{} is managed by {}; use `agent link`, `agent sync`, or `agent unlink` instead",
        segments.join("."),
        fragment_path.display()
      );
    }
  }
  Ok(())
}

fn load_doc(path: &std::path::Path) -> Result<DocumentMut> {
  if !path.exists() {
    return Ok(DocumentMut::new());
  }
  let raw = std::fs::read_to_string(path)?;
  raw.parse().context("invalid TOML")
}

#[cfg(test)]
mod tests {
  use super::*;
  use clap::Parser;

  fn doc(s: &str) -> DocumentMut {
    s.parse().unwrap()
  }

  fn write_v2_config(path: &std::path::Path) {
    std::fs::write(
      path,
      r#"# v2 config comment
schema_version = 2

[service.outbound]
use_system_proxy = false

[service.request_limits]
max_wire_bytes = 1024
max_decoded_bytes = 2048

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
"#,
    )
    .unwrap();
  }

  #[test]
  fn insert_top_level() {
    let mut d = doc("");
    insert(&mut d, &["copilot".into(), "user_agent".into()], value("x")).unwrap();
    assert!(d.to_string().contains("user_agent = \"x\""));
  }

  #[test]
  fn insert_account_field() {
    let mut d = doc("[[accounts]]\nid = \"work\"\n");
    insert(
      &mut d,
      &["accounts".into(), "work".into(), "label".into()],
      value("Work"),
    )
    .unwrap();
    let s = d.to_string();
    assert!(s.contains("label = \"Work\""));
  }

  #[test]
  fn remove_top_level() {
    let mut d = doc("[copilot]\nuser_agent = \"x\"\n");
    assert!(remove(&mut d, &["copilot".into(), "user_agent".into()]));
    assert!(!d.to_string().contains("user_agent"));
  }

  #[test]
  fn v2_get_list_set_and_unset_use_the_v2_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    write_v2_config(&path);

    cmd_get(
      &path,
      GetArgs {
        key: "schema_version".into(),
        account: None,
      },
    )
    .unwrap();
    cmd_set(
      &path,
      SetArgs {
        key: "service.request_limits.max_wire_bytes".into(),
        value: "4096".into(),
        add: false,
        account: None,
      },
    )
    .unwrap();
    cmd_unset(
      &path,
      UnsetArgs {
        key: "service.outbound.use_system_proxy".into(),
        account: None,
      },
    )
    .unwrap();
    cmd_list(&path).unwrap();

    let updated = std::fs::read_to_string(&path).unwrap();
    assert!(updated.starts_with("# v2 config comment\n"));
    assert!(!updated.contains("use_system_proxy"));
    let compiled = crate::config::v2::load_config(&path).unwrap();
    assert_eq!(compiled.service().request_limits().max_wire_bytes(), 4096);
    validate_config_path(&path, ConfigSchema::V2).unwrap();
    assert_eq!(schema_name(ConfigSchema::V2), "version 2");
  }

  #[test]
  fn set_continues_to_edit_legacy_documents() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[server]\nport = 4141\n").unwrap();

    cmd_set(
      &path,
      SetArgs {
        key: "server.port".into(),
        value: "5151".into(),
        add: false,
        account: None,
      },
    )
    .unwrap();

    let (config, _) = Config::load_primary(Some(&path)).unwrap();
    assert_eq!(config.server.port, 5151);
    cmd_list(&path).unwrap();
    validate_config_path(&path, ConfigSchema::Legacy).unwrap();
    assert_eq!(schema_name(ConfigSchema::Legacy), "legacy");
    print_fragment_editor_note(&path);
  }

  #[test]
  fn v2_set_rejects_invalid_post_images_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    write_v2_config(&path);
    let original = std::fs::read_to_string(&path).unwrap();

    let error = cmd_set(
      &path,
      SetArgs {
        key: "service.request_limits.max_wire_bytes".into(),
        value: "0".into(),
        add: false,
        account: None,
      },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("max_wire_bytes"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
  }

  #[test]
  fn v2_config_commands_reject_legacy_account_selectors_and_schema_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    write_v2_config(&path);
    let original = std::fs::read_to_string(&path).unwrap();

    let account_error = cmd_get(
      &path,
      GetArgs {
        key: "provider".into(),
        account: Some("work".into()),
      },
    )
    .unwrap_err()
    .to_string();
    assert!(account_error.contains("v2 accounts are managed"));

    let schema_error = cmd_unset(
      &path,
      UnsetArgs {
        key: "schema_version".into(),
        account: None,
      },
    )
    .unwrap_err()
    .to_string();
    assert!(schema_error.contains("explicit migration"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

    let edit_error = validate_config_path(&path, ConfigSchema::Legacy)
      .unwrap_err()
      .to_string();
    assert!(edit_error.contains("expected legacy, found version 2"));
  }

  #[test]
  fn v2_profile_keys_are_not_checked_against_legacy_fragments() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    write_v2_config(&path);

    assert!(ensure_root_key_is_not_fragment_managed(
      &path,
      ConfigSchema::V2,
      &["profiles".into(), "default".into(), "route".into()],
    )
    .is_ok());
    print_fragment_editor_note(&path);
  }

  #[test]
  fn v2_init_builds_the_minimal_managed_graph() {
    let path = Path::new("config.toml");
    let bind = init_listener_bind(Some("::1"), Some(5151)).unwrap();
    let (contents, compiled) = build_v2_init_config(path, bind).unwrap();
    let raw = tokn_config::v2::decode(&contents, path).unwrap();

    assert_eq!(raw.schema_version, 2);
    assert_eq!(raw.listeners.len(), 1);
    assert!(raw.defaults.is_some());
    assert!(raw.profiles.is_empty());
    assert!(raw.routes.is_empty());
    assert!(raw.bindings.is_empty());
    assert!(raw.connect_rules.is_empty());
    assert!(raw.providers.is_empty());
    assert!(contents.contains("bind = \"[::1]:5151\""));
    assert_eq!(compiled.gateway().profiles().len(), 1);
    assert_eq!(compiled.gateway().routes().len(), 1);
    assert_eq!(compiled.gateway().account_pools().len(), 1);
    // Exercise both checkout styles on every OS. Keep the expected graph in
    // native form instead of rewriting the legacy fixture with line matches.
    let fixture = include_str!("config_cmd/fixtures/profile_owned_v2.toml").replace("\r\n", "\n");
    for explicit in [fixture.clone(), fixture.replace('\n', "\r\n")] {
      let explicit = explicit.replace("127.0.0.1:4141", "[::1]:5151");
      assert_eq!(compiled, tokn_config::v2::parse_config(&explicit, path).unwrap());
      assert!(contents.lines().count() < explicit.lines().count());
    }

    let context = ConfigContext::from_v2(path.to_path_buf(), compiled);
    let provider = context.resolve_provider("zai-coding-plan").unwrap();
    assert_eq!(provider.provider_id(), "zai-coding-plan");
    assert!(context.provider_ids().contains(&"zai-coding-plan".to_string()));
  }

  #[test]
  fn v2_init_accepts_only_numeric_loopback_listener_addresses() {
    assert_eq!(
      init_listener_bind(None, None).unwrap(),
      SocketAddr::new(DEFAULT_HOST.parse().unwrap(), DEFAULT_PORT)
    );
    assert_eq!(
      interactive_listener_bind(Some("127.0.0.1"), Some(5151)).unwrap(),
      "127.0.0.1:5151".parse().unwrap()
    );
    assert!(init_listener_bind(Some("localhost"), None)
      .unwrap_err()
      .to_string()
      .contains("numeric IP"));
    assert!(init_listener_bind(Some("0.0.0.0"), None)
      .unwrap_err()
      .to_string()
      .contains("unauthenticated loopback"));
  }

  #[test]
  fn v2_init_rejects_legacy_only_options() {
    let args = InitArgs {
      route_mode: Some(RouteModeArg::Route),
      proxy_host: Some("127.0.0.1".into()),
      proxy_port: Some(4142),
      proxy_route_mode: Some(RouteModeArg::Exact),
      ..InitArgs::default()
    };
    let error = reject_legacy_init_options(&args).unwrap_err().to_string();

    assert!(error.contains("--route-mode"));
    assert!(error.contains("--proxy-host"));
    assert!(error.contains("--proxy-port"));
    assert!(error.contains("--proxy-route-mode"));
    assert!(error.contains("forward_proxy listener"));
  }

  #[test]
  fn v2_init_never_overwrites_an_existing_config() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let original = b"[server]\nport = 5151\n";
    std::fs::write(&path, original).unwrap();

    let error = ensure_init_target_missing(&path).unwrap_err().to_string();
    assert!(error.contains("never overwrites or migrates"));
    let create_error = create_v2_config(&path, V2_INIT_TEMPLATE).unwrap_err().to_string();
    assert!(create_error.contains("create version 2 config"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
  }

  #[test]
  fn v2_init_atomically_creates_a_compilable_config() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/config.toml");
    let bind = init_listener_bind(None, Some(5151)).unwrap();
    let (contents, _) = build_v2_init_config(&path, bind).unwrap();

    create_v2_config(&path, &contents).unwrap();

    let compiled = tokn_config::v2::load_config(&path).unwrap();
    assert_eq!(compiled.gateway().listeners().len(), 1);
    assert_eq!(compiled.gateway().retry_policies().len(), 1);
  }

  #[tokio::test]
  async fn non_interactive_v2_init_can_create_config_without_accounts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let args = InitArgs {
      yes: true,
      port: Some(5151),
      ..InitArgs::default()
    };

    cmd_init(&path, args).await.unwrap();

    let config = tokn_config::v2::load_config(&path).unwrap();
    let listener = config.gateway().listeners().values().next().unwrap();
    assert_eq!(listener.bind().port(), 5151);
  }

  #[test]
  fn v2_init_account_specs_require_non_interactive_mode() {
    let error =
      crate::cli::Cli::try_parse_from(["tokn-router", "config", "init", "--account", "id=work,provider=openai"])
        .unwrap_err();

    assert!(error.to_string().contains("--yes"));
  }

  #[test]
  fn rejects_edits_to_fragment_managed_agent_or_profile_keys() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, "[server]\nport = 9911\n").unwrap();
    let fragment = paths::agent_config_fragment_path(&root, "opencode");
    std::fs::create_dir_all(fragment.parent().unwrap()).unwrap();
    std::fs::write(
      &fragment,
      r#"
[agents.opencode]
profile = "opencode"

[profiles.opencode]
agent_id = "opencode"
"#,
    )
    .unwrap();

    let err = ensure_root_key_is_not_fragment_managed(
      &root,
      ConfigSchema::Legacy,
      &["agents".into(), "opencode".into(), "mode".into()],
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("managed by"));
    assert!(err.contains("agent link"));
    assert!(ensure_root_key_is_not_fragment_managed(
      &root,
      ConfigSchema::Legacy,
      &["profiles".into(), "other".into(), "mode".into()],
    )
    .is_ok());
    print_fragment_editor_note(&root);
  }

  #[test]
  fn coerce_keeps_existing_type() {
    let prior = value(true);
    let new = coerce("false", Some(&prior));
    assert!(matches!(new, Item::Value(EditValue::Boolean(_))));
  }

  #[test]
  fn insert_nested_hyphenated_proxy_provider_mode_key() {
    let mut d = doc("");
    insert(
      &mut d,
      &["proxy_mode".into(), "provider_modes".into(), "github-copilot".into()],
      value("passthrough"),
    )
    .unwrap();
    let s = d.to_string();
    assert!(s.contains("[proxy_mode.provider_modes]"));
    assert!(s.contains("github-copilot = \"passthrough\""));
  }

  #[test]
  fn parse_account_spec_happy_path() {
    let spec = parse_account_spec("id=work,provider=github-copilot,from=gh").unwrap();
    assert_eq!(spec.id, "work");
    assert_eq!(spec.provider, "github-copilot");
    assert_eq!(spec.from, "gh");
    assert_eq!(spec.env_var, None);
    assert_eq!(spec.credential, None);
    assert_eq!(spec.file, None);
    assert!(!spec.refresh_token);
    assert!(!spec.api_key);
  }

  #[test]
  fn parse_account_spec_defaults_from_to_env() {
    let spec = parse_account_spec("id=work,provider=zai").unwrap();
    assert_eq!(spec.from, "env");
  }

  #[test]
  fn parse_account_spec_requires_id_and_provider() {
    let err = parse_account_spec("provider=github-copilot,from=gh")
      .unwrap_err()
      .to_string();
    assert!(err.contains("missing required key 'id'"));

    let err = parse_account_spec("id=work,from=gh").unwrap_err().to_string();
    assert!(err.contains("missing required key 'provider'"));
  }

  #[test]
  fn parse_account_spec_rejects_conflicting_flavors() {
    let err = parse_account_spec("id=w,provider=github-copilot,refresh_token=true,api_key=true")
      .unwrap_err()
      .to_string();
    assert!(err.contains("cannot set both"), "got: {err}");
  }

  #[test]
  fn account_source_rejects_incompatible_provider_source() {
    let spec = AccountSpec {
      id: "cn".into(),
      provider: "zai".into(),
      from: "gh".into(),
      env_var: None,
      credential: None,
      file: None,
      refresh_token: false,
      api_key: false,
    };
    let provider = ResolvedProviderAuth::legacy(&spec.provider).unwrap();
    let err = account_source_from_spec(&spec, &provider, false)
      .unwrap_err()
      .to_string();
    assert!(err.contains("unsupported"), "got: {err}");
    assert!(err.contains("gh"), "got: {err}");
  }

  #[test]
  fn account_source_rejects_login_in_non_interactive() {
    let spec = AccountSpec {
      id: "work".into(),
      provider: "github-copilot".into(),
      from: "login".into(),
      env_var: None,
      credential: None,
      file: None,
      refresh_token: false,
      api_key: false,
    };
    let provider = ResolvedProviderAuth::legacy(&spec.provider).unwrap();
    let err = account_source_from_spec(&spec, &provider, false)
      .unwrap_err()
      .to_string();
    assert!(err.contains("interactive-only"));
  }

  #[test]
  fn account_source_accepts_refresh_token_literal() {
    let spec = AccountSpec {
      id: "work".into(),
      provider: "github-copilot".into(),
      from: "string".into(),
      env_var: None,
      credential: Some("rtok".into()),
      file: None,
      refresh_token: true,
      api_key: false,
    };
    let provider = ResolvedProviderAuth::legacy(&spec.provider).unwrap();
    let source = account_source_from_spec(&spec, &provider, false).unwrap();
    assert!(matches!(
      source,
      crate::cli::onboarding::CredentialSource::String {
        flavor: tokn_auth::CredentialFlavor::RefreshToken,
        ..
      }
    ));
  }
}
