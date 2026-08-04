//! `tokn-router config` subcommand — git-style key/value access. Comment-
//! preserving edits via `toml_edit`.

use self::v2_io::V2ConfigFile;
use crate::cli::command_config::CommandConfig;
use crate::config::{paths, Config};
use crate::util::http::build_client;
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use inquire::{Confirm, Select, Text};
use std::path::PathBuf;
use tokn_auth::AuthStore;
use tokn_config::RouteMode;
use toml_edit::{value, Array, DocumentMut, Item, Table, Value as EditValue};

mod migrate_v2;
mod v2_io;

#[derive(Args, Debug)]
pub struct ConfigArgs {
  #[command(subcommand)]
  pub cmd: ConfigCmd,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
  /// Print the value of a primary-config key (e.g. `copilot.user_agent`)
  Get(GetArgs),
  /// Set a primary-config key (e.g. `copilot.user_agent "vscode/<version>"`)
  Set(SetArgs),
  /// Remove a primary-config key
  Unset(UnsetArgs),
  /// Print effective config as TOML
  List,
  /// Open the primary config file in $EDITOR; validates after save
  Edit,
  /// Print the path to the config file
  Path,
  /// Initialize config with onboarding wizard
  Init(InitArgs),
  /// Preview or apply a validated version 2 config migration
  #[command(name = "migrate-v2")]
  MigrateV2(MigrateV2Args),
}

#[derive(Args, Debug)]
pub struct MigrateV2Args {
  /// Legacy listener surface to represent in the generated config
  #[arg(long, value_enum)]
  pub activate: V2ActivationArg,
  /// Permit non-loopback cleartext HTTP account upstreams
  #[arg(long)]
  pub allow_insecure_upstreams: bool,
  /// Back up the legacy config and activate the generated version 2 config
  #[arg(long)]
  pub apply: bool,
  /// Apply without an interactive confirmation
  #[arg(long, requires = "apply")]
  pub yes: bool,
  /// Acknowledge flattening effective config.d fragments into the version 2 root
  #[arg(long, requires = "apply")]
  pub flatten_config_d: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum V2ActivationArg {
  Api,
  Proxy,
  Both,
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

#[derive(Args, Debug)]
pub struct InitArgs {
  /// Non-interactive mode.
  #[arg(long)]
  pub yes: bool,
  /// Runtime route mode override.
  #[arg(long, value_enum)]
  pub route_mode: Option<RouteModeArg>,
  /// Runtime serve host override.
  #[arg(long)]
  pub host: Option<String>,
  /// Runtime serve port override.
  #[arg(long)]
  pub port: Option<u16>,
  /// Runtime proxy host override.
  #[arg(long)]
  pub proxy_host: Option<String>,
  /// Runtime proxy port override.
  #[arg(long)]
  pub proxy_port: Option<u16>,
  /// Runtime proxy default route mode override.
  #[arg(long, value_enum)]
  pub proxy_route_mode: Option<RouteModeArg>,
  /// Non-interactive repeatable account specs:
  /// id=...,provider=...,from=...[,env_var=...]
  #[arg(long = "account")]
  pub accounts: Vec<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
  pub key: String,
  /// Operate inside the [accounts.<id>] subtree
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
  /// Operate inside the [accounts.<id>] subtree
  #[arg(long)]
  pub account: Option<String>,
}

#[derive(Args, Debug)]
pub struct UnsetArgs {
  pub key: String,
  /// Operate inside the [accounts.<id>] subtree
  #[arg(long)]
  pub account: Option<String>,
}

pub async fn run(cfg_path: Option<PathBuf>, args: ConfigArgs) -> Result<()> {
  let path = paths::resolve_config_path(cfg_path.as_deref())?;

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
  let segments = key_segments(args.account.as_deref(), &args.key);
  ensure_root_key_is_not_fragment_managed(path, &segments)?;
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
  let segments = key_segments(args.account.as_deref(), &args.key);
  ensure_root_key_is_not_fragment_managed(path, &segments)?;
  edit_command_config(path, |doc| {
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

/// Apply a comment-preserving edit through the validator for the active
/// schema. Version 2 uses an exact file snapshot so a concurrent writer can
/// never be overwritten between validation and replacement.
fn edit_command_config<F>(path: &std::path::Path, edit: F) -> Result<()>
where
  F: FnOnce(&mut DocumentMut) -> Result<()>,
{
  let command_config = CommandConfig::load(Some(path))?;
  if command_config.is_v2() {
    let file = V2ConfigFile::read(path)?;
    let source = std::str::from_utf8(file.contents())
      .with_context(|| format!("read version 2 config `{}` as UTF-8", path.display()))?;
    let mut document: DocumentMut = source.parse().context("parse version 2 config as editable TOML")?;
    edit(&mut document)?;
    file.replace_contents(document.to_string().as_bytes())?;
    return Ok(());
  }

  #[allow(clippy::result_large_err)]
  Config::edit_in_place(path, |document| edit(document).map_err(Into::into))?;
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
  let segments = key_segments(args.account.as_deref(), &args.key);
  ensure_root_key_is_not_fragment_managed(path, &segments)?;
  edit_command_config(path, |doc| {
    if !remove(doc, &segments) {
      bail!("key not found: {}", args.key);
    }
    Ok(())
  })?;
  tracing::info!(key = %args.key, account = ?args.account, "config unset");
  println!("unset {}", args.key);
  Ok(())
}

// --- list / edit / path ------------------------------------------------

fn cmd_list(path: &std::path::Path) -> Result<()> {
  let command_config = CommandConfig::load(Some(path))?;
  let s = if command_config.is_v2() {
    toml::to_string_pretty(&tokn_config::v2::load_raw(path)?)?
  } else {
    let (cfg, _) = Config::load(Some(path))?;
    toml::to_string_pretty(&cfg)?
  };
  print!("{s}");
  Ok(())
}

fn cmd_edit(path: &std::path::Path) -> Result<()> {
  let command_config = CommandConfig::load(Some(path))?;
  if !command_config.is_v2() {
    let fragment_dir = paths::config_fragment_dir(path);
    if fragment_dir.is_dir() {
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
  }
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).ok();
  }
  open_in_editor(path)?;
  // Validate
  let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
  let _: DocumentMut = raw.parse().context("edited file is not valid TOML")?;
  CommandConfig::load(Some(path)).context("validation failed after edit")?;
  println!("ok");
  Ok(())
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
  // `config init` owns the primary config file. Do not flatten managed agent
  // overlays from `config.d` back into it when refreshing runtime settings.
  let (mut cfg, _) = Config::load_primary(Some(path))?;
  println!("Config path: {}", path.display());

  apply_runtime_overrides(&mut cfg, &args);

  if args.yes {
    if args.accounts.is_empty() {
      bail!("--yes requires at least one --account spec");
    }
    let mut store = AuthStore::load(None, Some(path))?;
    let client = build_client(&cfg.proxy)?;
    for raw in &args.accounts {
      let spec = parse_account_spec(raw)?;
      let source = account_source_from_spec(&spec, false)?;
      let account =
        crate::cli::onboarding::resolve_account(&client, &spec.provider, Some(spec.id.clone()), source).await?;
      store.upsert_in_main(account)?;
    }
    cfg.save(path)?;
    store.save()?;
    println!("Initialized config and upserted {} account(s).", args.accounts.len());
    return Ok(());
  }

  interactive_runtime_prompts(&mut cfg)?;
  let mut store = AuthStore::load(None, Some(path))?;
  let client = build_client(&cfg.proxy)?;
  let mut upserted = 0usize;
  loop {
    let account = crate::cli::onboarding::interactive_add_account(&client, None, None).await?;
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

  cfg.save(path)?;
  store.save()?;
  println!("Initialized config and upserted {upserted} account(s).");
  println!("Next: tokn-router serve");
  Ok(())
}

fn apply_runtime_overrides(cfg: &mut Config, args: &InitArgs) {
  if let Some(mode) = args.route_mode {
    cfg.defaults.mode = mode.into();
  }
  if let Some(host) = &args.host {
    cfg.server.host = host.clone();
  }
  if let Some(port) = args.port {
    cfg.server.port = port;
  }
  if let Some(host) = &args.proxy_host {
    cfg.proxy_mode.host = host.clone();
  }
  if let Some(port) = args.proxy_port {
    cfg.proxy_mode.port = port;
  }
  if let Some(mode) = args.proxy_route_mode {
    cfg.proxy_mode.route_mode = mode.into();
  }
}

fn interactive_runtime_prompts(cfg: &mut Config) -> Result<()> {
  let route_options = vec!["route", "passthrough", "switch", "exact", "fuzzy"];
  let default_idx = match cfg.defaults.mode {
    RouteMode::Route => 0,
    RouteMode::Passthrough => 1,
    RouteMode::Switch => 2,
    RouteMode::Exact => 3,
    RouteMode::Fuzzy => 4,
  };
  let selected = Select::new("Route mode:", route_options.clone())
    .with_starting_cursor(default_idx)
    .prompt()
    .context("route mode selection cancelled")?;
  cfg.defaults.mode = match selected {
    "route" => RouteMode::Route,
    "passthrough" => RouteMode::Passthrough,
    "switch" => RouteMode::Switch,
    "exact" => RouteMode::Exact,
    "fuzzy" => RouteMode::Fuzzy,
    _ => RouteMode::Route,
  };

  let proxy_default_idx = match cfg.proxy_mode.route_mode {
    RouteMode::Route => 0,
    RouteMode::Passthrough => 1,
    RouteMode::Switch => 2,
    RouteMode::Exact => 3,
    RouteMode::Fuzzy => 4,
  };
  let proxy_selected = Select::new("Proxy route mode:", route_options)
    .with_starting_cursor(proxy_default_idx)
    .prompt()
    .context("proxy route mode selection cancelled")?;
  cfg.proxy_mode.route_mode = match proxy_selected {
    "route" => RouteMode::Route,
    "passthrough" => RouteMode::Passthrough,
    "switch" => RouteMode::Switch,
    "exact" => RouteMode::Exact,
    "fuzzy" => RouteMode::Fuzzy,
    _ => RouteMode::Route,
  };

  if Confirm::new("Set serve host/port?")
    .with_default(false)
    .prompt()
    .context("serve host/port prompt cancelled")?
  {
    let host = Text::new("Serve host:")
      .with_initial_value(&cfg.server.host)
      .prompt()
      .context("serve host prompt cancelled")?;
    let port = Text::new("Serve port:")
      .with_initial_value(&cfg.server.port.to_string())
      .prompt()
      .context("serve port prompt cancelled")?;
    cfg.server.host = host;
    cfg.server.port = port.parse().context("serve port must be a valid u16")?;
  }

  if Confirm::new("Set proxy host/port?")
    .with_default(false)
    .prompt()
    .context("proxy host/port prompt cancelled")?
  {
    let host = Text::new("Proxy host:")
      .with_initial_value(&cfg.proxy_mode.host)
      .prompt()
      .context("proxy host prompt cancelled")?;
    let port = Text::new("Proxy port:")
      .with_initial_value(&cfg.proxy_mode.port.to_string())
      .prompt()
      .context("proxy port prompt cancelled")?;
    cfg.proxy_mode.host = host;
    cfg.proxy_mode.port = port.parse().context("proxy port must be a valid u16")?;
  }
  Ok(())
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

fn account_source_from_spec(spec: &AccountSpec, allow_login: bool) -> Result<crate::cli::onboarding::CredentialSource> {
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
  let source = crate::cli::import::build_source(&args)?;
  crate::cli::onboarding::validate_provider_source(&spec.provider, &source)?;
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

/// The generic config editor operates on the primary TOML source. Agent
/// overlays are deliberately separate and must be changed through `agent
/// link`, `agent sync`, or `agent unlink`; silently editing their shadowed
/// root keys would report a change that has no runtime effect.
fn ensure_root_key_is_not_fragment_managed(path: &std::path::Path, segments: &[String]) -> Result<()> {
  let [section, name, ..] = segments else {
    return Ok(());
  };
  if section != "agents" && section != "profiles" {
    return Ok(());
  }
  if CommandConfig::load(Some(path))?.is_v2() {
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

fn lookup<'a>(doc: &'a DocumentMut, segments: &[String]) -> Option<&'a Item> {
  if segments.is_empty() {
    return None;
  }
  // Special-case [[accounts]] array-of-tables when first two segments are
  // "accounts" "<id>".
  if segments.len() >= 2 && segments[0] == "accounts" {
    let arr = doc.get("accounts")?.as_array_of_tables()?;
    let entry = arr
      .iter()
      .find(|t| t.get("id").and_then(|i| i.as_str()) == Some(segments[1].as_str()))?;
    return descend_table(entry, &segments[2..]);
  }
  let first = doc.get(&segments[0])?;
  descend_item(first, &segments[1..])
}

fn descend_item<'a>(item: &'a Item, rest: &[String]) -> Option<&'a Item> {
  if rest.is_empty() {
    return Some(item);
  }
  match item {
    Item::Table(t) => descend_table(t, rest),
    Item::Value(EditValue::InlineTable(t)) => {
      // Convert path manually
      let next = t.get(&rest[0])?;
      // Wrap as Item temporarily — but lifetime hard; just stop traversal here.
      if rest.len() == 1 {
        // We can't return &Item from &Value cheaply; build a borrowed-shaped thing.
        // Safe shortcut: only support flat lookup inside inline tables via map_value path.
        return inline_value_as_item(next);
      }
      None
    }
    _ => None,
  }
}

fn inline_value_as_item(_v: &EditValue) -> Option<&Item> {
  // toml_edit doesn't let us cheaply borrow Item from inside a Value; for
  // CLI purposes we don't expect deep inline-table reads, so we return None
  // and let the caller report "key not found".
  None
}

fn descend_table<'a>(t: &'a Table, rest: &[String]) -> Option<&'a Item> {
  if rest.is_empty() {
    // Need an Item; manufacture by going through the underlying entry. We
    // can't, so just return None; callers handle "table" path via table
    // reference upstream. For our needs, only leaf reads matter.
    return None;
  }
  let item = t.get(&rest[0])?;
  descend_item(item, &rest[1..])
}

fn insert(doc: &mut DocumentMut, segments: &[String], new: Item) -> Result<()> {
  if segments.is_empty() {
    bail!("empty key");
  }
  if segments.len() >= 2 && segments[0] == "accounts" {
    let entry = ensure_account(doc, &segments[1])?;
    return insert_into_table(entry, &segments[2..], new);
  }
  if segments.len() == 1 {
    doc.insert(&segments[0], new);
    return Ok(());
  }
  let head = &segments[0];
  if doc.get(head).is_none() {
    doc.insert(head, Item::Table(Table::new()));
  }
  let item = doc.get_mut(head).unwrap();
  let table = item.as_table_mut().ok_or_else(|| anyhow!("`{head}` is not a table"))?;
  insert_into_table(table, &segments[1..], new)
}

fn insert_into_table(t: &mut Table, segments: &[String], new: Item) -> Result<()> {
  if segments.is_empty() {
    bail!("empty key");
  }
  if segments.len() == 1 {
    t.insert(&segments[0], new);
    return Ok(());
  }
  let head = &segments[0];
  if t.get(head).is_none() {
    t.insert(head, Item::Table(Table::new()));
  }
  let next = t
    .get_mut(head)
    .and_then(|i| i.as_table_mut())
    .ok_or_else(|| anyhow!("`{head}` is not a table"))?;
  insert_into_table(next, &segments[1..], new)
}

fn remove(doc: &mut DocumentMut, segments: &[String]) -> bool {
  if segments.is_empty() {
    return false;
  }
  if segments.len() >= 2 && segments[0] == "accounts" {
    let Some(arr) = doc.get_mut("accounts").and_then(|i| i.as_array_of_tables_mut()) else {
      return false;
    };
    let Some(entry) = arr
      .iter_mut()
      .find(|t| t.get("id").and_then(|i| i.as_str()) == Some(segments[1].as_str()))
    else {
      return false;
    };
    return remove_from_table(entry, &segments[2..]);
  }
  if segments.len() == 1 {
    return doc.remove(&segments[0]).is_some();
  }
  let Some(item) = doc.get_mut(&segments[0]) else {
    return false;
  };
  let Some(t) = item.as_table_mut() else {
    return false;
  };
  remove_from_table(t, &segments[1..])
}

fn remove_from_table(t: &mut Table, segments: &[String]) -> bool {
  if segments.is_empty() {
    return false;
  }
  if segments.len() == 1 {
    return t.remove(&segments[0]).is_some();
  }
  let Some(item) = t.get_mut(&segments[0]) else {
    return false;
  };
  let Some(inner) = item.as_table_mut() else {
    return false;
  };
  remove_from_table(inner, &segments[1..])
}

fn ensure_account<'a>(doc: &'a mut DocumentMut, id: &str) -> Result<&'a mut Table> {
  if doc.get("accounts").is_none() {
    doc.insert("accounts", Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
  }
  let arr = doc
    .get_mut("accounts")
    .and_then(|i| i.as_array_of_tables_mut())
    .ok_or_else(|| anyhow!("`accounts` is not an array of tables"))?;
  let pos = arr
    .iter()
    .position(|t| t.get("id").and_then(|i| i.as_str()) == Some(id));
  if pos.is_none() {
    let mut t = Table::new();
    t.insert("id", value(id));
    arr.push(t);
  }
  let idx = arr
    .iter()
    .position(|t| t.get("id").and_then(|i| i.as_str()) == Some(id))
    .unwrap();
  Ok(arr.get_mut(idx).unwrap())
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

  fn doc(s: &str) -> DocumentMut {
    s.parse().unwrap()
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

    let err = ensure_root_key_is_not_fragment_managed(&root, &["agents".into(), "opencode".into(), "mode".into()])
      .unwrap_err()
      .to_string();
    assert!(err.contains("managed by"));
    assert!(err.contains("agent link"));
    assert!(
      ensure_root_key_is_not_fragment_managed(&root, &["profiles".into(), "other".into(), "mode".into()],).is_ok()
    );
  }

  #[test]
  fn v2_set_and_unset_preserve_comments_and_validate_the_result() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "# operator note\nschema_version = 2\n").unwrap();

    cmd_set(
      &path,
      SetArgs {
        key: "service.persistence.enabled".into(),
        value: "false".into(),
        add: false,
        account: None,
      },
    )
    .unwrap();

    let after_set = std::fs::read_to_string(&path).unwrap();
    assert!(after_set.contains("# operator note"));
    assert!(after_set.contains("enabled = false"));
    tokn_config::v2::parse(&after_set, &path).unwrap();

    cmd_unset(
      &path,
      UnsetArgs {
        key: "service.persistence.enabled".into(),
        account: None,
      },
    )
    .unwrap();

    let after_unset = std::fs::read_to_string(&path).unwrap();
    assert!(after_unset.contains("# operator note"));
    assert!(!after_unset.contains("enabled = false"));
    tokn_config::v2::parse(&after_unset, &path).unwrap();
  }

  #[test]
  fn invalid_v2_set_does_not_replace_the_config() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let original = "# unchanged\nschema_version = 2\n";
    std::fs::write(&path, original).unwrap();

    let error = cmd_set(
      &path,
      SetArgs {
        key: "schema_version".into(),
        value: "3".into(),
        add: false,
        account: None,
      },
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("unsupported schema version"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
  }

  #[test]
  fn legacy_fragments_do_not_shadow_v2_root_keys() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("config.toml");
    std::fs::write(&root, "schema_version = 2\n").unwrap();
    let fragment = paths::agent_config_fragment_path(&root, "opencode");
    std::fs::create_dir_all(fragment.parent().unwrap()).unwrap();
    std::fs::write(&fragment, "[profiles.opencode]\nagent_id = \"opencode\"\n").unwrap();

    ensure_root_key_is_not_fragment_managed(&root, &["profiles".into(), "opencode".into(), "mode".into()]).unwrap();
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
    let err = account_source_from_spec(&spec, false).unwrap_err().to_string();
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
    let err = account_source_from_spec(&spec, false).unwrap_err().to_string();
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
    let source = account_source_from_spec(&spec, false).unwrap();
    assert!(matches!(
      source,
      crate::cli::onboarding::CredentialSource::String {
        flavor: tokn_auth::CredentialFlavor::RefreshToken,
        ..
      }
    ));
  }
}
