use crate::cli::config_context::{AccountView, ConfigContext, ResolvedProviderAuth};
use crate::cli::import::ImportArgs;
use crate::cli::login::LoginArgs;
use crate::config::{Account, AccountState, AccountTier};
use crate::util::secret::Secret;
use crate::util::timefmt::{relative_from_now, relative_from_now_ms};
use anyhow::{anyhow, bail, Result};
use clap::{Args, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use tokn_auth::AuthStore;

#[derive(Subcommand, Debug)]
pub enum AccountCmd {
  /// List configured accounts (grouped by provider, sorted by tier)
  List(ListArgs),
  /// Remove an account by id
  Remove { id: String },
  /// Show details for an account
  Show(ShowArgs),
  /// Add an account interactively (provider → credential source → id)
  Add(AddArgs),
  /// Add a Copilot account via GitHub device-flow login
  Login(LoginArgs),
  /// Import an existing GitHub token (from `gh` or the Copilot plugin),
  /// or a static API key (from an env var). Flag-driven; suitable for CI.
  Import(ImportArgs),
  /// Force-refresh an account's short-lived access token (no-op for
  /// providers that use a static API key)
  Refresh { id: String },
  /// Print one-line per-account status (gh-auth-style)
  Status(StatusArgs),
  /// Change account activation tiers (active / fallback / disabled).
  /// See `--only`, `--all`, and repeatable `--account` flags.
  Switch(SwitchArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
  #[command(flatten)]
  pub view: AccountViewArgs,
  /// Skip live upstream quota lookups (faster, no network).
  #[arg(long)]
  pub no_quota: bool,
  /// Per-upstream timeout in seconds for the live quota probe.
  #[arg(long, default_value_t = 5u64)]
  pub timeout: u64,
}

#[derive(Args, Debug, Default)]
pub struct AccountViewArgs {
  /// Filter by a v2 account pool. Active/fallback state remains global.
  #[arg(long, value_name = "ID", conflicts_with = "profile")]
  pub pool: Option<String>,

  /// Filter through a profile's effective account selection. Read-only.
  #[arg(long, value_name = "ID", conflicts_with = "pool")]
  pub profile: Option<String>,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
  pub id: String,

  #[command(flatten)]
  pub view: AccountViewArgs,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
  pub id: Option<String>,

  #[command(flatten)]
  pub view: AccountViewArgs,
}

#[derive(Args, Debug)]
pub struct AddArgs {
  /// Provider id (skip the provider picker).
  #[arg(long)]
  pub provider: Option<String>,
  /// Account id (skip the id prompt).
  #[arg(long)]
  pub id: Option<String>,
}

/// Activation surface. Three mutually-exclusive primary modes:
///
/// 1. `--only <id>` — set `<id>` Active and demote every other enabled
///    account in the same provider to Fallback.
/// 2. `--all --provider <p>` — set every enabled account in provider `<p>`
///    to Active.
/// 3. `--account <id>` (repeatable) — set each listed `<id>` to Active and
///    demote every other enabled account in the affected providers to
///    Fallback.
#[derive(Args, Debug)]
pub struct SwitchArgs {
  /// Mode 1. Single Active account; others (same provider) become Fallback.
  #[arg(long, value_name = "ID")]
  pub only: Option<String>,

  /// Mode 2. Mark every enabled account of `--provider` as Active.
  #[arg(long, requires = "provider", conflicts_with_all = ["only", "account_multi"])]
  pub all: bool,

  /// Provider scope for `--all`.
  #[arg(long, value_name = "ID")]
  pub provider: Option<String>,

  /// Mode 3. Repeatable: each listed account becomes Active; other enabled
  /// accounts in the same provider(s) are demoted to Fallback.
  #[arg(long = "account", value_name = "ID", conflicts_with_all = ["only", "all"])]
  pub account_multi: Vec<String>,

  /// Also operate on currently-disabled accounts (re-enable as needed).
  #[arg(long)]
  pub include_disabled: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, cmd: AccountCmd) -> Result<()> {
  let context = ConfigContext::load(cfg_path.as_deref())?;
  let mut store = AuthStore::load(None, Some(context.path()))?;
  match cmd {
    AccountCmd::List(args) => list(&context, &mut store, args).await?,
    AccountCmd::Remove { id } => {
      let removed = store.remove(&id).ok_or_else(|| anyhow!("no account with id '{id}'"))?;
      store.save()?;
      tracing::info!(account = %removed.id, remaining = store.accounts.len(), "account removed");
      println!("Removed '{id}'");
    }
    AccountCmd::Show(args) => show(&context, &store, args)?,
    AccountCmd::Add(args) => add(&context, &mut store, args).await?,
    AccountCmd::Login(args) => crate::cli::login::run_with_context(&context, &mut store, args).await?,
    AccountCmd::Import(args) => crate::cli::import::run_with_context(&context, &mut store, args).await?,
    AccountCmd::Refresh { id } => refresh(&context, &mut store, &id).await?,
    AccountCmd::Status(args) => status(&context, &mut store, args).await?,
    AccountCmd::Switch(args) => switch(&mut store, args)?,
  }
  Ok(())
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

async fn list(context: &ConfigContext, store: &mut AuthStore, args: ListArgs) -> Result<()> {
  let view = resolve_account_view(context, &args.view)?;
  let visible = account_indices(store, view.as_ref());
  if visible.is_empty() {
    print_no_accounts(view.as_ref(), None);
    return Ok(());
  }

  let quotas = probe_accounts(
    context,
    store,
    &visible,
    args.no_quota,
    Duration::from_secs(args.timeout.max(1)),
  )
  .await?;

  // Render: group by provider (alphabetical), within each group sort by
  // effective state (Active → Fallback → Disabled). Account index in the
  // original Vec is preserved so we can pick the right quota slot.
  let mut by_provider: BTreeMap<String, Vec<usize>> = BTreeMap::new();
  for &i in &visible {
    let a = &store.accounts[i];
    by_provider.entry(a.provider.clone()).or_default().push(i);
  }
  print_account_view(view.as_ref());
  let mut first = true;
  for (provider, mut idxs) in by_provider {
    idxs.sort_by_key(|&i| state_sort_key(store.accounts[i].state()));
    if !first {
      println!();
    }
    first = false;
    println!("# {provider}");
    for i in idxs {
      render_account(&store.accounts[i], quotas.get(&i).expect("visible account was probed"));
    }
  }
  Ok(())
}

fn resolve_account_view(context: &ConfigContext, args: &AccountViewArgs) -> Result<Option<AccountView>> {
  context.resolve_account_view(args.pool.as_deref(), args.profile.as_deref())
}

fn account_indices(store: &AuthStore, view: Option<&AccountView>) -> Vec<usize> {
  store
    .accounts
    .iter()
    .enumerate()
    .filter_map(|(index, account)| view.is_none_or(|view| view.contains(account)).then_some(index))
    .collect()
}

fn print_account_view(view: Option<&AccountView>) {
  let Some(view) = view else {
    return;
  };
  println!("scope: {}", view.description());
  println!("activation: shared auth store");
  println!();
}

fn print_no_accounts(view: Option<&AccountView>, suffix: Option<&str>) {
  match view {
    Some(view) => println!("(no accounts selected by {})", view.description()),
    None => println!("(no accounts){}", suffix.unwrap_or_default()),
  }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum QuotaResult {
  Skipped,
  Ok {
    snap: tokn_auth::QuotaSnapshot,
    /// Fresh access token returned by a piggy-backed `refresh_credential`
    /// call (Copilot only). Persisted to auth.yaml so the daemon — which
    /// never writes at runtime — starts up with a non-expired cache.
    refreshed: Option<tokn_auth::RefreshOutcome>,
  },
  Err(String),
}

async fn probe_accounts(
  context: &ConfigContext,
  store: &mut AuthStore,
  indices: &[usize],
  skip: bool,
  timeout: Duration,
) -> Result<BTreeMap<usize, QuotaResult>> {
  let results = if skip {
    indices.iter().map(|_| QuotaResult::Skipped).collect()
  } else {
    // Fetch concurrently, with an outer timeout per account so one hung
    // upstream cannot freeze the command.
    let http = context.build_http_client(false)?;
    let futs = indices.iter().map(|&index| {
      let account = &store.accounts[index];
      fetch_quota(
        http.clone(),
        account.clone(),
        context.resolve_account_provider(account),
        timeout,
      )
    });
    futures::future::join_all(futs).await
  };
  let quotas: BTreeMap<usize, QuotaResult> = indices.iter().copied().zip(results).collect();

  // Persist refreshed credentials produced by the quota probe instead of
  // issuing a second refresh request.
  let mut dirty = false;
  for (&index, quota) in &quotas {
    let QuotaResult::Ok {
      refreshed:
        Some(tokn_auth::RefreshOutcome::Refreshed {
          access_token,
          expires_at,
          username,
          provider_account_id,
        }),
      ..
    } = quota
    else {
      continue;
    };
    let account = &mut store.accounts[index];
    let same_token = account
      .access_token
      .as_ref()
      .is_some_and(|secret| secret.expose().as_str() == access_token.as_str());
    if !same_token || account.access_token_expires_at != Some(*expires_at) {
      account.access_token = Some(Secret::new(access_token.clone()));
      account.access_token_expires_at = Some(*expires_at);
      account.last_refresh = Some(time::OffsetDateTime::now_utc().unix_timestamp());
      dirty = true;
    }
    if let Some(name) = username.as_ref().filter(|name| !name.trim().is_empty()) {
      if account.username.as_deref() != Some(name.as_str()) {
        account.username = Some(name.clone());
        dirty = true;
      }
    }
    if let Some(provider_account_id) = provider_account_id.as_ref().filter(|id| !id.trim().is_empty()) {
      if account.provider_account_id.as_deref() != Some(provider_account_id.as_str()) {
        account.provider_account_id = Some(provider_account_id.clone());
        dirty = true;
      }
    }
  }
  if dirty {
    store.save()?;
  }
  Ok(quotas)
}

async fn fetch_quota(
  http: reqwest::Client,
  account: Account,
  provider: Result<ResolvedProviderAuth>,
  timeout: Duration,
) -> QuotaResult {
  let provider = match provider {
    Ok(provider) => provider,
    Err(error) => return QuotaResult::Err(short_err(&error)),
  };
  let provider_auth = provider.auth();
  // Two parallel calls so the operator gets a single round-trip latency:
  //   * refresh_credential — for Copilot also doubles as a "token still
  //     valid?" check; for Z.ai it's a NotApplicable no-op.
  //   * probe_quota       — the actual quota snapshot.
  // We bound the *combined* future by the caller-supplied timeout so a
  // single hung upstream cannot freeze the entire CLI invocation.
  let acct = provider.account_for_auth(&account);
  let acct2 = acct.clone();
  let http2 = http.clone();
  let fut = async move {
    let (refresh_res, quota_res) = tokio::join!(
      provider_auth.refresh_credential(&http, &acct),
      provider_auth.probe_quota(&http2, &acct2),
    );
    (refresh_res, quota_res)
  };
  match tokio::time::timeout(timeout, fut).await {
    Err(_) => QuotaResult::Err("timeout".into()),
    Ok((Err(e), _)) => QuotaResult::Err(short_err(&e)),
    Ok((Ok(refresh), quota_res)) => {
      let refreshed = match refresh {
        tokn_auth::RefreshOutcome::Refreshed { .. } => Some(refresh),
        tokn_auth::RefreshOutcome::NotApplicable => None,
      };
      match quota_res {
        Err(e) => QuotaResult::Err(short_err(&e)),
        Ok(snap) => QuotaResult::Ok { snap, refreshed },
      }
    }
  }
}

fn short_err<E: std::fmt::Display>(e: &E) -> String {
  let s = e.to_string();
  if s.len() > 80 {
    format!("{}…", &s[..80])
  } else {
    s
  }
}

fn render_account(a: &Account, q: &QuotaResult) {
  println!("[{}] {}", state_marker(a.state()), a.id);

  let has = a.access_token.is_some() || a.api_key.is_some() || a.refresh_token.is_some();
  println!("  credentials : {}", if has { "present" } else { "missing" });

  // Expiry: short-lived OAuth (access_token_expires_at) vs static api_key.
  match a.access_token_expires_at {
    Some(ts) => println!("  expires     : {} (access_token)", relative_from_now(ts)),
    None if a.api_key.is_some() => println!("  expires     : never (static api_key)"),
    None => println!("  expires     : -"),
  }

  match q {
    QuotaResult::Skipped => {}
    QuotaResult::Err(e) => println!("  quota       : unavailable ({e})"),
    QuotaResult::Ok { snap, .. } => render_snapshot(snap),
  }
}

fn render_snapshot(snap: &tokn_auth::QuotaSnapshot) {
  if let Some(plan) = &snap.plan {
    println!("  plan        : {plan}");
  }
  let reset = snap
    .reset_date
    .as_deref()
    .map(|d| format!(" — resets {d}"))
    .unwrap_or_default();
  if let Some(m) = &snap.metered {
    match m.entitlement {
      Some(0) => println!("  quota       : 0 / 0 {} (0.0%){reset}", m.label),
      Some(e) => {
        let pct = 100.0 * (m.remaining as f64) / (e as f64);
        println!("  quota       : {} / {e} {} ({pct:.1}%){reset}", m.remaining, m.label);
      }
      None => println!("  quota       : unlimited {}{reset}", m.label),
    }
  } else if !reset.is_empty() {
    println!("  quota       : monthly{reset}");
  }
  for b in &snap.secondary {
    print_usage_bucket(b);
  }
}

fn print_usage_bucket(b: &tokn_auth::UsageBucket) {
  let body = match (b.used, b.total, b.percent_used) {
    (Some(u), Some(t), Some(p)) => format!("{u} / {t} ({p:.1}%)"),
    (Some(u), Some(t), None) if t > 0 => {
      let p = 100.0 * (u as f64) / (t as f64);
      format!("{u} / {t} ({p:.1}%)")
    }
    (Some(u), Some(t), None) => format!("{u} / {t}"),
    (None, Some(t), Some(p)) => format!("{p:.1}% of {}", fmt_int(t)),
    (None, None, Some(p)) => format!("{p:.1}%"),
    (Some(u), None, _) => format!("{u} used"),
    _ => "-".to_string(),
  };
  let reset = b
    .reset_at_ms
    .map(|t| format!(" — resets {}", relative_from_now_ms(t)))
    .unwrap_or_default();
  println!("  {:<12}: {body}{reset}", b.label);
}

fn fmt_int(mut n: u64) -> String {
  // Thousands separator without pulling in num-format.
  if n == 0 {
    return "0".into();
  }
  let mut parts = Vec::new();
  while n > 0 {
    parts.push(format!("{:03}", n % 1000));
    n /= 1000;
  }
  let mut out = parts.pop().unwrap().trim_start_matches('0').to_string();
  if out.is_empty() {
    out.push('0');
  }
  while let Some(p) = parts.pop() {
    out.push(',');
    out.push_str(&p);
  }
  out
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn show(context: &ConfigContext, store: &AuthStore, args: ShowArgs) -> Result<()> {
  let view = resolve_account_view(context, &args.view)?;
  let a = store
    .get(&args.id)
    .ok_or_else(|| anyhow!("no account with id '{}'", args.id))?;
  if let Some(view) = &view {
    if !view.contains(a) {
      bail!("account '{}' is not selected by {}", args.id, view.description());
    }
  }
  print_account_view(view.as_ref());
  println!("id: {}", a.id);
  println!("provider: {}", a.provider);
  println!("enabled: {}", a.enabled);
  println!("state: {}", state_label(a.state()));
  if !a.tags.is_empty() {
    println!("tags: {}", a.tags.join(", "));
  }
  if let Some(label) = &a.label {
    println!("label: {label}");
  }
  if let Some(refresh) = a.refresh_token.as_ref().map(|s| s.expose()) {
    println!("refresh_token: {}", mask(refresh));
  }
  if let Some(k) = a.api_key.as_ref().map(|s| s.expose()) {
    println!("api_key: {}", mask(k));
  }
  if a.access_token.is_some() || a.access_token_expires_at.is_some() {
    println!(
      "access_token: {}",
      a.access_token
        .as_ref()
        .map(|s| mask(s.expose()))
        .unwrap_or_else(|| "-".into())
    );
    match a.access_token_expires_at {
      Some(ts) => println!("access_token_expires_at: {ts} ({})", relative_from_now(ts)),
      None => println!("access_token_expires_at: -"),
    }
  }
  if let Some(b) = &a.base_url {
    println!("base_url: {b}");
  }
  if let Some(ts) = a.last_refresh {
    println!("last_refresh: {ts} ({})", relative_from_now(ts));
  }
  if !a.settings.is_empty() {
    println!("settings: {} keys", a.settings.len());
  }
  Ok(())
}

fn mask(s: &str) -> String {
  let n = s.len();
  if n <= 8 {
    return "***".into();
  }
  format!("{}…{}", &s[..4], &s[n - 4..])
}

// ---------------------------------------------------------------------------
// state / tier helpers
// ---------------------------------------------------------------------------

fn state_marker(s: AccountState) -> char {
  match s {
    AccountState::Active => 'A',
    AccountState::Fallback => 'F',
    AccountState::Disabled => 'D',
  }
}

fn state_sort_key(s: AccountState) -> u8 {
  match s {
    AccountState::Active => 0,
    AccountState::Fallback => 1,
    AccountState::Disabled => 2,
  }
}

fn state_label(s: AccountState) -> &'static str {
  match s {
    AccountState::Active => "active",
    AccountState::Fallback => "fallback",
    AccountState::Disabled => "disabled",
  }
}

// ---------------------------------------------------------------------------
// add (interactive wizard)
// ---------------------------------------------------------------------------

async fn add(context: &ConfigContext, store: &mut AuthStore, args: AddArgs) -> Result<()> {
  let provider_id = match args.provider {
    Some(provider) => provider,
    None => {
      let provider_ids = context.provider_ids();
      if provider_ids.is_empty() {
        bail!("the config has no enabled providers that support account credentials");
      }
      crate::cli::onboarding::pick_provider(&provider_ids)?
    }
  };
  let provider = context.resolve_provider(&provider_id)?;
  let client = context.build_http_client(false)?;
  let account = crate::cli::onboarding::interactive_add_account(&client, &provider, args.id).await?;
  let id = account.id.clone();
  let provider = account.provider.clone();
  store.upsert_in_main(account)?;
  store.save()?;
  tracing::info!(account = %id, %provider, path = %store.path().display(), "account added");
  println!("Saved account '{id}' ({provider}) to {}", store.path().display());
  Ok(())
}

// ---------------------------------------------------------------------------
// refresh (force token re-exchange for github-copilot)
// ---------------------------------------------------------------------------

async fn refresh(context: &ConfigContext, store: &mut AuthStore, id: &str) -> Result<()> {
  let account = store
    .get(id)
    .ok_or_else(|| anyhow!("no account with id '{id}'"))?
    .clone();

  let provider = context.resolve_account_provider(&account)?;
  let provider_auth = provider.auth();
  let auth_account = provider.account_for_auth(&account);
  let http = context.build_http_client(false)?;
  match provider_auth
    .refresh_credential(&http, &auth_account)
    .await
    .map_err(|e| anyhow!("refresh failed: {e}"))?
  {
    tokn_auth::RefreshOutcome::NotApplicable => {
      println!(
        "nothing to refresh: provider '{}' uses a static credential",
        account.provider
      );
      Ok(())
    }
    tokn_auth::RefreshOutcome::Refreshed {
      access_token,
      expires_at,
      username,
      provider_account_id,
    } => {
      let acct = store.get_mut(id).expect("checked above");
      acct.access_token = Some(Secret::new(access_token));
      acct.access_token_expires_at = Some(expires_at);
      if let Some(name) = username.filter(|name| !name.trim().is_empty()) {
        acct.username = Some(name);
      }
      if let Some(pid) = provider_account_id.filter(|s| !s.trim().is_empty()) {
        acct.provider_account_id = Some(pid);
      }
      acct.last_refresh = Some(time::OffsetDateTime::now_utc().unix_timestamp());
      store.save()?;
      tracing::info!(account = %id, "access token refreshed");
      println!(
        "Refreshed '{id}': access_token expires {}",
        relative_from_now(expires_at)
      );
      Ok(())
    }
  }
}

// ---------------------------------------------------------------------------
// status (gh-auth-style one-line per account)
// ---------------------------------------------------------------------------

async fn status(context: &ConfigContext, store: &mut AuthStore, args: StatusArgs) -> Result<()> {
  let view = resolve_account_view(context, &args.view)?;
  let mut visible = account_indices(store, view.as_ref());
  if let Some(id) = &args.id {
    let account = store.get(id).ok_or_else(|| anyhow!("no account with id '{id}'"))?;
    if let Some(view) = &view {
      if !view.contains(account) {
        bail!("account '{id}' is not selected by {}", view.description());
      }
    }
    visible.retain(|&index| store.accounts[index].id == *id);
  }
  if visible.is_empty() {
    print_no_accounts(view.as_ref(), Some(" — run `tokn-router account add` to add one"));
    return Ok(());
  }
  let quotas = probe_accounts(context, store, &visible, false, Duration::from_secs(5)).await?;

  print_account_view(view.as_ref());
  for index in visible {
    print_status_line(
      &store.accounts[index],
      quotas.get(&index).expect("visible account was probed"),
    );
  }
  Ok(())
}

fn print_status_line(a: &Account, q: &QuotaResult) {
  let state = state_label(a.state());
  let expiry = match a.access_token_expires_at {
    Some(ts) => relative_from_now(ts),
    None if a.api_key.is_some() => "static".into(),
    None => "-".into(),
  };
  let extra = match q {
    QuotaResult::Ok { snap, .. } => snap.plan.clone().unwrap_or_default(),
    QuotaResult::Err(e) => format!("quota: {e}"),
    _ => String::new(),
  };
  let extra = if extra.is_empty() {
    String::new()
  } else {
    format!(" · {extra}")
  };
  println!("{} ({}) [{state}] · expires {expiry}{extra}", a.id, a.provider);
}

// ---------------------------------------------------------------------------
// switch (tri-state activation)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct SwitchChange {
  id: String,
  provider: String,
  old: AccountState,
  new: AccountState,
}

fn switch(store: &mut AuthStore, args: SwitchArgs) -> Result<()> {
  let changes = apply_switch(&mut store.accounts, &args)?;
  if changes.is_empty() {
    println!("no changes");
    return Ok(());
  }
  store.save()?;
  for c in &changes {
    println!(
      "{}  ({})  {} → {}",
      c.id,
      c.provider,
      state_label(c.old),
      state_label(c.new)
    );
  }
  tracing::info!(changes = changes.len(), "account switch applied");
  Ok(())
}

/// Pure mutation kernel for `switch`. Extracted for unit-testing.
fn apply_switch(accounts: &mut [Account], args: &SwitchArgs) -> Result<Vec<SwitchChange>> {
  // Validate exactly one mode is set.
  let modes_set = (args.only.is_some() as u8) + (args.all as u8) + (!args.account_multi.is_empty() as u8);
  if modes_set == 0 {
    bail!("specify exactly one of `--only <id>`, `--all --provider <p>`, or `--account <id>` (repeatable)");
  }
  if modes_set > 1 {
    bail!("`--only`, `--all`, and `--account` are mutually exclusive");
  }

  // Resolve the set of target ids and the affected provider scope.
  let (active_ids, providers): (Vec<String>, Vec<String>) = if let Some(id) = &args.only {
    let provider = lookup_provider(accounts, id)?;
    (vec![id.clone()], vec![provider])
  } else if args.all {
    let p = args.provider.clone().expect("clap: --all requires --provider");
    if !accounts.iter().any(|a| a.provider == p) {
      bail!("no accounts for provider '{p}'");
    }
    let ids: Vec<String> = accounts
      .iter()
      .filter(|a| a.provider == p && (args.include_disabled || a.enabled))
      .map(|a| a.id.clone())
      .collect();
    (ids, vec![p])
  } else {
    let ids = args.account_multi.clone();
    let mut providers = Vec::new();
    for id in &ids {
      let p = lookup_provider(accounts, id)?;
      if !providers.contains(&p) {
        providers.push(p);
      }
    }
    (ids, providers)
  };

  let active_set: std::collections::HashSet<&str> = active_ids.iter().map(String::as_str).collect();

  let mut changes = Vec::new();
  for a in accounts.iter_mut() {
    if !providers.contains(&a.provider) {
      continue;
    }
    let want_active = active_set.contains(a.id.as_str());
    // Disabled accounts only flip if --include-disabled was passed (or
    // they're explicitly named via --account / --only).
    let touches_disabled = !a.enabled && (args.include_disabled || want_active);
    if !a.enabled && !touches_disabled {
      continue;
    }
    let old = a.state();
    let (new_enabled, new_tier) = if want_active {
      (true, AccountTier::Active)
    } else {
      // Demote to Fallback if we're modifying actives in this provider; but
      // for `--all` the expected behaviour is "everyone in provider becomes
      // Active" — so non-named accounts are simply unchanged.
      if args.all {
        continue;
      }
      (true, AccountTier::Fallback)
    };
    let new = if !new_enabled {
      AccountState::Disabled
    } else {
      match new_tier {
        AccountTier::Active => AccountState::Active,
        AccountTier::Fallback => AccountState::Fallback,
      }
    };
    if old == new && a.enabled == new_enabled {
      continue;
    }
    a.enabled = new_enabled;
    a.tier = new_tier;
    changes.push(SwitchChange {
      id: a.id.clone(),
      provider: a.provider.clone(),
      old,
      new,
    });
  }
  Ok(changes)
}

fn lookup_provider(accounts: &[Account], id: &str) -> Result<String> {
  accounts
    .iter()
    .find(|a| a.id == id)
    .map(|a| a.provider.clone())
    .ok_or_else(|| anyhow!("no account with id '{id}'"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use clap::Parser;
  use tokn_core::account::AccountTier;

  fn write_v2_openai_config(path: &std::path::Path) {
    std::fs::write(
      path,
      r#"
schema_version = 2

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"

[profiles.coding]
route = "managed"
binding = { path = "/v1" }

[profiles.coding.account_pool]
accounts = ["primary"]

[routes.managed]
kind = "managed"
providers = ["company-openai"]
provider = { kind = "any" }
model = { kind = "capability" }
operation = "preserve"

[providers.company-openai]
driver = "openai"
base_url = "https://llm.example.test/v1"
"#,
    )
    .unwrap();
  }

  #[test]
  fn fmt_int_groups_thousands() {
    assert_eq!(fmt_int(0), "0");
    assert_eq!(fmt_int(7), "7");
    assert_eq!(fmt_int(999), "999");
    assert_eq!(fmt_int(1_000), "1,000");
    assert_eq!(fmt_int(80_000_000), "80,000,000");
    assert_eq!(fmt_int(6_000_000), "6,000,000");
  }

  #[test]
  fn read_only_account_views_accept_pool_or_profile() {
    let cli =
      crate::cli::Cli::try_parse_from(["tokn-router", "account", "list", "--pool", "primary", "--no-quota"]).unwrap();
    let crate::cli::Cmd::Account(AccountCmd::List(args)) = cli.cmd else {
      panic!("expected account list");
    };
    assert_eq!(args.view.pool.as_deref(), Some("primary"));
    assert_eq!(args.view.profile, None);

    let cli =
      crate::cli::Cli::try_parse_from(["tokn-router", "account", "show", "primary", "--profile", "coding"]).unwrap();
    let crate::cli::Cmd::Account(AccountCmd::Show(args)) = cli.cmd else {
      panic!("expected account show");
    };
    assert_eq!(args.id, "primary");
    assert_eq!(args.view.profile.as_deref(), Some("coding"));

    assert!(crate::cli::Cli::try_parse_from([
      "tokn-router",
      "account",
      "status",
      "--pool",
      "primary",
      "--profile",
      "coding",
    ])
    .is_err());
    assert!(
      crate::cli::Cli::try_parse_from(["tokn-router", "account", "switch", "--pool", "primary", "--only", "a"])
        .is_err()
    );
  }

  #[tokio::test]
  async fn v2_account_views_filter_list_and_show() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    write_v2_openai_config(&config_path);
    let context = ConfigContext::load(Some(&config_path)).unwrap();
    let auth_path = directory.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store.accounts.extend([
      acct("primary", "company-openai", true, AccountTier::Active),
      acct("secondary", "company-openai", true, AccountTier::Fallback),
    ]);

    list(
      &context,
      &mut store,
      ListArgs {
        view: AccountViewArgs {
          pool: Some("profile.coding".into()),
          profile: None,
        },
        no_quota: true,
        timeout: 1,
      },
    )
    .await
    .unwrap();
    show(
      &context,
      &store,
      ShowArgs {
        id: "primary".into(),
        view: AccountViewArgs {
          pool: None,
          profile: Some("coding".into()),
        },
      },
    )
    .unwrap();
    assert!(show(
      &context,
      &store,
      ShowArgs {
        id: "secondary".into(),
        view: AccountViewArgs {
          pool: Some("profile.coding".into()),
          profile: None,
        },
      },
    )
    .is_err());
  }

  fn acct(id: &str, provider: &str, enabled: bool, tier: AccountTier) -> Account {
    Account {
      id: id.into(),
      provider: provider.into(),
      enabled,
      tier,
      label: None,
      tags: vec![],
      base_url: None,
      headers: std::collections::BTreeMap::new(),
      auth_type: None,
      username: None,
      api_key: None,
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: std::collections::BTreeMap::new(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  fn switch_args(
    only: Option<&str>,
    all: bool,
    provider: Option<&str>,
    accts: &[&str],
    include_disabled: bool,
  ) -> SwitchArgs {
    SwitchArgs {
      only: only.map(String::from),
      all,
      provider: provider.map(String::from),
      account_multi: accts.iter().map(|s| s.to_string()).collect(),
      include_disabled,
    }
  }

  #[test]
  fn switch_only_promotes_named_demotes_others_in_same_provider() {
    let mut accts = vec![
      acct("a1", "p1", true, AccountTier::Active),
      acct("a2", "p1", true, AccountTier::Active),
      acct("b1", "p2", true, AccountTier::Active), // untouched (different provider)
    ];
    let changes = apply_switch(&mut accts, &switch_args(Some("a2"), false, None, &[], false)).unwrap();
    // a1: Active→Fallback; a2: already Active→no change; b1: untouched.
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].id, "a1");
    assert_eq!(changes[0].new, AccountState::Fallback);
    assert_eq!(accts[0].tier, AccountTier::Fallback);
    assert_eq!(accts[1].tier, AccountTier::Active);
    assert_eq!(accts[2].tier, AccountTier::Active);
  }

  #[test]
  fn switch_all_marks_every_enabled_account_in_provider_active() {
    let mut accts = vec![
      acct("a1", "p1", true, AccountTier::Fallback),
      acct("a2", "p1", true, AccountTier::Fallback),
      acct("a3", "p1", false, AccountTier::Fallback), // disabled, skipped
    ];
    let changes = apply_switch(&mut accts, &switch_args(None, true, Some("p1"), &[], false)).unwrap();
    assert_eq!(changes.len(), 2);
    assert!(accts[0].tier == AccountTier::Active);
    assert!(accts[1].tier == AccountTier::Active);
    assert!(!accts[2].enabled); // unchanged
  }

  #[test]
  fn switch_account_repeatable_promotes_listed_demotes_rest() {
    let mut accts = vec![
      acct("a1", "p1", true, AccountTier::Active),
      acct("a2", "p1", true, AccountTier::Active),
      acct("a3", "p1", true, AccountTier::Fallback),
    ];
    apply_switch(&mut accts, &switch_args(None, false, None, &["a1", "a3"], false)).unwrap();
    assert_eq!(accts[0].tier, AccountTier::Active);
    assert_eq!(accts[1].tier, AccountTier::Fallback);
    assert_eq!(accts[2].tier, AccountTier::Active);
  }

  #[test]
  fn switch_rejects_zero_or_multiple_modes() {
    let mut accts = vec![acct("a1", "p1", true, AccountTier::Active)];
    assert!(apply_switch(&mut accts, &switch_args(None, false, None, &[], false)).is_err());
    assert!(apply_switch(&mut accts, &switch_args(Some("a1"), true, Some("p1"), &[], false)).is_err());
  }

  #[test]
  fn switch_unknown_id_errors() {
    let mut accts = vec![acct("a1", "p1", true, AccountTier::Active)];
    assert!(apply_switch(&mut accts, &switch_args(Some("ghost"), false, None, &[], false)).is_err());
  }

  #[tokio::test]
  async fn v2_list_status_and_refresh_resolve_configured_provider() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    write_v2_openai_config(&config_path);
    let context = ConfigContext::load(Some(&config_path)).unwrap();
    let auth_path = directory.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = acct("primary", "company-openai", true, AccountTier::Active);
    account.api_key = Some(Secret::new("sk-test".into()));
    store.accounts.push(account);

    list(
      &context,
      &mut store,
      ListArgs {
        view: AccountViewArgs::default(),
        no_quota: true,
        timeout: 1,
      },
    )
    .await
    .unwrap();
    status(
      &context,
      &mut store,
      StatusArgs {
        id: Some("primary".into()),
        view: AccountViewArgs::default(),
      },
    )
    .await
    .unwrap();
    refresh(&context, &mut store, "primary").await.unwrap();

    let client = context.build_http_client(true).unwrap();
    let failed = fetch_quota(
      client,
      store.accounts[0].clone(),
      Err(anyhow!("provider resolution failed")),
      Duration::from_secs(1),
    )
    .await;
    assert!(matches!(failed, QuotaResult::Err(message) if message == "provider resolution failed"));
  }

  #[tokio::test]
  async fn empty_account_views_return_without_network_access() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    write_v2_openai_config(&config_path);
    let context = ConfigContext::load(Some(&config_path)).unwrap();
    let auth_path = directory.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();

    list(
      &context,
      &mut store,
      ListArgs {
        view: AccountViewArgs::default(),
        no_quota: false,
        timeout: 1,
      },
    )
    .await
    .unwrap();
    status(
      &context,
      &mut store,
      StatusArgs {
        id: None,
        view: AccountViewArgs {
          pool: Some("profile.coding".into()),
          profile: None,
        },
      },
    )
    .await
    .unwrap();
  }
}
