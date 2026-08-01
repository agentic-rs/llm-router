use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use tokn_access::AccessStore;

#[derive(Subcommand, Debug)]
pub enum ApiKeyCmd {
  /// Create a key. With no --provider flags, the key can use every provider.
  Create(CreateArgs),
  /// List API keys without exposing their secrets.
  List,
  /// Revoke a key immediately.
  Revoke { id: String },
}

#[derive(Args, Debug)]
pub struct CreateArgs {
  /// Human-readable name for this key.
  pub name: String,
  /// Allowed provider id. Repeat for multiple providers; defaults to `*`.
  #[arg(long = "provider", value_name = "ID")]
  pub providers: Vec<String>,
}

pub async fn run(command: ApiKeyCmd) -> Result<()> {
  let store = AccessStore::open_default()?;
  match command {
    ApiKeyCmd::Create(args) => create(&store, args),
    ApiKeyCmd::List => list(&store),
    ApiKeyCmd::Revoke { id } => revoke(&store, &id),
  }
}

fn create(store: &AccessStore, args: CreateArgs) -> Result<()> {
  validate_providers(&args.providers)?;
  let created = store.create_key(args.name, args.providers)?;
  println!("API key created");
  println!("id: {}", created.id);
  println!("name: {}", created.name);
  println!("providers: {}", created.providers.display());
  println!("key: {}", created.token);
  println!("Store this key now; it will not be shown again.");
  println!("Enable enforcement with `[api_key].enabled = true` in config.toml.");
  Ok(())
}

fn list(store: &AccessStore) -> Result<()> {
  let keys = store.list_keys()?;
  if keys.is_empty() {
    println!("(no API keys)");
    return Ok(());
  }
  println!("ID\tNAME\tPROVIDERS\tSTATUS");
  for key in keys {
    let status = if key.revoked_at.is_some() { "revoked" } else { "active" };
    println!("{}\t{}\t{}\t{}", key.id, key.name, key.providers.display(), status);
  }
  Ok(())
}

fn revoke(store: &AccessStore, id: &str) -> Result<()> {
  if !store.revoke_key(id)? {
    bail!("no API key with id '{id}'");
  }
  println!("Revoked '{id}'");
  Ok(())
}

fn validate_providers(providers: &[String]) -> Result<()> {
  if providers.is_empty() {
    return Ok(());
  }
  if providers.iter().any(|provider| provider == "*") {
    if providers.len() != 1 {
      bail!("provider `*` cannot be combined with specific provider ids");
    }
    return Ok(());
  }
  let registry = tokn_accounts::registry::Registry::builtin();
  let unknown = providers
    .iter()
    .filter(|provider| registry.resolve(provider).is_none())
    .cloned()
    .collect::<Vec<_>>();
  if !unknown.is_empty() {
    bail!("unknown provider ids: {}", unknown.join(", "));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepts_default_wildcard_and_known_providers() {
    validate_providers(&[]).unwrap();
    validate_providers(&["*".into()]).unwrap();
    validate_providers(&["openai".into(), "deepseek".into()]).unwrap();
  }

  #[test]
  fn rejects_unknown_provider() {
    assert!(validate_providers(&["not-real".into()]).is_err());
  }
}
