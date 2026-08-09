use std::path::Path;
use tokn_accounts::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph, PoolAcquire};
use tokn_accounts::registry::Registry;
use tokn_core::account::AccountConfig;
use tokn_policy::AccountPoolId;

const CONFIG: &str = r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "default" }

[profiles.default]
route = "default"

[routes.default]
kind = "managed"
account_pool = "primary"
upstream = { kind = "fixed", upstream = "local" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.primary]
accounts = ["first", "second"]
providers = ["llama-cpp"]
strategy = "round_robin"

[upstreams.local]
provider = "llama-cpp"
accounts = ["first", "second"]
base_url = "http://127.0.0.1:11434/v1"
"#;

fn account(id: &str) -> AccountConfig {
  let mut account: AccountConfig = toml::from_str(
    r#"
      id = "fixture"
      provider = "llama-cpp"
    "#,
  )
  .unwrap();
  account.id = id.to_string();
  account
}

#[test]
fn compiled_v2_plan_builds_upstream_specific_round_robin_pool() {
  let plan = tokn_config::v2::parse(CONFIG, Path::new("gateway.toml")).unwrap();
  let accounts = [account("first"), account("second")];
  let registry = Registry::builtin();

  let providers = link_provider_graph(&plan, &accounts, &registry).unwrap();
  assert_eq!(providers.target_count(), 1);
  assert_eq!(providers.binding_count(), 2);

  let pools = link_account_pools(&plan, &providers, &registry).unwrap();
  let runtimes = build_account_pool_runtimes(&pools);
  let pool = runtimes.runtime(&AccountPoolId::new("primary").unwrap()).unwrap();

  let selected = (0..4)
    .map(|_| match pool.acquire(None, |_| true) {
      PoolAcquire::Selected(binding) => (
        binding.account_id().to_string(),
        binding.upstream_id().as_str().to_string(),
      ),
      outcome => panic!("expected an eligible binding, got {outcome:?}"),
    })
    .collect::<Vec<_>>();

  assert_eq!(
    selected,
    [
      ("first".into(), "local".into()),
      ("second".into(), "local".into()),
      ("first".into(), "local".into()),
      ("second".into(), "local".into()),
    ]
  );
}
