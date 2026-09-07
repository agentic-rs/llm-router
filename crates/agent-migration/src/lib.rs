//! Agent binding helpers for local tools that should route through
//! `tokn-router` profiles.

mod adapter;
mod adapters;
mod config;
mod jsonc;
mod manifest;
mod opencode_markdown;
mod projection;
mod reconcile;
mod status;

use tokn_auth::AuthStore;
use tokn_config::{Account, Config};

pub use config::{
  agent_config_path, load_agent_config, load_agent_config_with_legacy, AgentIntegrationConfig,
  AGENT_CONFIG_SCHEMA_VERSION,
};
pub use manifest::FileBackup;
pub use reconcile::{
  apply_reconcile, import_accounts, plan_reconcile, unlink, unlink_with_legacy_root, AgentProfileLayout, ApplyReport,
  FileAction, ImportReport, ImportRequest, PlannedEdit, ReconcilePlan, ReconcileRequest, UnlinkReport, UnlinkRequest,
};
pub use status::{list_agents, show_agent, show_agent_with_config, AgentBindingStatus, AgentStatus};

fn effective_main_accounts<'a>(cfg: &'a Config, store: &'a AuthStore) -> impl Iterator<Item = &'a Account> + 'a {
  store.accounts.iter().filter(move |account| {
    account.enabled
      && cfg
        .defaults
        .providers
        .as_ref()
        .is_none_or(|providers| providers.contains(&account.provider))
      && cfg
        .defaults
        .accounts
        .as_ref()
        .is_none_or(|accounts| accounts.contains(&account.id))
  })
}
