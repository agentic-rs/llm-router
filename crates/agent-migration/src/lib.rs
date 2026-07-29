//! Agent binding helpers for local tools that should route through
//! `tokn-router` profiles.

mod adapter;
mod adapters;
mod jsonc;
mod manifest;
mod opencode_markdown;
mod projection;
mod reconcile;
mod status;

pub use manifest::FileBackup;
pub use reconcile::{
  apply_reconcile, import_accounts, plan_reconcile, unlink, unlink_with_legacy_root, AgentProfileLayout, ApplyReport,
  FileAction, ImportReport, ImportRequest, PlannedEdit, ReconcilePlan, ReconcileRequest, UnlinkReport, UnlinkRequest,
};
pub use status::{list_agents, show_agent, AgentBindingStatus, AgentStatus};
