mod listeners;
mod resources;

use crate::v2::{CompileError, RawConfig};
use std::path::Path;
use tokn_policy::GatewayPlan;

pub(super) fn compile_plan(raw: &RawConfig, source: &Path) -> Result<GatewayPlan, CompileError> {
  if raw.listeners.is_empty() {
    return Err(CompileError::EmptyRegistry { resource: "listener" });
  }

  let resources = resources::compile_resources(raw)?;
  let listeners = listeners::compile_listeners(raw, source, &resources.profiles, &resources.routes)?;

  Ok(GatewayPlan::new(
    listeners,
    resources.profiles,
    resources.routes,
    resources.account_pools,
    resources.providers,
    resources.model_groups,
  ))
}
