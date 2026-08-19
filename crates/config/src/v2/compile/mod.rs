mod listeners;
mod resources;
mod service;

use crate::v2::{CompileError, CompiledConfig, RawConfig};
use std::path::Path;
use tokn_policy::GatewayPlan;

pub(super) fn compile_config(raw: &RawConfig, source: &Path) -> Result<CompiledConfig, CompileError> {
  let gateway = compile_gateway(raw, source)?;
  let service = service::compile_service(&raw.service)?;
  Ok(CompiledConfig::new(gateway, service))
}

fn compile_gateway(raw: &RawConfig, source: &Path) -> Result<GatewayPlan, CompileError> {
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
  ))
}
