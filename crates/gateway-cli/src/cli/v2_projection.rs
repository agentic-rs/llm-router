use std::collections::BTreeMap;

use tokn_config::RouteMode;
use tokn_router_legacy_config::v2::V2ForwardProxyProjectionOptions;

pub(super) fn forward_proxy_options(route_mode: RouteMode) -> V2ForwardProxyProjectionOptions {
  let registry = tokn_router::accounts::registry::Registry::builtin();
  let provider_hosts = registry
    .iter()
    .map(|descriptor| {
      (
        descriptor.id.to_string(),
        descriptor.hosts.iter().map(|host| (*host).to_string()).collect(),
      )
    })
    .collect::<BTreeMap<_, _>>();
  V2ForwardProxyProjectionOptions {
    route_mode,
    default_intercept_hosts: tokn_router::proxy_default_intercept_hosts()
      .map(str::to_string)
      .collect(),
    provider_hosts,
  }
}
