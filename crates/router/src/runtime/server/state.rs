//! Immutable serving dependencies for one linked runtime generation.
//!
//! Transport clients are built once before listener binding and then shared
//! by every request through the generation's execution coordinator. A
//! listener retains this complete state alongside its own materialized
//! authentication and interception resources.

use super::super::{HttpExecutionCoordinator, LinkedGatewayRuntime, LinkedListener, MaterializedListener};
use super::{RequestBodyLimits, TunnelConnector, TunnelConnectorBuildError};
use snafu::Snafu;
use std::sync::Arc;
use tokn_core::util::http::{build_client, build_managed_client, build_opaque_client, HttpClientOptions};
use tokn_requests::execution::{ManagedHttpExecutor, OpaqueHttpExecutor};

/// Generation-wide serving values used when a listener has no narrower
/// override.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayServingDefaults {
  request_body_limits: RequestBodyLimits,
}

impl GatewayServingDefaults {
  pub const fn new(request_body_limits: RequestBodyLimits) -> Self {
    Self { request_body_limits }
  }

  pub const fn request_body_limits(self) -> RequestBodyLimits {
    self.request_body_limits
  }
}

/// Shared request-serving state for one exact linked runtime generation.
///
/// Construct this state before binding listeners. Its coordinator owns the
/// control-plane authorization client and both data-plane clients, preventing
/// per-request client pools and ensuring invalid transport options fail
/// startup atomically.
#[derive(Debug)]
pub struct GatewayServerState {
  runtime: Arc<LinkedGatewayRuntime>,
  http_execution: HttpExecutionCoordinator,
  tunnel_connector: TunnelConnector,
  defaults: GatewayServingDefaults,
}

impl GatewayServerState {
  pub fn build(
    runtime: Arc<LinkedGatewayRuntime>,
    http_options: &HttpClientOptions,
    defaults: GatewayServingDefaults,
  ) -> GatewayServerStateResult<Self> {
    let authorization_http =
      build_client(http_options).map_err(|source| GatewayServerStateError::AuthorizationHttpClient { source })?;
    let managed_http =
      build_managed_client(http_options).map_err(|source| GatewayServerStateError::ManagedHttpClient { source })?;
    let opaque_http =
      build_opaque_client(http_options).map_err(|source| GatewayServerStateError::OpaqueHttpClient { source })?;
    let http_execution = HttpExecutionCoordinator::new(
      ManagedHttpExecutor::new(managed_http),
      OpaqueHttpExecutor::new(authorization_http, opaque_http),
    );
    let tunnel_connector =
      TunnelConnector::build(http_options).map_err(|source| GatewayServerStateError::TunnelConnector { source })?;

    Ok(Self {
      runtime,
      http_execution,
      tunnel_connector,
      defaults,
    })
  }

  pub fn runtime(&self) -> &Arc<LinkedGatewayRuntime> {
    &self.runtime
  }

  pub fn http_execution(&self) -> &HttpExecutionCoordinator {
    &self.http_execution
  }

  pub fn tunnel_connector(&self) -> &TunnelConnector {
    &self.tunnel_connector
  }

  pub const fn defaults(&self) -> GatewayServingDefaults {
    self.defaults
  }
}

/// State shared by every connection entering one listener.
///
/// Keeping the materialized listener beside the complete serving generation
/// prevents authentication, CA, routing, and transport resources from being
/// mixed across reload generations.
#[derive(Debug)]
pub struct ListenerServerState {
  gateway: Arc<GatewayServerState>,
  resource: MaterializedListener,
}

impl ListenerServerState {
  pub(super) fn new(gateway: Arc<GatewayServerState>, resource: MaterializedListener) -> Self {
    Self { gateway, resource }
  }

  pub fn gateway(&self) -> &Arc<GatewayServerState> {
    &self.gateway
  }

  pub fn resource(&self) -> &MaterializedListener {
    &self.resource
  }

  pub fn listener(&self) -> &Arc<LinkedListener> {
    self.resource.listener()
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum GatewayServerStateError {
  #[snafu(display("failed to build the relay authorization HTTP client: {source}"))]
  AuthorizationHttpClient { source: anyhow::Error },

  #[snafu(display("failed to build the managed data-plane HTTP client: {source}"))]
  ManagedHttpClient { source: anyhow::Error },

  #[snafu(display("failed to build the opaque data-plane HTTP client: {source}"))]
  OpaqueHttpClient { source: anyhow::Error },

  #[snafu(display("failed to build the CONNECT tunnel transport: {source}"))]
  TunnelConnector { source: TunnelConnectorBuildError },
}

pub type GatewayServerStateResult<T> = std::result::Result<T, GatewayServerStateError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_gateway_runtime, RuntimeNameRegistry};
  use std::collections::BTreeMap;
  use tokn_accounts::registry::Registry;
  use tokn_policy::GatewayPlan;

  fn empty_runtime() -> Arc<LinkedGatewayRuntime> {
    let plan = GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    Arc::new(link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap())
  }

  #[test]
  fn state_retains_one_exact_runtime_and_serving_defaults() {
    let runtime = empty_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    let limits = RequestBodyLimits::new(64 * 1024, 256 * 1024);
    let defaults = GatewayServingDefaults::new(limits);
    let state = GatewayServerState::build(runtime.clone(), &HttpClientOptions::default(), defaults).unwrap();

    assert!(Arc::ptr_eq(state.runtime(), &runtime));
    assert_eq!(state.defaults(), defaults);
    assert_eq!(state.defaults().request_body_limits(), limits);

    drop(runtime);
    assert!(weak_runtime.upgrade().is_some());
    drop(state);
    assert!(weak_runtime.upgrade().is_none());
  }

  #[test]
  fn invalid_transport_options_fail_generation_construction() {
    let options = HttpClientOptions {
      url: Some("http://[invalid".to_string()),
      ..HttpClientOptions::default()
    };

    let error = GatewayServerState::build(
      empty_runtime(),
      &options,
      GatewayServingDefaults::new(RequestBodyLimits::new(1, 1)),
    )
    .unwrap_err();

    assert!(matches!(error, GatewayServerStateError::AuthorizationHttpClient { .. }));
  }
}
