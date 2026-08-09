//! Config-driven HTTP services for one linked v2 gateway generation.
//!
//! This module stops at the Tower boundary. It does not bind sockets or own
//! connection accept loops; a later runtime may attach these services to any
//! compatible HTTP server.

use super::{
  connect_upgrade_channel, handle_forward_proxy_request, handle_llm_api_request, GatewayServerState,
  GatewayServerStateError, GatewayServingDefaults, ListenerServerState,
};
use crate::runtime::{
  link_gateway_runtime, materialize_listeners, ConnectUpgradeSender, GatewayLinkError, LinkedGatewayRuntime,
  ListenerResourceError, MaterializedListenerKind, RuntimeNameRegistry,
};
use axum::body::Body as AxumBody;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use tokn_accounts::registry::Registry;
use tokn_core::account::AccountConfig;
use tokn_core::util::http::HttpClientOptions;
use tokn_policy::{GatewayPlan, ListenerId};

/// Executable HTTP services compiled from one exact v2 gateway generation.
#[derive(Clone)]
pub struct GatewayEngine {
  runtime: Arc<LinkedGatewayRuntime>,
  listeners: Arc<BTreeMap<ListenerId, tokn_service::HttpService>>,
}

impl std::fmt::Debug for GatewayEngine {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("GatewayEngine")
      .field("listener_count", &self.listeners.len())
      .finish_non_exhaustive()
  }
}

impl GatewayEngine {
  /// Link a compiled v2 plan and build one native HTTP service per listener.
  ///
  /// Construction completes every configuration-, account-, authentication-,
  /// and transport-dependent step that can fail before socket binding.
  pub fn build(
    plan: &GatewayPlan,
    accounts: &[AccountConfig],
    registry: &Registry,
    names: &RuntimeNameRegistry,
    http_options: &HttpClientOptions,
    defaults: GatewayServingDefaults,
    local_key_db_path: Option<&Path>,
  ) -> GatewayEngineResult<Self> {
    let runtime = Arc::new(
      link_gateway_runtime(plan, accounts, registry, names).map_err(|source| GatewayEngineError::Link { source })?,
    );
    let resources = materialize_listeners(runtime.listeners(), local_key_db_path)
      .map_err(|source| GatewayEngineError::Resources { source })?;
    let gateway = Arc::new(
      GatewayServerState::build(runtime.clone(), http_options, defaults)
        .map_err(|source| GatewayEngineError::ServingState { source })?,
    );
    let listeners = resources
      .into_listeners()
      .map(|(listener_id, resource)| {
        let kind = resource.kind().clone();
        let state = Arc::new(ListenerServerState::new(gateway.clone(), resource));
        (listener_id, listener_http_service(state, kind))
      })
      .collect();

    Ok(Self {
      runtime,
      listeners: Arc::new(listeners),
    })
  }

  pub fn runtime(&self) -> &Arc<LinkedGatewayRuntime> {
    &self.runtime
  }

  /// Return the service for one configured listener.
  pub fn listener(&self, listener_id: &ListenerId) -> Option<&tokn_service::HttpService> {
    self.listeners.get(listener_id)
  }

  pub fn listeners(&self) -> impl ExactSizeIterator<Item = (&ListenerId, &tokn_service::HttpService)> {
    self.listeners.iter()
  }
}

fn listener_http_service(state: Arc<ListenerServerState>, kind: MaterializedListenerKind) -> tokn_service::HttpService {
  tokn_service::HttpService::new(tower::service_fn(move |request: tokn_service::Request| {
    let state = state.clone();
    let kind = kind.clone();
    async move {
      let connect_upgrades = request.extensions().get::<ConnectUpgradeSender>().cloned();
      if matches!(kind, MaterializedListenerKind::ForwardProxy { .. })
        && request.method() == http::Method::CONNECT
        && connect_upgrades.is_none()
      {
        return Err(ListenerServiceError::MissingConnectUpgradeHandoff);
      }

      let request = request.map(AxumBody::new);
      let response = match kind {
        MaterializedListenerKind::LlmApi => handle_llm_api_request(&state, request).await,
        MaterializedListenerKind::ForwardProxy { .. } => {
          let fallback;
          let upgrades = match connect_upgrades.as_ref() {
            Some(upgrades) => upgrades,
            None => {
              let (sender, _receiver) = connect_upgrade_channel();
              fallback = sender;
              &fallback
            }
          };
          handle_forward_proxy_request(&state, request, upgrades).await
        }
      };
      Ok(response.map(axum_body_to_service))
    }
  }))
}

fn axum_body_to_service(body: AxumBody) -> tokn_service::Body {
  tokn_service::body::stream(body.into_data_stream())
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum GatewayEngineError {
  #[snafu(display("failed to link the v2 gateway plan: {source}"))]
  Link { source: GatewayLinkError },

  #[snafu(display("failed to materialize v2 listener resources: {source}"))]
  Resources { source: ListenerResourceError },

  #[snafu(display("failed to build v2 gateway serving state: {source}"))]
  ServingState { source: GatewayServerStateError },
}

pub type GatewayEngineResult<T> = std::result::Result<T, GatewayEngineError>;

#[derive(Debug, Snafu)]
enum ListenerServiceError {
  #[snafu(display("forward-proxy CONNECT requires a ConnectUpgradeSender request extension"))]
  MissingConnectUpgradeHandoff,
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::Bytes;
  use http::{Request, StatusCode};
  use std::net::{Ipv4Addr, SocketAddr};
  use tokn_policy::{
    ClientAuthPlan, ConnectAction, ForwardProxyListenerPlan, HttpAction, ListenerPlan, LlmApiListenerPlan,
  };

  fn listener_id() -> ListenerId {
    ListenerId::new("api").unwrap()
  }

  fn rejecting_plan() -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::from([(
        listener_id(),
        ListenerPlan::LlmApi(LlmApiListenerPlan::new(
          SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
          ClientAuthPlan::None,
          Box::default(),
          HttpAction::Reject,
        )),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    )
  }

  fn rejecting_proxy_plan() -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::from([(
        listener_id(),
        ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
          SocketAddr::from((Ipv4Addr::LOCALHOST, 42_501)),
          ClientAuthPlan::None,
          Box::default(),
          HttpAction::Reject,
          Box::default(),
          ConnectAction::Reject,
          None,
        )),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    )
  }

  fn build_engine(plan: &GatewayPlan) -> GatewayEngine {
    GatewayEngine::build(
      plan,
      &[],
      &Registry::builtin(),
      &RuntimeNameRegistry::builtin(),
      &HttpClientOptions::default(),
      GatewayServingDefaults::new(super::super::RequestBodyLimits::new(1024, 1024)),
      None,
    )
    .unwrap()
  }

  #[tokio::test]
  async fn builds_native_service_for_configured_listener() {
    let engine = build_engine(&rejecting_plan());
    let request = Request::post("/v1/responses")
      .header(http::header::HOST, "client.example")
      .body(tokn_service::body::full(Bytes::from_static(br#"{"model":"ignored"}"#)))
      .unwrap();

    let response = engine.listener(&listener_id()).unwrap().execute(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
  }

  #[tokio::test]
  async fn forward_http_does_not_require_connect_handoff() {
    let engine = build_engine(&rejecting_proxy_plan());
    let request = Request::get("http://upstream.example/v1/models")
      .body(tokn_service::body::empty())
      .unwrap();

    let response = engine.listener(&listener_id()).unwrap().execute(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
  }

  #[tokio::test]
  async fn connect_requires_server_owned_upgrade_handoff() {
    let engine = build_engine(&rejecting_proxy_plan());
    let request = Request::builder()
      .method(http::Method::CONNECT)
      .uri("upstream.example:443")
      .body(tokn_service::body::empty())
      .unwrap();

    let error = engine
      .listener(&listener_id())
      .unwrap()
      .execute(request)
      .await
      .unwrap_err();

    assert!(error.to_string().contains("ConnectUpgradeSender"));
  }
}
