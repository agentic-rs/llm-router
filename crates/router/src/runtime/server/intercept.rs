//! Fallible TLS identity preparation for intercepted CONNECT sessions.
//!
//! Leaf creation and server configuration happen before the outer 200 is
//! committed. The prepared configuration contains one CONNECT-pinned
//! identity; ClientHello SNI can validate that identity but cannot select it.

use super::ListenerServerState;
use crate::runtime::ConnectDispatch;
use anyhow::{anyhow, Context};
use std::sync::Arc;

pub(super) struct PreparedTlsIntercept {
  config: Arc<rustls::ServerConfig>,
}

impl PreparedTlsIntercept {
  pub(super) fn into_config(self) -> Arc<rustls::ServerConfig> {
    self.config
  }
}

pub(super) fn prepare_tls_intercept(
  state: &ListenerServerState,
  dispatch: &ConnectDispatch,
) -> anyhow::Result<PreparedTlsIntercept> {
  let ca = state
    .resource()
    .kind()
    .proxy_ca()
    .ok_or_else(|| anyhow!("intercepting listener has no materialized proxy CA"))?;
  let host = dispatch.authority().host();
  let config = ca
    .pinned_server_config(host)
    .with_context(|| format!("prepare pinned TLS identity for {host}"))?;
  Ok(PreparedTlsIntercept { config })
}
