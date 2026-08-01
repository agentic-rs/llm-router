//! Prepared CONNECT upgrades and post-response execution state.
//!
//! CONNECT setup is split at the response boundary. Policy rejection,
//! pinned TLS identity creation, and upstream dialing all complete before a 200
//! response can be returned. Once the response is committed, the owning
//! connection task runs the prepared upgrade and reports only post-response
//! transport failures.

use super::intercept::{prepare_tls_intercept, PreparedTlsIntercept};
use super::{BoxTunnelIo, ConnectUpgradeUnavailableReason, ListenerServerState, ServerError};
use crate::runtime::{ConnectDispatch, ConnectDispatchSite};
use axum::body::Body;
use http::Request;
use hyper::upgrade::OnUpgrade;
use snafu::Snafu;
use std::io;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokn_access::AccessContext;
use tokn_policy::ConnectAction;

/// Authenticated policy decision retained for the complete CONNECT lifetime.
#[derive(Debug)]
pub(super) struct ConnectSession {
  dispatch: ConnectDispatch,
  access: AccessContext,
}

impl ConnectSession {
  pub(super) fn dispatch(&self) -> &ConnectDispatch {
    &self.dispatch
  }

  pub(super) fn access(&self) -> &AccessContext {
    &self.access
  }
}

/// A CONNECT upgrade whose upstream transport is already ready.
///
/// The listener adapter transfers this value to the owning connection task
/// before returning 200. Dropping it closes the prepared upstream.
pub(super) struct ConnectUpgrade {
  session: Arc<ConnectSession>,
  on_upgrade: OnUpgrade,
  transport: ConnectTransport,
}

impl ConnectUpgrade {
  pub(super) fn session(&self) -> &ConnectSession {
    &self.session
  }

  pub(super) fn into_parts(self) -> (Arc<ConnectSession>, OnUpgrade, ConnectTransport) {
    (self.session, self.on_upgrade, self.transport)
  }
}

pub(super) enum ConnectTransport {
  Tunnel { upstream: BoxTunnelIo },
  Intercept { prepared: PreparedTlsIntercept },
}

/// Session identity and transport-specific outcome for one completed CONNECT.
#[derive(Debug)]
pub(super) struct ConnectRunReport {
  session: Arc<ConnectSession>,
  outcome: ConnectRunOutcome,
}

impl ConnectRunReport {
  pub(super) fn tunnel(session: Arc<ConnectSession>, client_to_upstream: u64, upstream_to_client: u64) -> Self {
    Self {
      session,
      outcome: ConnectRunOutcome::Tunnel {
        client_to_upstream,
        upstream_to_client,
      },
    }
  }

  pub(super) fn intercepted(session: Arc<ConnectSession>) -> Self {
    Self {
      session,
      outcome: ConnectRunOutcome::Intercept,
    }
  }

  pub(super) fn session(&self) -> &ConnectSession {
    &self.session
  }

  pub(super) const fn outcome(&self) -> ConnectRunOutcome {
    self.outcome
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectRunOutcome {
  Tunnel {
    client_to_upstream: u64,
    upstream_to_client: u64,
  },
  Intercept,
}

/// A failure after a successful CONNECT response was committed.
#[derive(Debug, Snafu)]
pub(super) enum ConnectRunError {
  #[snafu(display("downstream upgrade failed for {site}: {source}"))]
  DownstreamUpgrade {
    site: ConnectDispatchSite,
    source: hyper::Error,
  },

  #[snafu(display("tunnel byte pump failed for {site}: {source}"))]
  TunnelPump {
    site: ConnectDispatchSite,
    source: io::Error,
  },

  #[snafu(display("TLS handshake timed out for {site}"))]
  TlsHandshakeTimeout { site: ConnectDispatchSite },

  #[snafu(display("TLS handshake failed for {site}: {source}"))]
  TlsHandshake {
    site: ConnectDispatchSite,
    source: io::Error,
  },

  #[snafu(display("intercepted HTTPS connection failed for {site}: {source}"))]
  InterceptHttp {
    site: ConnectDispatchSite,
    source: hyper::Error,
  },
}

impl ConnectRunError {
  pub(super) fn site(&self) -> &ConnectDispatchSite {
    match self {
      Self::DownstreamUpgrade { site, .. }
      | Self::TunnelPump { site, .. }
      | Self::TlsHandshakeTimeout { site }
      | Self::TlsHandshake { site, .. }
      | Self::InterceptHttp { site, .. } => site,
    }
  }
}

pub(super) type ConnectRunResult<T> = std::result::Result<T, ConnectRunError>;
pub(super) type ConnectUpgradeSender = mpsc::Sender<ConnectUpgrade>;
pub(super) type ConnectUpgradeReceiver = mpsc::Receiver<ConnectUpgrade>;

/// Create the single-slot handoff used by one forward-proxy connection.
pub(super) fn connect_upgrade_channel() -> (ConnectUpgradeSender, ConnectUpgradeReceiver) {
  mpsc::channel(1)
}

/// Complete every fallible CONNECT setup step that must precede a 200.
pub(super) async fn prepare_connect_upgrade(
  state: &ListenerServerState,
  dispatch: ConnectDispatch,
  access: AccessContext,
  request: &mut Request<Body>,
) -> Result<ConnectUpgrade, ServerError> {
  if dispatch.action() == ConnectAction::Reject {
    return Err(ServerError::connect_rejected(dispatch.site().clone()));
  }
  if request.extensions().get::<OnUpgrade>().is_none() {
    return Err(ServerError::connect_upgrade_unavailable(
      dispatch.site().clone(),
      ConnectUpgradeUnavailableReason::MissingToken,
    ));
  }

  let transport = match dispatch.action() {
    ConnectAction::Reject => unreachable!("rejected CONNECT returned before transport preparation"),
    ConnectAction::Intercept => {
      let prepared = prepare_tls_intercept(state, &dispatch)
        .map_err(|source| ServerError::connect_interception_setup(dispatch.site().clone(), source))?;
      ConnectTransport::Intercept { prepared }
    }
    ConnectAction::Tunnel => {
      let upstream = state
        .gateway()
        .tunnel_connector()
        .connect(dispatch.authority().authority())
        .await
        .map_err(|source| ServerError::tunnel_connect(dispatch.site().clone(), source))?;
      ConnectTransport::Tunnel { upstream }
    }
  };

  // Taking `OnUpgrade` is intentionally last: all recoverable setup
  // failures must remain materializable as an HTTP response.
  let on_upgrade = hyper::upgrade::on(request);
  Ok(ConnectUpgrade {
    session: Arc::new(ConnectSession { dispatch, access }),
    on_upgrade,
    transport,
  })
}
