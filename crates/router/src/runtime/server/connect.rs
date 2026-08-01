//! Prepared CONNECT upgrades and post-response tunnel execution.
//!
//! CONNECT setup is split at the response boundary. Policy rejection,
//! interception availability, and upstream dialing all complete before a 200
//! response can be returned. Once the response is committed, the owning
//! connection task runs the prepared upgrade and reports only post-response
//! transport failures.

use super::{BoxTunnelIo, ConnectUpgradeUnavailableReason, ListenerServerState, ServerError};
use crate::runtime::{ConnectDispatch, ConnectDispatchSite};
use axum::body::Body;
use http::Request;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use snafu::Snafu;
use std::io;
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
  session: ConnectSession,
  on_upgrade: OnUpgrade,
  upstream: BoxTunnelIo,
}

impl ConnectUpgrade {
  pub(super) fn session(&self) -> &ConnectSession {
    &self.session
  }

  /// Await Hyper's downstream upgrade and pump bytes in both directions.
  pub(super) async fn run(self) -> ConnectRunResult<ConnectRunReport> {
    let Self {
      session,
      on_upgrade,
      mut upstream,
    } = self;
    let site = session.dispatch().site().clone();
    let upgraded = on_upgrade.await.map_err(|source| ConnectRunError::DownstreamUpgrade {
      site: site.clone(),
      source,
    })?;
    let mut downstream = TokioIo::new(upgraded);
    let (client_to_upstream, upstream_to_client) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
      .await
      .map_err(|source| ConnectRunError::TunnelPump { site, source })?;

    Ok(ConnectRunReport {
      session,
      client_to_upstream,
      upstream_to_client,
    })
  }
}

/// Successful byte counts and session identity for one completed tunnel.
#[derive(Debug)]
pub(super) struct ConnectRunReport {
  session: ConnectSession,
  client_to_upstream: u64,
  upstream_to_client: u64,
}

impl ConnectRunReport {
  pub(super) fn session(&self) -> &ConnectSession {
    &self.session
  }

  pub(super) const fn client_to_upstream(&self) -> u64 {
    self.client_to_upstream
  }

  pub(super) const fn upstream_to_client(&self) -> u64 {
    self.upstream_to_client
  }
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
}

impl ConnectRunError {
  pub(super) fn site(&self) -> &ConnectDispatchSite {
    match self {
      Self::DownstreamUpgrade { site, .. } | Self::TunnelPump { site, .. } => site,
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
  match dispatch.action() {
    ConnectAction::Reject => Err(ServerError::connect_rejected(dispatch.site().clone())),
    ConnectAction::Intercept => Err(ServerError::connect_interception_unavailable(dispatch.site().clone())),
    ConnectAction::Tunnel => {
      if request.extensions().get::<OnUpgrade>().is_none() {
        return Err(ServerError::connect_upgrade_unavailable(
          dispatch.site().clone(),
          ConnectUpgradeUnavailableReason::MissingToken,
        ));
      }

      let upstream = state
        .gateway()
        .tunnel_connector()
        .connect(dispatch.authority().authority())
        .await
        .map_err(|source| ServerError::tunnel_connect(dispatch.site().clone(), source))?;

      // Taking `OnUpgrade` is intentionally last: all recoverable setup
      // failures must remain materializable as an HTTP response.
      let on_upgrade = hyper::upgrade::on(request);
      Ok(ConnectUpgrade {
        session: ConnectSession { dispatch, access },
        on_upgrade,
        upstream,
      })
    }
  }
}
