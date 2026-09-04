//! Owned HTTP connections and a bounded shutdown shared with forward proxies.
//! Keeping connection tasks in a JoinSet lets us cancel and join stragglers
//! before the caller flushes request persistence.

use anyhow::{bail, Result};
use axum::extract::{ConnectInfo, Extension};
use axum::Router;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

pub const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

pub async fn serve_http<F>(app: Router, listener: TcpListener, shutdown: F) -> Result<()>
where
  F: Future<Output = ()> + Send,
{
  let app = app.layer(Extension(listener.local_addr()?));
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let mut connections = JoinSet::new();
  tokio::pin!(shutdown);
  let result = loop {
    tokio::select! {
      biased;
      _ = &mut shutdown => break Ok(()),
      Some(joined) = connections.join_next(), if !connections.is_empty() => report_join(joined),
      accepted = listener.accept() => {
        let (stream, peer) = match accepted {
          Ok(accepted) => accepted,
          Err(error) => break Err(error.into()),
        };
        let service = TowerToHyperService::new(app.clone().layer(Extension(ConnectInfo(peer))));
        let mut shutdown = shutdown_rx.clone();
        connections.spawn(async move {
          let mut builder = Builder::new();
          builder.timer(TokioTimer::new());
          let connection = builder.serve_connection(TokioIo::new(stream), service).with_upgrades();
          tokio::pin!(connection);
          let result = tokio::select! {
            result = &mut connection => result,
            _ = shutdown_requested(&mut shutdown) => {
              connection.as_mut().graceful_shutdown();
              connection.await
            }
          };
          if let Err(error) = result {
            tracing::debug!(%peer, %error, "HTTP connection closed");
          }
        });
      }
    }
  };
  drop(listener);
  let _ = shutdown_tx.send(true);
  let drained = drain_connections(&mut connections, SHUTDOWN_GRACE_PERIOD).await;
  result.and(drained)
}

pub(crate) async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
  if !*shutdown.borrow() {
    let _ = shutdown.changed().await;
  }
}

pub(crate) async fn drain_connections(connections: &mut JoinSet<()>, grace: Duration) -> Result<()> {
  let drained = tokio::time::timeout(grace, async {
    while let Some(joined) = connections.join_next().await {
      report_join(joined);
    }
  })
  .await;
  if drained.is_err() {
    let remaining = connections.len();
    tracing::warn!(
      remaining,
      "shutdown grace period expired; cancelling remaining connections"
    );
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    bail!("shutdown grace period expired with {remaining} connection(s) still active");
  }
  Ok(())
}

fn report_join(joined: Result<(), tokio::task::JoinError>) {
  if let Err(error) = joined {
    tracing::warn!(%error, "connection task failed");
  }
}

#[cfg(test)]
mod tests;
