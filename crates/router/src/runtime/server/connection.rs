//! Immutable transport facts for one accepted listener connection.

use std::net::SocketAddr;

/// Socket endpoints captured when a listener accepts a connection.
///
/// Keeping these facts outside the HTTP request prevents untrusted headers
/// from influencing transport attribution. A copied value follows every
/// request on the connection, including intercepted HTTPS child requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConnectionMetadata {
  local_addr: SocketAddr,
  peer_addr: SocketAddr,
}

impl ConnectionMetadata {
  pub(super) const fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
    Self { local_addr, peer_addr }
  }

  pub(super) const fn local_addr(self) -> SocketAddr {
    self.local_addr
  }

  pub(super) const fn peer_addr(self) -> SocketAddr {
    self.peer_addr
  }
}
