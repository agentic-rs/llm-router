use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

pub async fn wait_for_listener_closed(address: SocketAddr) {
  wait_for_connection_refused(|| async { TcpStream::connect(address).await.map(drop) }).await;
}

async fn wait_for_connection_refused<F, C>(mut connect: F)
where
  F: FnMut() -> C,
  C: Future<Output = io::Result<()>>,
{
  // Windows can take several seconds to report refusal. On Linux, closing the
  // listener can first reset a probe already in the accept queue. Retry those
  // races; only a fresh refused connection proves that admission has stopped.
  tokio::time::timeout(Duration::from_secs(10), async {
    loop {
      match connect().await {
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => break,
        Err(error)
          if !matches!(
            error.kind(),
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::Interrupted
          ) =>
        {
          panic!("unexpected listener closure probe error: {error}");
        }
        _ => tokio::time::sleep(Duration::from_millis(10)).await,
      }
    }
  })
  .await
  .expect("accept socket must close while the admitted response is still active");
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn retries_successful_and_reset_probes_until_connection_is_refused() {
    let mut results = [
      Ok(()),
      Err(ErrorKind::ConnectionReset.into()),
      Err(ErrorKind::ConnectionAborted.into()),
      Err(ErrorKind::Interrupted.into()),
      Err(ErrorKind::ConnectionRefused.into()),
    ]
    .into_iter();
    wait_for_connection_refused(|| std::future::ready(results.next().expect("probe after refusal"))).await;
    assert!(results.next().is_none(), "reset must not count as listener closure");
  }

  #[tokio::test]
  #[should_panic(expected = "unexpected listener closure probe error")]
  async fn unrelated_probe_errors_do_not_count_as_listener_closure() {
    wait_for_connection_refused(|| std::future::ready(Err(ErrorKind::PermissionDenied.into()))).await;
  }
}
