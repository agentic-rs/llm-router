//! Process-owned shutdown signals. Construct before starting listeners so a
//! ready server never has a window without its termination handler installed.

use std::io;

pub struct ShutdownSignal {
  #[cfg(unix)]
  interrupt: tokio::signal::unix::Signal,
  #[cfg(unix)]
  terminate: tokio::signal::unix::Signal,
  #[cfg(windows)]
  interrupt: tokio::signal::windows::CtrlC,
  #[cfg(windows)]
  terminate: tokio::signal::windows::CtrlBreak,
}

impl ShutdownSignal {
  pub fn new() -> io::Result<Self> {
    #[cfg(unix)]
    {
      use tokio::signal::unix::{signal, SignalKind};
      Ok(Self {
        interrupt: signal(SignalKind::interrupt())?,
        terminate: signal(SignalKind::terminate())?,
      })
    }
    #[cfg(windows)]
    {
      Ok(Self {
        interrupt: tokio::signal::windows::ctrl_c()?,
        terminate: tokio::signal::windows::ctrl_break()?,
      })
    }
    #[cfg(not(any(unix, windows)))]
    Ok(Self {})
  }

  pub async fn wait(mut self) -> io::Result<()> {
    #[cfg(any(unix, windows))]
    {
      let received = tokio::select! {
        signal = self.interrupt.recv() => signal,
        signal = self.terminate.recv() => signal,
      };
      received.ok_or_else(|| io::Error::other("shutdown signal stream closed"))
    }
    #[cfg(not(any(unix, windows)))]
    tokio::signal::ctrl_c().await
  }
}
