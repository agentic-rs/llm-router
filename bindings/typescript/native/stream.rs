use crate::error::{native_error, sdk_error, SERIALIZATION_ERROR, STREAM_ERROR};
use crate::lifecycle::{cancellation_error, lock_unpoisoned, CancelReason, Cancellation, OperationGuard};
use futures_util::{Stream, StreamExt};
use napi::bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, Buffer};
use napi::{Env, Result};
use napi_derive::napi;
use std::sync::{Arc, Mutex};
use tokn_sdk::{ByteStream, GenerateStream, TextStream};

struct ClosableStream<S> {
  stream: Mutex<Option<(S, OperationGuard)>>,
  next: tokio::sync::Mutex<()>,
  cancellation: Arc<Cancellation>,
}

impl<S> ClosableStream<S>
where
  S: Send + 'static,
{
  fn new(stream: S, guard: OperationGuard, cancellation: Arc<Cancellation>) -> Arc<Self> {
    let state = Arc::new(Self {
      stream: Mutex::new(Some((stream, guard))),
      next: tokio::sync::Mutex::new(()),
      cancellation: cancellation.clone(),
    });
    let weak = Arc::downgrade(&state);
    cancellation.set_cleanup(move || {
      if let Some(state) = weak.upgrade() {
        state.discard();
      }
    });
    state
  }

  fn discard(&self) {
    lock_unpoisoned(&self.stream).take();
  }

  fn close(&self) {
    self.cancellation.cancel(CancelReason::StreamClosed);
    self.discard();
  }

  fn cancellation_result(&self, reason: CancelReason) -> Result<Option<()>> {
    match reason {
      CancelReason::StreamClosed => Ok(None),
      CancelReason::Live => Ok(Some(())),
      reason => Err(cancellation_error(reason)),
    }
  }
}

impl<S, T, E> ClosableStream<S>
where
  S: Stream<Item = std::result::Result<T, E>> + Unpin + Send + 'static,
{
  async fn next(&self) -> Result<Option<std::result::Result<T, E>>> {
    let next = tokio::select! {
      biased;
      reason = self.cancellation.cancelled() => {
        return self.cancellation_result(reason).map(|_| None);
      }
      next = self.next.lock() => next,
    };

    let Some((mut stream, guard)) = lock_unpoisoned(&self.stream).take() else {
      drop(next);
      return match self.cancellation.reason() {
        CancelReason::Live | CancelReason::StreamClosed => Ok(None),
        reason => Err(cancellation_error(reason)),
      };
    };

    let item = tokio::select! {
      biased;
      reason = self.cancellation.cancelled() => {
        drop(guard);
        drop(next);
        return self.cancellation_result(reason).map(|_| None);
      }
      item = stream.next() => item,
    };

    match item {
      Some(Ok(item)) => {
        let mut stored = lock_unpoisoned(&self.stream);
        if self.cancellation.reason() == CancelReason::Live {
          *stored = Some((stream, guard));
          Ok(Some(Ok(item)))
        } else {
          let reason = self.cancellation.reason();
          drop(stored);
          drop(guard);
          self.cancellation_result(reason).map(|_| None)
        }
      }
      Some(Err(error)) => {
        drop(guard);
        self.cancellation.cancel(CancelReason::StreamClosed);
        Ok(Some(Err(error)))
      }
      None => {
        drop(guard);
        self.cancellation.cancel(CancelReason::StreamClosed);
        Ok(None)
      }
    }
  }
}

#[napi]
pub struct NativeByteStream {
  status: u32,
  headers_json: String,
  stream: Arc<ClosableStream<ByteStream>>,
}

impl NativeByteStream {
  pub(crate) fn new(
    status: u16,
    headers_json: String,
    stream: ByteStream,
    guard: OperationGuard,
    cancellation: Arc<Cancellation>,
  ) -> Self {
    Self {
      status: u32::from(status),
      headers_json,
      stream: ClosableStream::new(stream, guard, cancellation),
    }
  }
}

impl Drop for NativeByteStream {
  fn drop(&mut self) {
    self.stream.close();
  }
}

#[napi]
impl NativeByteStream {
  #[napi(getter)]
  pub fn status(&self) -> u32 {
    self.status
  }

  #[napi(getter)]
  pub fn headers_json(&self) -> String {
    self.headers_json.clone()
  }

  #[napi]
  pub fn next(&self, env: Env) -> Result<AsyncBlock<Option<Buffer>>> {
    let stream = self.stream.clone();
    AsyncBlockBuilder::new(async move {
      match stream.next().await? {
        Some(Ok(chunk)) => Ok(Some(Buffer::from(chunk.to_vec()))),
        Some(Err(error)) => {
          stream.close();
          Err(native_error(STREAM_ERROR, format!("stream read failed: {error}")))
        }
        None => Ok(None),
      }
    })
    .build(&env)
  }

  #[napi]
  pub fn close(&self, env: Env) -> Result<AsyncBlock<()>> {
    let stream = self.stream.clone();
    AsyncBlockBuilder::new(async move {
      stream.close();
      Ok(())
    })
    .build(&env)
  }
}

#[napi]
pub struct NativeGenerateStream {
  stream: Arc<ClosableStream<GenerateStream>>,
}

impl NativeGenerateStream {
  pub(crate) fn new(stream: GenerateStream, guard: OperationGuard, cancellation: Arc<Cancellation>) -> Self {
    Self {
      stream: ClosableStream::new(stream, guard, cancellation),
    }
  }
}

impl Drop for NativeGenerateStream {
  fn drop(&mut self) {
    self.stream.close();
  }
}

#[napi]
impl NativeGenerateStream {
  #[napi]
  pub fn next(&self, env: Env) -> Result<AsyncBlock<Option<String>>> {
    let stream = self.stream.clone();
    AsyncBlockBuilder::new(async move {
      match stream.next().await? {
        Some(Ok(event)) => serde_json::to_string(&event).map(Some).map_err(|error| {
          stream.close();
          native_error(
            SERIALIZATION_ERROR,
            format!("failed to serialize generation stream event: {error}"),
          )
        }),
        Some(Err(error)) => {
          stream.close();
          Err(sdk_error(error))
        }
        None => Ok(None),
      }
    })
    .build(&env)
  }

  #[napi]
  pub fn close(&self, env: Env) -> Result<AsyncBlock<()>> {
    let stream = self.stream.clone();
    AsyncBlockBuilder::new(async move {
      stream.close();
      Ok(())
    })
    .build(&env)
  }
}

#[napi]
pub struct NativeTextStream {
  stream: Arc<ClosableStream<TextStream>>,
}

impl NativeTextStream {
  pub(crate) fn new(stream: TextStream, guard: OperationGuard, cancellation: Arc<Cancellation>) -> Self {
    Self {
      stream: ClosableStream::new(stream, guard, cancellation),
    }
  }
}

impl Drop for NativeTextStream {
  fn drop(&mut self) {
    self.stream.close();
  }
}

#[napi]
impl NativeTextStream {
  #[napi]
  pub fn next(&self, env: Env) -> Result<AsyncBlock<Option<String>>> {
    let stream = self.stream.clone();
    AsyncBlockBuilder::new(async move {
      match stream.next().await? {
        Some(Ok(text)) => Ok(Some(text)),
        Some(Err(error)) => {
          stream.close();
          Err(sdk_error(error))
        }
        None => Ok(None),
      }
    })
    .build(&env)
  }

  #[napi]
  pub fn close(&self, env: Env) -> Result<AsyncBlock<()>> {
    let stream = self.stream.clone();
    AsyncBlockBuilder::new(async move {
      stream.close();
      Ok(())
    })
    .build(&env)
  }
}
