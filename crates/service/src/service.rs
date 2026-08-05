//! Cloneable Tower service boundary for low-level HTTP execution.

use crate::{Request, Response};
use std::error::Error as StdError;
use std::task::{Context, Poll};
use tower::util::BoxCloneSyncService;
use tower::{Service, ServiceExt};

/// Type-erased failure returned by a low-level request service.
#[derive(Debug)]
pub struct ServiceError {
  source: crate::BoxError,
}

impl ServiceError {
  /// Erase a concrete service failure.
  pub fn new(source: impl StdError + Send + Sync + 'static) -> Self {
    Self {
      source: Box::new(source),
    }
  }

  /// Retain an error that is already type-erased.
  pub fn from_boxed(source: crate::BoxError) -> Self {
    Self { source }
  }

  /// Return the concrete error when its type is known.
  pub fn downcast_ref<E>(&self) -> Option<&E>
  where
    E: StdError + 'static,
  {
    self.source.downcast_ref()
  }

  /// Recover the type-erased source.
  pub fn into_source(self) -> crate::BoxError {
    self.source
  }
}

impl std::fmt::Display for ServiceError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.source.fmt(formatter)
  }
}

impl StdError for ServiceError {
  fn source(&self) -> Option<&(dyn StdError + 'static)> {
    Some(self.source.as_ref())
  }
}

/// Cloneable, type-erased Tower service over native HTTP messages.
///
/// Request extensions are preserved, so higher-level adapters can attach
/// routing or lifecycle context without adding those concepts to this crate.
#[derive(Clone)]
pub struct RequestService {
  inner: BoxCloneSyncService<Request, Response, ServiceError>,
}

impl std::fmt::Debug for RequestService {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.debug_struct("RequestService").finish_non_exhaustive()
  }
}

impl RequestService {
  /// Erase a cloneable Tower HTTP service behind the public boundary.
  pub fn new<S>(service: S) -> Self
  where
    S: Service<Request, Response = Response> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Error: StdError + Send + Sync + 'static,
  {
    Self {
      inner: BoxCloneSyncService::new(service.map_err(ServiceError::new)),
    }
  }

  /// Wait for readiness and execute one request.
  pub async fn execute(&self, request: Request) -> Result<Response, ServiceError> {
    self.clone().oneshot(request).await
  }
}

impl Service<Request> for RequestService {
  type Response = Response;
  type Error = ServiceError;
  type Future = <BoxCloneSyncService<Request, Response, ServiceError> as Service<Request>>::Future;

  fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(context)
  }

  fn call(&mut self, request: Request) -> Self::Future {
    self.inner.call(request)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::body;
  use bytes::Bytes;
  use http_body_util::BodyExt;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Arc;

  #[tokio::test]
  async fn executes_native_http_service_after_readiness() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = RequestService::new(tower::service_fn({
      let calls = calls.clone();
      move |request: Request| {
        let calls = calls.clone();
        async move {
          calls.fetch_add(1, Ordering::Relaxed);
          assert_eq!(request.uri(), "/v1/responses");
          let body = request.into_body().collect().await.unwrap().to_bytes();
          Ok::<_, std::io::Error>(http::Response::new(body::full(body)))
        }
      }
    }));
    let request = http::Request::post("/v1/responses")
      .body(body::full(Bytes::from_static(br#"{"model":"test"}"#)))
      .unwrap();

    let response = service.execute(request).await.unwrap();

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
      response.into_body().collect().await.unwrap().to_bytes(),
      Bytes::from_static(br#"{"model":"test"}"#)
    );
  }
}
