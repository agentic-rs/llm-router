//! Common browser-access behavior for legacy and v2 API listeners.

use axum::http::{HeaderName, HeaderValue, Method};
use std::time::Duration;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

/// The predicate reads live policy; apply this layer only to client API routes,
/// outside authentication, never to health or administration endpoints.
pub(crate) fn layer(allowed: impl Fn(&str) -> bool + Send + Sync + 'static) -> CorsLayer {
  layer_for_request(move |origin, _| allowed(origin))
}

/// Dynamic API mounts also need to exclude unmatched fallback paths.
pub(crate) fn layer_for_request(
  allowed: impl Fn(&str, &axum::http::request::Parts) -> bool + Send + Sync + 'static,
) -> CorsLayer {
  CorsLayer::new()
    .allow_origin(AllowOrigin::predicate(move |origin: &HeaderValue, parts| {
      origin.to_str().ok().is_some_and(|origin| allowed(origin, parts))
    }))
    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
    .allow_headers(AllowHeaders::mirror_request())
    .expose_headers([HeaderName::from_static(crate::request_id::REQUEST_ID_HEADER)])
    .max_age(Duration::from_secs(600))
}

/// Match the existing localhost policy without accepting lookalike domains,
/// non-HTTP origins, URL paths, or embedded credentials.
pub(crate) fn is_localhost_origin(origin: &str) -> bool {
  let Ok(origin) = reqwest::Url::parse(origin) else {
    return false;
  };
  if !matches!(origin.scheme(), "http" | "https")
    || !origin.username().is_empty()
    || origin.password().is_some()
    || origin.path() != "/"
    || origin.query().is_some()
    || origin.fragment().is_some()
  {
    return false;
  }
  origin.host_str().is_some_and(|host| {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || matches!(host, "::1" | "[::1]")
  })
}
