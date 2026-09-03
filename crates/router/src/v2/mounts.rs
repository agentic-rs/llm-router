//! Exact API dispatch for profile-owned mounts. The index belongs to a runtime
//! generation, so authentication, discovery and dispatch observe one snapshot.

use super::*;
use std::borrow::Cow;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ApiOperation {
  Generate(Endpoint),
  Models,
  Providers,
}

#[derive(Debug)]
pub(super) struct MountedEndpoint {
  pub(super) profile: ProfileId,
  pub(super) operation: ApiOperation,
  pub(super) enabled: bool,
}

#[derive(Default)]
pub(super) struct ApiMounts {
  paths: BTreeMap<String, MountedEndpoint>,
}

impl ApiMounts {
  pub(super) fn new(plan: &GatewayPlan) -> anyhow::Result<Self> {
    let mut mounts = Self::default();
    for (id, profile) in plan.profiles() {
      let Some(binding) = profile.api_binding() else {
        continue;
      };
      for (suffix, operation) in [
        ("chat/completions", ApiOperation::Generate(Endpoint::ChatCompletions)),
        ("responses", ApiOperation::Generate(Endpoint::Responses)),
        ("messages", ApiOperation::Generate(Endpoint::Messages)),
        ("models", ApiOperation::Models),
        ("providers", ApiOperation::Providers),
      ] {
        let path = format!("{}/{suffix}", binding.path());
        let enabled = match operation {
          ApiOperation::Generate(endpoint) => binding
            .endpoints()
            .iter()
            .any(|id| id.as_str() == operation_name(endpoint)),
          _ => true,
        };
        let entry = MountedEndpoint {
          profile: id.clone(),
          operation,
          enabled,
        };
        if let Some(previous) = mounts.paths.insert(path.clone(), entry) {
          anyhow::bail!("API path '{path}' is owned by both '{}' and '{id}'", previous.profile);
        }
      }
    }
    Ok(mounts)
  }

  pub(super) fn get(&self, path: &str) -> Option<&MountedEndpoint> {
    self.paths.get(canonical_path(path).as_ref())
  }
}

// Normalize hex case only. Never decode escaped slashes or alias distinct raw
// paths: doing so could cross a profile's API namespace.
fn canonical_path(path: &str) -> Cow<'_, str> {
  if !path.contains('%') {
    return Cow::Borrowed(path);
  }
  let mut bytes = path.as_bytes().to_vec();
  let mut i = 0;
  while i + 2 < bytes.len() {
    if bytes[i] == b'%' && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
      bytes[i + 1] = bytes[i + 1].to_ascii_uppercase();
      bytes[i + 2] = bytes[i + 2].to_ascii_uppercase();
      i += 3;
    } else {
      i += 1;
    }
  }
  Cow::Owned(String::from_utf8(bytes).expect("ASCII substitutions preserve UTF-8"))
}

pub(super) async fn dispatch(
  Extension(state): Extension<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  connection: InboundConnectionInfo,
  request: Request,
) -> Response {
  let Some(entry) = state.mounts.get(request.uri().path()) else {
    return ApiError::not_found("API path is not exposed").into_response();
  };
  if !entry.enabled {
    return ApiError::not_found("generation endpoint is disabled for this profile").into_response();
  }
  let expected = match entry.operation {
    ApiOperation::Generate(_) => Method::POST,
    _ => Method::GET,
  };
  if request.method() != expected && !(expected == Method::GET && request.method() == Method::HEAD) {
    return (
      StatusCode::METHOD_NOT_ALLOWED,
      [(
        axum::http::header::ALLOW,
        if expected == Method::POST { "POST" } else { "GET, HEAD" },
      )],
    )
      .into_response();
  }
  let operation = entry.operation;
  let profile = entry.profile.clone();
  let result = match operation {
    ApiOperation::Generate(endpoint) => {
      let (parts, body) = request.into_parts();
      let body = match axum::body::to_bytes(body, state.request_limits.max_wire_bytes()).await {
        Ok(body) => body,
        Err(error)
          if error
            .source()
            .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
          return ApiError::payload_too_large("request body exceeds the configured limit").into_response()
        }
        Err(_) => return ApiError::bad_request("could not read request body").into_response(),
      };
      handle(
        state,
        ApiRequestContext { access, connection },
        parts.method,
        parts.uri,
        parts.headers,
        body,
        endpoint,
      )
      .await
    }
    ApiOperation::Models => state
      .discovery
      .models(&profile, &access)
      .await
      .map(|body| Json(body).into_response()),
    ApiOperation::Providers => state
      .discovery
      .providers(&profile, &access)
      .map(|body| Json(body).into_response()),
  };
  // Axum sets Content-Length from the representation before stripping HEAD
  // bodies, including for fallback dispatch and error responses.
  result.unwrap_or_else(IntoResponse::into_response)
}
