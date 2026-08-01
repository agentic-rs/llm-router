//! Listener-free execution for embedded managed profile consumers.
//!
//! SDK and CLI callers provide an explicit linked profile for every request.
//! This facade applies the same body, correlation, target-selection,
//! settlement, and response-adaptation semantics as listener-backed serving
//! without constructing a synthetic listener or opaque transport client.

use super::{
  managed_profile_route, resolve_managed_profile, ManagedAttemptCoordinator, ManagedAttemptCoordinatorError,
  ManagedProfileResolveError, ManagedProfileSite, ManagedRequestBody, ManagedRequestBodyError, ManagedSelectionSummary,
};
use crate::runtime::LinkedGatewayRuntime;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;
use serde_json::Value;
use smol_str::SmolStr;
use snafu::Snafu;
use std::sync::Arc;
use std::time::Instant;
use tokn_access::ProviderAccess;
use tokn_accounts::link::{NoEligibleReason, TargetResolution};
use tokn_core::generation::GenerationOptions;
use tokn_core::provider::Endpoint;
use tokn_core::util::http::{build_managed_client, HttpClientOptions};
use tokn_policy::ProfileId;
use tokn_requests::execution::{ManagedAttemptError, ManagedClientResponse, ManagedHttpExecutor, ManagedResponseError};

/// One listener-free managed request against an explicit linked profile.
#[derive(Clone, Debug)]
pub struct ManagedGatewayRequest {
  endpoint: Endpoint,
  body: Value,
  headers: HeaderMap,
  session_id: Option<SmolStr>,
  provider_access: ProviderAccess,
  generation_options: Option<GenerationOptions>,
}

impl ManagedGatewayRequest {
  pub fn new(endpoint: Endpoint, body: Value) -> Self {
    Self {
      endpoint,
      body,
      headers: HeaderMap::new(),
      session_id: None,
      provider_access: ProviderAccess::All,
      generation_options: None,
    }
  }

  pub fn with_headers(mut self, headers: HeaderMap) -> Self {
    self.headers = headers;
    self
  }

  /// Set authoritative session affinity for both selection and provider
  /// persona rendering. This replaces any semantic `x-session-id` value.
  pub fn with_session_id(mut self, session_id: impl Into<SmolStr>) -> Self {
    self.session_id = Some(session_id.into());
    self
  }

  pub fn with_provider_access(mut self, provider_access: ProviderAccess) -> Self {
    self.provider_access = provider_access;
    self
  }

  pub fn with_generation_options(mut self, generation_options: GenerationOptions) -> Self {
    self.generation_options = Some(generation_options);
    self
  }

  pub fn endpoint(&self) -> Endpoint {
    self.endpoint
  }

  pub fn body(&self) -> &Value {
    &self.body
  }

  pub fn headers(&self) -> &HeaderMap {
    &self.headers
  }

  pub fn session_id(&self) -> Option<&str> {
    self.session_id.as_deref()
  }

  pub fn provider_access(&self) -> &ProviderAccess {
    &self.provider_access
  }

  pub fn generation_options(&self) -> Option<&GenerationOptions> {
    self.generation_options.as_ref()
  }
}

/// Listener-free managed execution over one immutable linked runtime.
#[derive(Clone, Debug)]
pub struct ManagedGatewayExecutor {
  runtime: Arc<LinkedGatewayRuntime>,
  attempts: ManagedAttemptCoordinator,
}

impl ManagedGatewayExecutor {
  /// Build only the managed data-plane transport needed by embedded callers.
  pub fn build(
    runtime: Arc<LinkedGatewayRuntime>,
    http_options: &HttpClientOptions,
  ) -> ManagedGatewayBuildResult<Self> {
    let http =
      build_managed_client(http_options).map_err(|source| ManagedGatewayBuildError::ManagedHttpClient { source })?;
    Ok(Self::new(runtime, ManagedHttpExecutor::new(http)))
  }

  pub(crate) fn new(runtime: Arc<LinkedGatewayRuntime>, executor: ManagedHttpExecutor) -> Self {
    Self {
      runtime,
      attempts: ManagedAttemptCoordinator::new(executor),
    }
  }

  pub fn runtime(&self) -> &Arc<LinkedGatewayRuntime> {
    &self.runtime
  }

  /// Resolve and execute exactly one attempt for `profile_id`.
  pub async fn execute(
    &self,
    profile_id: &ProfileId,
    request: ManagedGatewayRequest,
  ) -> ManagedGatewayResult<ManagedGatewayOutcome> {
    let profile = self
      .runtime
      .profiles()
      .profile(profile_id)
      .ok_or_else(|| ManagedGatewayError::ProfileNotLinked {
        profile: profile_id.clone(),
      })?;

    // Route-family admission precedes payload semantics for the same reason it
    // does in listener-backed serving: request data cannot change the selected
    // profile or hide a configuration-family error.
    let (site, _) = managed_profile_route(profile).map_err(|source| ManagedGatewayError::Resolve { source })?;
    let ManagedGatewayRequest {
      endpoint,
      body,
      headers,
      session_id,
      provider_access,
      generation_options,
    } = request;
    let body = ManagedRequestBody::try_from(body).map_err(|source| ManagedGatewayError::InvalidBody {
      site: site.clone(),
      source,
    })?;
    let (headers, session_id) = prepare_semantic_headers(headers, session_id);
    let resolution = resolve_managed_profile(
      profile,
      SmolStr::new(body.requested_model()),
      endpoint,
      session_id.as_deref(),
      &provider_access,
    )
    .map_err(|source| ManagedGatewayError::Resolve { source })?;

    let target = match resolution {
      TargetResolution::Selected(target) => target,
      TargetResolution::CoolingDown { retry_at } => {
        return Ok(ManagedGatewayOutcome::CoolingDown { site, retry_at });
      }
      TargetResolution::NoEligible { reason } => {
        return Ok(ManagedGatewayOutcome::NoEligible { site, reason });
      }
    };

    match self
      .attempts
      .execute(target, &headers, body.value(), generation_options.as_ref())
      .await
    {
      Ok(success) => {
        let (site, selection, response) = success.into_parts();
        Ok(ManagedGatewayOutcome::Response {
          site,
          selection: Box::new(selection),
          response,
        })
      }
      Err(ManagedAttemptCoordinatorError::Attempt { site, summary, source }) => Err(ManagedGatewayError::Attempt {
        site,
        selection: Box::new(summary),
        source,
      }),
      Err(ManagedAttemptCoordinatorError::Response { site, summary, source }) => Err(ManagedGatewayError::Response {
        site,
        selection: Box::new(summary),
        source,
      }),
    }
  }
}

fn prepare_semantic_headers(
  mut headers: HeaderMap,
  explicit_session_id: Option<SmolStr>,
) -> (tokn_headers::HeaderMap, Option<SmolStr>) {
  headers.remove(CONTENT_ENCODING);
  headers.remove(CONTENT_LENGTH);
  headers.remove(TRANSFER_ENCODING);

  let mut headers = tokn_headers::HeaderMap::from(&headers);
  let session_id = match explicit_session_id {
    Some(session_id) => {
      headers.insert(&tokn_headers::keys::X_SESSION_ID, session_id.clone());
      Some(session_id)
    }
    None => tokn_headers::inbound::inbound_correlation(&headers).session_id,
  };
  (headers, session_id)
}

/// Policy-free result of one embedded managed request.
#[derive(Debug)]
pub enum ManagedGatewayOutcome {
  Response {
    site: ManagedProfileSite,
    selection: Box<ManagedSelectionSummary>,
    response: ManagedClientResponse,
  },
  CoolingDown {
    site: ManagedProfileSite,
    retry_at: Instant,
  },
  NoEligible {
    site: ManagedProfileSite,
    reason: NoEligibleReason,
  },
}

impl ManagedGatewayOutcome {
  pub fn site(&self) -> &ManagedProfileSite {
    match self {
      Self::Response { site, .. } | Self::CoolingDown { site, .. } | Self::NoEligible { site, .. } => site,
    }
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedGatewayBuildError {
  #[snafu(display("could not build the managed HTTP client: {source}"))]
  ManagedHttpClient { source: anyhow::Error },
}

pub type ManagedGatewayBuildResult<T> = std::result::Result<T, ManagedGatewayBuildError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedGatewayError {
  #[snafu(display("profile '{profile}' is not linked into this gateway runtime"))]
  ProfileNotLinked { profile: ProfileId },

  #[snafu(display("{site} has an invalid request body: {source}"))]
  InvalidBody {
    site: ManagedProfileSite,
    source: ManagedRequestBodyError,
  },

  #[snafu(display("could not resolve embedded managed request: {source}"))]
  Resolve { source: ManagedProfileResolveError },

  #[snafu(display("{site} selected managed attempt failed before a final response head: {source}"))]
  Attempt {
    site: ManagedProfileSite,
    selection: Box<ManagedSelectionSummary>,
    source: ManagedAttemptError,
  },

  #[snafu(display("{site} selected managed response failed after its final head was settled: {source}"))]
  Response {
    site: ManagedProfileSite,
    selection: Box<ManagedSelectionSummary>,
    source: ManagedResponseError,
  },
}

pub type ManagedGatewayResult<T> = std::result::Result<T, ManagedGatewayError>;

#[cfg(test)]
mod tests {
  use super::*;
  use http::header::HeaderValue;

  #[test]
  fn explicit_session_replaces_header_correlation_and_strips_wire_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", HeaderValue::from_static("header-session"));
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("120"));
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

    let (headers, session_id) = prepare_semantic_headers(headers, Some(SmolStr::new("explicit-session")));

    assert_eq!(session_id.as_deref(), Some("explicit-session"));
    assert_eq!(
      headers
        .get(&tokn_headers::keys::X_SESSION_ID)
        .map(|value| value.as_str()),
      Some("explicit-session")
    );
    assert!(!headers.contains_key(&tokn_headers::keys::CONTENT_ENCODING));
    assert!(!headers.contains_key(&tokn_headers::keys::CONTENT_LENGTH));
    assert!(!headers.contains_key("transfer-encoding"));
  }

  #[test]
  fn header_correlation_is_used_when_session_is_not_explicit() {
    let mut headers = HeaderMap::new();
    headers.insert("x-client-session-id", HeaderValue::from_static("header-session"));

    let (headers, session_id) = prepare_semantic_headers(headers, None);

    assert_eq!(session_id.as_deref(), Some("header-session"));
    assert_eq!(
      headers.get("x-client-session-id").map(|value| value.as_str()),
      Some("header-session")
    );
    assert!(!headers.contains_key(&tokn_headers::keys::X_SESSION_ID));
  }
}
