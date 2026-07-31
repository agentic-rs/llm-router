//! Client authentication at the v2 listener boundary.

use super::super::MaterializedClientAuth;
use http::{header, HeaderMap, HeaderValue};
use std::fmt;
use tokn_access::{AccessContext, AuthenticationError};

const API_KEY_HEADER: &str = "x-api-key";

/// A listener could not establish the client's gateway access context.
///
/// Rejections are safe to map to an authentication response. `Unavailable`
/// instead means the blocking authentication task itself could not complete;
/// callers should treat that as an internal service failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthError {
  Rejected(AuthenticationError),
  Unavailable,
}

impl fmt::Display for ClientAuthError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Rejected(AuthenticationError::Missing) => {
        formatter.write_str("client authentication credential is missing")
      }
      Self::Rejected(AuthenticationError::Invalid) => {
        formatter.write_str("client authentication credential is invalid")
      }
      Self::Rejected(AuthenticationError::Revoked) => {
        formatter.write_str("client authentication credential is revoked")
      }
      Self::Unavailable => formatter.write_str("client authentication task is unavailable"),
    }
  }
}

impl std::error::Error for ClientAuthError {}

/// Authenticate an LLM API client and strip its gateway credential on success.
///
/// Local-key listeners accept exactly one credential: either a bearer
/// `Authorization` value or one `x-api-key` value. Origin credentials are
/// preserved when authentication is disabled or rejected.
pub async fn authenticate_llm_api_client(
  client_auth: &MaterializedClientAuth,
  headers: &mut HeaderMap,
) -> Result<AccessContext, ClientAuthError> {
  let store = match client_auth {
    MaterializedClientAuth::None => return Ok(AccessContext::unrestricted()),
    MaterializedClientAuth::LocalKeys(store) => store,
  };
  let token = llm_api_token(headers).map_err(ClientAuthError::Rejected)?;
  let context = authenticate_local_key(store.clone(), token).await?;

  headers.remove(header::AUTHORIZATION);
  headers.remove(API_KEY_HEADER);
  Ok(context)
}

/// Authenticate a forward-proxy client and consume its proxy credential.
///
/// Local-key proxy listeners accept exactly one bearer `Proxy-Authorization`
/// value. `Authorization` and `x-api-key` belong to the origin request and are
/// never consumed by this authentication boundary. `Proxy-Authorization` is
/// hop-by-hop, so it is also stripped when authentication is disabled.
pub async fn authenticate_forward_proxy_client(
  client_auth: &MaterializedClientAuth,
  headers: &mut HeaderMap,
) -> Result<AccessContext, ClientAuthError> {
  let store = match client_auth {
    MaterializedClientAuth::None => {
      headers.remove(header::PROXY_AUTHORIZATION);
      return Ok(AccessContext::unrestricted());
    }
    MaterializedClientAuth::LocalKeys(store) => store,
  };
  let value = single_header(headers, header::PROXY_AUTHORIZATION.as_str())
    .map_err(ClientAuthError::Rejected)?
    .ok_or(ClientAuthError::Rejected(AuthenticationError::Missing))?;
  let token = bearer_token(value).map_err(ClientAuthError::Rejected)?;
  let context = authenticate_local_key(store.clone(), token).await?;

  headers.remove(header::PROXY_AUTHORIZATION);
  Ok(context)
}

async fn authenticate_local_key(
  store: std::sync::Arc<tokn_access::AccessStore>,
  token: String,
) -> Result<AccessContext, ClientAuthError> {
  tokio::task::spawn_blocking(move || store.authenticate(Some(token.as_str())))
    .await
    .map_err(|error| {
      tracing::error!(%error, "client authentication task failed");
      ClientAuthError::Unavailable
    })?
    .map_err(ClientAuthError::Rejected)
}

fn llm_api_token(headers: &HeaderMap) -> Result<String, AuthenticationError> {
  let authorization = single_header(headers, header::AUTHORIZATION.as_str())?;
  let api_key = single_header(headers, API_KEY_HEADER)?;

  match (authorization, api_key) {
    (None, None) => Err(AuthenticationError::Missing),
    (Some(_), Some(_)) => Err(AuthenticationError::Invalid),
    (Some(value), None) => bearer_token(value),
    (None, Some(value)) => raw_token(value),
  }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a HeaderValue>, AuthenticationError> {
  let mut values = headers.get_all(name).iter();
  let value = values.next();
  if values.next().is_some() {
    return Err(AuthenticationError::Invalid);
  }
  Ok(value)
}

fn bearer_token(value: &HeaderValue) -> Result<String, AuthenticationError> {
  let mut parts = value
    .to_str()
    .map_err(|_| AuthenticationError::Invalid)?
    .split_ascii_whitespace();
  match (parts.next(), parts.next(), parts.next()) {
    (Some(scheme), Some(token), None) if scheme.eq_ignore_ascii_case("bearer") => Ok(token.to_owned()),
    _ => Err(AuthenticationError::Invalid),
  }
}

fn raw_token(value: &HeaderValue) -> Result<String, AuthenticationError> {
  let token = value.to_str().map_err(|_| AuthenticationError::Invalid)?.trim();
  if token.is_empty() {
    return Err(AuthenticationError::Invalid);
  }
  Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;
  use tokn_access::AccessStore;

  fn local_keys() -> (tempfile::TempDir, MaterializedClientAuth, tokn_access::CreatedApiKey) {
    let temp = tempfile::tempdir().unwrap();
    let store = AccessStore::open(temp.path().join("access.db")).unwrap();
    let key = store.create_key("listener test", vec!["openai".into()]).unwrap();
    (temp, MaterializedClientAuth::LocalKeys(Arc::new(store)), key)
  }

  #[tokio::test]
  async fn disabled_auth_is_unrestricted_and_proxy_auth_is_consumed_at_proxy_boundary() {
    let mut headers = HeaderMap::new();
    headers.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer origin-secret"));
    headers.append(API_KEY_HEADER, HeaderValue::from_static("origin-api-key"));
    headers.append(
      header::PROXY_AUTHORIZATION,
      HeaderValue::from_static("Bearer proxy-secret"),
    );
    let original = headers.clone();

    let access = authenticate_llm_api_client(&MaterializedClientAuth::None, &mut headers)
      .await
      .unwrap();
    assert_eq!(access, AccessContext::unrestricted());
    assert_eq!(headers, original);

    let access = authenticate_forward_proxy_client(&MaterializedClientAuth::None, &mut headers)
      .await
      .unwrap();
    assert_eq!(access, AccessContext::unrestricted());
    assert_eq!(headers[header::AUTHORIZATION], original[header::AUTHORIZATION]);
    assert_eq!(headers[API_KEY_HEADER], original[API_KEY_HEADER]);
    assert!(!headers.contains_key(header::PROXY_AUTHORIZATION));
  }

  #[tokio::test]
  async fn llm_api_accepts_each_supported_credential_and_removes_only_that_credential() {
    let (_temp, client_auth, key) = local_keys();
    let mut bearer_headers = HeaderMap::new();
    bearer_headers.insert(
      header::AUTHORIZATION,
      HeaderValue::from_str(&format!("Bearer {}", key.token)).unwrap(),
    );
    bearer_headers.insert("x-preserved", HeaderValue::from_static("yes"));

    let bearer_access = authenticate_llm_api_client(&client_auth, &mut bearer_headers)
      .await
      .unwrap();
    assert_eq!(bearer_access.key_id.as_deref(), Some(key.id.as_str()));
    assert!(!bearer_headers.contains_key(header::AUTHORIZATION));
    assert!(!bearer_headers.contains_key(API_KEY_HEADER));
    assert_eq!(bearer_headers["x-preserved"], "yes");

    let mut api_key_headers = HeaderMap::new();
    api_key_headers.insert(API_KEY_HEADER, HeaderValue::from_str(&key.token).unwrap());
    api_key_headers.insert("x-preserved", HeaderValue::from_static("yes"));

    let api_key_access = authenticate_llm_api_client(&client_auth, &mut api_key_headers)
      .await
      .unwrap();
    assert_eq!(api_key_access.key_id.as_deref(), Some(key.id.as_str()));
    assert!(!api_key_headers.contains_key(header::AUTHORIZATION));
    assert!(!api_key_headers.contains_key(API_KEY_HEADER));
    assert_eq!(api_key_headers["x-preserved"], "yes");
  }

  #[tokio::test]
  async fn forward_proxy_removes_proxy_auth_and_preserves_origin_credentials() {
    let (_temp, client_auth, key) = local_keys();
    let mut headers = HeaderMap::new();
    headers.insert(
      header::PROXY_AUTHORIZATION,
      HeaderValue::from_str(&format!("Bearer {}", key.token)).unwrap(),
    );
    headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer origin-secret"));
    headers.insert(API_KEY_HEADER, HeaderValue::from_static("origin-api-key"));

    let access = authenticate_forward_proxy_client(&client_auth, &mut headers)
      .await
      .unwrap();

    assert_eq!(access.key_id.as_deref(), Some(key.id.as_str()));
    assert!(!headers.contains_key(header::PROXY_AUTHORIZATION));
    assert_eq!(headers[header::AUTHORIZATION], "Bearer origin-secret");
    assert_eq!(headers[API_KEY_HEADER], "origin-api-key");
  }

  #[tokio::test]
  async fn llm_api_rejects_duplicate_or_ambiguous_credentials_without_removing_them() {
    let (_temp, client_auth, key) = local_keys();
    let bearer = HeaderValue::from_str(&format!("Bearer {}", key.token)).unwrap();
    let mut duplicate = HeaderMap::new();
    duplicate.append(header::AUTHORIZATION, bearer.clone());
    duplicate.append(header::AUTHORIZATION, bearer.clone());

    assert_eq!(
      authenticate_llm_api_client(&client_auth, &mut duplicate).await,
      Err(ClientAuthError::Rejected(AuthenticationError::Invalid))
    );
    assert_eq!(duplicate.get_all(header::AUTHORIZATION).iter().count(), 2);

    let mut ambiguous = HeaderMap::new();
    ambiguous.insert(header::AUTHORIZATION, bearer);
    ambiguous.insert(API_KEY_HEADER, HeaderValue::from_str(&key.token).unwrap());

    assert_eq!(
      authenticate_llm_api_client(&client_auth, &mut ambiguous).await,
      Err(ClientAuthError::Rejected(AuthenticationError::Invalid))
    );
    assert!(ambiguous.contains_key(header::AUTHORIZATION));
    assert!(ambiguous.contains_key(API_KEY_HEADER));
  }

  #[tokio::test]
  async fn forward_proxy_rejects_duplicate_credentials_without_removing_them() {
    let (_temp, client_auth, key) = local_keys();
    let bearer = HeaderValue::from_str(&format!("Bearer {}", key.token)).unwrap();
    let mut headers = HeaderMap::new();
    headers.append(header::PROXY_AUTHORIZATION, bearer.clone());
    headers.append(header::PROXY_AUTHORIZATION, bearer);

    assert_eq!(
      authenticate_forward_proxy_client(&client_auth, &mut headers).await,
      Err(ClientAuthError::Rejected(AuthenticationError::Invalid))
    );
    assert_eq!(headers.get_all(header::PROXY_AUTHORIZATION).iter().count(), 2);
  }

  #[tokio::test]
  async fn invalid_schemes_are_rejected_without_removing_headers() {
    let (_temp, client_auth, key) = local_keys();
    let basic = HeaderValue::from_str(&format!("Basic {}", key.token)).unwrap();
    let mut llm_headers = HeaderMap::new();
    llm_headers.insert(header::AUTHORIZATION, basic.clone());
    let mut proxy_headers = HeaderMap::new();
    proxy_headers.insert(header::PROXY_AUTHORIZATION, basic);

    assert_eq!(
      authenticate_llm_api_client(&client_auth, &mut llm_headers).await,
      Err(ClientAuthError::Rejected(AuthenticationError::Invalid))
    );
    assert!(llm_headers.contains_key(header::AUTHORIZATION));

    assert_eq!(
      authenticate_forward_proxy_client(&client_auth, &mut proxy_headers).await,
      Err(ClientAuthError::Rejected(AuthenticationError::Invalid))
    );
    assert!(proxy_headers.contains_key(header::PROXY_AUTHORIZATION));
  }
}
