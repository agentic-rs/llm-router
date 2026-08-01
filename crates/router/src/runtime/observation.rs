//! Shared disclosure-safe projections of application-boundary HTTP facts.

use http::header::ACCEPT;
use http::uri::PathAndQuery;
use http::{HeaderMap, Uri};
use serde_json::Value;
use smol_str::SmolStr;
use tokn_events::{is_sensitive_header_name, CapturedHeader, CapturedHeaders, CapturedUri, Correlation};
use tokn_headers::inbound::{first_present_smol, inbound_correlation, PROJECT_ID_HEADERS, REQUEST_ID_HEADERS};
use tokn_headers::keys::{X_CLIENT_REQUEST_ID, X_PARENT_SESSION_ID};

/// Preserve duplicate and non-UTF-8 field values while enforcing the event
/// contract's minimum credential denylist.
pub(crate) fn capture_headers(headers: &HeaderMap) -> CapturedHeaders {
  headers
    .iter()
    .map(|(name, value)| {
      if is_sensitive_header_name(name.as_str()) {
        CapturedHeader::redacted(name.as_str())
      } else {
        CapturedHeader::value(name.as_str(), bytes::Bytes::copy_from_slice(value.as_bytes()))
      }
    })
    .collect()
}

/// Capture an inbound request target without publishing URI credentials.
///
/// Query values and authority userinfo are omitted as whole components. Query
/// parameter names can themselves disclose credential schemes, so the event
/// boundary does not attempt a key-by-key allowlist.
pub(crate) fn capture_request_target(uri: &Uri) -> CapturedUri {
  let (authority, userinfo_removed) = uri
    .authority()
    .map(|authority| authority_without_userinfo(authority.as_str()))
    .unwrap_or(("", false));
  let query_removed = uri.query().is_some();

  if !userinfo_removed && !query_removed {
    return CapturedUri::exact(uri.to_string());
  }

  let mut value = String::new();
  if let Some(scheme) = uri.scheme_str() {
    value.push_str(scheme);
    value.push(':');
    if uri.authority().is_some() {
      value.push_str("//");
    }
  }
  value.push_str(authority);
  value.push_str(uri.path());
  CapturedUri::redacted(value)
}

/// Capture an admitted path while omitting its complete query component.
pub(crate) fn capture_path_and_query(path_and_query: &PathAndQuery) -> CapturedUri {
  if path_and_query.query().is_some() {
    CapturedUri::redacted(path_and_query.path())
  } else {
    CapturedUri::exact(path_and_query.as_str())
  }
}

/// Capture the final provider-prepared URL without URI credentials.
pub(crate) fn capture_upstream_uri(url: &reqwest::Url) -> CapturedUri {
  let userinfo_removed = !url.username().is_empty() || url.password().is_some();
  let query_removed = url.query().is_some();
  let fragment_removed = url.fragment().is_some();

  if !userinfo_removed && !query_removed && !fragment_removed {
    return CapturedUri::exact(url.as_str());
  }

  let mut sanitized = url.clone();
  if userinfo_removed && (sanitized.set_username("").is_err() || sanitized.set_password(None).is_err()) {
    // HTTP request URLs are hierarchical, but retain a disclosure-safe
    // fallback if a future transport exposes a URL that cannot edit userinfo.
    return CapturedUri::redacted(url.path());
  }
  sanitized.set_query(None);
  sanitized.set_fragment(None);
  CapturedUri::redacted(sanitized.as_str())
}

fn authority_without_userinfo(authority: &str) -> (&str, bool) {
  match authority.rsplit_once('@') {
    Some((_, authority)) => (authority, true),
    None => (authority, false),
  }
}

/// Resolve supported correlation fields from the exact string-backed header
/// semantics shared by listener and embedded managed requests.
pub(crate) fn correlation(headers: &tokn_headers::HeaderMap) -> Correlation {
  let inbound = inbound_correlation(headers);
  let client_request_id = first_present_smol(headers, &[X_CLIENT_REQUEST_ID.as_str()])
    .or_else(|| first_present_smol(headers, REQUEST_ID_HEADERS));

  Correlation {
    client_request_id,
    session_id: inbound.session_id,
    thread_id: inbound.thread_id,
    parent_thread_id: inbound.parent_thread_id,
    parent_session_id: first_present_smol(headers, &[X_PARENT_SESSION_ID.as_str()]),
    project_id: first_present_smol(headers, PROJECT_ID_HEADERS),
    turn_id: inbound.turn_id,
  }
}

pub(crate) fn native_correlation(headers: &HeaderMap) -> Correlation {
  correlation(&tokn_headers::HeaderMap::from(headers))
}

/// Initial semantic facts available before JSON inspection.
pub(crate) fn body_header_facts(headers: &HeaderMap) -> (Option<bool>, Option<SmolStr>) {
  (accepts_event_stream(headers).then_some(true), header_initiator(headers))
}

/// Semantic facts contributed by one decoded JSON request body.
pub(crate) fn body_json_facts(headers: &HeaderMap, body: &Value) -> (Option<SmolStr>, Option<bool>, Option<SmolStr>) {
  let (header_stream, header_initiator) = body_header_facts(headers);
  merge_body_json_facts(header_stream, header_initiator, body)
}

pub(crate) fn merge_body_json_facts(
  header_stream: Option<bool>,
  header_initiator: Option<SmolStr>,
  body: &Value,
) -> (Option<SmolStr>, Option<bool>, Option<SmolStr>) {
  let requested_model = body.get("model").and_then(Value::as_str).map(SmolStr::new);
  let stream = Some(
    body
      .get("stream")
      .and_then(Value::as_bool)
      .unwrap_or(header_stream == Some(true)),
  );
  let initiator = header_initiator.or_else(|| infer_body_initiator(body).map(SmolStr::new));
  (requested_model, stream, initiator)
}

fn accepts_event_stream(headers: &HeaderMap) -> bool {
  headers.get_all(ACCEPT).iter().any(|value| {
    value.to_str().is_ok_and(|value| {
      value.split(',').any(|part| {
        part
          .split(';')
          .next()
          .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
      })
    })
  })
}

fn header_initiator(headers: &HeaderMap) -> Option<SmolStr> {
  let value = headers.get("x-initiator")?.to_str().ok()?.trim().to_ascii_lowercase();
  matches!(value.as_str(), "user" | "agent").then(|| SmolStr::new(value))
}

fn infer_body_initiator(body: &Value) -> Option<&'static str> {
  if body.get("input").is_some() {
    tokn_core::util::initiator::classify_initiator_responses(body)
  } else {
    tokn_core::util::initiator::classify_initiator(body).or_else(|| {
      body
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| !tools.is_empty())
        .then_some("agent")
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn inbound_targets_omit_query_and_userinfo_components() {
    let origin: Uri = "/v1/responses?access_token=secret".parse().unwrap();
    let origin = capture_request_target(&origin);
    assert_eq!(origin.as_str(), "/v1/responses");
    assert!(origin.is_redacted());

    let absolute: Uri = "https://user:secret@api.example:8443/v1/responses?api_key=secret"
      .parse()
      .unwrap();
    let absolute = capture_request_target(&absolute);
    assert_eq!(absolute.as_str(), "https://api.example:8443/v1/responses");
    assert!(absolute.is_redacted());
    assert!(!absolute.as_str().contains("secret"));
    assert!(!absolute.as_str().contains("user"));

    let authority: Uri = "user:secret@api.example:443".parse().unwrap();
    let authority = capture_request_target(&authority);
    assert_eq!(authority.as_str(), "api.example:443");
    assert!(authority.is_redacted());
  }

  #[test]
  fn query_free_http_request_target_forms_remain_exact() {
    for target in ["/v1/responses", "api.example:443", "*"] {
      let target: Uri = target.parse().unwrap();
      let captured = capture_request_target(&target);
      assert_eq!(captured.as_str(), target.to_string());
      assert!(!captured.is_redacted());
    }
  }

  #[test]
  fn admitted_paths_omit_the_complete_query_component() {
    let path_and_query: PathAndQuery = "/v1/responses?stream=true&access_token=secret".parse().unwrap();
    let captured = capture_path_and_query(&path_and_query);

    assert_eq!(captured.as_str(), "/v1/responses");
    assert!(captured.is_redacted());
    assert!(!captured.as_str().contains("access_token"));
  }

  #[test]
  fn prepared_urls_omit_userinfo_query_and_fragment_components() {
    let url = reqwest::Url::parse("https://user:secret@api.example/v1/responses?api_key=secret#private").unwrap();
    let captured = capture_upstream_uri(&url);

    assert_eq!(captured.as_str(), "https://api.example/v1/responses");
    assert!(captured.is_redacted());
    assert!(!captured.as_str().contains("secret"));
    assert!(!captured.as_str().contains("user"));
    assert!(!captured.as_str().contains("private"));
  }

  #[test]
  fn credential_free_uris_remain_exact() {
    let target: Uri = "https://api.example/v1/responses".parse().unwrap();
    let target = capture_request_target(&target);
    assert_eq!(target.as_str(), "https://api.example/v1/responses");
    assert!(!target.is_redacted());

    let path_and_query: PathAndQuery = "/v1/responses".parse().unwrap();
    assert!(!capture_path_and_query(&path_and_query).is_redacted());

    let upstream = reqwest::Url::parse("https://api.example/v1/responses").unwrap();
    assert!(!capture_upstream_uri(&upstream).is_redacted());
  }
}
