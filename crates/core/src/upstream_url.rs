use http::uri::PathAndQuery;
use reqwest::Url;
use smol_str::SmolStr;
use std::fmt;
use tokn_policy::{CanonicalAuthority, CanonicalHost, InvalidAuthority};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleartextHttpPolicy {
  LoopbackOnly,
  Allow,
}

/// A strict, canonical base URL prefix for a credential-bearing upstream.
///
/// The URL has no query or fragment and always ends in a slash, so operation
/// paths can be appended relative to the configured prefix. Parsing rejects
/// syntax that WHATWG URL normalization could obscure, including whitespace,
/// backslashes, legacy IPv4 forms, and literal or encoded dot segments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalUpstreamUrl {
  url: Url,
}

impl CanonicalUpstreamUrl {
  pub fn parse(raw: &str, cleartext: CleartextHttpPolicy) -> Result<Self, InvalidUpstreamUrl> {
    let (url, authority) = parse_http_url(raw)?;
    reject_query_or_fragment(&url)?;
    enforce_cleartext_policy(&url, &authority, cleartext)?;

    let url = if url.as_str().ends_with('/') {
      url
    } else {
      Url::parse(&format!("{url}/")).map_err(|error| InvalidUpstreamUrl::Parse(error.to_string()))?
    };
    Ok(Self { url })
  }

  pub fn as_str(&self) -> &str {
    self.url.as_str()
  }

  pub fn as_url(&self) -> &Url {
    &self.url
  }

  pub fn origin(&self) -> CanonicalHttpOrigin {
    CanonicalHttpOrigin(SmolStr::new(self.url.origin().ascii_serialization()))
  }

  /// Append operation path segments without allowing a relative reference to
  /// replace the configured origin or discard its path prefix.
  ///
  /// Query parameters are intentionally separate: mutate the returned URL
  /// with [`Url::query_pairs_mut`] so query data cannot be confused with path
  /// structure.
  pub fn operation_url<I, S>(&self, segments: I) -> Result<Url, InvalidOperationPath>
  where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
  {
    let mut segments = segments.into_iter().enumerate().peekable();
    if segments.peek().is_none() {
      return Err(InvalidOperationPath::Empty);
    }

    let mut url = self.url.clone();
    let mut path = url
      .path_segments_mut()
      .map_err(|()| InvalidOperationPath::InvalidBase)?;
    path.pop_if_empty();
    for (index, segment) in segments {
      let segment = segment.as_ref();
      if segment.is_empty() {
        return Err(InvalidOperationPath::EmptySegment { index });
      }
      if matches!(segment, "." | "..") {
        return Err(InvalidOperationPath::DotSegment { index });
      }
      path.push(segment);
    }
    drop(path);
    Ok(url)
  }

  /// Append an opaque relay request target beneath this configured prefix.
  pub fn relay_url(&self, target: &PathAndQuery) -> Result<Url, InvalidRequestUrl> {
    let path = validated_request_path(target)?;
    let relative_path = path.strip_prefix('/').expect("validated HTTP paths start with '/'");
    let raw = compose_request_url(self.as_str(), relative_path, target.query());
    let url = parse_composed_request_url(&raw)?;
    let expected_origin = self.url.origin().ascii_serialization();
    ensure_origin(&url, &expected_origin)?;
    if !url.path().starts_with(self.url.path()) {
      return Err(InvalidRequestUrl::DiscardedPrefix {
        expected: SmolStr::new(self.url.path()),
        found: SmolStr::new(url.path()),
      });
    }
    let expected_path = format!("{}{}", self.url.path(), relative_path);
    ensure_path_and_query(&url, &expected_path, target.query())?;
    Ok(url)
  }
}

impl AsRef<str> for CanonicalUpstreamUrl {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Display for CanonicalUpstreamUrl {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

/// A strict canonical HTTP origin without a trailing slash.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalHttpOrigin(SmolStr);

impl CanonicalHttpOrigin {
  pub fn parse(raw: &str, cleartext: CleartextHttpPolicy) -> Result<Self, InvalidUpstreamUrl> {
    let (url, authority) = parse_http_url(raw)?;
    reject_query_or_fragment(&url)?;
    enforce_cleartext_policy(&url, &authority, cleartext)?;
    if url.path() != "/" {
      return Err(InvalidUpstreamUrl::ExpectedOrigin);
    }
    Ok(Self(SmolStr::new(url.origin().ascii_serialization())))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Build a request URL at this exact admitted origin.
  pub fn request_url(&self, target: &PathAndQuery) -> Result<Url, InvalidRequestUrl> {
    let path = validated_request_path(target)?;
    let raw = compose_request_url(self.as_str(), &path, target.query());
    let url = parse_composed_request_url(&raw)?;
    ensure_origin(&url, self.as_str())?;
    ensure_path_and_query(&url, &path, target.query())?;
    Ok(url)
  }
}

impl AsRef<str> for CanonicalHttpOrigin {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Display for CanonicalHttpOrigin {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidUpstreamUrl {
  NonAscii,
  ObscuredSyntax,
  NonCanonicalScheme,
  InvalidAuthority(InvalidAuthority),
  DotSegment,
  Parse(String),
  UnsupportedScheme,
  MissingHostOrCredentials,
  ParserChangedAuthority,
  QueryOrFragment,
  InsecureHttp,
  ExpectedOrigin,
}

impl fmt::Display for InvalidUpstreamUrl {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NonAscii => formatter.write_str("URL must be ASCII; use an ASCII domain and percent-encoded path"),
      Self::ObscuredSyntax => {
        formatter.write_str("URL must not contain whitespace, control characters, or backslashes")
      }
      Self::NonCanonicalScheme => formatter.write_str("scheme must use canonical https:// or http:// syntax"),
      Self::InvalidAuthority(source) => write!(formatter, "invalid URL authority: {source}"),
      Self::DotSegment => formatter.write_str("URL path must not contain literal or percent-encoded dot segments"),
      Self::Parse(message) => write!(formatter, "invalid URL: {message}"),
      Self::UnsupportedScheme => formatter.write_str("scheme must be http or https"),
      Self::MissingHostOrCredentials => formatter.write_str("URL must contain a host and must not contain credentials"),
      Self::ParserChangedAuthority => {
        formatter.write_str("URL parser changed the authority; use a canonical host and port")
      }
      Self::QueryOrFragment => formatter.write_str("upstream URL must not contain a query or fragment"),
      Self::InsecureHttp => formatter
        .write_str("non-loopback HTTP can expose account credentials; use HTTPS or explicitly allow insecure HTTP"),
      Self::ExpectedOrigin => formatter.write_str("expected only scheme, host, and optional port"),
    }
  }
}

impl std::error::Error for InvalidUpstreamUrl {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidAuthority(source) => Some(source),
      _ => None,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidOperationPath {
  Empty,
  EmptySegment { index: usize },
  DotSegment { index: usize },
  InvalidBase,
}

impl fmt::Display for InvalidOperationPath {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Empty => formatter.write_str("operation path must contain at least one segment"),
      Self::EmptySegment { index } => write!(formatter, "operation path segment {index} must not be empty"),
      Self::DotSegment { index } => write!(formatter, "operation path segment {index} must not be '.' or '..'"),
      Self::InvalidBase => formatter.write_str("upstream URL cannot be used as a path base"),
    }
  }
}

impl std::error::Error for InvalidOperationPath {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidRequestUrl {
  InvalidPath(String),
  InvalidUrl(InvalidUpstreamUrl),
  ChangedOrigin {
    expected: SmolStr,
    found: SmolStr,
  },
  DiscardedPrefix {
    expected: SmolStr,
    found: SmolStr,
  },
  ChangedPath {
    expected: SmolStr,
    found: SmolStr,
  },
  ChangedQuery {
    expected: Option<SmolStr>,
    found: Option<SmolStr>,
  },
}

impl fmt::Display for InvalidRequestUrl {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidPath(message) => write!(formatter, "invalid HTTP request path: {message}"),
      Self::InvalidUrl(source) => write!(formatter, "invalid composed request URL: {source}"),
      Self::ChangedOrigin { expected, found } => {
        write!(
          formatter,
          "request target changed origin from '{expected}' to '{found}'"
        )
      }
      Self::DiscardedPrefix { expected, found } => {
        write!(
          formatter,
          "request target discarded prefix '{expected}', producing '{found}'"
        )
      }
      Self::ChangedPath { expected, found } => {
        write!(
          formatter,
          "URL parsing changed request path from '{expected}' to '{found}'"
        )
      }
      Self::ChangedQuery { expected, found } => {
        write!(
          formatter,
          "URL parsing changed request query from {expected:?} to {found:?}"
        )
      }
    }
  }
}

impl std::error::Error for InvalidRequestUrl {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidUrl(source) => Some(source),
      _ => None,
    }
  }
}

fn validated_request_path(target: &PathAndQuery) -> Result<String, InvalidRequestUrl> {
  let raw = target.path();
  if raw.is_empty() || !raw.starts_with('/') || !raw.is_ascii() {
    return Err(InvalidRequestUrl::InvalidPath(
      "path must be non-empty ASCII and start with '/'".into(),
    ));
  }
  if raw
    .split('/')
    .any(|segment| matches!(canonical_dot_segment(segment).as_deref(), Some(".") | Some("..")))
  {
    return Err(InvalidRequestUrl::InvalidPath("dot segments are not allowed".into()));
  }
  Ok(raw.to_string())
}

fn canonical_dot_segment(segment: &str) -> Option<String> {
  let bytes = segment.as_bytes();
  let mut dots = String::new();
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'.' {
      dots.push('.');
      index += 1;
    } else if bytes
      .get(index..index + 3)
      .is_some_and(|value| value[0] == b'%' && value[1] == b'2' && value[2].eq_ignore_ascii_case(&b'e'))
    {
      dots.push('.');
      index += 3;
    } else {
      return None;
    }
  }
  Some(dots)
}

fn compose_request_url(base: &str, path: &str, query: Option<&str>) -> String {
  let mut raw = String::with_capacity(base.len() + path.len() + query.map_or(0, |query| query.len() + 1));
  raw.push_str(base);
  raw.push_str(path);
  if let Some(query) = query {
    raw.push('?');
    raw.push_str(query);
  }
  raw
}

fn parse_composed_request_url(raw: &str) -> Result<Url, InvalidRequestUrl> {
  parse_http_url(raw)
    .map(|(url, _)| url)
    .map_err(InvalidRequestUrl::InvalidUrl)
}

fn ensure_origin(url: &Url, expected: &str) -> Result<(), InvalidRequestUrl> {
  let found = url.origin().ascii_serialization();
  if found == expected {
    Ok(())
  } else {
    Err(InvalidRequestUrl::ChangedOrigin {
      expected: SmolStr::new(expected),
      found: SmolStr::new(found),
    })
  }
}

fn ensure_path_and_query(
  url: &Url,
  expected_path: &str,
  expected_query: Option<&str>,
) -> Result<(), InvalidRequestUrl> {
  if url.path() != expected_path {
    return Err(InvalidRequestUrl::ChangedPath {
      expected: SmolStr::new(expected_path),
      found: SmolStr::new(url.path()),
    });
  }
  if url.query() != expected_query {
    return Err(InvalidRequestUrl::ChangedQuery {
      expected: expected_query.map(SmolStr::new),
      found: url.query().map(SmolStr::new),
    });
  }
  Ok(())
}

fn parse_http_url(raw: &str) -> Result<(Url, CanonicalAuthority), InvalidUpstreamUrl> {
  if !raw.is_ascii() {
    return Err(InvalidUpstreamUrl::NonAscii);
  }
  if raw
    .bytes()
    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    || raw.contains('\\')
  {
    return Err(InvalidUpstreamUrl::ObscuredSyntax);
  }

  let remainder = raw
    .strip_prefix("https://")
    .or_else(|| raw.strip_prefix("http://"))
    .ok_or(InvalidUpstreamUrl::NonCanonicalScheme)?;
  let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
  let authority =
    CanonicalAuthority::parse(&remainder[..authority_end]).map_err(InvalidUpstreamUrl::InvalidAuthority)?;

  let raw_path_and_suffix = &remainder[authority_end..];
  let raw_path = raw_path_and_suffix
    .split(['?', '#'])
    .next()
    .unwrap_or(raw_path_and_suffix);
  if raw_path.split('/').any(is_raw_dot_segment) {
    return Err(InvalidUpstreamUrl::DotSegment);
  }

  let url = Url::parse(raw).map_err(|error| InvalidUpstreamUrl::Parse(error.to_string()))?;
  if !matches!(url.scheme(), "http" | "https") {
    return Err(InvalidUpstreamUrl::UnsupportedScheme);
  }
  if url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
    return Err(InvalidUpstreamUrl::MissingHostOrCredentials);
  }

  let parsed_host = CanonicalHost::parse(url.host_str().expect("host presence was checked"))
    .map_err(|_| InvalidUpstreamUrl::ParserChangedAuthority)?;
  let default_port = match url.scheme() {
    "http" => 80,
    "https" => 443,
    _ => return Err(InvalidUpstreamUrl::UnsupportedScheme),
  };
  if authority.host() != &parsed_host || authority.port().unwrap_or(default_port) != url.port().unwrap_or(default_port)
  {
    return Err(InvalidUpstreamUrl::ParserChangedAuthority);
  }

  Ok((url, authority))
}

fn reject_query_or_fragment(url: &Url) -> Result<(), InvalidUpstreamUrl> {
  if url.query().is_some() || url.fragment().is_some() {
    Err(InvalidUpstreamUrl::QueryOrFragment)
  } else {
    Ok(())
  }
}

fn enforce_cleartext_policy(
  url: &Url,
  authority: &CanonicalAuthority,
  cleartext: CleartextHttpPolicy,
) -> Result<(), InvalidUpstreamUrl> {
  if url.scheme() == "http" && cleartext == CleartextHttpPolicy::LoopbackOnly && !authority.host().is_loopback() {
    Err(InvalidUpstreamUrl::InsecureHttp)
  } else {
    Ok(())
  }
}

fn is_raw_dot_segment(segment: &str) -> bool {
  let bytes = segment.as_bytes();
  let mut dots = 0;
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'.' {
      dots += 1;
      index += 1;
    } else if bytes
      .get(index..index + 3)
      .is_some_and(|encoded| encoded[0] == b'%' && encoded[1] == b'2' && encoded[2].eq_ignore_ascii_case(&b'e'))
    {
      dots += 1;
      index += 3;
    } else {
      return false;
    }
  }
  matches!(dots, 1 | 2)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn canonicalizes_base_prefixes_and_origins() {
    let base = CanonicalUpstreamUrl::parse(
      "https://API.Example.com:443/gateway/v1",
      CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();
    assert_eq!(base.as_str(), "https://api.example.com/gateway/v1/");
    assert_eq!(base.origin().as_str(), "https://api.example.com");

    let origin = CanonicalHttpOrigin::parse("https://API.Example.com:443", CleartextHttpPolicy::LoopbackOnly).unwrap();
    assert_eq!(origin.as_str(), "https://api.example.com");
  }

  #[test]
  fn rejects_obscured_or_ambiguous_url_syntax() {
    for raw in [
      " https://api.example.com/v1",
      "https://api.example.com/\n/v1",
      r"https:\api.example.com\v1",
      "HTTPS://api.example.com/v1",
      "https://api.example.com/a/../v1",
      "https://api.example.com/%2E%2e/v1",
      "https://127.1/v1",
      "https://example.0x10/v1",
      "https://api.example.com./v1",
      "https://user@api.example.com/v1",
      "https://api.example.com:0/v1",
      "https://api.example.com/v1?token=secret",
    ] {
      assert!(
        CanonicalUpstreamUrl::parse(raw, CleartextHttpPolicy::LoopbackOnly).is_err(),
        "accepted {raw:?}"
      );
    }
  }

  #[test]
  fn cleartext_requires_a_literal_loopback_or_explicit_permission() {
    CanonicalUpstreamUrl::parse("http://127.0.0.1:8080/v1", CleartextHttpPolicy::LoopbackOnly).unwrap();
    CanonicalUpstreamUrl::parse("http://[::1]:8080/v1", CleartextHttpPolicy::LoopbackOnly).unwrap();
    assert!(CanonicalUpstreamUrl::parse("http://localhost:8080/v1", CleartextHttpPolicy::LoopbackOnly).is_err());
    CanonicalUpstreamUrl::parse("http://api.example.com/v1", CleartextHttpPolicy::Allow).unwrap();
  }

  #[test]
  fn operation_urls_preserve_the_configured_prefix() {
    let base = CanonicalUpstreamUrl::parse(
      "https://api.example.com/proxy/openai/v1",
      CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();

    assert_eq!(
      base.operation_url(["chat", "completions"]).unwrap().as_str(),
      "https://api.example.com/proxy/openai/v1/chat/completions"
    );

    let root = CanonicalUpstreamUrl::parse("https://api.example.com", CleartextHttpPolicy::LoopbackOnly).unwrap();
    assert_eq!(
      root.operation_url(["models"]).unwrap().as_str(),
      "https://api.example.com/models"
    );
  }

  #[test]
  fn operation_segments_cannot_replace_authority_or_inject_url_structure() {
    let base = CanonicalUpstreamUrl::parse("https://api.example.com/v1", CleartextHttpPolicy::LoopbackOnly).unwrap();

    let authority = base.operation_url(["//evil.example", "models"]).unwrap();
    assert_eq!(authority.origin().ascii_serialization(), "https://api.example.com");
    assert_eq!(authority.path(), "/v1/%2F%2Fevil.example/models");

    let reserved = base.operation_url(["model/id?x#y%2f"]).unwrap();
    assert_eq!(reserved.path(), "/v1/model%2Fid%3Fx%23y%252f");
    assert!(reserved.query().is_none());
    assert!(reserved.fragment().is_none());

    let encoded_dot = base.operation_url(["%2e%2e", "models"]).unwrap();
    assert_eq!(encoded_dot.path(), "/v1/%252e%252e/models");
  }

  #[test]
  fn operation_urls_reject_empty_and_dot_segments() {
    let base = CanonicalUpstreamUrl::parse("https://api.example.com/v1", CleartextHttpPolicy::LoopbackOnly).unwrap();

    assert_eq!(
      base.operation_url::<[&str; 0], &str>([]),
      Err(InvalidOperationPath::Empty)
    );
    assert_eq!(
      base.operation_url(["models", ""]),
      Err(InvalidOperationPath::EmptySegment { index: 1 })
    );
    assert_eq!(
      base.operation_url(["models", "."]),
      Err(InvalidOperationPath::DotSegment { index: 1 })
    );
    assert_eq!(
      base.operation_url(["..", "models"]),
      Err(InvalidOperationPath::DotSegment { index: 0 })
    );
  }

  #[test]
  fn operation_queries_are_encoded_separately() {
    let base =
      CanonicalUpstreamUrl::parse("https://api.example.com/backend", CleartextHttpPolicy::LoopbackOnly).unwrap();
    let mut url = base.operation_url(["models"]).unwrap();
    url.query_pairs_mut().append_pair("client_version", "0.130.0+dev");

    assert_eq!(
      url.as_str(),
      "https://api.example.com/backend/models?client_version=0.130.0%2Bdev"
    );
  }

  #[test]
  fn relay_urls_preserve_prefix_path_and_query() {
    let base = CanonicalUpstreamUrl::parse(
      "https://api.example.com/proxy/openai/v1",
      CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();
    let target = "/chat/completions?stream=true".parse::<PathAndQuery>().unwrap();
    assert_eq!(
      base.relay_url(&target).unwrap().as_str(),
      "https://api.example.com/proxy/openai/v1/chat/completions?stream=true"
    );

    let root = "/".parse::<PathAndQuery>().unwrap();
    assert_eq!(
      base.relay_url(&root).unwrap().as_str(),
      "https://api.example.com/proxy/openai/v1/"
    );
  }

  #[test]
  fn origin_request_urls_preserve_exact_origin() {
    let origin = CanonicalHttpOrigin::parse("https://api.example.com:8443", CleartextHttpPolicy::LoopbackOnly).unwrap();
    let target = "/models?limit=10".parse::<PathAndQuery>().unwrap();
    assert_eq!(
      origin.request_url(&target).unwrap().as_str(),
      "https://api.example.com:8443/models?limit=10"
    );
  }

  #[test]
  fn request_urls_reject_dot_segments() {
    let base = CanonicalUpstreamUrl::parse("https://api.example.com/v1", CleartextHttpPolicy::LoopbackOnly).unwrap();
    let origin = CanonicalHttpOrigin::parse("https://api.example.com", CleartextHttpPolicy::LoopbackOnly).unwrap();
    for raw in ["/../models", "/%2e%2e/models", "/.%2E/models"] {
      let target = raw.parse::<PathAndQuery>().unwrap();
      assert!(base.relay_url(&target).is_err(), "accepted {raw:?}");
      assert!(origin.request_url(&target).is_err(), "accepted {raw:?}");
    }
  }

  #[test]
  fn origin_rejects_a_path() {
    assert!(CanonicalHttpOrigin::parse("https://api.example.com/v1", CleartextHttpPolicy::LoopbackOnly).is_err());
  }
}
