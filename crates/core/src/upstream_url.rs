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
  fn origin_rejects_a_path() {
    assert!(CanonicalHttpOrigin::parse("https://api.example.com/v1", CleartextHttpPolicy::LoopbackOnly).is_err());
  }
}
