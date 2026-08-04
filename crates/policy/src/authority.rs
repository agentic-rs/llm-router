use smol_str::SmolStr;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum HostKind {
  Dns,
  Ipv4,
  Ipv6,
}

/// A strictly parsed, canonical DNS name or IP address.
///
/// DNS names are lowercase ASCII without a trailing dot. IP literals use
/// their standard library canonical representation and never include IPv6
/// brackets. Numeric forms that URL parsers could reinterpret as legacy IPv4
/// addresses are rejected instead of being treated as DNS names.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalHost {
  value: SmolStr,
  kind: HostKind,
}

impl CanonicalHost {
  pub fn parse(raw: &str) -> Result<Self, InvalidHost> {
    raw.parse()
  }

  pub fn as_str(&self) -> &str {
    self.value.as_str()
  }

  pub fn is_dns(&self) -> bool {
    self.kind == HostKind::Dns
  }

  pub fn is_ip(&self) -> bool {
    matches!(self.kind, HostKind::Ipv4 | HostKind::Ipv6)
  }

  pub fn is_ipv6(&self) -> bool {
    self.kind == HostKind::Ipv6
  }

  pub fn is_loopback(&self) -> bool {
    match self.kind {
      HostKind::Dns => false,
      HostKind::Ipv4 | HostKind::Ipv6 => self.value.parse::<IpAddr>().is_ok_and(|address| address.is_loopback()),
    }
  }

  pub fn is_strict_subdomain_of(&self, suffix: &Self) -> bool {
    self.is_dns()
      && suffix.is_dns()
      && self
        .as_str()
        .strip_suffix(suffix.as_str())
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
  }

  fn write_authority_host(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.is_ipv6() {
      write!(formatter, "[{}]", self.as_str())
    } else {
      formatter.write_str(self.as_str())
    }
  }
}

impl fmt::Display for CanonicalHost {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

impl FromStr for CanonicalHost {
  type Err = InvalidHost;

  fn from_str(raw: &str) -> Result<Self, Self::Err> {
    if raw.is_empty() {
      return Err(InvalidHost::Empty);
    }
    if !raw.is_ascii() {
      return Err(InvalidHost::NonAscii);
    }
    if raw
      .bytes()
      .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
      return Err(InvalidHost::WhitespaceOrControl);
    }

    if let Some(inner) = raw.strip_prefix('[').and_then(|value| value.strip_suffix(']')) {
      let address = inner
        .parse::<Ipv6Addr>()
        .map_err(|_| InvalidHost::InvalidBracketedIpv6)?;
      return Ok(Self {
        value: SmolStr::new(address.to_string()),
        kind: HostKind::Ipv6,
      });
    }
    if raw.contains(['[', ']']) {
      return Err(InvalidHost::MalformedBrackets);
    }

    if let Ok(address) = raw.parse::<IpAddr>() {
      return Ok(Self {
        value: SmolStr::new(address.to_string()),
        kind: match address {
          IpAddr::V4(_) => HostKind::Ipv4,
          IpAddr::V6(_) => HostKind::Ipv6,
        },
      });
    }
    if raw.contains(':') {
      return Err(InvalidHost::PortNotAllowed);
    }
    if raw.ends_with('.') {
      return Err(InvalidHost::TrailingDot);
    }
    if let Some(address) = parse_legacy_ipv4(raw) {
      return Err(InvalidHost::NonCanonicalIpv4 { canonical: address });
    }
    validate_dns_name(raw)?;

    Ok(Self {
      value: SmolStr::new(raw.to_ascii_lowercase()),
      kind: HostKind::Dns,
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidHost {
  Empty,
  NonAscii,
  WhitespaceOrControl,
  MalformedBrackets,
  InvalidBracketedIpv6,
  PortNotAllowed,
  TrailingDot,
  TooLong,
  InvalidDnsLabel,
  AmbiguousNumericSuffix,
  NonCanonicalIpv4 { canonical: Ipv4Addr },
}

impl fmt::Display for InvalidHost {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Empty => formatter.write_str("host must not be empty"),
      Self::NonAscii => formatter.write_str("host must contain ASCII characters only"),
      Self::WhitespaceOrControl => formatter.write_str("host must not contain whitespace or control characters"),
      Self::MalformedBrackets => formatter.write_str("host has malformed IPv6 brackets"),
      Self::InvalidBracketedIpv6 => formatter.write_str("brackets may only contain a valid IPv6 address"),
      Self::PortNotAllowed => formatter.write_str("host must not include a port"),
      Self::TrailingDot => formatter.write_str("host must not have a trailing dot"),
      Self::TooLong => formatter.write_str("DNS name exceeds 253 bytes"),
      Self::InvalidDnsLabel => {
        formatter.write_str("DNS labels must be 1-63 ASCII letters, digits, or interior hyphens")
      }
      Self::AmbiguousNumericSuffix => {
        formatter.write_str("the final DNS label is numeric-like and ambiguous with legacy IPv4 syntax")
      }
      Self::NonCanonicalIpv4 { canonical } => {
        write!(formatter, "noncanonical IPv4 address; use `{canonical}`")
      }
    }
  }
}

impl std::error::Error for InvalidHost {}

fn validate_dns_name(raw: &str) -> Result<(), InvalidHost> {
  if raw.len() > 253 {
    return Err(InvalidHost::TooLong);
  }

  for label in raw.split('.') {
    let valid_length = !label.is_empty() && label.len() <= 63;
    let valid_edges = label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
      && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric);
    let valid_characters = label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if !(valid_length && valid_edges && valid_characters) {
      return Err(InvalidHost::InvalidDnsLabel);
    }
  }

  let top_level = raw.rsplit_once('.').map_or(raw, |(_, top_level)| top_level);
  if top_level.bytes().all(|byte| byte.is_ascii_digit()) || parse_legacy_ipv4_number(top_level).is_some() {
    return Err(InvalidHost::AmbiguousNumericSuffix);
  }
  Ok(())
}

fn parse_legacy_ipv4(raw: &str) -> Option<Ipv4Addr> {
  let pieces = raw.split('.').collect::<Vec<_>>();
  if pieces.is_empty() || pieces.len() > 4 {
    return None;
  }

  let numbers = pieces
    .iter()
    .map(|piece| parse_legacy_ipv4_number(piece))
    .collect::<Option<Vec<_>>>()?;
  if numbers[..numbers.len() - 1].iter().any(|number| *number > 255) {
    return None;
  }

  let last_bytes = 5 - numbers.len();
  let last_limit = 1_u64 << (last_bytes * 8);
  if numbers[numbers.len() - 1] >= last_limit {
    return None;
  }

  let mut value = numbers[numbers.len() - 1];
  for (index, number) in numbers[..numbers.len() - 1].iter().enumerate() {
    value += number << (8 * (3 - index));
  }
  Some(Ipv4Addr::from(value as u32))
}

fn parse_legacy_ipv4_number(raw: &str) -> Option<u64> {
  if raw.is_empty() {
    return None;
  }

  let (digits, radix) = if let Some(digits) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
    (digits, 16)
  } else if raw.len() > 1 {
    raw.strip_prefix('0').map_or((raw, 10), |digits| (digits, 8))
  } else {
    (raw, 10)
  };
  if digits.is_empty() {
    return Some(0);
  }
  u64::from_str_radix(digits, radix).ok()
}

/// A canonical HTTP authority with an optional explicit port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalAuthority {
  host: CanonicalHost,
  port: Option<NonZeroU16>,
}

impl CanonicalAuthority {
  pub fn new(host: CanonicalHost, port: Option<NonZeroU16>) -> Self {
    Self { host, port }
  }

  pub fn parse(raw: &str) -> Result<Self, InvalidAuthority> {
    raw.parse()
  }

  pub fn host(&self) -> &CanonicalHost {
    &self.host
  }

  pub fn port(&self) -> Option<u16> {
    self.port.map(NonZeroU16::get)
  }

  pub fn into_resolved(self, default_port: NonZeroU16) -> ResolvedAuthority {
    ResolvedAuthority {
      host: self.host,
      port: self.port.unwrap_or(default_port),
    }
  }

  fn into_explicit(self) -> Result<ResolvedAuthority, InvalidAuthority> {
    let port = self.port.ok_or(InvalidAuthority::MissingPort)?;
    Ok(ResolvedAuthority { host: self.host, port })
  }
}

impl fmt::Display for CanonicalAuthority {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.host.write_authority_host(formatter)?;
    if let Some(port) = self.port {
      write!(formatter, ":{port}")?;
    }
    Ok(())
  }
}

impl FromStr for CanonicalAuthority {
  type Err = InvalidAuthority;

  fn from_str(raw: &str) -> Result<Self, Self::Err> {
    if raw.is_empty() {
      return Err(InvalidAuthority::Empty);
    }
    if !raw.is_ascii()
      || raw
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
      return Err(InvalidAuthority::InvalidCharacters);
    }
    if raw.contains('@') {
      return Err(InvalidAuthority::UserInfoNotAllowed);
    }
    if raw.contains(['/', '?', '#', '\\', '%']) {
      return Err(InvalidAuthority::InvalidCharacters);
    }

    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
      let closing = rest.find(']').ok_or(InvalidAuthority::MalformedIpv6Brackets)?;
      let raw_host = &rest[..closing];
      let suffix = &rest[closing + 1..];
      let host = CanonicalHost::parse(raw_host).map_err(InvalidAuthority::Host)?;
      if !host.is_ipv6() {
        return Err(InvalidAuthority::BracketsRequireIpv6);
      }
      (host, parse_authority_port_suffix(suffix)?)
    } else {
      if raw.contains(['[', ']']) {
        return Err(InvalidAuthority::MalformedIpv6Brackets);
      }
      let colon_count = raw.bytes().filter(|byte| *byte == b':').count();
      if colon_count > 1 {
        return Err(InvalidAuthority::Ipv6MustBeBracketed);
      }
      let (raw_host, port) = match raw.split_once(':') {
        Some((host, raw_port)) => (host, Some(parse_port(raw_port)?)),
        None => (raw, None),
      };
      let host = CanonicalHost::parse(raw_host).map_err(InvalidAuthority::Host)?;
      (host, port)
    };

    Ok(Self { host, port })
  }
}

fn parse_authority_port_suffix(raw: &str) -> Result<Option<NonZeroU16>, InvalidAuthority> {
  if raw.is_empty() {
    return Ok(None);
  }
  let port = raw.strip_prefix(':').ok_or(InvalidAuthority::MalformedIpv6Brackets)?;
  Ok(Some(parse_port(port)?))
}

fn parse_port(raw: &str) -> Result<NonZeroU16, InvalidAuthority> {
  if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
    return Err(InvalidAuthority::InvalidPort);
  }
  raw
    .parse::<u16>()
    .ok()
    .and_then(NonZeroU16::new)
    .ok_or(InvalidAuthority::InvalidPort)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidAuthority {
  Empty,
  InvalidCharacters,
  UserInfoNotAllowed,
  MalformedIpv6Brackets,
  BracketsRequireIpv6,
  Ipv6MustBeBracketed,
  InvalidPort,
  MissingPort,
  Host(InvalidHost),
}

impl fmt::Display for InvalidAuthority {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Empty => formatter.write_str("authority must not be empty"),
      Self::InvalidCharacters => formatter.write_str("authority contains invalid characters"),
      Self::UserInfoNotAllowed => formatter.write_str("authority must not contain user information"),
      Self::MalformedIpv6Brackets => formatter.write_str("authority has malformed IPv6 brackets"),
      Self::BracketsRequireIpv6 => formatter.write_str("authority brackets may only contain an IPv6 address"),
      Self::Ipv6MustBeBracketed => formatter.write_str("an IPv6 authority must enclose its host in brackets"),
      Self::InvalidPort => formatter.write_str("authority port must be an integer from 1 through 65535"),
      Self::MissingPort => formatter.write_str("authority must include an explicit port"),
      Self::Host(source) => write!(formatter, "invalid authority host: {source}"),
    }
  }
}

impl std::error::Error for InvalidAuthority {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Host(source) => Some(source),
      _ => None,
    }
  }
}

/// A canonical endpoint authority with a materialized nonzero port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolvedAuthority {
  host: CanonicalHost,
  port: NonZeroU16,
}

impl ResolvedAuthority {
  pub fn new(host: CanonicalHost, port: NonZeroU16) -> Self {
    Self { host, port }
  }

  pub fn host(&self) -> &CanonicalHost {
    &self.host
  }

  pub fn port(&self) -> u16 {
    self.port.get()
  }
}

impl fmt::Display for ResolvedAuthority {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.host.write_authority_host(formatter)?;
    write!(formatter, ":{}", self.port)
  }
}

/// The transport scheme of a validated HTTP request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HttpScheme {
  Http,
  Https,
}

impl HttpScheme {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Https => "https",
    }
  }

  pub fn default_port(self) -> NonZeroU16 {
    let port = match self {
      Self::Http => 80,
      Self::Https => 443,
    };
    NonZeroU16::new(port).expect("HTTP scheme default ports are nonzero")
  }
}

impl fmt::Display for HttpScheme {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IngressAuthoritySource {
  DirectHttp,
  Connect,
}

/// The immutable original destination used for request policy decisions.
///
/// For intercepted traffic this is created from the original CONNECT
/// authority and must not be replaced by an inner request authority. The
/// source is retained so request handling cannot confuse a direct HTTP
/// authority with a CONNECT security boundary.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IngressAuthority {
  authority: ResolvedAuthority,
  source: IngressAuthoritySource,
}

impl IngressAuthority {
  pub fn from_http(authority: CanonicalAuthority, default_port: NonZeroU16) -> Self {
    Self {
      authority: authority.into_resolved(default_port),
      source: IngressAuthoritySource::DirectHttp,
    }
  }

  pub fn from_connect(raw: &str) -> Result<Self, InvalidAuthority> {
    Self::from_connect_authority(CanonicalAuthority::parse(raw)?)
  }

  pub fn from_connect_authority(authority: CanonicalAuthority) -> Result<Self, InvalidAuthority> {
    Ok(Self {
      authority: authority.into_explicit()?,
      source: IngressAuthoritySource::Connect,
    })
  }

  pub fn authority(&self) -> &ResolvedAuthority {
    &self.authority
  }

  pub fn source(&self) -> IngressAuthoritySource {
    self.source
  }

  pub fn host(&self) -> &CanonicalHost {
    self.authority.host()
  }

  pub fn port(&self) -> u16 {
    self.authority.port()
  }

  /// Verify an inner request authority against the immutable ingress target.
  ///
  /// `default_port` belongs to the inner request's scheme. It must never be
  /// replaced by the CONNECT target port: an omitted HTTPS inner port means
  /// 443 even when the CONNECT target used another port.
  pub fn validate_inner(&self, inner: CanonicalAuthority, default_port: NonZeroU16) -> Result<(), AuthorityMismatch> {
    let found = inner.into_resolved(default_port);
    if found == self.authority {
      Ok(())
    } else {
      Err(AuthorityMismatch {
        expected: self.authority.clone(),
        found,
      })
    }
  }
}

impl fmt::Display for IngressAuthority {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.authority.fmt(formatter)
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityMismatch {
  expected: ResolvedAuthority,
  found: ResolvedAuthority,
}

impl AuthorityMismatch {
  pub fn expected(&self) -> &ResolvedAuthority {
    &self.expected
  }

  pub fn found(&self) -> &ResolvedAuthority {
    &self.found
  }
}

impl fmt::Display for AuthorityMismatch {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "inner request authority `{}` does not match ingress authority `{}`",
      self.found, self.expected
    )
  }
}

impl std::error::Error for AuthorityMismatch {}

/// A scheme and immutable authority admitted through the HTTP trust boundary.
///
/// Direct traffic resolves omitted ports from its typed scheme. Intercepted
/// HTTPS traffic retains the original CONNECT authority only after verifying
/// that the inner request authority names the same destination.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HttpIngress {
  scheme: HttpScheme,
  authority: IngressAuthority,
}

impl HttpIngress {
  pub fn direct(scheme: HttpScheme, authority: CanonicalAuthority) -> Self {
    Self {
      scheme,
      authority: IngressAuthority::from_http(authority, scheme.default_port()),
    }
  }

  pub fn intercepted_https(connect: &IngressAuthority, inner: CanonicalAuthority) -> Result<Self, HttpIngressError> {
    if connect.source() != IngressAuthoritySource::Connect {
      return Err(HttpIngressError::ConnectIngressRequired {
        found: connect.source(),
      });
    }
    connect
      .validate_inner(inner, HttpScheme::Https.default_port())
      .map_err(HttpIngressError::AuthorityMismatch)?;
    Ok(Self {
      scheme: HttpScheme::Https,
      authority: connect.clone(),
    })
  }

  pub fn scheme(&self) -> HttpScheme {
    self.scheme
  }

  pub fn authority(&self) -> &IngressAuthority {
    &self.authority
  }

  pub fn host(&self) -> &CanonicalHost {
    self.authority.host()
  }

  pub fn port(&self) -> u16 {
    self.authority.port()
  }
}

/// Failure to admit an intercepted request into the HTTP trust boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpIngressError {
  ConnectIngressRequired { found: IngressAuthoritySource },
  AuthorityMismatch(AuthorityMismatch),
}

impl fmt::Display for HttpIngressError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ConnectIngressRequired { found } => {
        write!(
          formatter,
          "intercepted HTTPS ingress requires a CONNECT authority, found {found:?}"
        )
      }
      Self::AuthorityMismatch(source) => source.fmt(formatter),
    }
  }
}

impl std::error::Error for HttpIngressError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::ConnectIngressRequired { .. } => None,
      Self::AuthorityMismatch(source) => Some(source),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn canonicalizes_dns_and_ip_hosts() {
    assert_eq!(
      CanonicalHost::parse("API.Example.COM").unwrap().as_str(),
      "api.example.com"
    );
    assert_eq!(CanonicalHost::parse("127.0.0.1").unwrap().as_str(), "127.0.0.1");
    assert_eq!(
      CanonicalHost::parse("[2001:0DB8:0:0::1]").unwrap().as_str(),
      "2001:db8::1"
    );
    assert!(CanonicalHost::parse("127.0.0.1").unwrap().is_loopback());
    assert!(!CanonicalHost::parse("localhost").unwrap().is_loopback());
  }

  #[test]
  fn rejects_ambiguous_or_noncanonical_hosts() {
    for raw in [
      "example.com.",
      "bad_name.example",
      "example.123",
      "example.0x10",
      "example.0x100000000",
      "2130706433",
      "127.1",
      "0177.0.0.1",
      "0x7f000001",
      "example.com:443",
      " example.com",
      "café.example",
    ] {
      assert!(CanonicalHost::parse(raw).is_err(), "accepted {raw:?}");
    }
  }

  #[test]
  fn recognizes_only_strict_dns_subdomains() {
    let suffix = CanonicalHost::parse("example.com").unwrap();
    assert!(CanonicalHost::parse("api.example.com")
      .unwrap()
      .is_strict_subdomain_of(&suffix));
    assert!(!CanonicalHost::parse("example.com")
      .unwrap()
      .is_strict_subdomain_of(&suffix));
    assert!(!CanonicalHost::parse("notexample.com")
      .unwrap()
      .is_strict_subdomain_of(&suffix));
  }

  #[test]
  fn parses_and_formats_canonical_authorities() {
    let dns = CanonicalAuthority::parse("API.Example.COM:0443").unwrap();
    assert_eq!(dns.host().as_str(), "api.example.com");
    assert_eq!(dns.port(), Some(443));
    assert_eq!(dns.to_string(), "api.example.com:443");

    let ipv6 = CanonicalAuthority::parse("[2001:0DB8::1]:8443").unwrap();
    assert_eq!(ipv6.host().as_str(), "2001:db8::1");
    assert_eq!(ipv6.to_string(), "[2001:db8::1]:8443");
  }

  #[test]
  fn rejects_unsafe_authority_syntax() {
    for raw in [
      "user@example.com:443",
      "example.com/path",
      "example.com:0",
      "example.com:",
      "2001:db8::1:443",
      "[127.0.0.1]:443",
      "[::1]extra",
      "example.com%2f.evil",
    ] {
      assert!(CanonicalAuthority::parse(raw).is_err(), "accepted {raw:?}");
    }
  }

  #[test]
  fn connect_authority_requires_and_preserves_a_port() {
    assert_eq!(
      IngressAuthority::from_connect("Example.com:443").unwrap().to_string(),
      "example.com:443"
    );
    assert_eq!(
      IngressAuthority::from_connect("[::1]:8443").unwrap().to_string(),
      "[::1]:8443"
    );
    assert_eq!(
      IngressAuthority::from_connect("[::1]:8443").unwrap().source(),
      IngressAuthoritySource::Connect
    );
    assert_eq!(
      IngressAuthority::from_connect("example.com"),
      Err(InvalidAuthority::MissingPort)
    );
  }

  #[test]
  fn materializes_an_optional_authority_port_once() {
    let default_port = NonZeroU16::new(443).unwrap();
    let ingress = IngressAuthority::from_http(CanonicalAuthority::parse("example.com").unwrap(), default_port);
    assert_eq!(ingress.to_string(), "example.com:443");
    assert_eq!(ingress.source(), IngressAuthoritySource::DirectHttp);
  }

  #[test]
  fn http_ingress_resolves_typed_scheme_defaults_and_preserves_explicit_ports() {
    assert_eq!(HttpScheme::Http.as_str(), "http");
    assert_eq!(HttpScheme::Https.to_string(), "https");
    assert_eq!(HttpScheme::Http.default_port().get(), 80);
    assert_eq!(HttpScheme::Https.default_port().get(), 443);

    let http = HttpIngress::direct(HttpScheme::Http, CanonicalAuthority::parse("example.com").unwrap());
    let https = HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse("example.com").unwrap());
    let nondefault = HttpIngress::direct(
      HttpScheme::Https,
      CanonicalAuthority::parse("example.com:8443").unwrap(),
    );

    assert_eq!(http.scheme(), HttpScheme::Http);
    assert_eq!(http.host().as_str(), "example.com");
    assert_eq!(http.port(), 80);
    assert_eq!(http.authority().source(), IngressAuthoritySource::DirectHttp);
    assert_eq!(https.port(), 443);
    assert_eq!(nondefault.port(), 8443);
  }

  #[test]
  fn intercepted_https_validates_then_retains_the_connect_authority() {
    let connect = IngressAuthority::from_connect("example.com:443").unwrap();
    let ingress = HttpIngress::intercepted_https(&connect, CanonicalAuthority::parse("example.com").unwrap()).unwrap();

    assert_eq!(ingress.scheme(), HttpScheme::Https);
    assert_eq!(ingress.authority(), &connect);
    assert_eq!(ingress.authority().source(), IngressAuthoritySource::Connect);
  }

  #[test]
  fn intercepted_https_distinguishes_wrong_source_from_authority_mismatch() {
    let direct = IngressAuthority::from_http(
      CanonicalAuthority::parse("example.com").unwrap(),
      HttpScheme::Https.default_port(),
    );
    assert_eq!(
      HttpIngress::intercepted_https(&direct, CanonicalAuthority::parse("example.com").unwrap()).unwrap_err(),
      HttpIngressError::ConnectIngressRequired {
        found: IngressAuthoritySource::DirectHttp,
      }
    );

    let connect = IngressAuthority::from_connect("example.com:8443").unwrap();
    let error =
      HttpIngress::intercepted_https(&connect, CanonicalAuthority::parse("example.com").unwrap()).unwrap_err();
    let HttpIngressError::AuthorityMismatch(mismatch) = error else {
      panic!("expected an authority mismatch");
    };
    assert_eq!(mismatch.expected().to_string(), "example.com:8443");
    assert_eq!(mismatch.found().to_string(), "example.com:443");
  }

  #[test]
  fn validates_inner_authority_with_its_own_scheme_default() {
    let ingress = IngressAuthority::from_connect("example.com:8443").unwrap();
    let https_port = NonZeroU16::new(443).unwrap();

    let mismatch = ingress
      .validate_inner(CanonicalAuthority::parse("example.com").unwrap(), https_port)
      .unwrap_err();
    assert_eq!(mismatch.expected().to_string(), "example.com:8443");
    assert_eq!(mismatch.found().to_string(), "example.com:443");
    assert!(ingress
      .validate_inner(CanonicalAuthority::parse("example.com:8443").unwrap(), https_port)
      .is_ok());
  }
}
