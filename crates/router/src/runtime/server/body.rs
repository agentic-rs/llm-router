//! Request-body admission for the v2 serving path.
//!
//! Listener matching has already pinned a profile and route before this
//! boundary runs. Opaque route families therefore collect only bounded wire
//! bytes, while managed routes decode and validate their structured payload
//! without allowing payload facts to change the matched route.

use super::super::MatchedHttpRoute;
use axum::body::Body;
use bytes::{Bytes, BytesMut};
use flate2::read::MultiGzDecoder;
use futures_util::StreamExt;
use http::header::CONTENT_ENCODING;
use http::HeaderMap;
use serde_json::Value;
use smol_str::SmolStr;
use snafu::Snafu;
use std::io::{self, Read};
use tokn_accounts::link::LinkedRouteKind;
use tokn_core::provider::ProviderRequestKind;

const MAX_CONTENT_ENCODING_LAYERS: usize = 4;
// The reference zstd encoder may declare a multi-megabyte window even for a
// small payload. Keep a bounded compatibility floor while independently
// enforcing the exact decoded-output limit below.
const MIN_ZSTD_WINDOW_LOG: u32 = 23;
const MAX_ZSTD_WINDOW_LOG: u32 = 27;
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// Independent limits for bytes received from the client and bytes produced
/// by managed content decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBodyLimits {
  max_wire_bytes: usize,
  max_decoded_bytes: usize,
}

impl RequestBodyLimits {
  pub const fn new(max_wire_bytes: usize, max_decoded_bytes: usize) -> Self {
    Self {
      max_wire_bytes,
      max_decoded_bytes,
    }
  }

  pub const fn max_wire_bytes(self) -> usize {
    self.max_wire_bytes
  }

  pub const fn max_decoded_bytes(self) -> usize {
    self.max_decoded_bytes
  }
}

/// A request body admitted according to its already-matched route family.
#[derive(Clone, Debug)]
pub enum BufferedRequestBody {
  /// Relay and transparent routes preserve the client's exact data bytes.
  /// `None` means the request had no body framing; `Some(Bytes::new())` means
  /// a body was present but contained zero data bytes.
  Opaque { wire_body: Option<Bytes> },
  /// Managed routes retain only validated request semantics. Execution owns
  /// identity-encoded JSON serialization and never needs the compressed wire
  /// representation or an encoding stack.
  Managed(ManagedRequestBody),
}

impl BufferedRequestBody {
  pub fn opaque_wire_body(&self) -> Option<Option<&Bytes>> {
    match self {
      Self::Opaque { wire_body } => Some(wire_body.as_ref()),
      Self::Managed(_) => None,
    }
  }

  pub fn managed(&self) -> Option<&ManagedRequestBody> {
    match self {
      Self::Managed(body) => Some(body),
      Self::Opaque { .. } => None,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentEncoding {
  Identity,
  Gzip,
  Zstd,
}

/// A decoded and validated managed request body.
#[derive(Clone, Debug)]
pub struct ManagedRequestBody {
  value: Value,
  requested_model: SmolStr,
}

impl ManagedRequestBody {
  pub fn value(&self) -> &Value {
    &self.value
  }

  pub fn requested_model(&self) -> &str {
    self.requested_model.as_str()
  }

  pub fn into_parts(self) -> (Value, SmolStr) {
    (self.value, self.requested_model)
  }
}

/// Buffer and validate one request body after listener matching but before
/// account/upstream resolution.
///
/// `body_present` is a framing fact retained by the HTTP server before it
/// consumes the body. It deliberately distinguishes no representation from a
/// present, zero-length representation for opaque forwarding.
pub async fn buffer_matched_body(
  matched: &MatchedHttpRoute,
  headers: &HeaderMap,
  body: Body,
  body_present: bool,
  limits: RequestBodyLimits,
) -> RequestBodyResult<BufferedRequestBody> {
  match matched.route().kind() {
    LinkedRouteKind::Relay(_) | LinkedRouteKind::Transparent(_) => {
      if !body_present {
        return Ok(BufferedRequestBody::Opaque { wire_body: None });
      }
      let wire_body = collect_wire_body(body, limits.max_wire_bytes()).await?;
      Ok(BufferedRequestBody::Opaque {
        wire_body: Some(wire_body),
      })
    }
    LinkedRouteKind::Managed(_) => {
      if !matches!(matched.request_kind(), ProviderRequestKind::Operation(_)) {
        return Err(RequestBodyError::ManagedOperationRequired {
          request_kind: matched.request_kind(),
        });
      }
      if !body_present {
        return Err(RequestBodyError::ManagedBodyRequired);
      }

      // Encoding metadata is a managed semantic. Parse it before polling the
      // body so malformed metadata cannot consume request data or affect an
      // opaque route family.
      let encodings = parse_content_encodings(headers)?;
      let wire_body = collect_wire_body(body, limits.max_wire_bytes()).await?;
      let decoded_limit = limits.max_decoded_bytes();
      tokio::task::spawn_blocking(move || decode_and_validate(wire_body, encodings, decoded_limit))
        .await
        .map_err(|source| RequestBodyError::ManagedProcessingUnavailable { source })?
    }
  }
}

async fn collect_wire_body(body: Body, limit: usize) -> RequestBodyResult<Bytes> {
  let mut stream = body.into_data_stream();
  let mut output = BytesMut::new();
  while let Some(chunk) = stream.next().await {
    let chunk = chunk.map_err(|source| RequestBodyError::BodyRead { source })?;
    if chunk.len() > limit.saturating_sub(output.len()) {
      return Err(RequestBodyError::WireBodyTooLarge { limit });
    }
    output.extend_from_slice(&chunk);
  }
  Ok(output.freeze())
}

fn parse_content_encodings(headers: &HeaderMap) -> RequestBodyResult<Vec<ContentEncoding>> {
  let mut encodings = Vec::new();
  for (field_index, value) in headers.get_all(CONTENT_ENCODING).iter().enumerate() {
    let value = value
      .to_str()
      .map_err(|_| RequestBodyError::InvalidContentEncodingHeader { field_index })?;
    for (member_index, member) in value.split(',').map(str::trim).enumerate() {
      if member.is_empty() {
        return Err(RequestBodyError::EmptyContentEncodingMember {
          field_index,
          member_index,
        });
      }
      let encoding = if member.eq_ignore_ascii_case("identity") {
        ContentEncoding::Identity
      } else if member.eq_ignore_ascii_case("gzip") {
        ContentEncoding::Gzip
      } else if member.eq_ignore_ascii_case("zstd") {
        ContentEncoding::Zstd
      } else {
        return Err(RequestBodyError::UnsupportedContentEncoding {
          encoding: member.to_owned(),
        });
      };
      encodings.push(encoding);
      if encodings.len() > MAX_CONTENT_ENCODING_LAYERS {
        return Err(RequestBodyError::TooManyContentEncodings {
          limit: MAX_CONTENT_ENCODING_LAYERS,
          actual: encodings.len(),
        });
      }
    }
  }
  Ok(encodings)
}

fn decode_and_validate(
  wire_body: Bytes,
  content_encodings: Vec<ContentEncoding>,
  decoded_limit: usize,
) -> RequestBodyResult<BufferedRequestBody> {
  let mut decoded_body = wire_body;
  if content_encodings.is_empty() {
    ensure_decoded_limit(decoded_body.len(), decoded_limit)?;
  }

  for encoding in content_encodings.iter().rev().copied() {
    decoded_body = match encoding {
      ContentEncoding::Identity => {
        ensure_decoded_limit(decoded_body.len(), decoded_limit)?;
        decoded_body
      }
      ContentEncoding::Gzip => decode_gzip(decoded_body, decoded_limit)?,
      ContentEncoding::Zstd => decode_zstd(decoded_body, decoded_limit)?,
    };
  }

  let value: Value =
    serde_json::from_slice(&decoded_body).map_err(|source| RequestBodyError::InvalidManagedJson { source })?;
  let object = value.as_object().ok_or(RequestBodyError::ManagedBodyObjectRequired)?;
  let model = object
    .get("model")
    .and_then(Value::as_str)
    .ok_or(RequestBodyError::ManagedModelStringRequired)?;
  if model.trim().is_empty() {
    return Err(RequestBodyError::ManagedModelEmpty);
  }
  if model.trim() != model {
    return Err(RequestBodyError::ManagedModelSurroundingWhitespace);
  }
  let requested_model = SmolStr::new(model);

  Ok(BufferedRequestBody::Managed(ManagedRequestBody {
    value,
    requested_model,
  }))
}

fn decode_gzip(body: Bytes, limit: usize) -> RequestBodyResult<Bytes> {
  let decoder = MultiGzDecoder::new(body.as_ref());
  read_decoded(decoder, limit).map_err(|error| match error {
    DecodeReadError::Io(source) => RequestBodyError::GzipDecode { source },
    DecodeReadError::TooLarge => RequestBodyError::DecodedBodyTooLarge { limit },
  })
}

fn decode_zstd(body: Bytes, limit: usize) -> RequestBodyResult<Bytes> {
  let mut decoder =
    zstd::stream::read::Decoder::new(body.as_ref()).map_err(|source| RequestBodyError::ZstdDecode { source })?;
  decoder
    .window_log_max(zstd_window_log(limit))
    .map_err(|source| RequestBodyError::ZstdDecode { source })?;
  read_decoded(decoder, limit).map_err(|error| match error {
    DecodeReadError::Io(source) => RequestBodyError::ZstdDecode { source },
    DecodeReadError::TooLarge => RequestBodyError::DecodedBodyTooLarge { limit },
  })
}

fn zstd_window_log(limit: usize) -> u32 {
  let bytes = limit.max(1 << MIN_ZSTD_WINDOW_LOG);
  let ceiling_log = usize::BITS - bytes.saturating_sub(1).leading_zeros();
  ceiling_log.clamp(MIN_ZSTD_WINDOW_LOG, MAX_ZSTD_WINDOW_LOG)
}

fn ensure_decoded_limit(actual: usize, limit: usize) -> RequestBodyResult<()> {
  if actual > limit {
    return Err(RequestBodyError::DecodedBodyTooLarge { limit });
  }
  Ok(())
}

fn read_decoded(mut reader: impl Read, limit: usize) -> Result<Bytes, DecodeReadError> {
  let mut output = Vec::with_capacity(limit.min(READ_BUFFER_BYTES));
  let mut buffer = [0_u8; READ_BUFFER_BYTES];
  loop {
    let remaining = limit.saturating_sub(output.len());
    let read_length = buffer.len().min(remaining.saturating_add(1));
    let read = reader.read(&mut buffer[..read_length]).map_err(DecodeReadError::Io)?;
    if read == 0 {
      return Ok(Bytes::from(output));
    }
    if read > remaining {
      return Err(DecodeReadError::TooLarge);
    }
    output.extend_from_slice(&buffer[..read]);
  }
}

enum DecodeReadError {
  Io(io::Error),
  TooLarge,
}

/// A request body rejected before target selection or upstream execution.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum RequestBodyError {
  #[snafu(display("managed route requires an LLM operation request, got {request_kind:?}"))]
  ManagedOperationRequired { request_kind: ProviderRequestKind },

  #[snafu(display("managed route requires a request body"))]
  ManagedBodyRequired,

  #[snafu(display("request body exceeds the {limit}-byte wire limit"))]
  WireBodyTooLarge { limit: usize },

  #[snafu(display("could not read request body: {source}"))]
  BodyRead { source: axum::Error },

  #[snafu(display("content-encoding field {} is not valid text", field_index + 1))]
  InvalidContentEncodingHeader { field_index: usize },

  #[snafu(display(
    "content-encoding field {} contains an empty list member at position {}",
    field_index + 1,
    member_index + 1
  ))]
  EmptyContentEncodingMember { field_index: usize, member_index: usize },

  #[snafu(display("unsupported content-encoding '{encoding}'"))]
  UnsupportedContentEncoding { encoding: String },

  #[snafu(display("request declares {actual} content-encoding layers; at most {limit} are allowed"))]
  TooManyContentEncodings { limit: usize, actual: usize },

  #[snafu(display("decoded request body exceeds the {limit}-byte limit"))]
  DecodedBodyTooLarge { limit: usize },

  #[snafu(display("could not decode gzip request body: {source}"))]
  GzipDecode { source: io::Error },

  #[snafu(display("could not decode zstd request body: {source}"))]
  ZstdDecode { source: io::Error },

  #[snafu(display("managed request body processing task was unavailable: {source}"))]
  ManagedProcessingUnavailable { source: tokio::task::JoinError },

  #[snafu(display("managed request body is not valid JSON: {source}"))]
  InvalidManagedJson { source: serde_json::Error },

  #[snafu(display("managed request body must be a JSON object"))]
  ManagedBodyObjectRequired,

  #[snafu(display("managed request body field 'model' must be a string"))]
  ManagedModelStringRequired,

  #[snafu(display("managed request body field 'model' must not be empty"))]
  ManagedModelEmpty,

  #[snafu(display("managed request body field 'model' must not have surrounding whitespace"))]
  ManagedModelSurroundingWhitespace,
}

pub type RequestBodyResult<T> = std::result::Result<T, RequestBodyError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{
    link_gateway_runtime, match_http, HttpRequestHead, HttpRouteMatch, MatchedHttpRoute, RuntimeNameRegistry,
  };
  use flate2::write::GzEncoder;
  use flate2::Compression;
  use http::{HeaderValue, Method};
  use hyper::body::{Body as HttpBody, Frame};
  use smol_str::SmolStr;
  use std::collections::{BTreeMap, BTreeSet};
  use std::convert::Infallible;
  use std::io::Write;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::pin::Pin;
  use std::task::{Context, Poll};
  use std::time::Duration;
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalAuthority, ClientAuthPlan,
    ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction, HttpIngress, HttpScheme, ListenerId,
    ListenerPlan, LlmApiListenerPlan, ManagedRetry, ManagedRoute, ManagedTarget, ModelGroupId, ModelSelector,
    ProfileId, ProfilePlan, ProviderId, RelayRetry, RelayRoute, RelayTarget, RouteId, RoutePlan, UpstreamId,
    UpstreamPlan, UpstreamSelector, WireIdentity,
  };

  #[derive(Clone, Copy)]
  enum FixtureFamily {
    Managed,
    Relay,
    Transparent,
  }

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn profile_id(value: &str) -> ProfileId {
    ProfileId::new(value).unwrap()
  }

  fn route_id(value: &str) -> RouteId {
    RouteId::new(value).unwrap()
  }

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn upstream_id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
  }

  fn account() -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.tier = AccountTier::Active;
    account
  }

  fn matched_route(family: FixtureFamily, request_kind: ProviderRequestKind) -> MatchedHttpRoute {
    let listener = listener_id("listener");
    let profile = profile_id("profile");
    let route = route_id("route");
    let pool = pool_id("pool");
    let upstream = upstream_id("upstream");
    let listener_plan = match family {
      FixtureFamily::Managed | FixtureFamily::Relay => ListenerPlan::LlmApi(LlmApiListenerPlan::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
        ClientAuthPlan::None,
        Box::default(),
        HttpAction::Route(profile.clone()),
      )),
      FixtureFamily::Transparent => ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
        ClientAuthPlan::None,
        Box::default(),
        HttpAction::Route(profile.clone()),
        Box::default(),
        ConnectAction::Tunnel,
        None,
      )),
    };
    let route_plan = match family {
      FixtureFamily::Managed => RoutePlan::Managed(ManagedRoute::new(
        ManagedTarget::new(
          pool.clone(),
          UpstreamSelector::Fixed(upstream.clone()),
          ModelSelector::Capability,
        ),
        tokn_policy::OperationPolicy::TranslateCompatible,
        None,
        ManagedRetry::Never,
      )),
      FixtureFamily::Relay => RoutePlan::Relay(RelayRoute::new(
        RelayTarget::FixedUpstream {
          upstream: upstream.clone(),
          account_pool: pool.clone(),
        },
        None,
        RelayRetry::Never,
      )),
      FixtureFamily::Transparent => RoutePlan::Transparent(Default::default()),
    };
    let needs_provider_graph = !matches!(family, FixtureFamily::Transparent);
    let pools = if needs_provider_graph {
      BTreeMap::from([(
        pool,
        AccountPoolPlan::new(
          AccountSelector::all(),
          AccountSelectionStrategy::RoundRobin,
          Duration::from_secs(30),
          None,
        ),
      )])
    } else {
      BTreeMap::new()
    };
    let upstreams = if needs_provider_graph {
      BTreeMap::from([(
        upstream,
        UpstreamPlan::new(
          provider_id(ID_LLAMA_CPP),
          Some("https://upstream.example/v1/".into()),
          Box::default(),
          false,
        )
        .with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("fixture")]))),
      )])
    } else {
      BTreeMap::new()
    };
    let plan = GatewayPlan::new(
      BTreeMap::from([(listener.clone(), listener_plan)]),
      BTreeMap::from([(profile, ProfilePlan::new(route.clone(), WireIdentity::None))]),
      BTreeMap::from([(route, route_plan)]),
      pools,
      upstreams,
      BTreeMap::<ModelGroupId, _>::new(),
    );
    let accounts = needs_provider_graph.then(account).into_iter().collect::<Vec<_>>();
    let runtime =
      link_gateway_runtime(&plan, &accounts, &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap();
    let linked_listener = runtime.listeners().listener(&listener).unwrap();
    let head = HttpRequestHead::new(
      HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse("client.example").unwrap()),
      Method::POST,
      "/v1/responses".parse().unwrap(),
    )
    .unwrap();
    let HttpRouteMatch::Route(matched) = match_http(linked_listener, head, request_kind) else {
      panic!("fixture listener must route the request");
    };
    matched
  }

  #[derive(Debug)]
  struct PanicOnPollBody;

  impl HttpBody for PanicOnPollBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
      self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
      panic!("request body must not be polled")
    }
  }

  fn panic_body() -> Body {
    Body::new(PanicOnPollBody)
  }

  fn gzip(body: &[u8]) -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    Bytes::from(encoder.finish().unwrap())
  }

  fn zstd(body: &[u8]) -> Bytes {
    Bytes::from(zstd::stream::encode_all(body, 0).unwrap())
  }

  fn generous_limits() -> RequestBodyLimits {
    RequestBodyLimits::new(128 * 1024, 256 * 1024)
  }

  #[test]
  fn zstd_window_limit_has_a_compatibility_floor_and_hard_cap() {
    assert_eq!(zstd_window_log(0), MIN_ZSTD_WINDOW_LOG);
    assert_eq!(zstd_window_log(1 << 24), 24);
    assert_eq!(zstd_window_log(usize::MAX), MAX_ZSTD_WINDOW_LOG);
  }

  #[tokio::test]
  async fn opaque_families_preserve_exact_data_without_inspecting_encoding() {
    for family in [FixtureFamily::Relay, FixtureFamily::Transparent] {
      let matched = matched_route(family, ProviderRequestKind::Opaque);
      let mut headers = HeaderMap::new();
      headers.insert(CONTENT_ENCODING, HeaderValue::from_bytes(b"\x80").unwrap());
      let body = Body::from_stream(futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"first\0")),
        Ok(Bytes::from_static(b"\xfflast")),
      ]));

      let buffered = buffer_matched_body(&matched, &headers, body, true, RequestBodyLimits::new(11, 0))
        .await
        .unwrap();

      assert_eq!(
        buffered.opaque_wire_body(),
        Some(Some(&Bytes::from_static(b"first\0\xfflast")))
      );
    }
  }

  #[tokio::test]
  async fn opaque_absent_and_present_empty_bodies_remain_distinct() {
    let matched = matched_route(FixtureFamily::Transparent, ProviderRequestKind::Opaque);

    let absent = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      panic_body(),
      false,
      RequestBodyLimits::new(0, 0),
    )
    .await
    .unwrap();
    let present = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::empty(),
      true,
      RequestBodyLimits::new(0, 0),
    )
    .await
    .unwrap();

    assert_eq!(absent.opaque_wire_body(), Some(None));
    assert_eq!(present.opaque_wire_body(), Some(Some(&Bytes::new())));
  }

  #[tokio::test]
  async fn opaque_collection_enforces_the_wire_limit_and_surfaces_read_errors() {
    let matched = matched_route(FixtureFamily::Relay, ProviderRequestKind::Opaque);
    let exact = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from("1234"),
      true,
      RequestBodyLimits::new(4, 0),
    )
    .await
    .unwrap();
    assert_eq!(exact.opaque_wire_body(), Some(Some(&Bytes::from_static(b"1234"))));

    let too_large = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from_stream(futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"12")),
        Ok(Bytes::from_static(b"345")),
      ])),
      true,
      RequestBodyLimits::new(4, 0),
    )
    .await
    .unwrap_err();
    assert!(matches!(too_large, RequestBodyError::WireBodyTooLarge { limit: 4 }));

    let read_error = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from_stream(futures_util::stream::once(async {
        Err::<Bytes, _>(io::Error::other("fixture read failure"))
      })),
      true,
      generous_limits(),
    )
    .await
    .unwrap_err();
    assert!(matches!(read_error, RequestBodyError::BodyRead { .. }));
  }

  #[tokio::test]
  async fn managed_route_rejects_non_operations_and_absent_bodies_without_polling() {
    for request_kind in [ProviderRequestKind::Models, ProviderRequestKind::Opaque] {
      let matched = matched_route(FixtureFamily::Managed, request_kind);
      let error = buffer_matched_body(&matched, &HeaderMap::new(), panic_body(), true, generous_limits())
        .await
        .unwrap_err();
      assert!(matches!(
        error,
        RequestBodyError::ManagedOperationRequired {
          request_kind: actual
        } if actual == request_kind
      ));
    }

    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let error = buffer_matched_body(&matched, &HeaderMap::new(), panic_body(), false, generous_limits())
      .await
      .unwrap_err();
    assert!(matches!(error, RequestBodyError::ManagedBodyRequired));
  }

  #[tokio::test]
  async fn managed_body_decodes_all_encoding_fields_in_reverse_order() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let decoded = Bytes::from_static(br#"{"model":"inbound-model","input":"hello"}"#);
    let gzip_encoded = gzip(&decoded);
    let wire = zstd(&gzip_encoded);
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_ENCODING, HeaderValue::from_static("GZip, identity"));
    headers.append(CONTENT_ENCODING, HeaderValue::from_static("ZSTD"));

    let buffered = buffer_matched_body(&matched, &headers, Body::from(wire), true, generous_limits())
      .await
      .unwrap();
    let BufferedRequestBody::Managed(managed) = buffered else {
      panic!("managed route must produce managed semantics");
    };

    assert_eq!(managed.requested_model(), "inbound-model");
    assert_eq!(managed.value()["input"], "hello");
    let (value, requested_model) = managed.into_parts();
    assert_eq!(value["model"], "inbound-model");
    assert_eq!(requested_model, "inbound-model");
  }

  #[tokio::test]
  async fn managed_gzip_supports_concatenated_members() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let mut wire = gzip(br#"{"model":"multi""#).to_vec();
    wire.extend_from_slice(&gzip(br#", "input":"member"}"#));
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

    let buffered = buffer_matched_body(&matched, &headers, Body::from(wire), true, generous_limits())
      .await
      .unwrap();

    assert_eq!(buffered.managed().unwrap().requested_model(), "multi");
    assert_eq!(buffered.managed().unwrap().value()["input"], "member");
  }

  #[tokio::test]
  async fn managed_encoding_metadata_is_strict_and_checked_before_polling() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let mut too_many = HeaderMap::new();
    too_many.append(CONTENT_ENCODING, HeaderValue::from_static("gzip, identity"));
    too_many.append(CONTENT_ENCODING, HeaderValue::from_static("zstd, identity, gzip"));
    let error = buffer_matched_body(&matched, &too_many, panic_body(), true, generous_limits())
      .await
      .unwrap_err();
    assert!(matches!(
      error,
      RequestBodyError::TooManyContentEncodings { limit: 4, actual: 5 }
    ));

    let mut unsupported = HeaderMap::new();
    unsupported.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
    let error = buffer_matched_body(&matched, &unsupported, panic_body(), true, generous_limits())
      .await
      .unwrap_err();
    assert!(matches!(
      error,
      RequestBodyError::UnsupportedContentEncoding { encoding } if encoding == "br"
    ));

    let mut invalid_text = HeaderMap::new();
    invalid_text.insert(CONTENT_ENCODING, HeaderValue::from_bytes(b"\x80").unwrap());
    let error = buffer_matched_body(&matched, &invalid_text, panic_body(), true, generous_limits())
      .await
      .unwrap_err();
    assert!(matches!(
      error,
      RequestBodyError::InvalidContentEncodingHeader { field_index: 0 }
    ));

    for value in ["", "   ", "gzip,", ",gzip", "gzip,,zstd", "gzip, ,zstd"] {
      let mut empty_member = HeaderMap::new();
      empty_member.insert(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
      let error = buffer_matched_body(&matched, &empty_member, panic_body(), true, generous_limits())
        .await
        .unwrap_err();
      assert!(
        matches!(error, RequestBodyError::EmptyContentEncodingMember { .. }),
        "expected empty member rejection for {value:?}, got {error}"
      );
    }
  }

  #[tokio::test]
  async fn managed_limits_apply_to_wire_final_and_intermediate_decoded_bytes() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let decoded = Bytes::from_static(br#"{"model":"m"}"#);

    let wire_error = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from(decoded.clone()),
      true,
      RequestBodyLimits::new(decoded.len() - 1, decoded.len()),
    )
    .await
    .unwrap_err();
    assert!(matches!(wire_error, RequestBodyError::WireBodyTooLarge { .. }));

    let decoded_error = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from(decoded.clone()),
      true,
      RequestBodyLimits::new(decoded.len(), decoded.len() - 1),
    )
    .await
    .unwrap_err();
    assert!(matches!(
      decoded_error,
      RequestBodyError::DecodedBodyTooLarge { limit } if limit == decoded.len() - 1
    ));

    let gzip_encoded = gzip(&decoded);
    assert!(gzip_encoded.len() > decoded.len());
    let wire = zstd(&gzip_encoded);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip, zstd"));
    let intermediate_error = buffer_matched_body(
      &matched,
      &headers,
      Body::from(wire),
      true,
      RequestBodyLimits::new(1024, decoded.len()),
    )
    .await
    .unwrap_err();
    assert!(matches!(
      intermediate_error,
      RequestBodyError::DecodedBodyTooLarge { limit } if limit == decoded.len()
    ));
  }

  #[tokio::test]
  async fn managed_body_validates_json_object_and_model_shape() {
    type ErrorPredicate = fn(&RequestBodyError) -> bool;

    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let cases: &[(&[u8], ErrorPredicate)] = &[
      (b"not-json", |error| {
        matches!(error, RequestBodyError::InvalidManagedJson { .. })
      }),
      (b"[]", |error| {
        matches!(error, RequestBodyError::ManagedBodyObjectRequired)
      }),
      (b"{}", |error| {
        matches!(error, RequestBodyError::ManagedModelStringRequired)
      }),
      (br#"{"model":42}"#, |error| {
        matches!(error, RequestBodyError::ManagedModelStringRequired)
      }),
      (br#"{"model":""}"#, |error| {
        matches!(error, RequestBodyError::ManagedModelEmpty)
      }),
      (br#"{"model":"   "}"#, |error| {
        matches!(error, RequestBodyError::ManagedModelEmpty)
      }),
      (br#"{"model":" model"}"#, |error| {
        matches!(error, RequestBodyError::ManagedModelSurroundingWhitespace)
      }),
      (br#"{"model":"model "}"#, |error| {
        matches!(error, RequestBodyError::ManagedModelSurroundingWhitespace)
      }),
    ];

    for (body, expected) in cases {
      let error = buffer_matched_body(
        &matched,
        &HeaderMap::new(),
        Body::from(Bytes::copy_from_slice(body)),
        true,
        generous_limits(),
      )
      .await
      .unwrap_err();
      assert!(expected(&error), "unexpected error for {body:?}: {error}");
    }
  }

  #[tokio::test]
  async fn managed_corrupt_compressed_bodies_report_the_selected_codec() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    for encoding in ["gzip", "zstd"] {
      let mut headers = HeaderMap::new();
      headers.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding).unwrap());
      let error = buffer_matched_body(
        &matched,
        &headers,
        Body::from("not-compressed"),
        true,
        generous_limits(),
      )
      .await
      .unwrap_err();
      match encoding {
        "gzip" => assert!(matches!(error, RequestBodyError::GzipDecode { .. })),
        "zstd" => assert!(matches!(error, RequestBodyError::ZstdDecode { .. })),
        _ => unreachable!(),
      }
    }
  }
}
