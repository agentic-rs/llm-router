use crate::v2::{CompileError, RawBindingAction, RawClientAuth, RawConfig, RawConnectAction, RawListener};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use tokn_policy::{
  BindingId, CanonicalHost, ClientAuthPlan, ConnectAction, ConnectMatch, ConnectRulePlan, ForwardProxyListenerPlan,
  HostPattern, HttpAction, HttpBindingPlan, HttpMatch, ListenerId, ListenerPlan, LlmApiListenerPlan, OperationId,
  ProfileId, ProfilePlan, TlsPlan,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerFlavor {
  LlmApi,
  ForwardProxy,
}

struct ListenerDraft {
  flavor: ListenerFlavor,
  bind: SocketAddr,
  client_auth: ClientAuthPlan,
  cors: tokn_policy::CorsPlan,
  request_body_max_bytes: Option<NonZeroUsize>,
  default_http_action: Option<HttpAction>,
  default_connect_action: Option<ConnectAction>,
  ca_dir: Option<PathBuf>,
}

struct HttpActionContext<'a> {
  owner_kind: &'static str,
  owner: &'a str,
  reference_field: &'static str,
}

fn dimension_subsumes<T>(covering: &[T], covered: &[T], subsumes: impl Fn(&T, &T) -> bool) -> bool {
  covering.is_empty()
    || (!covered.is_empty()
      && covered
        .iter()
        .all(|candidate| covering.iter().any(|alternative| subsumes(alternative, candidate))))
}

fn dimension_subsumes_atom<T>(covering: &[T], atom: Option<&T>, subsumes: impl Fn(&T, &T) -> bool) -> bool {
  match atom {
    None => covering.is_empty(),
    Some(atom) => covering.is_empty() || covering.iter().any(|alternative| subsumes(alternative, atom)),
  }
}

fn all_atoms<T>(alternatives: &[T], mut predicate: impl FnMut(Option<&T>) -> bool) -> bool {
  if alternatives.is_empty() {
    predicate(None)
  } else {
    alternatives.iter().all(|atom| predicate(Some(atom)))
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpMatchKey {
  hosts: Vec<HostPattern>,
  path_prefixes: Vec<String>,
  methods: Vec<String>,
  operations: Vec<String>,
}

impl HttpMatchKey {
  fn subsumes(&self, other: &Self) -> bool {
    dimension_subsumes(&self.hosts, &other.hosts, HostPattern::subsumes)
      && dimension_subsumes(&self.path_prefixes, &other.path_prefixes, |prefix, path| {
        path.starts_with(prefix)
      })
      && dimension_subsumes(&self.methods, &other.methods, PartialEq::eq)
      && dimension_subsumes(&self.operations, &other.operations, PartialEq::eq)
  }

  fn subsumes_atom(
    &self,
    host: Option<&HostPattern>,
    path_prefix: Option<&String>,
    method: Option<&String>,
    operation: Option<&String>,
  ) -> bool {
    dimension_subsumes_atom(&self.hosts, host, HostPattern::subsumes)
      && dimension_subsumes_atom(&self.path_prefixes, path_prefix, |prefix, path| {
        path.starts_with(prefix)
      })
      && dimension_subsumes_atom(&self.methods, method, PartialEq::eq)
      && dimension_subsumes_atom(&self.operations, operation, PartialEq::eq)
  }
}

fn http_matchers_subsume_union(prior: &[(HttpMatchKey, BindingId)], matcher: &HttpMatchKey) -> bool {
  all_atoms(&matcher.hosts, |host| {
    all_atoms(&matcher.path_prefixes, |path_prefix| {
      all_atoms(&matcher.methods, |method| {
        all_atoms(&matcher.operations, |operation| {
          prior
            .iter()
            .any(|(candidate, _)| candidate.subsumes_atom(host, path_prefix, method, operation))
        })
      })
    })
  })
}

pub(super) fn compile_listeners(
  raw: &RawConfig,
  source: &Path,
  profiles: &BTreeMap<ProfileId, ProfilePlan>,
) -> Result<BTreeMap<ListenerId, ListenerPlan>, CompileError> {
  if raw.listeners.is_empty() {
    return Err(CompileError::EmptyRegistry { resource: "listener" });
  }

  let mut drafts = BTreeMap::new();
  let mut binds = Vec::<(SocketAddr, ListenerId)>::new();
  for (raw_id, raw_listener) in &raw.listeners {
    let id = parse_id::<ListenerId>("listener id", raw_id)?;
    let (
      flavor,
      raw_bind,
      raw_client_auth,
      cors,
      allow_insecure_public,
      request_body_max_bytes,
      raw_default_http_action,
      default_connect_action,
      ca_dir,
    ) = match raw_listener {
      RawListener::LlmApi {
        bind,
        client_auth,
        cors,
        allow_insecure_public,
      } => (
        ListenerFlavor::LlmApi,
        bind,
        client_auth,
        cors.compile(raw_id)?,
        *allow_insecure_public,
        None,
        None,
        None,
        None,
      ),
      RawListener::ForwardProxy {
        bind,
        client_auth,
        allow_insecure_public,
        request_body_max_bytes,
        default_http_action,
        default_connect,
        ca_dir,
      } => (
        ListenerFlavor::ForwardProxy,
        bind,
        client_auth,
        tokn_policy::CorsPlan::default(),
        *allow_insecure_public,
        NonZeroUsize::new(*request_body_max_bytes),
        Some(default_http_action),
        Some(compile_connect_action(*default_connect)),
        resolve_ca_dir(ca_dir.as_deref(), source, raw_id)?,
      ),
    };

    let bind = compile_bind(raw_bind, raw_id)?;
    let client_auth = compile_client_auth(*raw_client_auth);
    if matches!(raw_listener, RawListener::ForwardProxy { .. }) && request_body_max_bytes.is_none() {
      return Err(invalid_value(
        format!("listeners.{raw_id}.request_body_max_bytes"),
        "must be greater than zero",
      ));
    }
    if !bind.ip().is_loopback() {
      if client_auth == ClientAuthPlan::None {
        return Err(invalid_value(
          format!("listeners.{raw_id}.client_auth"),
          "unauthenticated listeners must bind to a loopback address",
        ));
      }
      if !allow_insecure_public {
        return Err(invalid_value(
          format!("listeners.{raw_id}.allow_insecure_public"),
          "non-loopback listeners are plaintext; bind to loopback or explicitly set allow_insecure_public = true",
        ));
      }
    }
    if let Some((first_bind, first_listener)) = binds
      .iter()
      .find(|(first_bind, _)| bind_addresses_overlap(*first_bind, bind))
    {
      return Err(CompileError::DuplicateBind {
        first_listener: first_listener.to_string(),
        first_bind: first_bind.to_string(),
        second_listener: raw_id.clone(),
        second_bind: bind.to_string(),
      });
    }
    binds.push((bind, id.clone()));

    let default_http_action = raw_default_http_action
      .map(|action| {
        compile_http_action(
          action,
          HttpActionContext {
            owner_kind: "listener",
            owner: raw_id,
            reference_field: "default_http_action.profile",
          },
          profiles,
        )
      })
      .transpose()?;
    drafts.insert(
      id,
      ListenerDraft {
        flavor,
        bind,
        client_auth,
        cors,
        request_body_max_bytes,
        default_http_action,
        default_connect_action,
        ca_dir,
      },
    );
  }

  let mut binding_ids = BTreeSet::new();
  let mut http_bindings = BTreeMap::<ListenerId, Vec<HttpBindingPlan>>::new();
  let mut http_matchers = BTreeMap::<ListenerId, Vec<(HttpMatchKey, BindingId)>>::new();
  for raw_binding in &raw.bindings {
    let id = claim_binding_id(&raw_binding.id, &mut binding_ids)?;
    let listener_id = resolve_listener(&raw_binding.listener, "binding", &raw_binding.id, "listener", &drafts)?;
    let listener = &drafts[&listener_id];
    if listener.flavor != ListenerFlavor::ForwardProxy {
      return Err(invalid_value(
        format!("bindings.{}.listener", raw_binding.id),
        "HTTP bindings are only supported on forward-proxy listeners; configure profiles.<id>.binding for API paths",
      ));
    }
    let (matcher, key) = compile_http_match(raw_binding)?;
    let prior_matchers = http_matchers.entry(listener_id.clone()).or_default();
    if let Some((_, first)) = prior_matchers.iter().find(|(prior, _)| prior.subsumes(&key)) {
      return Err(invalid_value(
        format!("bindings.{}", raw_binding.id),
        format!(
          "matcher is unreachable because binding `{first}` matches all of its requests on listener `{listener_id}`"
        ),
      ));
    }
    if http_matchers_subsume_union(prior_matchers, &key) {
      return Err(invalid_value(
        format!("bindings.{}", raw_binding.id),
        format!(
          "matcher is unreachable because earlier bindings collectively match all of its requests on listener `{listener_id}`"
        ),
      ));
    }
    prior_matchers.push((key, id.clone()));
    let action = compile_http_action(
      &raw_binding.action,
      HttpActionContext {
        owner_kind: "binding",
        owner: &raw_binding.id,
        reference_field: "action.profile",
      },
      profiles,
    )?;
    http_bindings
      .entry(listener_id)
      .or_default()
      .push(HttpBindingPlan::new(id, matcher, action));
  }

  let mut connect_rules = BTreeMap::<ListenerId, Vec<ConnectRulePlan>>::new();
  let mut connect_matchers = BTreeMap::<ListenerId, Vec<(ConnectMatchKey, BindingId)>>::new();
  for raw_rule in &raw.connect_rules {
    let id = claim_binding_id(&raw_rule.id, &mut binding_ids)?;
    let listener_id = resolve_listener(&raw_rule.listener, "CONNECT rule", &raw_rule.id, "listener", &drafts)?;
    if drafts[&listener_id].flavor != ListenerFlavor::ForwardProxy {
      return Err(invalid_value(
        format!("connect_rules.{}.listener", raw_rule.id),
        format!("listener `{listener_id}` is not a forward proxy"),
      ));
    }
    let (matcher, key) = compile_connect_match(raw_rule)?;
    let prior_matchers = connect_matchers.entry(listener_id.clone()).or_default();
    if let Some((_, first)) = prior_matchers.iter().find(|(prior, _)| prior.subsumes(&key)) {
      return Err(invalid_value(
        format!("connect_rules.{}", raw_rule.id),
        format!(
          "matcher is unreachable because CONNECT rule `{first}` matches all of its requests on listener `{listener_id}`"
        ),
      ));
    }
    if connect_matchers_subsume_union(prior_matchers, &key) {
      return Err(invalid_value(
        format!("connect_rules.{}", raw_rule.id),
        format!(
          "matcher is unreachable because earlier CONNECT rules collectively match all of its requests on listener `{listener_id}`"
        ),
      ));
    }
    prior_matchers.push((key, id.clone()));
    connect_rules.entry(listener_id).or_default().push(ConnectRulePlan::new(
      id,
      matcher,
      compile_connect_action(raw_rule.action),
    ));
  }

  drafts
    .into_iter()
    .map(|(id, draft)| {
      let listener_http_bindings = http_bindings.remove(&id).unwrap_or_default().into_boxed_slice();
      let plan = match draft.flavor {
        ListenerFlavor::LlmApi => {
          ListenerPlan::LlmApi(LlmApiListenerPlan::new(draft.bind, draft.client_auth).with_cors(draft.cors))
        }
        ListenerFlavor::ForwardProxy => {
          let listener_connect_rules = connect_rules.remove(&id).unwrap_or_default().into_boxed_slice();
          let default_connect_action = draft
            .default_connect_action
            .expect("forward-proxy drafts have a default CONNECT action");
          let needs_tls = default_connect_action == ConnectAction::Intercept
            || listener_connect_rules
              .iter()
              .any(|rule| rule.action() == ConnectAction::Intercept);
          if needs_tls && draft.ca_dir.is_none() {
            return Err(invalid_value(
              format!("listeners.{id}.ca_dir"),
              "ca_dir is required when the listener can intercept CONNECT requests",
            ));
          }
          ListenerPlan::ForwardProxy(
            ForwardProxyListenerPlan::new(
              draft.bind,
              draft.client_auth,
              listener_http_bindings,
              draft
                .default_http_action
                .expect("forward-proxy drafts have a default HTTP action"),
              listener_connect_rules,
              default_connect_action,
              draft.ca_dir.map(TlsPlan::new),
            )
            .with_request_body_max_bytes(
              draft
                .request_body_max_bytes
                .expect("forward-proxy drafts have a request body limit"),
            ),
          )
        }
      };
      Ok((id, plan))
    })
    .collect()
}

fn compile_bind(raw: &str, listener_id: &str) -> Result<SocketAddr, CompileError> {
  let bind = raw.parse::<SocketAddr>().map_err(|_| {
    invalid_value(
      format!("listeners.{listener_id}.bind"),
      "must be a numeric IP socket address such as `127.0.0.1:8080` or `[::1]:8080`",
    )
  })?;
  if bind.port() == 0 {
    return Err(invalid_value(
      format!("listeners.{listener_id}.bind"),
      "port zero is not allowed",
    ));
  }
  Ok(bind)
}

fn bind_addresses_overlap(first: SocketAddr, second: SocketAddr) -> bool {
  first.port() == second.port()
    && (first.ip() == second.ip() || first.ip().is_unspecified() || second.ip().is_unspecified())
}

fn compile_client_auth(raw: RawClientAuth) -> ClientAuthPlan {
  match raw {
    RawClientAuth::None => ClientAuthPlan::None,
    RawClientAuth::LocalKeys => ClientAuthPlan::LocalKeys,
  }
}

fn resolve_ca_dir(raw: Option<&Path>, source: &Path, listener_id: &str) -> Result<Option<PathBuf>, CompileError> {
  let Some(raw) = raw else {
    return Ok(None);
  };
  if raw.as_os_str().is_empty() {
    return Err(invalid_value(
      format!("listeners.{listener_id}.ca_dir"),
      "must not be empty",
    ));
  }
  if raw.is_absolute() {
    Ok(Some(raw.to_path_buf()))
  } else {
    Ok(Some(source.parent().unwrap_or_else(|| Path::new("")).join(raw)))
  }
}

fn claim_binding_id(raw: &str, ids: &mut BTreeSet<BindingId>) -> Result<BindingId, CompileError> {
  let id = parse_id::<BindingId>("binding id", raw)?;
  if !ids.insert(id.clone()) {
    return Err(CompileError::DuplicateId {
      resource: "binding",
      id: raw.to_string(),
    });
  }
  Ok(id)
}

fn resolve_listener(
  raw_listener: &str,
  owner_kind: &'static str,
  owner: &str,
  field: &'static str,
  listeners: &BTreeMap<ListenerId, ListenerDraft>,
) -> Result<ListenerId, CompileError> {
  let listener = parse_id::<ListenerId>("listener reference", raw_listener)?;
  if listeners.contains_key(&listener) {
    Ok(listener)
  } else {
    Err(CompileError::UnresolvedReference {
      owner_kind,
      owner: owner.to_string(),
      field,
      target_kind: "listener",
      target: raw_listener.to_string(),
    })
  }
}

fn compile_http_action(
  raw: &RawBindingAction,
  context: HttpActionContext<'_>,
  profiles: &BTreeMap<ProfileId, ProfilePlan>,
) -> Result<HttpAction, CompileError> {
  let RawBindingAction::Route { profile: raw_profile } = raw else {
    return Ok(HttpAction::Reject);
  };
  let profile_id = parse_id::<ProfileId>("profile reference", raw_profile)?;
  profiles
    .get(&profile_id)
    .ok_or_else(|| CompileError::UnresolvedReference {
      owner_kind: context.owner_kind,
      owner: context.owner.to_string(),
      field: context.reference_field,
      target_kind: "profile",
      target: raw_profile.clone(),
    })?;

  Ok(HttpAction::Route(profile_id))
}

fn compile_http_match(raw: &crate::v2::RawBinding) -> Result<(HttpMatch, HttpMatchKey), CompileError> {
  let hosts_location = format!("bindings.{}.hosts", raw.id);
  let (hosts, mut host_keys) = compile_hosts(&raw.hosts, hosts_location)?;
  let (path_prefixes, mut path_keys) = compile_path_prefixes(&raw.path_prefixes, &raw.id)?;
  let (methods, mut method_keys) = compile_methods(&raw.methods, &raw.id)?;
  let (operations, mut operation_keys) = compile_operations(&raw.operations, &raw.id)?;

  let matcher = HttpMatch::new(
    hosts.into_boxed_slice(),
    path_prefixes.into_iter().map(Into::into).collect(),
    methods.into_iter().map(Into::into).collect(),
    operations.into_boxed_slice(),
  )
  .map_err(|error| invalid_value(format!("bindings.{}", raw.id), error.to_string()))?;

  host_keys.sort_unstable();
  path_keys.sort_unstable();
  method_keys.sort_unstable();
  operation_keys.sort_unstable();
  Ok((
    matcher,
    HttpMatchKey {
      hosts: host_keys,
      path_prefixes: path_keys,
      methods: method_keys,
      operations: operation_keys,
    },
  ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectMatchKey {
  hosts: Vec<HostPattern>,
  ports: Vec<u16>,
}

impl ConnectMatchKey {
  fn subsumes(&self, other: &Self) -> bool {
    dimension_subsumes(&self.hosts, &other.hosts, HostPattern::subsumes)
      && dimension_subsumes(&self.ports, &other.ports, PartialEq::eq)
  }

  fn subsumes_atom(&self, host: Option<&HostPattern>, port: Option<&u16>) -> bool {
    dimension_subsumes_atom(&self.hosts, host, HostPattern::subsumes)
      && dimension_subsumes_atom(&self.ports, port, PartialEq::eq)
  }
}

fn connect_matchers_subsume_union(prior: &[(ConnectMatchKey, BindingId)], matcher: &ConnectMatchKey) -> bool {
  all_atoms(&matcher.hosts, |host| {
    all_atoms(&matcher.ports, |port| {
      prior.iter().any(|(candidate, _)| candidate.subsumes_atom(host, port))
    })
  })
}

fn compile_connect_match(raw: &crate::v2::RawConnectRule) -> Result<(ConnectMatch, ConnectMatchKey), CompileError> {
  let hosts_location = format!("connect_rules.{}.hosts", raw.id);
  let (hosts, mut host_keys) = compile_hosts(&raw.hosts, hosts_location)?;
  let mut ports = Vec::with_capacity(raw.ports.len());
  let mut claimed_ports = BTreeSet::new();
  for port in &raw.ports {
    if *port == 0 {
      return Err(invalid_value(
        format!("connect_rules.{}.ports", raw.id),
        "port zero is not allowed",
      ));
    }
    if !claimed_ports.insert(*port) {
      return Err(duplicate_value(
        format!("connect_rules.{}.ports", raw.id),
        &port.to_string(),
      ));
    }
    ports.push(*port);
  }

  let matcher = ConnectMatch::new(hosts.into_boxed_slice(), ports.clone().into_boxed_slice())
    .map_err(|error| invalid_value(format!("connect_rules.{}", raw.id), error.to_string()))?;
  host_keys.sort_unstable();
  let mut port_keys = ports;
  port_keys.sort_unstable();
  Ok((
    matcher,
    ConnectMatchKey {
      hosts: host_keys,
      ports: port_keys,
    },
  ))
}

fn compile_hosts(raw_hosts: &[String], location: String) -> Result<(Vec<HostPattern>, Vec<HostPattern>), CompileError> {
  let mut patterns = Vec::with_capacity(raw_hosts.len());
  let mut keys = Vec::with_capacity(raw_hosts.len());
  let mut claimed = Vec::<(String, HostPattern)>::new();
  for raw_host in raw_hosts {
    let pattern = compile_host(raw_host, &location)?;
    for (prior_raw, prior) in &claimed {
      if prior == &pattern {
        return Err(duplicate_value(location.clone(), raw_host));
      }
      if prior.subsumes(&pattern) {
        return Err(redundant_value(location.clone(), raw_host, prior_raw));
      }
      if pattern.subsumes(prior) {
        return Err(redundant_value(location.clone(), prior_raw, raw_host));
      }
    }
    claimed.push((raw_host.clone(), pattern.clone()));
    patterns.push(pattern.clone());
    keys.push(pattern);
  }
  Ok((patterns, keys))
}

fn compile_host(raw: &str, location: &str) -> Result<HostPattern, CompileError> {
  if let Some(raw_suffix) = raw.strip_prefix("*.") {
    if raw_suffix.contains('*') {
      return Err(invalid_host(
        location,
        "wildcard is only allowed once as the `*.` prefix",
      ));
    }
    let suffix = CanonicalHost::parse(raw_suffix).map_err(|error| invalid_host(location, error.to_string()))?;
    return HostPattern::subdomains_of(suffix).map_err(|error| invalid_host(location, error.to_string()));
  }
  if raw.contains('*') {
    return Err(invalid_host(
      location,
      "wildcard is only allowed as a `*.` prefix; a lone `*` is not a catch-all",
    ));
  }

  CanonicalHost::parse(raw)
    .map(HostPattern::exact)
    .map_err(|error| invalid_host(location, error.to_string()))
}

fn invalid_host(location: &str, message: impl Into<String>) -> CompileError {
  invalid_value(location.to_string(), message)
}

fn compile_path_prefixes(raw_paths: &[String], binding_id: &str) -> Result<(Vec<String>, Vec<String>), CompileError> {
  let location = format!("bindings.{binding_id}.path_prefixes");
  let mut values = Vec::with_capacity(raw_paths.len());
  let mut claimed = Vec::<(String, String)>::new();
  for raw_path in raw_paths {
    let path = canonical_path_prefix(raw_path, &location)?;
    for (prior_raw, prior) in &claimed {
      if prior == &path {
        return Err(duplicate_value(location.clone(), raw_path));
      }
      if path.starts_with(prior) {
        return Err(redundant_value(location.clone(), raw_path, prior_raw));
      }
      if prior.starts_with(path.as_str()) {
        return Err(redundant_value(location.clone(), prior_raw, raw_path));
      }
    }
    claimed.push((raw_path.clone(), path.clone()));
    values.push(path);
  }
  Ok((values.clone(), values))
}

pub(super) fn canonical_path_prefix(raw: &str, location: &str) -> Result<String, CompileError> {
  if raw.is_empty() || !raw.starts_with('/') {
    return Err(invalid_value(
      location.to_string(),
      "path prefixes must be non-empty and start with `/`",
    ));
  }
  if raw == "/" {
    return Err(invalid_value(
      location.to_string(),
      "`/` matches every path; omit this dimension (and use the listener default action if no constraints remain)",
    ));
  }
  if !raw.is_ascii() {
    return Err(invalid_value(
      location.to_string(),
      "path prefixes must be ASCII URI paths; percent-encode non-ASCII bytes",
    ));
  }

  let bytes = raw.as_bytes();
  let mut canonical = String::with_capacity(raw.len());
  let mut index = 0;
  while index < bytes.len() {
    let byte = bytes[index];
    if byte == b'%' {
      let Some(encoded) = bytes.get(index + 1..index + 3) else {
        return Err(invalid_value(
          location.to_string(),
          "percent escapes in path prefixes must contain exactly two hexadecimal digits",
        ));
      };
      if !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_value(
          location.to_string(),
          "percent escapes in path prefixes must contain exactly two hexadecimal digits",
        ));
      }
      canonical.push('%');
      canonical.push(char::from(encoded[0].to_ascii_uppercase()));
      canonical.push(char::from(encoded[1].to_ascii_uppercase()));
      index += 3;
      continue;
    }
    if byte != b'/' && !is_rfc3986_pchar(byte) {
      return Err(invalid_value(
        location.to_string(),
        "path prefixes may only contain RFC 3986 path characters and percent escapes",
      ));
    }
    canonical.push(char::from(byte));
    index += 1;
  }

  if canonical.split('/').any(is_dot_segment) {
    return Err(invalid_value(
      location.to_string(),
      "path prefixes must not contain literal or percent-encoded `.` or `..` segments",
    ));
  }
  Ok(canonical)
}

fn is_rfc3986_pchar(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&byte)
}

fn is_dot_segment(segment: &str) -> bool {
  let bytes = segment.as_bytes();
  let mut dots = 0;
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'.' {
      dots += 1;
      index += 1;
    } else if bytes.get(index..index + 3) == Some(b"%2E") {
      dots += 1;
      index += 3;
    } else {
      return false;
    }
  }
  matches!(dots, 1 | 2)
}

fn compile_methods(raw_methods: &[String], binding_id: &str) -> Result<(Vec<String>, Vec<String>), CompileError> {
  let location = format!("bindings.{binding_id}.methods");
  let mut values = Vec::with_capacity(raw_methods.len());
  let mut claimed = BTreeSet::new();
  for raw_method in raw_methods {
    if raw_method.is_empty() || !raw_method.bytes().all(is_http_token_byte) {
      return Err(invalid_value(
        location.clone(),
        "methods must be valid non-empty HTTP tokens",
      ));
    }
    if raw_method.contains('*') {
      return Err(invalid_value(
        location.clone(),
        "`*` is not a supported method selector",
      ));
    }
    if raw_method.bytes().any(|byte| byte.is_ascii_lowercase()) {
      return Err(invalid_value(
        location.clone(),
        "methods are case-sensitive and must use canonical uppercase ASCII tokens",
      ));
    }
    if !claimed.insert(raw_method.clone()) {
      return Err(duplicate_value(location.clone(), raw_method));
    }
    values.push(raw_method.clone());
  }
  Ok((values.clone(), values))
}

fn is_http_token_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn compile_operations(
  raw_operations: &[String],
  binding_id: &str,
) -> Result<(Vec<OperationId>, Vec<String>), CompileError> {
  let location = format!("bindings.{binding_id}.operations");
  let mut operations = Vec::with_capacity(raw_operations.len());
  let mut claimed = BTreeSet::new();
  for raw_operation in raw_operations {
    let operation = parse_id::<OperationId>("operation selector", raw_operation)?;
    if !claimed.insert(operation.clone()) {
      return Err(duplicate_value(location.clone(), raw_operation));
    }
    operations.push(operation);
  }
  let keys = operations.iter().map(ToString::to_string).collect();
  Ok((operations, keys))
}

fn compile_connect_action(raw: RawConnectAction) -> ConnectAction {
  match raw {
    RawConnectAction::Intercept => ConnectAction::Intercept,
    RawConnectAction::Tunnel => ConnectAction::Tunnel,
    RawConnectAction::Reject => ConnectAction::Reject,
  }
}

fn parse_id<T>(resource: &'static str, value: &str) -> Result<T, CompileError>
where
  T: TryFrom<String, Error = tokn_policy::InvalidIdentifier>,
{
  T::try_from(value.to_string()).map_err(|source| CompileError::InvalidIdentifier { resource, source })
}

fn invalid_value(location: String, message: impl Into<String>) -> CompileError {
  CompileError::InvalidValue {
    location,
    message: message.into(),
  }
}

fn duplicate_value(location: String, value: &str) -> CompileError {
  invalid_value(
    location,
    format!("contains duplicate value `{value}` after normalization"),
  )
}

fn redundant_value(location: String, redundant: &str, covering: &str) -> CompileError {
  invalid_value(
    location,
    format!("selector `{redundant}` is redundant because `{covering}` already covers it"),
  )
}

#[cfg(test)]
mod tests;
