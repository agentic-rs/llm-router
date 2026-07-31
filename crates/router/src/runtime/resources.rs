//! I/O-backed listener resources materialized before socket startup.
//!
//! Listener policy linking remains pure. This phase opens the shared inbound
//! access store and prepares every proxy CA required by the linked graph, but
//! deliberately does not bind or otherwise inspect listener sockets.

use super::{LinkedListener, LinkedListenerKind, LinkedListeners};
use crate::proxy::{load_or_generate_ca, ProxyCa};
use anyhow::Context;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokn_access::AccessStore;
use tokn_policy::{ClientAuthPlan, ListenerId};

/// Startup-ready listener entries in deterministic listener-id order.
#[derive(Clone, Debug)]
pub struct MaterializedListeners {
  listeners: BTreeMap<ListenerId, MaterializedListener>,
}

impl MaterializedListeners {
  pub fn listener(&self, listener_id: &ListenerId) -> Option<&MaterializedListener> {
    self.listeners.get(listener_id)
  }

  pub fn listeners(&self) -> impl ExactSizeIterator<Item = (&ListenerId, &MaterializedListener)> {
    self.listeners.iter()
  }

  pub fn len(&self) -> usize {
    self.listeners.len()
  }

  pub fn is_empty(&self) -> bool {
    self.listeners.is_empty()
  }
}

/// One linked listener paired with all I/O-backed resources it needs to bind.
#[derive(Clone, Debug)]
pub struct MaterializedListener {
  listener: Arc<LinkedListener>,
  client_auth: MaterializedClientAuth,
  kind: MaterializedListenerKind,
}

impl MaterializedListener {
  pub fn listener(&self) -> &Arc<LinkedListener> {
    &self.listener
  }

  pub fn client_auth(&self) -> &MaterializedClientAuth {
    &self.client_auth
  }

  pub fn kind(&self) -> &MaterializedListenerKind {
    &self.kind
  }
}

/// Runtime client authentication with secret-bearing state kept out of policy.
#[derive(Clone, Debug)]
pub enum MaterializedClientAuth {
  None,
  LocalKeys(Arc<AccessStore>),
}

impl MaterializedClientAuth {
  pub fn access_store(&self) -> Option<&Arc<AccessStore>> {
    match self {
      Self::None => None,
      Self::LocalKeys(store) => Some(store),
    }
  }
}

/// Listener-family-specific startup resources.
#[derive(Clone, Debug)]
pub enum MaterializedListenerKind {
  LlmApi,
  ForwardProxy { ca: Option<Arc<ProxyCa>> },
}

impl MaterializedListenerKind {
  pub fn proxy_ca(&self) -> Option<&Arc<ProxyCa>> {
    match self {
      Self::LlmApi | Self::ForwardProxy { ca: None } => None,
      Self::ForwardProxy { ca: Some(ca) } => Some(ca),
    }
  }
}

/// Open shared listener resources without binding any sockets.
///
/// `local_key_db_path` overrides the conventional access-store path. It is
/// consulted only when at least one linked listener enables local-key auth.
pub fn materialize_listeners(
  linked: &LinkedListeners,
  local_key_db_path: Option<&Path>,
) -> ListenerResourceResult<MaterializedListeners> {
  let access_store = linked
    .listeners()
    .any(|(_, listener)| listener.client_auth() == ClientAuthPlan::LocalKeys)
    .then(|| open_access_store(local_key_db_path))
    .transpose()?;
  let mut proxy_cas = BTreeMap::<PathBuf, Arc<ProxyCa>>::new();
  let mut listeners = BTreeMap::new();

  for (listener_id, listener) in linked.listeners() {
    let client_auth = match listener.client_auth() {
      ClientAuthPlan::None => MaterializedClientAuth::None,
      ClientAuthPlan::LocalKeys => MaterializedClientAuth::LocalKeys(
        access_store
          .as_ref()
          .expect("local-key listeners always materialize one shared access store")
          .clone(),
      ),
    };
    let kind = match listener.linked_kind() {
      LinkedListenerKind::LlmApi => MaterializedListenerKind::LlmApi,
      LinkedListenerKind::ForwardProxy(proxy) => {
        let ca = if proxy.requires_interception() {
          let tls = proxy
            .tls_plan()
            .expect("linked intercepting proxies always have a TLS plan");
          Some(materialize_proxy_ca(listener_id, tls.ca_dir(), &mut proxy_cas)?)
        } else {
          None
        };
        MaterializedListenerKind::ForwardProxy { ca }
      }
    };
    listeners.insert(
      listener_id.clone(),
      MaterializedListener {
        listener: listener.clone(),
        client_auth,
        kind,
      },
    );
  }

  Ok(MaterializedListeners { listeners })
}

fn open_access_store(explicit_path: Option<&Path>) -> ListenerResourceResult<Arc<AccessStore>> {
  match explicit_path {
    Some(path) => AccessStore::open(path)
      .map(Arc::new)
      .map_err(|source| ListenerResourceError::LocalKeyStore {
        path: path.to_path_buf(),
        source,
      }),
    None => AccessStore::open_default()
      .map(Arc::new)
      .map_err(|source| ListenerResourceError::DefaultLocalKeyStore { source }),
  }
}

fn materialize_proxy_ca(
  listener: &ListenerId,
  configured_path: &Path,
  proxy_cas: &mut BTreeMap<PathBuf, Arc<ProxyCa>>,
) -> ListenerResourceResult<Arc<ProxyCa>> {
  let canonical_path = canonicalize_ca_dir(configured_path).map_err(|source| ListenerResourceError::ProxyCa {
    listener: listener.clone(),
    path: configured_path.to_path_buf(),
    source,
  })?;
  if let Some(ca) = proxy_cas.get(&canonical_path) {
    return Ok(ca.clone());
  }

  let ca = Arc::new(
    load_or_generate_ca(&canonical_path, false).map_err(|source| ListenerResourceError::ProxyCa {
      listener: listener.clone(),
      path: configured_path.to_path_buf(),
      source,
    })?,
  );
  proxy_cas.insert(canonical_path, ca.clone());
  Ok(ca)
}

fn canonicalize_ca_dir(path: &Path) -> anyhow::Result<PathBuf> {
  std::fs::create_dir_all(path).with_context(|| format!("create CA directory {}", path.display()))?;
  path
    .canonicalize()
    .with_context(|| format!("canonicalize CA directory {}", path.display()))
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ListenerResourceError {
  #[snafu(display("failed to open local-key store at '{}': {source}", path.display()))]
  LocalKeyStore { path: PathBuf, source: anyhow::Error },

  #[snafu(display("failed to open the default local-key store: {source}"))]
  DefaultLocalKeyStore { source: anyhow::Error },

  #[snafu(display(
    "failed to materialize proxy CA for listener '{listener}' at '{}': {source}",
    path.display()
  ))]
  ProxyCa {
    listener: ListenerId,
    path: PathBuf,
    source: anyhow::Error,
  },
}

pub type ListenerResourceResult<T> = std::result::Result<T, ListenerResourceError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_gateway_runtime, RuntimeNameRegistry};
  use std::collections::BTreeMap;
  use std::net::{Ipv4Addr, SocketAddr, TcpListener};
  use tokn_accounts::registry::Registry;
  use tokn_policy::{
    ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction, ListenerPlan, LlmApiListenerPlan, TlsPlan,
  };

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn bind(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
  }

  fn llm_listener(bind: SocketAddr, client_auth: ClientAuthPlan) -> ListenerPlan {
    ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      bind,
      client_auth,
      Box::default(),
      HttpAction::Reject,
    ))
  }

  fn proxy_listener(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    default_connect_action: ConnectAction,
    tls: Option<TlsPlan>,
  ) -> ListenerPlan {
    ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      bind,
      client_auth,
      Box::default(),
      HttpAction::Reject,
      Box::default(),
      default_connect_action,
      tls,
    ))
  }

  fn linked_listeners(listeners: impl IntoIterator<Item = (&'static str, ListenerPlan)>) -> LinkedListeners {
    let listeners = listeners
      .into_iter()
      .map(|(id, listener)| (listener_id(id), listener))
      .collect();
    let plan = GatewayPlan::new(
      listeners,
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::new())
      .unwrap()
      .listeners()
      .clone()
  }

  #[test]
  fn no_auth_or_interception_creates_no_backing_resources() {
    let temp = tempfile::tempdir().unwrap();
    let access_path = temp.path().join("unused-access.db");
    let ca_path = temp.path().join("unused-ca");
    let listener_key = listener_id("proxy");
    let linked = linked_listeners([(
      "proxy",
      proxy_listener(
        bind(42_001),
        ClientAuthPlan::None,
        ConnectAction::Tunnel,
        Some(TlsPlan::new(ca_path.clone())),
      ),
    )]);

    let materialized = materialize_listeners(&linked, Some(&access_path)).unwrap();
    let listener = materialized.listener(&listener_key).unwrap();

    assert!(Arc::ptr_eq(
      listener.listener(),
      linked.listener(&listener_key).unwrap()
    ));
    assert!(matches!(listener.client_auth(), MaterializedClientAuth::None));
    assert!(matches!(
      listener.kind(),
      MaterializedListenerKind::ForwardProxy { ca: None }
    ));
    assert!(!access_path.exists());
    assert!(!ca_path.exists());
  }

  #[test]
  fn all_local_key_listeners_share_one_access_store() {
    let temp = tempfile::tempdir().unwrap();
    let access_path = temp.path().join("access.db");
    let api_id = listener_id("api");
    let proxy_id = listener_id("proxy");
    let linked = linked_listeners([
      (
        "proxy",
        proxy_listener(bind(42_003), ClientAuthPlan::LocalKeys, ConnectAction::Reject, None),
      ),
      ("api", llm_listener(bind(42_002), ClientAuthPlan::LocalKeys)),
    ]);

    let materialized = materialize_listeners(&linked, Some(&access_path)).unwrap();
    let api = materialized.listener(&api_id).unwrap();
    let proxy = materialized.listener(&proxy_id).unwrap();
    let api_store = api.client_auth().access_store().unwrap();
    let proxy_store = proxy.client_auth().access_store().unwrap();

    assert!(Arc::ptr_eq(api_store, proxy_store));
    assert_eq!(api_store.path(), access_path);
    assert!(access_path.is_file());
    assert!(Arc::ptr_eq(api.listener(), linked.listener(&api_id).unwrap()));
    assert!(Arc::ptr_eq(proxy.listener(), linked.listener(&proxy_id).unwrap()));
    assert_eq!(
      materialized.listeners().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
      ["api", "proxy"]
    );
  }

  #[test]
  fn intercepting_proxies_prepare_and_share_canonical_ca_directories() {
    let temp = tempfile::tempdir().unwrap();
    let alias_parent = temp.path().join("alias-parent");
    std::fs::create_dir(&alias_parent).unwrap();
    let ca_path = temp.path().join("ca");
    let aliased_ca_path = alias_parent.join("..").join("ca");
    let unused_access_path = temp.path().join("unused-access.db");
    let first_id = listener_id("first");
    let second_id = listener_id("second");
    let linked = linked_listeners([
      (
        "second",
        proxy_listener(
          bind(42_005),
          ClientAuthPlan::None,
          ConnectAction::Intercept,
          Some(TlsPlan::new(aliased_ca_path)),
        ),
      ),
      (
        "first",
        proxy_listener(
          bind(42_004),
          ClientAuthPlan::None,
          ConnectAction::Intercept,
          Some(TlsPlan::new(ca_path.clone())),
        ),
      ),
    ]);

    let materialized = materialize_listeners(&linked, Some(&unused_access_path)).unwrap();
    let first = materialized.listener(&first_id).unwrap();
    let second = materialized.listener(&second_id).unwrap();
    let first_ca = first.kind().proxy_ca().unwrap();
    let second_ca = second.kind().proxy_ca().unwrap();

    assert!(Arc::ptr_eq(first_ca, second_ca));
    assert_eq!(first_ca.cert_path().parent().unwrap(), ca_path.canonicalize().unwrap());
    assert!(first_ca.cert_path().is_file());
    assert!(first_ca.key_path().is_file());
    assert!(!unused_access_path.exists());
  }

  #[test]
  fn invalid_ca_path_fails_during_the_pure_pre_bind_phase() {
    let temp = tempfile::tempdir().unwrap();
    let invalid_ca_path = temp.path().join("not-a-directory");
    std::fs::write(&invalid_ca_path, "occupied by a file").unwrap();

    // Holding this socket proves materialization does not try to bind the
    // listener before reporting the CA failure.
    let socket_guard = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listener_bind = socket_guard.local_addr().unwrap();
    let linked = linked_listeners([(
      "proxy",
      proxy_listener(
        listener_bind,
        ClientAuthPlan::None,
        ConnectAction::Intercept,
        Some(TlsPlan::new(invalid_ca_path.clone())),
      ),
    )]);

    let error = materialize_listeners(&linked, None).unwrap_err();

    assert!(matches!(
      error,
      ListenerResourceError::ProxyCa { listener, path, .. }
        if listener.as_str() == "proxy" && path == invalid_ca_path
    ));
    assert_eq!(socket_guard.local_addr().unwrap(), listener_bind);
  }

  #[test]
  fn explicit_local_key_store_errors_retain_the_configured_path() {
    let temp = tempfile::tempdir().unwrap();
    let occupied_parent = temp.path().join("not-a-directory");
    std::fs::write(&occupied_parent, "occupied by a file").unwrap();
    let access_path = occupied_parent.join("access.db");
    let linked = linked_listeners([("api", llm_listener(bind(42_006), ClientAuthPlan::LocalKeys))]);

    let error = materialize_listeners(&linked, Some(&access_path)).unwrap_err();

    assert!(matches!(
      error,
      ListenerResourceError::LocalKeyStore { path, .. } if path == access_path
    ));
  }
}
