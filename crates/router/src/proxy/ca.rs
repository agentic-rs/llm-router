use anyhow::{Context, Result};
use parking_lot::Mutex;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokn_policy::CanonicalHost;

const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key";
const CA_BUNDLE_FILE: &str = "ca-bundle.crt";
const LEAF_VALIDITY: TimeDuration = TimeDuration::days(7);
const LEAF_REFRESH_AFTER: TimeDuration = TimeDuration::days(6);
const LEAF_CACHE_CAPACITY: usize = 256;

pub fn load_or_generate_ca(dir: &Path, force_regenerate: bool) -> Result<ProxyCa> {
  std::fs::create_dir_all(dir).with_context(|| format!("create ca dir {}", dir.display()))?;
  let cert_path = dir.join(CA_CERT_FILE);
  let key_path = dir.join(CA_KEY_FILE);

  if force_regenerate || !cert_path.exists() || !key_path.exists() {
    return generate_ca(dir);
  }

  let cert_pem = std::fs::read_to_string(&cert_path).with_context(|| format!("read {}", cert_path.display()))?;
  let key_pem = std::fs::read_to_string(&key_path).with_context(|| format!("read {}", key_path.display()))?;
  let signing_key = KeyPair::from_pem(&key_pem).context("parse CA private key")?;
  let issuer = Issuer::new(ca_params(), signing_key);
  Ok(ProxyCa {
    dir: dir.to_path_buf(),
    cert_pem,
    issuer: Arc::new(issuer),
    cert_cache: Arc::new(Mutex::new(HashMap::new())),
  })
}

fn generate_ca(dir: &Path) -> Result<ProxyCa> {
  let params = ca_params();
  let key = KeyPair::generate().context("generate CA key")?;
  let issuer = CertifiedIssuer::self_signed(params, key).context("generate CA certificate")?;

  let cert_pem = issuer.pem();
  let key_pem = issuer.key().serialize_pem();
  write_ca_file(&dir.join(CA_CERT_FILE), cert_pem.as_bytes(), 0o644)?;
  write_ca_file(&dir.join(CA_KEY_FILE), key_pem.as_bytes(), 0o600)?;

  Ok(ProxyCa {
    dir: dir.to_path_buf(),
    cert_pem,
    issuer: Arc::new(Issuer::new(ca_params(), KeyPair::from_pem(&key_pem)?)),
    cert_cache: Arc::new(Mutex::new(HashMap::new())),
  })
}

fn ca_params() -> CertificateParams {
  let mut params = CertificateParams::default();
  params
    .distinguished_name
    .push(rcgen::DnType::CommonName, "tokn-router local proxy");
  params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
  params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
  params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(3650);
  params.key_usages = vec![
    rcgen::KeyUsagePurpose::KeyCertSign,
    rcgen::KeyUsagePurpose::DigitalSignature,
    rcgen::KeyUsagePurpose::CrlSign,
  ];
  params
}

fn write_ca_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
  std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
      .with_context(|| format!("chmod {}", path.display()))?;
  }
  #[cfg(not(unix))]
  let _ = mode;
  Ok(())
}

#[derive(Clone)]
pub struct ProxyCa {
  dir: PathBuf,
  cert_pem: String,
  issuer: Arc<Issuer<'static, KeyPair>>,
  cert_cache: Arc<Mutex<HashMap<String, CachedCertificate>>>,
}

#[derive(Clone)]
struct CachedCertificate {
  certified_key: Arc<CertifiedKey>,
  refresh_at: OffsetDateTime,
  last_used_at: OffsetDateTime,
}

impl ProxyCa {
  pub fn cert_path(&self) -> PathBuf {
    self.dir.join(CA_CERT_FILE)
  }

  pub fn bundle_path(&self) -> PathBuf {
    self.dir.join(CA_BUNDLE_FILE)
  }

  pub fn key_path(&self) -> PathBuf {
    self.dir.join(CA_KEY_FILE)
  }

  pub fn fingerprint_sha256(&self) -> String {
    let digest = Sha256::digest(self.cert_pem.as_bytes());
    hexify(&digest)
  }

  pub fn ensure_bundle(&self) -> Result<PathBuf> {
    let bundle_path = self.bundle_path();
    let mut bundle = match detect_system_ca_bundle() {
      Some(path) => std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
      None => String::new(),
    };
    if !bundle.is_empty() && !bundle.ends_with('\n') {
      bundle.push('\n');
    }
    if !bundle.contains(&self.cert_pem) {
      bundle.push_str(&self.cert_pem);
      if !bundle.ends_with('\n') {
        bundle.push('\n');
      }
    }
    write_ca_file(&bundle_path, bundle.as_bytes(), 0o644)?;
    Ok(bundle_path)
  }

  /// Build one server configuration whose identity is fixed by CONNECT.
  ///
  /// Certificate selection must never follow an untrusted ClientHello SNI.
  /// Missing SNI is accepted because the certificate remains pinned; a
  /// supplied SNI must name the exact canonical CONNECT host.
  pub(crate) fn pinned_server_config(&self, host: &CanonicalHost) -> Result<Arc<rustls::ServerConfig>> {
    let certified_key = self.certified_key_for(host.as_str())?;
    let resolver = Arc::new(PinnedResolver {
      host: host.clone(),
      certified_key,
    });
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
      .with_safe_default_protocol_versions()
      .context("select safe TLS protocol versions for intercepted connections")?
      .with_no_client_auth()
      .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
  }

  pub(super) fn certified_key_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
    self.certified_key_for_at(host, OffsetDateTime::now_utc())
  }

  fn certified_key_for_at(&self, host: &str, now: OffsetDateTime) -> Result<Arc<CertifiedKey>> {
    {
      let mut cache = self.cert_cache.lock();
      if let Some(existing) = cache.get_mut(host).filter(|cached| now < cached.refresh_at) {
        existing.last_used_at = now;
        return Ok(existing.certified_key.clone());
      }
    }

    let mut params = CertificateParams::new(vec![host.to_string()]).context("build leaf certificate params")?;
    params.distinguished_name.push(rcgen::DnType::CommonName, host);
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + LEAF_VALIDITY;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
      rcgen::KeyUsagePurpose::DigitalSignature,
      rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    let leaf_key = KeyPair::generate().context("generate leaf key")?;
    let cert = params
      .signed_by(&leaf_key, self.issuer.as_ref())
      .context("sign leaf certificate")?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let certified = Arc::new(
      CertifiedKey::from_der(
        vec![cert.der().clone()],
        private_key,
        &rustls::crypto::ring::default_provider(),
      )
      .context("build rustls certified key")?,
    );
    let cached = CachedCertificate {
      certified_key: certified.clone(),
      refresh_at: now + LEAF_REFRESH_AFTER,
      last_used_at: now,
    };
    let mut cache = self.cert_cache.lock();
    if let Some(existing) = cache.get_mut(host).filter(|existing| now < existing.refresh_at) {
      existing.last_used_at = now;
      return Ok(existing.certified_key.clone());
    }
    cache.retain(|_, existing| now < existing.refresh_at);
    if cache.len() >= LEAF_CACHE_CAPACITY {
      let least_recently_used = cache
        .iter()
        .min_by_key(|(_, existing)| existing.last_used_at)
        .map(|(host, _)| host.clone())
        .expect("a full leaf cache always has one entry");
      cache.remove(&least_recently_used);
    }
    cache.insert(host.to_string(), cached);
    Ok(certified)
  }
}

fn detect_system_ca_bundle() -> Option<PathBuf> {
  let env_path = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
  let mut candidates = env_path.into_iter().chain(
    [
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/ssl/ca-bundle.pem",
      "/etc/pki/tls/cacert.pem",
      "/etc/ssl/cert.pem",
    ]
    .into_iter()
    .map(PathBuf::from),
  );
  candidates.find(|path| path.is_file())
}

impl fmt::Debug for ProxyCa {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ProxyCa")
      .field("dir", &self.dir)
      .field("cert_path", &self.cert_path())
      .field("key_path", &self.key_path())
      .field("key_pem", &"***")
      .finish()
  }
}

pub(super) fn hexify(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    use std::fmt::Write as _;
    let _ = write!(out, "{b:02x}");
  }
  out
}

#[derive(Debug)]
struct PinnedResolver {
  host: CanonicalHost,
  certified_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for PinnedResolver {
  fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    server_name_matches(&self.host, client_hello.server_name()).then(|| self.certified_key.clone())
  }
}

fn server_name_matches(expected: &CanonicalHost, server_name: Option<&str>) -> bool {
  let Some(server_name) = server_name else {
    return true;
  };
  CanonicalHost::parse(server_name).is_ok_and(|server_name| &server_name == expected)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cached_leaf_is_refreshed_before_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let ca = load_or_generate_ca(dir.path(), false).unwrap();
    let generated_at = OffsetDateTime::now_utc();

    let initial = ca.certified_key_for_at("example.com", generated_at).unwrap();
    let cached = ca
      .certified_key_for_at(
        "example.com",
        generated_at + LEAF_REFRESH_AFTER - TimeDuration::seconds(1),
      )
      .unwrap();
    let refreshed = ca
      .certified_key_for_at("example.com", generated_at + LEAF_REFRESH_AFTER)
      .unwrap();
    let refreshed_cached = ca
      .certified_key_for_at(
        "example.com",
        generated_at + LEAF_REFRESH_AFTER + TimeDuration::seconds(1),
      )
      .unwrap();

    assert!(Arc::ptr_eq(&initial, &cached));
    assert!(!Arc::ptr_eq(&initial, &refreshed));
    assert!(Arc::ptr_eq(&refreshed, &refreshed_cached));
  }

  #[test]
  fn pinned_identity_accepts_only_the_connect_server_name() {
    let expected = CanonicalHost::parse("api.example.com").unwrap();

    assert!(server_name_matches(&expected, None));
    assert!(server_name_matches(&expected, Some("API.EXAMPLE.COM")));
    assert!(!server_name_matches(&expected, Some("other.example.com")));
    assert!(!server_name_matches(&expected, Some("api.example.com.")));
  }

  #[test]
  fn pinned_server_config_uses_the_connect_identity_and_http1() {
    let dir = tempfile::tempdir().unwrap();
    let ca = load_or_generate_ca(dir.path(), false).unwrap();
    let host = CanonicalHost::parse("api.example.com").unwrap();

    let config = ca.pinned_server_config(&host).unwrap();

    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    assert!(ca.cert_cache.lock().contains_key(host.as_str()));
  }

  #[test]
  fn leaf_cache_evicts_the_least_recently_used_identity() {
    let dir = tempfile::tempdir().unwrap();
    let ca = load_or_generate_ca(dir.path(), false).unwrap();
    let generated_at = OffsetDateTime::now_utc();
    let retained = ca.certified_key_for_at("retained.example", generated_at).unwrap();

    for index in 0..LEAF_CACHE_CAPACITY - 1 {
      ca.certified_key_for_at(
        &format!("host-{index}.example"),
        generated_at + TimeDuration::seconds(index as i64 + 1),
      )
      .unwrap();
    }
    let touched_at = generated_at + TimeDuration::seconds(LEAF_CACHE_CAPACITY as i64);
    assert!(Arc::ptr_eq(
      &retained,
      &ca.certified_key_for_at("retained.example", touched_at).unwrap()
    ));
    ca.certified_key_for_at("overflow.example", touched_at + TimeDuration::seconds(1))
      .unwrap();

    let cache = ca.cert_cache.lock();
    assert_eq!(cache.len(), LEAF_CACHE_CAPACITY);
    assert!(cache.contains_key("retained.example"));
    assert!(!cache.contains_key("host-0.example"));
  }
}
