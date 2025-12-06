use std::fs;
use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lru::LruCache;
use rcgen::{
    BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DistinguishedName,
    DnType, IsCa, KeyPair,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{any_supported_type, CertifiedKey};
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::config::CertificatesConfig;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("failed to create certificates directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read CA key from {path}: {source}")]
    ReadCaKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read CA certificate from {path}: {source}")]
    ReadCaCert {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse CA key: {0}")]
    ParseCaKey(String),

    #[error("failed to parse CA certificate: {0}")]
    ParseCaCert(String),

    #[error("failed to build TLS server config: {0}")]
    BuildServerConfig(String),

    #[error("failed to write certificate file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid max_cached_certs ({value}); must be at least 1")]
    InvalidCacheSize { value: usize },
}

struct Inner {
    ca_cert_path: PathBuf,
    dynamic_dir: PathBuf,
    ca_cert: RcgenCertificate,
    ca_key: KeyPair,
    cache_capacity: NonZeroUsize,
    server_configs: Mutex<LruCache<String, Arc<ServerConfig>>>,
}

#[derive(Clone)]
pub struct CertManager {
    inner: Arc<Inner>,
}

impl CertManager {
    pub fn from_config(cfg: &CertificatesConfig) -> Result<Self, CertError> {
        let certs_dir = PathBuf::from(cfg.certs_dir.trim_or_default());
        let certs_dir = if certs_dir.as_os_str().is_empty() {
            PathBuf::from("certs")
        } else {
            certs_dir
        };

        let (ca_key_path, ca_cert_path) = resolve_ca_paths(
            &certs_dir,
            cfg.ca_key_path.as_deref(),
            cfg.ca_cert_path.as_deref(),
        );

        let explicit_ca_paths = cfg
            .ca_key_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some();

        let dynamic_dir = certs_dir.join("dynamic");

        fs::create_dir_all(&certs_dir).map_err(|source| CertError::CreateDir {
            path: certs_dir.clone(),
            source,
        })?;
        fs::create_dir_all(&dynamic_dir).map_err(|source| CertError::CreateDir {
            path: dynamic_dir.clone(),
            source,
        })?;

        let (ca_cert, ca_key) =
            load_or_generate_ca(&ca_key_path, &ca_cert_path, explicit_ca_paths)?;

        let cache_capacity = NonZeroUsize::new(cfg.max_cached_certs).ok_or(
            CertError::InvalidCacheSize {
                value: cfg.max_cached_certs,
            },
        )?;

        let inner = Inner {
            ca_cert_path,
            dynamic_dir,
            ca_cert,
            ca_key,
            cache_capacity,
            server_configs: Mutex::new(LruCache::new(cache_capacity)),
        };

        Ok(CertManager {
            inner: Arc::new(inner),
        })
    }

    /// Build a `TlsAcceptor` that selects per-host certificates based on SNI.
    ///
    /// This is primarily used for the transparent HTTPS listener, where the
    /// proxy terminates TLS directly from clients and must choose a
    /// certificate matching the requested hostname.
    pub fn tls_acceptor_with_sni(&self) -> Result<TlsAcceptor, CertError> {
        // Seed the config with a placeholder certificate; the dynamic
        // `cert_resolver` below will be responsible for choosing the real
        // certificate based on SNI.
        let (cert_chain, key) = generate_host_certificate(
            &self.inner.ca_cert,
            &self.inner.ca_key,
            &self.inner.ca_cert_path,
            &self.inner.dynamic_dir,
            "default",
        )?;

        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.cert_resolver = Arc::new(SniResolver::new(self.inner.clone()));

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Build a `TlsAcceptor` for the given host, generating and caching a
    /// per-host certificate if needed.
    pub fn tls_acceptor_for_host(&self, host: &str) -> Result<TlsAcceptor, CertError> {
        let config = self.server_config_for_host(host)?;
        Ok(TlsAcceptor::from(config))
    }

    fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, CertError> {
        let host = host.to_ascii_lowercase();
        {
            let mut cache = self.inner.server_configs.lock().unwrap();
            if let Some(cfg) = cache.get(&host) {
                return Ok(cfg.clone());
            }
        }

        let (cert_chain, key) = generate_host_certificate(
            &self.inner.ca_cert,
            &self.inner.ca_key,
            &self.inner.ca_cert_path,
            &self.inner.dynamic_dir,
            &host,
        )?;

        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let cfg = Arc::new(config);
        let mut cache = self.inner.server_configs.lock().unwrap();
        cache.put(host.clone(), cfg.clone());
        Ok(cfg)
    }

    /// Path to the CA certificate on disk.
    pub fn ca_cert_path(&self) -> &Path {
        &self.inner.ca_cert_path
    }
}

struct SniResolver {
    inner: Arc<Inner>,
    keys: Mutex<LruCache<String, Arc<CertifiedKey>>>,
}

impl SniResolver {
    fn new(inner: Arc<Inner>) -> Self {
        let capacity = inner.cache_capacity;
        SniResolver {
            inner,
            keys: Mutex::new(LruCache::new(capacity)),
        }
    }

    fn certified_key_for_host(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.to_ascii_lowercase();
        {
            let mut cache = self.keys.lock().unwrap();
            if let Some(key) = cache.get(&host) {
                return Some(key.clone());
            }
        }

        let (cert_chain, key) = match generate_host_certificate(
            &self.inner.ca_cert,
            &self.inner.ca_key,
            &self.inner.ca_cert_path,
            &self.inner.dynamic_dir,
            &host,
        ) {
            Ok(v) => v,
            Err(err) => {
                tracing::error!("failed to generate certificate for SNI host {host}: {err}");
                return None;
            }
        };

        let signing_key = match any_supported_type(&key) {
            Ok(k) => k,
            Err(err) => {
                tracing::error!("failed to build signing key for SNI host {host}: {err}");
                return None;
            }
        };

        let certified = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        let mut cache = self.keys.lock().unwrap();
        cache.put(host, certified.clone());
        Some(certified)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name()?;
        self.certified_key_for_host(host)
    }
}

fn resolve_ca_paths(
    certs_dir: &Path,
    ca_key_path: Option<&str>,
    ca_cert_path: Option<&str>,
) -> (PathBuf, PathBuf) {
    match (ca_key_path, ca_cert_path) {
        (Some(key), Some(cert)) => (PathBuf::from(key), PathBuf::from(cert)),
        _ => (certs_dir.join("ca-key.pem"), certs_dir.join("ca-cert.pem")),
    }
}

fn load_or_generate_ca(
    ca_key_path: &Path,
    ca_cert_path: &Path,
    explicit: bool,
) -> Result<(RcgenCertificate, KeyPair), CertError> {
    let key_exists = ca_key_path.exists();
    let cert_exists = ca_cert_path.exists();

    if key_exists && cert_exists {
        match load_ca_from_files(ca_key_path, ca_cert_path) {
            Ok(pair) => return Ok(pair),
            Err(err) => {
                if explicit {
                    // When explicit CA paths are configured, treat parse
                    // failures as fatal instead of silently regenerating
                    // a new CA with different bytes.
                    return Err(err);
                }

                // Fall through to regeneration if existing files are invalid
                // for the default auto-generated CA path.
                tracing::warn!(
                    "failed to load existing CA from {} and {}: {err}; regenerating",
                    ca_key_path.display(),
                    ca_cert_path.display()
                );
            }
        }
    } else if explicit {
        // Explicit CA paths were configured but one or both files are missing.
        // Surface this as an error instead of auto-generating a new CA.
        if !key_exists {
            return Err(CertError::ReadCaKey {
                path: ca_key_path.to_path_buf(),
                source: IoError::new(IoErrorKind::NotFound, "CA key path does not exist"),
            });
        }
        if !cert_exists {
            return Err(CertError::ReadCaCert {
                path: ca_cert_path.to_path_buf(),
                source: IoError::new(IoErrorKind::NotFound, "CA certificate path does not exist"),
            });
        }
    }

    generate_ca(ca_key_path, ca_cert_path)
}

fn load_ca_from_files(
    ca_key_path: &Path,
    ca_cert_path: &Path,
) -> Result<(RcgenCertificate, KeyPair), CertError> {
    let key_pem = fs::read_to_string(ca_key_path).map_err(|source| CertError::ReadCaKey {
        path: ca_key_path.to_path_buf(),
        source,
    })?;
    let cert_pem = fs::read_to_string(ca_cert_path).map_err(|source| CertError::ReadCaCert {
        path: ca_cert_path.to_path_buf(),
        source,
    })?;

    let key_pair =
        KeyPair::from_pem(&key_pem).map_err(|e| CertError::ParseCaKey(format!("{e}")))?;

    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;
    let ca_cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;

    Ok((ca_cert, key_pair))
}

fn generate_ca(
    ca_key_path: &Path,
    ca_cert_path: &Path,
) -> Result<(RcgenCertificate, KeyPair), CertError> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "acl-proxy CA");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate().map_err(|e| CertError::ParseCaKey(format!("{e}")))?;
    let ca_cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;

    let cert_pem = ca_cert.pem();
    let key_pem = key_pair.serialize_pem();

    if let Some(parent) = ca_cert_path.parent() {
        fs::create_dir_all(parent).map_err(|source| CertError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    fs::write(ca_cert_path, cert_pem.as_bytes()).map_err(|source| CertError::WriteFile {
        path: ca_cert_path.to_path_buf(),
        source,
    })?;
    fs::write(ca_key_path, key_pem.as_bytes()).map_err(|source| CertError::WriteFile {
        path: ca_key_path.to_path_buf(),
        source,
    })?;

    Ok((ca_cert, key_pair))
}

fn generate_host_certificate(
    ca_cert: &RcgenCertificate,
    ca_key: &KeyPair,
    ca_cert_path: &Path,
    dynamic_dir: &Path,
    host: &str,
) -> Result<(Vec<RustlsCertificate>, PrivateKey), CertError> {
    let mut params = CertificateParams::new(vec![host.to_string()])
        .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn
    };

    // Validity window – not critical for tests, but keep reasonable.
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2030, 1, 1);

    let leaf_key = KeyPair::generate().map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
    let leaf_cert = params
        .signed_by(&leaf_key, ca_cert, ca_key)
        .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;

    let cert_der: Vec<u8> = leaf_cert.der().to_vec();
    let key_der = leaf_key.serialize_der();

    let leaf = RustlsCertificate(cert_der);
    let ca_pem = fs::read_to_string(ca_cert_path).map_err(|source| CertError::ReadCaCert {
        path: ca_cert_path.to_path_buf(),
        source,
    })?;

    let mut reader = Cursor::new(ca_pem.as_bytes());
    let ca_der = rustls_pemfile::certs(&mut reader)
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?
        .into_iter()
        .next()
        .ok_or_else(|| CertError::ParseCaCert("no CA certificate found in PEM".to_string()))?;
    let ca_cert_rls = RustlsCertificate(ca_der);

    // Persist PEM files on disk for transparency and debugging.
    //
    // The active certificates used for TLS handshakes are generated on
    // demand from the in-memory CA and cached in this process; the
    // per-host PEM files under `certs/dynamic/` are not currently
    // reloaded on startup and should be treated as an audit/debug view,
    // not as the authoritative runtime cache.
    fs::create_dir_all(dynamic_dir).map_err(|source| CertError::CreateDir {
        path: dynamic_dir.to_path_buf(),
        source,
    })?;

    let leaf_pem = leaf_cert.pem();
    let key_pem = leaf_key.serialize_pem();
    let chain_pem = format!("{leaf_pem}{ca_pem}");

    let leaf_path = dynamic_dir.join(format!("{host}.crt"));
    let key_path = dynamic_dir.join(format!("{host}.key"));
    let chain_path = dynamic_dir.join(format!("{host}-chain.crt"));

    fs::write(&leaf_path, leaf_pem.as_bytes()).map_err(|source| CertError::WriteFile {
        path: leaf_path,
        source,
    })?;
    fs::write(&key_path, key_pem.as_bytes()).map_err(|source| CertError::WriteFile {
        path: key_path,
        source,
    })?;
    fs::write(&chain_path, chain_pem.as_bytes()).map_err(|source| CertError::WriteFile {
        path: chain_path,
        source,
    })?;

    Ok((vec![leaf, ca_cert_rls], PrivateKey(key_der)))
}

trait TrimOrDefault {
    fn trim_or_default(&self) -> &str;
}

impl TrimOrDefault for String {
    fn trim_or_default(&self) -> &str {
        let s = self.trim();
        if s.is_empty() {
            ""
        } else {
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CertificatesConfig;
    use tempfile::TempDir;

    #[test]
    fn ca_is_generated_and_reused_in_tempdir() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let mut cfg = CertificatesConfig::default();
        cfg.certs_dir = certs_dir.to_string_lossy().to_string();

        let mgr1 = CertManager::from_config(&cfg).expect("first cert manager");
        let ca_cert_path = mgr1.ca_cert_path().to_path_buf();
        assert!(ca_cert_path.exists());

        // Second manager should reuse existing CA.
        let mgr2 = CertManager::from_config(&cfg).expect("second cert manager");
        assert_eq!(
            mgr2.ca_cert_path().to_string_lossy(),
            ca_cert_path.to_string_lossy()
        );
    }

    #[test]
    fn dynamic_certificates_are_created_for_hosts() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let mut cfg = CertificatesConfig::default();
        cfg.certs_dir = certs_dir.to_string_lossy().to_string();

        let mgr = CertManager::from_config(&cfg).expect("cert manager");

        let host = "example.com";
        let _acceptor = mgr.tls_acceptor_for_host(host).expect("tls acceptor");

        let dynamic_dir = certs_dir.join("dynamic");
        let leaf = dynamic_dir.join(format!("{host}.crt"));
        let key = dynamic_dir.join(format!("{host}.key"));
        let chain = dynamic_dir.join(format!("{host}-chain.crt"));

        assert!(leaf.exists(), "leaf cert should exist");
        assert!(key.exists(), "key should exist");
        assert!(chain.exists(), "chain cert should exist");
    }

    #[test]
    fn server_config_cache_uses_lru_eviction() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let mut cfg = CertificatesConfig::default();
        cfg.certs_dir = certs_dir.to_string_lossy().to_string();
        cfg.max_cached_certs = 1;

        let mgr = CertManager::from_config(&cfg).expect("cert manager");

        // With capacity 1, caching behavior should:
        // - Cache host1.
        // - Evict host1 when host2 is inserted.
        // - Regenerate host1 when requested again.
        let host1 = "one.example.com";
        let host2 = "two.example.com";

        let cfg1 = mgr.server_config_for_host(host1).expect("cfg1");
        let cfg1_again = mgr.server_config_for_host(host1).expect("cfg1 again");
        assert!(
            std::sync::Arc::ptr_eq(&cfg1, &cfg1_again),
            "host1 should be cached on repeated access"
        );

        let cfg2 = mgr.server_config_for_host(host2).expect("cfg2");
        assert!(
            !std::sync::Arc::ptr_eq(&cfg1, &cfg2),
            "different hosts should have different configs"
        );

        let cfg1_new = mgr.server_config_for_host(host1).expect("cfg1 new");
        assert!(
            !std::sync::Arc::ptr_eq(&cfg1, &cfg1_new),
            "host1 should be regenerated after eviction when capacity is 1"
        );
    }

    #[test]
    fn configured_ca_cert_bytes_are_used_in_chain() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");
        fs::create_dir_all(&certs_dir).expect("create certs dir");

        let ca_key_path = certs_dir.join("custom-ca-key.pem");
        let ca_cert_path = certs_dir.join("custom-ca-cert.pem");

        // Pre-generate a CA on disk so that `from_config` takes the
        // "existing CA" path instead of generating a new one.
        generate_ca(&ca_key_path, &ca_cert_path).expect("generate ca");
        let ca_cert_pem = fs::read_to_string(&ca_cert_path).expect("read ca cert");

        let mut cfg = CertificatesConfig::default();
        cfg.certs_dir = certs_dir.to_string_lossy().to_string();
        cfg.ca_key_path = Some(ca_key_path.to_string_lossy().to_string());
        cfg.ca_cert_path = Some(ca_cert_path.to_string_lossy().to_string());

        let mgr = CertManager::from_config(&cfg).expect("cert manager");

        let host = "example.com";
        let _acceptor = mgr.tls_acceptor_for_host(host).expect("tls acceptor");

        let dynamic_dir = certs_dir.join("dynamic");
        let chain = dynamic_dir.join(format!("{host}-chain.crt"));
        assert!(chain.exists(), "chain cert should exist");

        let chain_pem = fs::read_to_string(chain).expect("read chain pem");
        assert!(
            chain_pem.ends_with(&ca_cert_pem),
            "host chain should end with the configured CA cert PEM",
        );
    }

    #[test]
    fn explicit_ca_paths_missing_files_error() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let mut cfg = CertificatesConfig::default();
        cfg.certs_dir = certs_dir.to_string_lossy().to_string();
        cfg.ca_key_path = Some(
            certs_dir
                .join("nonexistent-ca-key.pem")
                .to_string_lossy()
                .to_string(),
        );
        cfg.ca_cert_path = Some(
            certs_dir
                .join("nonexistent-ca-cert.pem")
                .to_string_lossy()
                .to_string(),
        );

        let err = CertManager::from_config(&cfg)
            .err()
            .expect("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to read CA key")
                || msg.contains("failed to read CA certificate")
                || msg.contains("failed to parse CA"),
            "expected error about explicit CA paths, got: {msg}"
        );
    }
}
