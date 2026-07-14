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
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::config::compiler::StaticMitmConfig;
use crate::config::CertificatesConfig;
use crate::filesystem::{create_private_dir_all, write_private_file};

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

    #[error("certificate generation is already in progress")]
    GenerationBusy,

    #[error("CA certificate and private key do not form a valid identity")]
    CaIdentityMismatch,

    #[cfg(unix)]
    #[error("CA private key {path} must not grant group or other permissions")]
    InsecureCaKeyPermissions { path: PathBuf },
}

struct CaMaterial {
    cert: RcgenCertificate,
    key: KeyPair,
    cert_pem: String,
    cert_der: Vec<u8>,
}

struct Inner {
    ca_cert_path: PathBuf,
    dynamic_dir: PathBuf,
    persist_dynamic_certs: bool,
    ca_cert: RcgenCertificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
    ca_cert_der: Vec<u8>,
    cache_capacity: NonZeroUsize,
    generation_permits: Semaphore,
    server_configs: Mutex<LruCache<ServerConfigCacheKey, Arc<ServerConfig>>>,
    sni_acceptor: Mutex<Option<TlsAcceptor>>,
}

#[derive(Clone)]
pub struct CertManager {
    inner: Arc<Inner>,
}

#[derive(Clone)]
pub(crate) struct MitmCertificateManager {
    inner: Arc<Inner>,
}

impl MitmCertificateManager {
    pub(crate) fn from_static(config: &StaticMitmConfig) -> Result<Self, CertError> {
        let (
            directory,
            ca_cert_path,
            ca_material,
            max_cached_certificates,
            persist_leaf_certificates,
        ) = match config {
            StaticMitmConfig::Generated {
                directory,
                max_cached_certificates,
                persist_leaf_certificates,
            } => {
                create_private_dir_all(directory).map_err(|source| CertError::CreateDir {
                    path: directory.clone(),
                    source,
                })?;
                let key = directory.join("ca-key.pem");
                let certificate = directory.join("ca-cert.pem");
                let material = match (key.exists(), certificate.exists()) {
                    (false, false) => generate_ca(&key, &certificate)?,
                    (true, true) => {
                        validate_private_key_permissions(&key)?;
                        load_ca_from_files(&key, &certificate)?
                    }
                    (false, true) => {
                        return Err(CertError::ReadCaKey {
                            path: key,
                            source: IoError::new(
                                IoErrorKind::NotFound,
                                "generated CA private key is missing",
                            ),
                        })
                    }
                    (true, false) => {
                        return Err(CertError::ReadCaCert {
                            path: certificate,
                            source: IoError::new(
                                IoErrorKind::NotFound,
                                "generated CA certificate is missing",
                            ),
                        })
                    }
                };
                (
                    directory.clone(),
                    certificate,
                    material,
                    *max_cached_certificates,
                    *persist_leaf_certificates,
                )
            }
            StaticMitmConfig::Files {
                ca_certificate,
                ca_private_key,
                directory,
                max_cached_certificates,
                persist_leaf_certificates,
            } => {
                create_private_dir_all(directory).map_err(|source| CertError::CreateDir {
                    path: directory.clone(),
                    source,
                })?;
                validate_private_key_permissions(ca_private_key)?;
                (
                    directory.clone(),
                    ca_certificate.clone(),
                    load_ca_from_files(ca_private_key, ca_certificate)?,
                    *max_cached_certificates,
                    *persist_leaf_certificates,
                )
            }
        };
        validate_ca_identity(&ca_material)?;
        let cache_capacity =
            NonZeroUsize::new(max_cached_certificates).ok_or(CertError::InvalidCacheSize {
                value: max_cached_certificates,
            })?;
        let dynamic_dir = directory.join("dynamic");
        if persist_leaf_certificates {
            create_private_dir_all(&dynamic_dir).map_err(|source| CertError::CreateDir {
                path: dynamic_dir.clone(),
                source,
            })?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                ca_cert_path,
                dynamic_dir,
                persist_dynamic_certs: persist_leaf_certificates,
                ca_cert: ca_material.cert,
                ca_key: ca_material.key,
                ca_cert_pem: ca_material.cert_pem,
                ca_cert_der: ca_material.cert_der,
                cache_capacity,
                generation_permits: Semaphore::new(1),
                server_configs: Mutex::new(LruCache::new(cache_capacity)),
                sni_acceptor: Mutex::new(None),
            }),
        })
    }

    pub(crate) fn tls_acceptor_with_sni(
        &self,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<TlsAcceptor, CertError> {
        build_sni_acceptor(&self.inner, alpn_protocols.to_vec())
    }

    pub(crate) fn tls_acceptor_for_host(
        &self,
        host: &str,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<TlsAcceptor, CertError> {
        tls_acceptor_for_host(&self.inner, host, alpn_protocols)
    }

    #[cfg(test)]
    fn cache_capacity(&self) -> usize {
        self.inner.cache_capacity.get()
    }

    #[cfg(test)]
    fn persists_leaf_certificates(&self) -> bool {
        self.inner.persist_dynamic_certs
    }

    #[cfg(test)]
    fn server_config_for_host_for_test(
        &self,
        host: &str,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<Arc<ServerConfig>, CertError> {
        server_config_for_host(&self.inner, host, alpn_protocols)
    }

    #[cfg(test)]
    fn sni_server_config_for_test(
        &self,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<ServerConfig, CertError> {
        build_sni_server_config(&self.inner, alpn_protocols.to_vec())
    }
}

fn validate_ca_identity(material: &CaMaterial) -> Result<(), CertError> {
    let private_key = PrivateKey(material.key.serialize_der());
    crate::tls_identity::validate_certificate_key_match(
        &[RustlsCertificate(material.cert_der.clone())],
        &private_key,
    )
    .map_err(|_| CertError::CaIdentityMismatch)
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<(), CertError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| CertError::ReadCaKey {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CertError::InsecureCaKeyPermissions {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(path: &Path) -> Result<(), CertError> {
    fs::metadata(path)
        .map(|_| ())
        .map_err(|source| CertError::ReadCaKey {
            path: path.to_path_buf(),
            source,
        })
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

        create_private_dir_all(&certs_dir).map_err(|source| CertError::CreateDir {
            path: certs_dir.clone(),
            source,
        })?;
        if cfg.persist_dynamic_certs {
            create_private_dir_all(&dynamic_dir).map_err(|source| CertError::CreateDir {
                path: dynamic_dir.clone(),
                source,
            })?;
        }

        let ca_material = load_or_generate_ca(&ca_key_path, &ca_cert_path, explicit_ca_paths)?;

        let cache_capacity =
            NonZeroUsize::new(cfg.max_cached_certs).ok_or(CertError::InvalidCacheSize {
                value: cfg.max_cached_certs,
            })?;

        let inner = Inner {
            ca_cert_path,
            dynamic_dir,
            persist_dynamic_certs: cfg.persist_dynamic_certs,
            ca_cert: ca_material.cert,
            ca_key: ca_material.key,
            ca_cert_pem: ca_material.cert_pem,
            ca_cert_der: ca_material.cert_der,
            cache_capacity,
            generation_permits: Semaphore::new(1),
            server_configs: Mutex::new(LruCache::new(cache_capacity)),
            sni_acceptor: Mutex::new(None),
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
        tls_acceptor_with_sni(&self.inner)
    }

    /// Build a `TlsAcceptor` for the given host, generating and caching a
    /// per-host certificate if needed.
    pub fn tls_acceptor_for_host(&self, host: &str) -> Result<TlsAcceptor, CertError> {
        tls_acceptor_for_host(&self.inner, host, &[b"http/1.1".to_vec()])
    }

    fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, CertError> {
        server_config_for_host(&self.inner, host, &[b"http/1.1".to_vec()])
    }

    /// Path to the CA certificate on disk.
    pub fn ca_cert_path(&self) -> &Path {
        &self.inner.ca_cert_path
    }
}

fn tls_acceptor_with_sni(inner: &Arc<Inner>) -> Result<TlsAcceptor, CertError> {
    {
        let guard = inner.sni_acceptor.lock().unwrap();
        if let Some(acceptor) = guard.as_ref() {
            return Ok(acceptor.clone());
        }
    }
    let acceptor = build_sni_acceptor(inner, vec![b"h2".to_vec(), b"http/1.1".to_vec()])?;
    let mut guard = inner.sni_acceptor.lock().unwrap();
    if let Some(existing) = guard.as_ref() {
        return Ok(existing.clone());
    }
    *guard = Some(acceptor.clone());
    Ok(acceptor)
}

fn build_sni_acceptor(
    inner: &Arc<Inner>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, CertError> {
    build_sni_server_config(inner, alpn_protocols).map(|config| TlsAcceptor::from(Arc::new(config)))
}

fn build_sni_server_config(
    inner: &Arc<Inner>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, CertError> {
    let (cert_chain, key) = generate_host_certificate(
        &inner.ca_cert,
        &inner.ca_key,
        &inner.ca_cert_pem,
        &inner.ca_cert_der,
        &inner.dynamic_dir,
        inner.persist_dynamic_certs,
        "default",
    )?;
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
    config.alpn_protocols = alpn_protocols;
    config.cert_resolver = Arc::new(SniResolver::new(inner.clone()));
    Ok(config)
}

fn tls_acceptor_for_host(
    inner: &Arc<Inner>,
    host: &str,
    alpn_protocols: &[Vec<u8>],
) -> Result<TlsAcceptor, CertError> {
    server_config_for_host(inner, host, alpn_protocols).map(TlsAcceptor::from)
}

fn server_config_for_host(
    inner: &Arc<Inner>,
    host: &str,
    alpn_protocols: &[Vec<u8>],
) -> Result<Arc<ServerConfig>, CertError> {
    let cache_key = ServerConfigCacheKey {
        host: host.to_ascii_lowercase(),
        alpn_protocols: alpn_protocols.to_vec().into_boxed_slice(),
    };
    {
        let mut cache = inner.server_configs.lock().unwrap();
        if let Some(cfg) = cache.get(&cache_key) {
            return Ok(cfg.clone());
        }
    }

    let _generation_permit = inner
        .generation_permits
        .try_acquire()
        .map_err(|_| CertError::GenerationBusy)?;

    {
        let mut cache = inner.server_configs.lock().unwrap();
        if let Some(cfg) = cache.get(&cache_key) {
            return Ok(cfg.clone());
        }
    }

    let (cert_chain, key) = generate_host_certificate(
        &inner.ca_cert,
        &inner.ca_key,
        &inner.ca_cert_pem,
        &inner.ca_cert_der,
        &inner.dynamic_dir,
        inner.persist_dynamic_certs,
        &cache_key.host,
    )?;

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
    config.alpn_protocols = alpn_protocols.to_vec();

    let cfg = Arc::new(config);
    let mut cache = inner.server_configs.lock().unwrap();
    cache.put(cache_key, cfg.clone());
    Ok(cfg)
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct ServerConfigCacheKey {
    host: String,
    alpn_protocols: Box<[Vec<u8>]>,
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
            &self.inner.ca_cert_pem,
            &self.inner.ca_cert_der,
            &self.inner.dynamic_dir,
            self.inner.persist_dynamic_certs,
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
) -> Result<CaMaterial, CertError> {
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

fn load_ca_from_files(ca_key_path: &Path, ca_cert_path: &Path) -> Result<CaMaterial, CertError> {
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

    let mut reader = Cursor::new(cert_pem.as_bytes());
    let mut certs =
        rustls_pemfile::certs(&mut reader).map_err(|e| CertError::ParseCaCert(format!("{e}")))?;
    let cert_der = if certs.is_empty() {
        return Err(CertError::ParseCaCert(
            "expected at least one CA certificate".to_string(),
        ));
    } else {
        certs.remove(0)
    };

    let params = CertificateParams::from_ca_cert_der(&cert_der.as_slice().into())
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;
    let ca_cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;

    Ok(CaMaterial {
        cert: ca_cert,
        key: key_pair,
        cert_pem,
        cert_der,
    })
}

fn generate_ca(ca_key_path: &Path, ca_cert_path: &Path) -> Result<CaMaterial, CertError> {
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
        create_private_dir_all(parent).map_err(|source| CertError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    write_private_file(ca_cert_path, cert_pem.as_bytes()).map_err(|source| {
        CertError::WriteFile {
            path: ca_cert_path.to_path_buf(),
            source,
        }
    })?;
    write_private_file(ca_key_path, key_pem.as_bytes()).map_err(|source| CertError::WriteFile {
        path: ca_key_path.to_path_buf(),
        source,
    })?;

    let cert_der = ca_cert.der().to_vec();

    Ok(CaMaterial {
        cert: ca_cert,
        key: key_pair,
        cert_pem,
        cert_der,
    })
}

fn generate_host_certificate(
    ca_cert: &RcgenCertificate,
    ca_key: &KeyPair,
    ca_cert_pem: &str,
    ca_cert_der: &[u8],
    dynamic_dir: &Path,
    persist_dynamic_certs: bool,
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
    let ca_cert_rls = RustlsCertificate(ca_cert_der.to_vec());

    if persist_dynamic_certs {
        // Optional debug/audit view. Runtime TLS uses the bounded in-memory
        // cache, and these files are not reloaded on startup.
        create_private_dir_all(dynamic_dir).map_err(|source| CertError::CreateDir {
            path: dynamic_dir.to_path_buf(),
            source,
        })?;

        let leaf_pem = leaf_cert.pem();
        let key_pem = leaf_key.serialize_pem();
        let chain_pem = format!("{leaf_pem}{ca_cert_pem}");

        let leaf_path = dynamic_dir.join(format!("{host}.crt"));
        let key_path = dynamic_dir.join(format!("{host}.key"));
        let chain_path = dynamic_dir.join(format!("{host}-chain.crt"));

        write_private_file(&leaf_path, leaf_pem.as_bytes()).map_err(|source| {
            CertError::WriteFile {
                path: leaf_path,
                source,
            }
        })?;
        write_private_file(&key_path, key_pem.as_bytes()).map_err(|source| {
            CertError::WriteFile {
                path: key_path,
                source,
            }
        })?;
        write_private_file(&chain_path, chain_pem.as_bytes()).map_err(|source| {
            CertError::WriteFile {
                path: chain_path,
                source,
            }
        })?;
    }

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

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn ca_is_generated_and_reused_in_tempdir() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            ..CertificatesConfig::default()
        };

        let mgr1 = CertManager::from_config(&cfg).expect("first cert manager");
        let ca_cert_path = mgr1.ca_cert_path().to_path_buf();
        assert!(ca_cert_path.exists());

        #[cfg(unix)]
        {
            assert_eq!(mode(&certs_dir), 0o700);
            assert_eq!(mode(&certs_dir.join("ca-key.pem")), 0o600);
            assert_eq!(mode(&ca_cert_path), 0o600);
        }

        // Second manager should reuse existing CA.
        let mgr2 = CertManager::from_config(&cfg).expect("second cert manager");
        assert_eq!(
            mgr2.ca_cert_path().to_string_lossy(),
            ca_cert_path.to_string_lossy()
        );
    }

    #[test]
    fn dynamic_certificates_stay_in_memory_by_default() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            ..CertificatesConfig::default()
        };

        let mgr = CertManager::from_config(&cfg).expect("cert manager");

        let host = "example.com";
        let _acceptor = mgr.tls_acceptor_for_host(host).expect("tls acceptor");

        let dynamic_dir = certs_dir.join("dynamic");
        assert!(
            !dynamic_dir.exists(),
            "dynamic cert directory should not be created by default"
        );
    }

    #[test]
    fn dynamic_certificates_are_persisted_when_enabled() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            persist_dynamic_certs: true,
            ..CertificatesConfig::default()
        };

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

        #[cfg(unix)]
        {
            assert_eq!(mode(&dynamic_dir), 0o700);
            assert_eq!(mode(&leaf), 0o600);
            assert_eq!(mode(&key), 0o600);
            assert_eq!(mode(&chain), 0o600);
        }
    }

    #[test]
    fn host_generation_uses_in_memory_ca_after_startup() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            persist_dynamic_certs: true,
            ..CertificatesConfig::default()
        };

        let mgr = CertManager::from_config(&cfg).expect("cert manager");
        fs::remove_file(mgr.ca_cert_path()).expect("remove ca cert after startup");

        let host = "example.com";
        let _acceptor = mgr
            .tls_acceptor_for_host(host)
            .expect("host cert should use in-memory CA");

        let chain = certs_dir.join("dynamic").join(format!("{host}-chain.crt"));
        assert!(chain.exists(), "chain cert should still be persisted");
        let chain_pem = fs::read_to_string(chain).expect("read chain pem");
        assert!(
            chain_pem.contains("-----BEGIN CERTIFICATE-----"),
            "chain should contain PEM certificates"
        );
    }

    #[test]
    fn sni_acceptor_reuses_default_placeholder_certificate() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            persist_dynamic_certs: true,
            ..CertificatesConfig::default()
        };

        let mgr = CertManager::from_config(&cfg).expect("cert manager");
        let _first = mgr.tls_acceptor_with_sni().expect("first acceptor");

        let default_key = certs_dir.join("dynamic").join("default.key");
        let first_key_pem = fs::read_to_string(&default_key).expect("read first default key");

        let _second = mgr.tls_acceptor_with_sni().expect("second acceptor");
        let second_key_pem = fs::read_to_string(default_key).expect("read second default key");

        assert_eq!(
            first_key_pem, second_key_pem,
            "cached SNI acceptor should not regenerate the default placeholder key"
        );
    }

    #[test]
    fn server_config_cache_uses_lru_eviction() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            max_cached_certs: 1,
            ..CertificatesConfig::default()
        };

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
    fn uncached_host_generation_fails_fast_when_generation_is_busy() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            ..CertificatesConfig::default()
        };

        let mgr = CertManager::from_config(&cfg).expect("cert manager");
        let cached_host = "cached.example.com";
        let cached_config = mgr
            .server_config_for_host(cached_host)
            .expect("prime cached host");

        let _permit = mgr
            .inner
            .generation_permits
            .try_acquire()
            .expect("hold generation permit");

        let cached_again = mgr
            .server_config_for_host(cached_host)
            .expect("cached host should not need generation permit");
        assert!(
            Arc::ptr_eq(&cached_config, &cached_again),
            "cached host should reuse existing server config"
        );

        let err = mgr
            .server_config_for_host("uncached.example.com")
            .expect_err("uncached host should fail while generation is busy");
        assert!(
            matches!(err, CertError::GenerationBusy),
            "unexpected error: {err}"
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

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            ca_key_path: Some(ca_key_path.to_string_lossy().to_string()),
            ca_cert_path: Some(ca_cert_path.to_string_lossy().to_string()),
            persist_dynamic_certs: true,
            ..CertificatesConfig::default()
        };

        let mgr = CertManager::from_config(&cfg).expect("cert manager");

        let host = "example.com";
        let _acceptor = mgr.tls_acceptor_for_host(host).expect("tls acceptor");

        let dynamic_dir = certs_dir.join("dynamic");
        let chain = dynamic_dir.join(format!("{host}-chain.crt"));
        assert!(chain.exists(), "chain cert should exist");

        let chain_pem = fs::read_to_string(chain).expect("read chain pem");
        let mut ca_reader = std::io::Cursor::new(ca_cert_pem.as_bytes());
        let ca_certs = rustls_pemfile::certs(&mut ca_reader).expect("parse ca cert");
        let ca_cert = ca_certs.last().expect("ca cert");

        let mut chain_reader = std::io::Cursor::new(chain_pem.as_bytes());
        let chain_certs = rustls_pemfile::certs(&mut chain_reader).expect("parse chain certs");
        assert!(
            chain_certs.last() == Some(ca_cert),
            "host chain should end with the configured CA cert",
        );
    }

    #[test]
    fn configured_ca_bundle_uses_first_certificate() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");
        fs::create_dir_all(&certs_dir).expect("create certs dir");

        let ca_key_path = certs_dir.join("custom-ca-key.pem");
        let ca_cert_path = certs_dir.join("custom-ca-cert.pem");
        let extra_key_path = certs_dir.join("extra-ca-key.pem");
        let extra_cert_path = certs_dir.join("extra-ca-cert.pem");

        generate_ca(&ca_key_path, &ca_cert_path).expect("generate ca");
        generate_ca(&extra_key_path, &extra_cert_path).expect("generate extra ca");
        let extra_cert_pem = fs::read_to_string(&extra_cert_path).expect("read extra cert");
        fs::write(
            &ca_cert_path,
            format!(
                "{}{}",
                fs::read_to_string(&ca_cert_path).expect("read ca cert"),
                extra_cert_pem
            ),
        )
        .expect("write bundle");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            ca_key_path: Some(ca_key_path.to_string_lossy().to_string()),
            ca_cert_path: Some(ca_cert_path.to_string_lossy().to_string()),
            ..CertificatesConfig::default()
        };

        let mut reader =
            std::io::Cursor::new(fs::read_to_string(&ca_cert_path).expect("read bundle"));
        let bundle_certs = rustls_pemfile::certs(&mut reader).expect("parse bundle");
        assert_eq!(bundle_certs.len(), 2);

        let mgr = CertManager::from_config(&cfg).expect("cert manager");

        assert_eq!(mgr.inner.ca_cert_der, bundle_certs[0]);
    }

    #[test]
    fn explicit_ca_paths_missing_files_error() {
        let tmp = TempDir::new().expect("tempdir");
        let certs_dir = tmp.path().join("certs");

        let cfg = CertificatesConfig {
            certs_dir: certs_dir.to_string_lossy().to_string(),
            ca_key_path: Some(
                certs_dir
                    .join("nonexistent-ca-key.pem")
                    .to_string_lossy()
                    .to_string(),
            ),
            ca_cert_path: Some(
                certs_dir
                    .join("nonexistent-ca-cert.pem")
                    .to_string_lossy()
                    .to_string(),
            ),
            ..CertificatesConfig::default()
        };

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

    #[test]
    fn strict_generated_mitm_uses_exact_cache_persistence_and_private_storage() {
        let tmp = TempDir::new().expect("tempdir");
        let directory = tmp.path().join("generated");
        let config = StaticMitmConfig::Generated {
            directory: directory.clone(),
            max_cached_certificates: 7,
            persist_leaf_certificates: true,
        };

        let manager = MitmCertificateManager::from_static(&config).expect("strict manager");

        assert_eq!(manager.cache_capacity(), 7);
        assert!(manager.persists_leaf_certificates());
        assert!(directory.join("ca-cert.pem").is_file());
        assert!(directory.join("ca-key.pem").is_file());
        manager
            .tls_acceptor_for_host("strict.example.test", &[b"http/1.1".to_vec()])
            .expect("host acceptor");
        assert!(directory.join("dynamic/strict.example.test.key").is_file());
        #[cfg(unix)]
        {
            assert_eq!(mode(&directory), 0o700);
            assert_eq!(mode(&directory.join("dynamic")), 0o700);
            assert_eq!(mode(&directory.join("ca-key.pem")), 0o600);
        }
    }

    #[test]
    fn strict_files_mitm_uses_exact_material_without_leaf_persistence() {
        let tmp = TempDir::new().expect("tempdir");
        let source = tmp.path().join("source");
        let generated = StaticMitmConfig::Generated {
            directory: source.clone(),
            max_cached_certificates: 2,
            persist_leaf_certificates: false,
        };
        MitmCertificateManager::from_static(&generated).expect("source CA");
        let directory = tmp.path().join("files-runtime");
        let configured_ca_certificate = source.join("ca-cert.pem");
        let files = StaticMitmConfig::Files {
            ca_certificate: configured_ca_certificate.clone(),
            ca_private_key: source.join("ca-key.pem"),
            directory: directory.clone(),
            max_cached_certificates: 3,
            persist_leaf_certificates: false,
        };

        let manager = MitmCertificateManager::from_static(&files).expect("file manager");

        assert_eq!(manager.cache_capacity(), 3);
        assert!(!manager.persists_leaf_certificates());
        assert_eq!(manager.inner.ca_cert_path, configured_ca_certificate);
        manager
            .tls_acceptor_with_sni(&[b"h2".to_vec()])
            .expect("transparent acceptor");
        assert!(!directory.join("dynamic").exists());
        #[cfg(unix)]
        assert_eq!(mode(&directory), 0o700);
    }

    #[test]
    fn strict_files_mitm_rejects_missing_and_mismatched_material() {
        let tmp = TempDir::new().expect("tempdir");
        let missing = StaticMitmConfig::Files {
            ca_certificate: tmp.path().join("missing-cert.pem"),
            ca_private_key: tmp.path().join("missing-key.pem"),
            directory: tmp.path().join("runtime"),
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };
        assert!(matches!(
            MitmCertificateManager::from_static(&missing),
            Err(CertError::ReadCaKey { .. })
        ));

        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        for directory in [&first, &second] {
            MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
                directory: directory.clone(),
                max_cached_certificates: 1,
                persist_leaf_certificates: false,
            })
            .expect("generate CA");
        }
        let mismatched = StaticMitmConfig::Files {
            ca_certificate: first.join("ca-cert.pem"),
            ca_private_key: second.join("ca-key.pem"),
            directory: tmp.path().join("mismatched-runtime"),
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };
        assert!(matches!(
            MitmCertificateManager::from_static(&mismatched),
            Err(CertError::CaIdentityMismatch)
        ));
    }

    #[test]
    fn strict_generated_mitm_rejects_partial_existing_ca_state() {
        let tmp = TempDir::new().expect("tempdir");
        let directory = tmp.path().join("partial");
        create_private_dir_all(&directory).unwrap();
        write_private_file(&directory.join("ca-cert.pem"), b"not-used").unwrap();
        let config = StaticMitmConfig::Generated {
            directory,
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };

        assert!(matches!(
            MitmCertificateManager::from_static(&config),
            Err(CertError::ReadCaKey { .. })
        ));
    }

    #[test]
    fn strict_mitm_preserves_single_and_dual_protocol_alpn_sets() {
        let tmp = TempDir::new().expect("tempdir");
        let manager = MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
            directory: tmp.path().join("mitm"),
            max_cached_certificates: 4,
            persist_leaf_certificates: false,
        })
        .unwrap();
        let single = vec![b"http/1.1".to_vec()];
        let dual = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let single_host = manager
            .server_config_for_host_for_test("alpn.example.test", &single)
            .unwrap();
        let dual_host = manager
            .server_config_for_host_for_test("alpn.example.test", &dual)
            .unwrap();
        assert_eq!(single_host.alpn_protocols, single);
        assert_eq!(dual_host.alpn_protocols, dual);
        assert!(!Arc::ptr_eq(&single_host, &dual_host));

        let single_sni = manager.sni_server_config_for_test(&single).unwrap();
        let dual_sni = manager.sni_server_config_for_test(&dual).unwrap();
        assert_eq!(single_sni.alpn_protocols, single);
        assert_eq!(dual_sni.alpn_protocols, dual);
    }

    #[cfg(unix)]
    #[test]
    fn strict_files_mitm_rejects_group_readable_private_key() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("tempdir");
        let source = tmp.path().join("source");
        MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
            directory: source.clone(),
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        })
        .expect("generate CA");
        let key = source.join("ca-key.pem");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        let config = StaticMitmConfig::Files {
            ca_certificate: source.join("ca-cert.pem"),
            ca_private_key: key,
            directory: tmp.path().join("runtime"),
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };

        assert!(matches!(
            MitmCertificateManager::from_static(&config),
            Err(CertError::InsecureCaKeyPermissions { .. })
        ));
    }
}
