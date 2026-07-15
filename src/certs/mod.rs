use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use lru::LruCache;
use rcgen::{
    BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DistinguishedName,
    DnType, IsCa, KeyPair,
};
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig};
use sha2::{Digest as _, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::Semaphore;

use crate::config::compiler::StaticMitmConfig;
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

    #[error("failed to manage persisted certificate files in {path}: {source}")]
    ManagePersistedCertificates {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid max_cached_certs ({value}); must be at least 1")]
    InvalidCacheSize { value: usize },

    #[error("certificate activation worker failed")]
    ActivationTask,

    #[error("certificate activation is shutting down")]
    ShuttingDown,

    #[error("CA certificate and private key do not form a valid identity")]
    CaIdentityMismatch,

    #[error("configured signing certificate is not CA-capable")]
    CaCertificateNotCapable,

    #[cfg(unix)]
    #[error("CA private key {path} must not grant group or other permissions")]
    InsecureCaKeyPermissions { path: PathBuf },
}

struct CaMaterial {
    cert: RcgenCertificate,
    key: KeyPair,
    cert_chain_pem: String,
    cert_chain_der: Vec<Vec<u8>>,
}

struct Inner {
    dynamic_dir: PathBuf,
    persist_dynamic_certs: bool,
    ca_cert: RcgenCertificate,
    ca_key: KeyPair,
    ca_cert_chain_pem: String,
    ca_cert_chain_der: Vec<Vec<u8>>,
    #[cfg(test)]
    cache_capacity: NonZeroUsize,
    generation_permits: Arc<Semaphore>,
    activation_open: AtomicBool,
    activation_workers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    server_configs: Mutex<LruCache<ServerConfigCacheKey, Arc<ServerConfig>>>,
    persisted_hosts: Option<Mutex<LruCache<String, ()>>>,
}

#[derive(Clone)]
pub(crate) struct MitmCertificateManager {
    inner: Arc<Inner>,
}

impl MitmCertificateManager {
    pub(crate) fn from_static(config: &StaticMitmConfig) -> Result<Self, CertError> {
        let (directory, ca_material, max_cached_certificates, persist_leaf_certificates) =
            match config {
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
                            let material = load_ca_from_files(&key, &certificate)?;
                            if material.cert_chain_der.len() != 1 {
                                return Err(CertError::ParseCaCert(
                                "generated CA certificate file must contain exactly one certificate"
                                    .to_string(),
                            ));
                            }
                            material
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
        let persisted_hosts = persist_leaf_certificates
            .then(|| load_persisted_hosts(&dynamic_dir, cache_capacity))
            .transpose()?
            .map(Mutex::new);
        Ok(Self {
            inner: Arc::new(Inner {
                dynamic_dir,
                persist_dynamic_certs: persist_leaf_certificates,
                ca_cert: ca_material.cert,
                ca_key: ca_material.key,
                ca_cert_chain_pem: ca_material.cert_chain_pem,
                ca_cert_chain_der: ca_material.cert_chain_der,
                #[cfg(test)]
                cache_capacity,
                generation_permits: Arc::new(Semaphore::new(1)),
                activation_open: AtomicBool::new(true),
                activation_workers: Mutex::new(Vec::new()),
                server_configs: Mutex::new(LruCache::new(cache_capacity)),
                persisted_hosts,
            }),
        })
    }

    pub(crate) async fn server_config_for_host(
        &self,
        host: &str,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<Arc<ServerConfig>, CertError> {
        self.server_config_for_host_with_hook(host, alpn_protocols, || {})
            .await
    }

    async fn server_config_for_host_with_hook<Hook>(
        &self,
        host: &str,
        alpn_protocols: &[Vec<u8>],
        before_generation: Hook,
    ) -> Result<Arc<ServerConfig>, CertError>
    where
        Hook: FnOnce() + Send + 'static,
    {
        if !self.inner.activation_open.load(Ordering::Acquire) {
            return Err(CertError::ShuttingDown);
        }
        let cache_key = ServerConfigCacheKey::new(host, alpn_protocols);
        if let Some(config) = cached_server_config(&self.inner, &cache_key) {
            return Ok(config);
        }

        let generation_permit = self
            .inner
            .generation_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| CertError::ShuttingDown)?;
        if let Some(config) = cached_server_config(&self.inner, &cache_key) {
            return Ok(config);
        }

        let (completed, result) = tokio::sync::oneshot::channel();
        let inner = self.inner.clone();
        {
            let mut workers = self
                .inner
                .activation_workers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !self.inner.activation_open.load(Ordering::Acquire) {
                return Err(CertError::ShuttingDown);
            }
            workers.retain(|worker| !worker.is_finished());
            workers.push(tokio::task::spawn_blocking(move || {
                let _generation_permit = generation_permit;
                before_generation();
                let _ = completed.send(generate_and_cache_server_config(&inner, cache_key));
            }));
        }
        result.await.map_err(|_| CertError::ActivationTask)?
    }

    pub(crate) fn begin_shutdown(&self) {
        if self.inner.activation_open.swap(false, Ordering::AcqRel) {
            self.inner.generation_permits.close();
        }
    }

    pub(crate) async fn shutdown_and_join(&self) {
        self.begin_shutdown();
        let workers = {
            let mut workers = self
                .inner
                .activation_workers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *workers)
        };
        for worker in workers {
            if let Err(error) = worker.await {
                tracing::error!(%error, "certificate activation worker failed during shutdown");
            }
        }
    }

    #[cfg(test)]
    fn cache_capacity(&self) -> usize {
        self.inner.cache_capacity.get()
    }

    #[cfg(test)]
    fn persists_leaf_certificates(&self) -> bool {
        self.inner.persist_dynamic_certs
    }
}

fn validate_ca_identity(material: &CaMaterial) -> Result<(), CertError> {
    let private_key = PrivateKey(material.key.serialize_der());
    crate::tls_identity::validate_certificate_key_match(
        &[RustlsCertificate(material.cert_chain_der[0].clone())],
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

fn cached_server_config(
    inner: &Inner,
    cache_key: &ServerConfigCacheKey,
) -> Option<Arc<ServerConfig>> {
    inner
        .server_configs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(cache_key)
        .cloned()
}

fn generate_and_cache_server_config(
    inner: &Arc<Inner>,
    cache_key: ServerConfigCacheKey,
) -> Result<Arc<ServerConfig>, CertError> {
    let (cert_chain, key) = generate_host_certificate(
        &inner.ca_cert,
        &inner.ca_key,
        &inner.ca_cert_chain_pem,
        &inner.ca_cert_chain_der,
        &inner.dynamic_dir,
        inner.persist_dynamic_certs,
        &cache_key.host,
    )?;

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
    config.alpn_protocols = cache_key.alpn_protocols.to_vec();

    record_persisted_host(inner, &cache_key.host)?;

    let cfg = Arc::new(config);
    let mut cache = inner
        .server_configs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.put(cache_key, cfg.clone());
    Ok(cfg)
}

fn load_persisted_hosts(
    directory: &Path,
    capacity: NonZeroUsize,
) -> Result<LruCache<String, ()>, CertError> {
    const LEAF: u8 = 1;
    const KEY: u8 = 2;
    const CHAIN: u8 = 4;
    const COMPLETE: u8 = LEAF | KEY | CHAIN;

    let mut discovered = BTreeMap::new();
    let entries =
        fs::read_dir(directory).map_err(|source| CertError::ManagePersistedCertificates {
            path: directory.to_path_buf(),
            source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| CertError::ManagePersistedCertificates {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            remove_persisted_file(&path)?;
            continue;
        };
        let Some((key, kind)) = persisted_file_key(name, LEAF, KEY, CHAIN) else {
            remove_persisted_file(&path)?;
            continue;
        };
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let state = discovered
            .entry(key.to_owned())
            .or_insert((std::time::SystemTime::UNIX_EPOCH, 0_u8));
        state.0 = state.0.max(modified);
        state.1 |= kind;
    }

    let mut hosts = Vec::new();
    for (key, (modified, files)) in discovered {
        if files == COMPLETE {
            hosts.push((modified, key));
        } else {
            remove_persisted_key(directory, &key)?;
        }
    }
    hosts.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let mut retained = LruCache::new(capacity);
    for (_, key) in hosts {
        if let Some((evicted, ())) = retained.push(key, ()) {
            remove_persisted_key(directory, &evicted)?;
        }
    }
    Ok(retained)
}

fn persisted_file_key(name: &str, leaf: u8, private_key: u8, chain: u8) -> Option<(&str, u8)> {
    let (opaque_key, kind) = if let Some(opaque_key) = name.strip_suffix(".leaf.crt") {
        (opaque_key, leaf)
    } else if let Some(opaque_key) = name.strip_suffix(".leaf.key") {
        (opaque_key, private_key)
    } else if let Some(opaque_key) = name.strip_suffix(".chain.crt") {
        (opaque_key, chain)
    } else {
        return None;
    };
    (opaque_key.len() == 64
        && opaque_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some((opaque_key, kind))
}

fn record_persisted_host(inner: &Inner, host: &str) -> Result<(), CertError> {
    let Some(hosts) = &inner.persisted_hosts else {
        return Ok(());
    };
    let mut hosts = hosts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let key = persisted_host_key(host);
    if hosts.get(&key).is_some() {
        return Ok(());
    }
    if hosts.len() == hosts.cap().get() {
        let evicted = hosts
            .peek_lru()
            .map(|(host, ())| host.clone())
            .expect("a full persisted-host cache has an LRU entry");
        if let Err(error) = remove_persisted_key(&inner.dynamic_dir, &evicted) {
            let _ = remove_persisted_key(&inner.dynamic_dir, &key);
            return Err(error);
        }
        hosts.pop(&evicted);
    }
    hosts.put(key, ());
    Ok(())
}

fn persisted_host_key(host: &str) -> String {
    format!("{:x}", Sha256::digest(host.as_bytes()))
}

fn persisted_certificate_paths(directory: &Path, host: &str) -> [PathBuf; 3] {
    persisted_certificate_paths_for_key(directory, &persisted_host_key(host))
}

fn persisted_certificate_paths_for_key(directory: &Path, key: &str) -> [PathBuf; 3] {
    [
        directory.join(format!("{key}.leaf.crt")),
        directory.join(format!("{key}.leaf.key")),
        directory.join(format!("{key}.chain.crt")),
    ]
}

fn remove_persisted_key(directory: &Path, key: &str) -> Result<(), CertError> {
    for path in persisted_certificate_paths_for_key(directory, key) {
        remove_persisted_file(&path)?;
    }
    Ok(())
}

fn remove_persisted_file(path: &Path) -> Result<(), CertError> {
    if let Err(source) = fs::remove_file(path) {
        if source.kind() != IoErrorKind::NotFound {
            return Err(CertError::ManagePersistedCertificates {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct ServerConfigCacheKey {
    host: String,
    alpn_protocols: Box<[Vec<u8>]>,
}

impl ServerConfigCacheKey {
    fn new(host: &str, alpn_protocols: &[Vec<u8>]) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            alpn_protocols: alpn_protocols.to_vec().into_boxed_slice(),
        }
    }
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
    let cert_chain_der =
        rustls_pemfile::certs(&mut reader).map_err(|e| CertError::ParseCaCert(format!("{e}")))?;
    let signer_der = if cert_chain_der.is_empty() {
        return Err(CertError::ParseCaCert(
            "expected at least one CA certificate".to_string(),
        ));
    } else {
        &cert_chain_der[0]
    };

    let params = CertificateParams::from_ca_cert_der(&signer_der.as_slice().into())
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;
    if !matches!(params.is_ca, IsCa::Ca(_)) {
        return Err(CertError::CaCertificateNotCapable);
    }
    let ca_cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::ParseCaCert(format!("{e}")))?;
    let cert_chain_pem = cert_chain_der
        .iter()
        .map(|certificate| encode_certificate_pem(certificate))
        .collect();

    Ok(CaMaterial {
        cert: ca_cert,
        key: key_pair,
        cert_chain_pem,
        cert_chain_der,
    })
}

fn encode_certificate_pem(certificate_der: &[u8]) -> String {
    let encoded = BASE64_STANDARD.encode(certificate_der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
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
        cert_chain_pem: cert_pem,
        cert_chain_der: vec![cert_der],
    })
}

fn generate_host_certificate(
    ca_cert: &RcgenCertificate,
    ca_key: &KeyPair,
    ca_cert_chain_pem: &str,
    ca_cert_chain_der: &[Vec<u8>],
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

    let now = OffsetDateTime::now_utc();
    params.not_before = (now - TimeDuration::minutes(5)).max(ca_cert.params().not_before);
    params.not_after =
        (now.max(params.not_before) + TimeDuration::days(30)).min(ca_cert.params().not_after);
    if params.not_after <= params.not_before {
        return Err(CertError::BuildServerConfig(
            "CA validity does not contain a usable leaf-certificate window".to_owned(),
        ));
    }

    let leaf_key = KeyPair::generate().map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;
    let leaf_cert = params
        .signed_by(&leaf_key, ca_cert, ca_key)
        .map_err(|e| CertError::BuildServerConfig(format!("{e}")))?;

    let cert_der: Vec<u8> = leaf_cert.der().to_vec();
    let key_der = leaf_key.serialize_der();

    let leaf = RustlsCertificate(cert_der);

    if persist_dynamic_certs {
        // Optional debug/audit view. Runtime TLS uses the bounded in-memory
        // cache, and these files are not reloaded on startup.
        create_private_dir_all(dynamic_dir).map_err(|source| CertError::CreateDir {
            path: dynamic_dir.to_path_buf(),
            source,
        })?;

        let leaf_pem = leaf_cert.pem();
        let key_pem = leaf_key.serialize_pem();
        let chain_pem = format!("{leaf_pem}{ca_cert_chain_pem}");

        let [leaf_path, key_path, chain_path] = persisted_certificate_paths(dynamic_dir, host);

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

    let mut chain = Vec::with_capacity(ca_cert_chain_der.len() + 1);
    chain.push(leaf);
    chain.extend(ca_cert_chain_der.iter().cloned().map(RustlsCertificate));
    Ok((chain, PrivateKey(key_der)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn strict_generated_mitm_uses_exact_cache_persistence_and_private_storage() {
        let tmp = TempDir::new().expect("tempdir");
        let directory = tmp.path().join("generated");
        let config = StaticMitmConfig::Generated {
            directory: directory.clone(),
            max_cached_certificates: 7,
            persist_leaf_certificates: true,
        };

        let manager = MitmCertificateManager::from_static(&config).expect("strict manager");
        let original_certificate = fs::read(directory.join("ca-cert.pem")).unwrap();
        let original_key = fs::read(directory.join("ca-key.pem")).unwrap();

        assert_eq!(manager.cache_capacity(), 7);
        assert!(manager.persists_leaf_certificates());
        assert!(directory.join("ca-cert.pem").is_file());
        assert!(directory.join("ca-key.pem").is_file());
        let host = "strict.example.test";
        manager
            .server_config_for_host(host, &[b"http/1.1".to_vec()])
            .await
            .expect("host config");
        let dynamic = directory.join("dynamic");
        let [leaf, key, chain] = persisted_certificate_paths(&dynamic, host);
        assert!(leaf.is_file());
        assert!(key.is_file());
        assert!(chain.is_file());
        let mut leaf_reader = Cursor::new(fs::read(&leaf).unwrap());
        let leaf_der = rustls_pemfile::certs(&mut leaf_reader).unwrap().remove(0);
        let leaf_params = CertificateParams::from_ca_cert_der(&leaf_der.as_slice().into()).unwrap();
        let now = OffsetDateTime::now_utc();
        assert!(leaf_params.not_before >= now - TimeDuration::minutes(10));
        assert!(leaf_params.not_before <= now);
        assert!(leaf_params.not_after > now + TimeDuration::days(29));
        assert!(leaf_params.not_after <= now + TimeDuration::days(31));
        #[cfg(unix)]
        {
            assert_eq!(mode(&directory), 0o700);
            assert_eq!(mode(&dynamic), 0o700);
            assert_eq!(mode(&directory.join("ca-cert.pem")), 0o600);
            assert_eq!(mode(&directory.join("ca-key.pem")), 0o600);
            assert_eq!(mode(&leaf), 0o600);
            assert_eq!(mode(&key), 0o600);
            assert_eq!(mode(&chain), 0o600);
        }

        drop(manager);
        MitmCertificateManager::from_static(&config).expect("reuse generated CA");
        assert_eq!(
            fs::read(directory.join("ca-cert.pem")).unwrap(),
            original_certificate
        );
        assert_eq!(
            fs::read(directory.join("ca-key.pem")).unwrap(),
            original_key
        );
    }

    #[tokio::test]
    async fn persisted_dynamic_certificates_are_bounded_across_runtime_and_restart() {
        let tmp = TempDir::new().expect("tempdir");
        let directory = tmp.path().join("generated");
        let config = StaticMitmConfig::Generated {
            directory: directory.clone(),
            max_cached_certificates: 2,
            persist_leaf_certificates: true,
        };
        let manager = MitmCertificateManager::from_static(&config).unwrap();
        for host in [
            "first.example.test",
            "second.example.test",
            "third.example.test",
        ] {
            manager
                .server_config_for_host(host, &[b"http/1.1".to_vec()])
                .await
                .unwrap();
        }
        let dynamic = directory.join("dynamic");
        assert!(persisted_certificate_paths(&dynamic, "first.example.test")
            .iter()
            .all(|path| !path.exists()));
        assert!(persisted_certificate_paths(&dynamic, "second.example.test")
            .iter()
            .all(|path| path.exists()));
        assert!(persisted_certificate_paths(&dynamic, "third.example.test")
            .iter()
            .all(|path| path.exists()));

        drop(manager);
        for path in persisted_certificate_paths(&dynamic, "stale.example.test") {
            fs::write(path, b"stale").unwrap();
        }
        let [partial_leaf, partial_key, partial_chain] =
            persisted_certificate_paths(&dynamic, "partial.example.test");
        fs::write(&partial_leaf, b"partial").unwrap();
        let manager = MitmCertificateManager::from_static(&config).unwrap();
        let entries = fs::read_dir(&dynamic)
            .unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        let leaf_count = entries
            .iter()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".leaf.crt"))
            .count();
        assert_eq!(leaf_count, 2);
        assert_eq!(entries.len(), 6);
        assert!(!partial_leaf.exists());
        assert!(!partial_key.exists());
        assert!(!partial_chain.exists());
        manager.shutdown_and_join().await;
    }

    #[tokio::test]
    async fn persisted_chain_suffix_host_is_counted_and_evictable_after_restart() {
        let tmp = TempDir::new().expect("tempdir");
        let directory = tmp.path().join("generated");
        let dynamic = directory.join("dynamic");
        let config = StaticMitmConfig::Generated {
            directory,
            max_cached_certificates: 1,
            persist_leaf_certificates: true,
        };
        let chain_suffix_host = "reachable.example-chain";
        let manager = MitmCertificateManager::from_static(&config).unwrap();
        manager
            .server_config_for_host(chain_suffix_host, &[b"http/1.1".to_vec()])
            .await
            .unwrap();
        let chain_suffix_paths = persisted_certificate_paths(&dynamic, chain_suffix_host);
        assert!(chain_suffix_paths.iter().all(|path| path.exists()));
        drop(manager);

        let manager = MitmCertificateManager::from_static(&config).unwrap();
        assert!(chain_suffix_paths.iter().all(|path| path.exists()));
        manager
            .server_config_for_host("replacement.example.test", &[b"http/1.1".to_vec()])
            .await
            .unwrap();
        assert!(chain_suffix_paths.iter().all(|path| !path.exists()));
        assert!(
            persisted_certificate_paths(&dynamic, "replacement.example.test")
                .iter()
                .all(|path| path.exists())
        );
        manager.shutdown_and_join().await;
    }

    #[tokio::test]
    async fn strict_files_mitm_uses_exact_material_without_leaf_persistence() {
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
        let mut configured_reader =
            Cursor::new(fs::read(&configured_ca_certificate).expect("read configured certificate"));
        let configured_chain = rustls_pemfile::certs(&mut configured_reader).unwrap();

        assert_eq!(manager.cache_capacity(), 3);
        assert!(!manager.persists_leaf_certificates());
        assert_eq!(manager.inner.ca_cert_chain_der, configured_chain);
        manager
            .server_config_for_host("files.example.test", &[b"http/1.1".to_vec()])
            .await
            .unwrap();
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

        let bundle_path = tmp.path().join("mismatched-bundle.pem");
        fs::write(
            &bundle_path,
            format!(
                "{}{}",
                fs::read_to_string(first.join("ca-cert.pem")).unwrap(),
                fs::read_to_string(second.join("ca-cert.pem")).unwrap(),
            ),
        )
        .unwrap();
        let later_certificate_matches_key = StaticMitmConfig::Files {
            ca_certificate: bundle_path,
            ca_private_key: second.join("ca-key.pem"),
            directory: tmp.path().join("later-match-runtime"),
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };
        assert!(matches!(
            MitmCertificateManager::from_static(&later_certificate_matches_key),
            Err(CertError::CaIdentityMismatch)
        ));
    }

    #[test]
    fn strict_files_mitm_serves_and_persists_the_exact_ordered_ca_chain() {
        let tmp = TempDir::new().expect("tempdir");
        let signer = tmp.path().join("signer");
        let extra = tmp.path().join("extra");
        for directory in [&signer, &extra] {
            MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
                directory: directory.clone(),
                max_cached_certificates: 1,
                persist_leaf_certificates: false,
            })
            .unwrap();
        }
        let bundle_path = tmp.path().join("bundle.pem");
        fs::write(
            &bundle_path,
            format!(
                "{}{}",
                fs::read_to_string(signer.join("ca-cert.pem")).unwrap(),
                fs::read_to_string(extra.join("ca-cert.pem")).unwrap(),
            ),
        )
        .unwrap();
        let runtime = tmp.path().join("runtime");
        let manager = MitmCertificateManager::from_static(&StaticMitmConfig::Files {
            ca_certificate: bundle_path.clone(),
            ca_private_key: signer.join("ca-key.pem"),
            directory: runtime.clone(),
            max_cached_certificates: 2,
            persist_leaf_certificates: true,
        })
        .unwrap();
        let mut bundle_reader = Cursor::new(fs::read(&bundle_path).unwrap());
        let configured_chain = rustls_pemfile::certs(&mut bundle_reader).unwrap();
        assert_eq!(configured_chain.len(), 2);
        assert_eq!(manager.inner.ca_cert_chain_der, configured_chain);

        let host = "chain.example.test";
        let (runtime_chain, _) = generate_host_certificate(
            &manager.inner.ca_cert,
            &manager.inner.ca_key,
            &manager.inner.ca_cert_chain_pem,
            &manager.inner.ca_cert_chain_der,
            &manager.inner.dynamic_dir,
            manager.inner.persist_dynamic_certs,
            host,
        )
        .unwrap();
        assert_eq!(
            runtime_chain[1..]
                .iter()
                .map(|certificate| certificate.0.clone())
                .collect::<Vec<_>>(),
            configured_chain
        );

        let [_, _, chain_path] = persisted_certificate_paths(&runtime.join("dynamic"), host);
        let mut persisted_reader = Cursor::new(fs::read(chain_path).unwrap());
        let persisted_chain = rustls_pemfile::certs(&mut persisted_reader).unwrap();
        assert_eq!(persisted_chain[0], runtime_chain[0].0);
        assert_eq!(persisted_chain[1..], configured_chain);

        let leaf_params =
            CertificateParams::from_ca_cert_der(&runtime_chain[0].0.as_slice().into()).unwrap();
        let now = OffsetDateTime::now_utc();
        assert!(leaf_params.not_before >= manager.inner.ca_cert.params().not_before);
        assert!(leaf_params.not_before >= now - TimeDuration::minutes(10));
        assert!(leaf_params.not_before <= now);
        assert!(leaf_params.not_after <= manager.inner.ca_cert.params().not_after);
        assert!(leaf_params.not_after > now + TimeDuration::days(29));
        assert!(leaf_params.not_after <= now + TimeDuration::days(31));
    }

    #[test]
    fn strict_files_mitm_rejects_non_ca_signing_certificate() {
        let tmp = TempDir::new().expect("tempdir");
        let certificate_path = tmp.path().join("not-ca.pem");
        let key_path = tmp.path().join("not-ca-key.pem");
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["not-ca.example.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        write_private_file(&certificate_path, certificate.pem().as_bytes()).unwrap();
        write_private_file(&key_path, key.serialize_pem().as_bytes()).unwrap();
        let config = StaticMitmConfig::Files {
            ca_certificate: certificate_path,
            ca_private_key: key_path,
            directory: tmp.path().join("runtime"),
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };

        assert!(matches!(
            MitmCertificateManager::from_static(&config),
            Err(CertError::CaCertificateNotCapable)
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
    fn strict_generated_mitm_rejects_a_ca_bundle_on_reuse() {
        let tmp = TempDir::new().expect("tempdir");
        let directory = tmp.path().join("generated");
        let extra = tmp.path().join("extra");
        for path in [&directory, &extra] {
            MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
                directory: path.clone(),
                max_cached_certificates: 1,
                persist_leaf_certificates: false,
            })
            .unwrap();
        }
        let certificate_path = directory.join("ca-cert.pem");
        fs::write(
            &certificate_path,
            format!(
                "{}{}",
                fs::read_to_string(&certificate_path).unwrap(),
                fs::read_to_string(extra.join("ca-cert.pem")).unwrap(),
            ),
        )
        .unwrap();
        let config = StaticMitmConfig::Generated {
            directory,
            max_cached_certificates: 1,
            persist_leaf_certificates: false,
        };

        assert!(matches!(
            MitmCertificateManager::from_static(&config),
            Err(CertError::ParseCaCert(message))
                if message == "generated CA certificate file must contain exactly one certificate"
        ));
    }

    #[tokio::test]
    async fn strict_mitm_preserves_single_and_dual_protocol_alpn_sets() {
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
            .server_config_for_host("alpn.example.test", &single)
            .await
            .unwrap();
        let dual_host = manager
            .server_config_for_host("alpn.example.test", &dual)
            .await
            .unwrap();
        assert_eq!(single_host.alpn_protocols, single);
        assert_eq!(dual_host.alpn_protocols, dual);
        assert!(!Arc::ptr_eq(&single_host, &dual_host));
    }

    #[tokio::test]
    async fn strict_mitm_async_activation_reuses_exact_cache_entry() {
        let tmp = TempDir::new().expect("tempdir");
        let manager = MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
            directory: tmp.path().join("mitm"),
            max_cached_certificates: 4,
            persist_leaf_certificates: false,
        })
        .unwrap();
        let alpn = [b"h2".to_vec(), b"http/1.1".to_vec()];

        let first = manager
            .server_config_for_host("CACHE.EXAMPLE.TEST", &alpn)
            .await
            .unwrap();
        let second = manager
            .server_config_for_host("cache.example.test", &alpn)
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.alpn_protocols, alpn);
    }

    #[tokio::test]
    async fn strict_mitm_activation_wait_is_cancellation_safe() {
        let tmp = TempDir::new().expect("tempdir");
        let manager = MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
            directory: tmp.path().join("mitm"),
            max_cached_certificates: 4,
            persist_leaf_certificates: false,
        })
        .unwrap();
        let held = manager
            .inner
            .generation_permits
            .clone()
            .acquire_owned()
            .await
            .unwrap();

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            manager.server_config_for_host("cancelled.example.test", &[b"http/1.1".to_vec()]),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(manager.inner.server_configs.lock().unwrap().len(), 0);

        drop(held);
        let config = manager
            .server_config_for_host("active.example.test", &[b"http/1.1".to_vec()])
            .await
            .unwrap();
        assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn post_spawn_cancellation_remains_joined_by_manager_shutdown() {
        let tmp = TempDir::new().expect("tempdir");
        let manager = MitmCertificateManager::from_static(&StaticMitmConfig::Generated {
            directory: tmp.path().join("mitm"),
            max_cached_certificates: 4,
            persist_leaf_certificates: false,
        })
        .unwrap();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let activating = manager.clone();
        let activation = tokio::spawn(async move {
            activating
                .server_config_for_host_with_hook(
                    "cancelled.example.test",
                    &[b"http/1.1".to_vec()],
                    move || {
                        let _ = started.send(());
                        release_rx.recv().expect("test releases worker");
                    },
                )
                .await
        });
        started_rx.await.expect("blocking worker started");
        activation.abort();
        assert!(activation.await.unwrap_err().is_cancelled());

        manager.begin_shutdown();
        let draining = manager.clone();
        let mut shutdown = tokio::spawn(async move { draining.shutdown_and_join().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut shutdown)
                .await
                .is_err(),
            "shutdown must wait for the registered blocking worker"
        );
        release.send(()).unwrap();
        shutdown.await.unwrap();

        assert!(manager.inner.activation_workers.lock().unwrap().is_empty());
        assert_eq!(manager.inner.server_configs.lock().unwrap().len(), 1);
        assert!(matches!(
            manager
                .server_config_for_host("later.example.test", &[b"http/1.1".to_vec()])
                .await,
            Err(CertError::ShuttingDown)
        ));
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
