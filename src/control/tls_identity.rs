use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::{Error as PemError, PemObject as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StaticTlsIdentityError {
    #[error("failed to read certificate chain {path}: {source}")]
    ReadCertificateChain {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("certificate chain {path} must contain valid PEM certificates: {source}")]
    InvalidCertificateChain {
        path: PathBuf,
        #[source]
        source: PemError,
    },

    #[error("certificate chain {path} must contain at least one PEM certificate")]
    EmptyCertificateChain { path: PathBuf },

    #[error("failed to read private key {path}: {source}")]
    ReadPrivateKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("private key {path} must contain valid PEM: {source}")]
    InvalidPrivateKey {
        path: PathBuf,
        #[source]
        source: PemError,
    },

    #[error("private key {path} must contain a supported PKCS8, RSA, or EC PEM private key")]
    UnsupportedPrivateKey { path: PathBuf },

    #[error("certificate chain and private key must form a valid TLS identity: {0}")]
    InvalidIdentity(String),
}

pub(crate) fn load_static_server_config(
    certificate_chain_path: &Path,
    private_key_path: &Path,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, StaticTlsIdentityError> {
    let certificates = load_pem_certificates(certificate_chain_path)?;
    let private_key = load_supported_private_key(private_key_path)?;
    validate_certificate_key_match(&certificates, &private_key)
        .map_err(StaticTlsIdentityError::InvalidIdentity)?;

    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|err| StaticTlsIdentityError::InvalidIdentity(err.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|err| StaticTlsIdentityError::InvalidIdentity(err.to_string()))?;
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

pub(crate) fn load_static_tls_acceptor(
    certificate_chain_path: &Path,
    private_key_path: &Path,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, StaticTlsIdentityError> {
    load_static_server_config(certificate_chain_path, private_key_path, alpn_protocols)
        .map(|config| TlsAcceptor::from(Arc::new(config)))
}

fn load_pem_certificates(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, StaticTlsIdentityError> {
    let file = std::fs::File::open(path).map_err(|source| {
        StaticTlsIdentityError::ReadCertificateChain {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let certificates = CertificateDer::pem_reader_iter(BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| StaticTlsIdentityError::InvalidCertificateChain {
            path: path.to_path_buf(),
            source,
        })?;
    if certificates.is_empty() {
        return Err(StaticTlsIdentityError::EmptyCertificateChain {
            path: path.to_path_buf(),
        });
    }
    Ok(certificates)
}

fn load_supported_private_key(
    path: &Path,
) -> Result<PrivateKeyDer<'static>, StaticTlsIdentityError> {
    let file =
        std::fs::File::open(path).map_err(|source| StaticTlsIdentityError::ReadPrivateKey {
            path: path.to_path_buf(),
            source,
        })?;
    for key in PrivateKeyDer::pem_reader_iter(BufReader::new(file)) {
        let key = key.map_err(|source| StaticTlsIdentityError::InvalidPrivateKey {
            path: path.to_path_buf(),
            source,
        })?;
        if parse_signing_key(&key).is_ok() {
            return Ok(key);
        }
    }
    Err(StaticTlsIdentityError::UnsupportedPrivateKey {
        path: path.to_path_buf(),
    })
}

pub(crate) fn validate_certificate_key_match(
    cert_chain: &[CertificateDer<'static>],
    private_key: &PrivateKeyDer<'_>,
) -> Result<(), String> {
    let mut parsed = cert_chain.iter().enumerate().map(|(index, certificate)| {
        webpki::EndEntityCert::try_from(certificate)
            .map_err(|err| format!("failed to parse certificate {}: {err}", index + 1))
    });
    parsed
        .next()
        .ok_or_else(|| "certificate chain is empty".to_string())??;
    for certificate in parsed {
        certificate?;
    }
    let signing_key =
        parse_signing_key(private_key).map_err(|err| format!("unsupported private key: {err}"))?;
    CertifiedKey::new(cert_chain.to_vec(), signing_key)
        .keys_match()
        .map_err(|_| "certificate public key does not match private key".to_string())
}

fn parse_signing_key(
    private_key: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    rustls::crypto::ring::sign::any_supported_type(private_key)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::test_certificates::TestTlsIdentity;

    fn write_identity(directory: &TempDir, name: &str) -> (PathBuf, PathBuf) {
        let identity = TestTlsIdentity::new("localhost");
        let certificate_path = directory.path().join(format!("{name}-certificate.pem"));
        let private_key_path = directory.path().join(format!("{name}-private-key.pem"));
        crate::filesystem::write_public_file(&certificate_path, identity.certificate_chain_pem())
            .expect("write certificate");
        crate::filesystem::write_private_file(&private_key_path, identity.private_key_pem())
            .expect("write private key");
        (certificate_path, private_key_path)
    }

    #[test]
    fn control_tls_identity_loads_valid_material() {
        let directory = TempDir::new().expect("temporary directory");
        let (certificate_path, private_key_path) = write_identity(&directory, "server");
        let expected_alpn = vec![b"custom/2".to_vec(), b"custom/1".to_vec()];

        let config =
            load_static_server_config(&certificate_path, &private_key_path, expected_alpn.clone())
                .expect("load identity");

        assert_eq!(config.alpn_protocols, expected_alpn);
        load_static_tls_acceptor(&certificate_path, &private_key_path, Vec::new())
            .expect("build TLS acceptor");
    }

    #[test]
    fn control_tls_identity_rejects_missing_and_empty_materials() {
        let directory = TempDir::new().expect("temporary directory");
        let missing = directory.path().join("missing.pem");
        let (_, private_key_path) = write_identity(&directory, "server");
        assert!(matches!(
            load_static_server_config(&missing, &private_key_path, Vec::new()),
            Err(StaticTlsIdentityError::ReadCertificateChain { .. })
        ));

        let (certificate_path, _) = write_identity(&directory, "second-server");
        assert!(matches!(
            load_static_server_config(&certificate_path, &missing, Vec::new()),
            Err(StaticTlsIdentityError::ReadPrivateKey { .. })
        ));

        let empty_key_path = directory.path().join("empty-key.pem");
        crate::filesystem::write_private_file(&empty_key_path, []).expect("write empty key");
        assert!(matches!(
            load_static_server_config(&certificate_path, &empty_key_path, Vec::new()),
            Err(StaticTlsIdentityError::UnsupportedPrivateKey { .. })
        ));

        let empty_certificate_path = directory.path().join("empty-certificate.pem");
        crate::filesystem::write_public_file(&empty_certificate_path, [])
            .expect("write empty certificate");
        assert!(matches!(
            load_static_server_config(&empty_certificate_path, &private_key_path, Vec::new()),
            Err(StaticTlsIdentityError::EmptyCertificateChain { .. })
        ));
    }

    #[test]
    fn control_tls_identity_rejects_malformed_private_key_pem() {
        let directory = TempDir::new().expect("temporary directory");
        let (certificate_path, private_key_path) = write_identity(&directory, "server");
        std::fs::write(
            &private_key_path,
            "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
        )
        .expect("write malformed key");

        assert!(matches!(
            load_static_server_config(&certificate_path, &private_key_path, Vec::new()),
            Err(StaticTlsIdentityError::InvalidPrivateKey { .. })
        ));
    }

    #[test]
    fn control_tls_identity_rejects_malformed_certificate_pem() {
        let directory = TempDir::new().expect("temporary directory");
        let (certificate_path, private_key_path) = write_identity(&directory, "server");
        std::fs::write(
            &certificate_path,
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        )
        .expect("write malformed certificate");

        assert!(matches!(
            load_static_server_config(&certificate_path, &private_key_path, Vec::new()),
            Err(StaticTlsIdentityError::InvalidCertificateChain { .. })
        ));
    }

    #[test]
    fn control_tls_identity_rejects_mismatched_certificate_and_private_key() {
        let directory = TempDir::new().expect("temporary directory");
        let (certificate_path, _) = write_identity(&directory, "first");
        let (_, private_key_path) = write_identity(&directory, "second");

        let error = load_static_server_config(&certificate_path, &private_key_path, Vec::new())
            .expect_err("mismatched identity must fail");
        assert!(matches!(
            error,
            StaticTlsIdentityError::InvalidIdentity(message)
                if message == "certificate public key does not match private key"
        ));
    }
}
