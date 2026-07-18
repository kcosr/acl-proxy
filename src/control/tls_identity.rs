use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::{Certificate, PrivateKey, ServerConfig, SignatureScheme};
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
        source: std::io::Error,
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
        source: std::io::Error,
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

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
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

fn load_pem_certificates(path: &Path) -> Result<Vec<Certificate>, StaticTlsIdentityError> {
    let file = std::fs::File::open(path).map_err(|source| {
        StaticTlsIdentityError::ReadCertificateChain {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader).map_err(|source| {
        StaticTlsIdentityError::InvalidCertificateChain {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if certificates.is_empty() {
        return Err(StaticTlsIdentityError::EmptyCertificateChain {
            path: path.to_path_buf(),
        });
    }
    Ok(certificates.into_iter().map(Certificate).collect())
}

fn load_supported_private_key(path: &Path) -> Result<PrivateKey, StaticTlsIdentityError> {
    let file =
        std::fs::File::open(path).map_err(|source| StaticTlsIdentityError::ReadPrivateKey {
            path: path.to_path_buf(),
            source,
        })?;
    let mut reader = BufReader::new(file);
    loop {
        let item = rustls_pemfile::read_one(&mut reader).map_err(|source| {
            StaticTlsIdentityError::InvalidPrivateKey {
                path: path.to_path_buf(),
                source,
            }
        })?;
        let key = match item {
            Some(rustls_pemfile::Item::PKCS8Key(key))
            | Some(rustls_pemfile::Item::RSAKey(key))
            | Some(rustls_pemfile::Item::ECKey(key)) => PrivateKey(key),
            Some(_) => continue,
            None => {
                return Err(StaticTlsIdentityError::UnsupportedPrivateKey {
                    path: path.to_path_buf(),
                })
            }
        };
        if rustls::sign::any_supported_type(&key).is_ok() {
            return Ok(key);
        }
    }
}

pub(crate) fn validate_certificate_key_match(
    cert_chain: &[Certificate],
    private_key: &PrivateKey,
) -> Result<(), String> {
    let mut parsed = cert_chain.iter().enumerate().map(|(index, certificate)| {
        webpki::EndEntityCert::try_from(certificate.0.as_slice())
            .map_err(|err| format!("failed to parse certificate {}: {err}", index + 1))
    });
    let end_entity = parsed
        .next()
        .ok_or_else(|| "certificate chain is empty".to_string())??;
    for certificate in parsed {
        certificate?;
    }
    let signing_key = rustls::sign::any_supported_type(private_key)
        .map_err(|err| format!("unsupported private key: {err}"))?;
    let offered = [
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];
    let signer = signing_key
        .choose_scheme(&offered)
        .ok_or_else(|| "private key has no supported signature scheme".to_string())?;
    let algorithm = match signer.scheme() {
        SignatureScheme::ED25519 => &webpki::ED25519,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &webpki::ECDSA_P256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384 => &webpki::ECDSA_P384_SHA384,
        SignatureScheme::RSA_PSS_SHA256 => &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        SignatureScheme::RSA_PKCS1_SHA256 => &webpki::RSA_PKCS1_2048_8192_SHA256,
        scheme => {
            return Err(format!(
                "unsupported private-key signature scheme {scheme:?}"
            ))
        }
    };

    let challenge = b"acl-proxy static TLS identity key check";
    let signature = signer
        .sign(challenge)
        .map_err(|err| format!("failed to sign key-check challenge: {err}"))?;
    end_entity
        .verify_signature(algorithm, challenge, &signature)
        .map_err(|_| "certificate public key does not match private key".to_string())
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use tempfile::TempDir;

    use super::*;

    fn write_identity(directory: &TempDir, name: &str) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().expect("generate key");
        let certificate = CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params")
            .self_signed(&key)
            .expect("self-signed certificate");
        let certificate_path = directory.path().join(format!("{name}-certificate.pem"));
        let private_key_path = directory.path().join(format!("{name}-private-key.pem"));
        std::fs::write(&certificate_path, certificate.pem()).expect("write certificate");
        std::fs::write(&private_key_path, key.serialize_pem()).expect("write private key");
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
        std::fs::write(&empty_key_path, []).expect("write empty key");
        assert!(matches!(
            load_static_server_config(&certificate_path, &empty_key_path, Vec::new()),
            Err(StaticTlsIdentityError::UnsupportedPrivateKey { .. })
        ));

        let empty_certificate_path = directory.path().join("empty-certificate.pem");
        std::fs::write(&empty_certificate_path, []).expect("write empty certificate");
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
