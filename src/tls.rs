use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, Error as RustlsError, RootCertStore, ServerName};

use crate::config::compiler::CompiledTlsTrust;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum TlsActivationError {
    #[error("TLS activation was cancelled")]
    ActivationCancelled,
    #[error("system certificate roots are unavailable")]
    NativeRoots,
    #[error("custom CA certificate bundle is unavailable")]
    CaUnavailable,
    #[error("custom CA certificate bundle is invalid")]
    CaInvalid,
    #[error("custom CA certificate bundle is empty")]
    CaEmpty,
    #[error("custom CA certificate bundle contains an unusable certificate")]
    CaUnusable,
}

#[derive(Clone)]
pub(crate) enum ClientTrust {
    Roots(RootCertStore),
    Insecure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientAlpn {
    Http1,
}

impl ClientAlpn {
    fn protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Http1 => vec![b"http/1.1".to_vec()],
        }
    }
}

pub(crate) fn load_client_trust(
    trust: CompiledTlsTrust,
    ca_certificate: Option<&Path>,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<ClientTrust, TlsActivationError> {
    match trust {
        CompiledTlsTrust::System => {
            root_store_with_native_roots(is_cancelled).map(ClientTrust::Roots)
        }
        CompiledTlsTrust::Custom => {
            let custom_ca_der = load_custom_ca_der(
                ca_certificate.ok_or(TlsActivationError::CaUnavailable)?,
                is_cancelled,
            )?;
            root_store_from_custom_ca(&custom_ca_der).map(ClientTrust::Roots)
        }
        CompiledTlsTrust::SystemPlusCustom => {
            let mut roots = root_store_with_native_roots(is_cancelled)?;
            let custom_ca_der = load_custom_ca_der(
                ca_certificate.ok_or(TlsActivationError::CaUnavailable)?,
                is_cancelled,
            )?;
            add_custom_ca(&mut roots, &custom_ca_der)?;
            Ok(ClientTrust::Roots(roots))
        }
        CompiledTlsTrust::Insecure => Ok(ClientTrust::Insecure),
    }
}

pub(crate) fn build_client_config(
    trust: &ClientTrust,
    alpn: ClientAlpn,
    enable_sni: bool,
) -> ClientConfig {
    let mut config = match trust {
        ClientTrust::Roots(roots) => ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
        ClientTrust::Insecure => {
            let mut config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifyServerCert));
            config
        }
    };
    config.alpn_protocols = alpn.protocols();
    config.enable_sni = enable_sni;
    config
}

fn root_store_with_native_roots(
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<RootCertStore, TlsActivationError> {
    let mut roots = RootCertStore::empty();
    check_activation_cancellation(is_cancelled)?;
    let certificates = rustls_native_certs::load_native_certs();
    check_activation_cancellation(is_cancelled)?;
    let certificates = certificates.map_err(|_| TlsActivationError::NativeRoots)?;
    for certificate in certificates {
        roots
            .add(&Certificate(certificate.0))
            .map_err(|_| TlsActivationError::NativeRoots)?;
    }
    validate_native_root_store(roots)
}

fn validate_native_root_store(roots: RootCertStore) -> Result<RootCertStore, TlsActivationError> {
    if roots.is_empty() {
        Err(TlsActivationError::NativeRoots)
    } else {
        Ok(roots)
    }
}

fn root_store_from_custom_ca(
    certificates: &[Vec<u8>],
) -> Result<RootCertStore, TlsActivationError> {
    let mut roots = RootCertStore::empty();
    add_custom_ca(&mut roots, certificates)?;
    Ok(roots)
}

fn add_custom_ca(
    roots: &mut RootCertStore,
    certificates: &[Vec<u8>],
) -> Result<(), TlsActivationError> {
    for certificate in certificates {
        roots
            .add(&Certificate(certificate.clone()))
            .map_err(|_| TlsActivationError::CaUnusable)?;
    }
    Ok(())
}

pub(crate) fn load_custom_ca_der(
    path: &Path,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<Vec<Vec<u8>>, TlsActivationError> {
    check_activation_cancellation(is_cancelled)?;
    let file = File::open(path);
    check_activation_cancellation(is_cancelled)?;
    let file = file.map_err(|_| TlsActivationError::CaUnavailable)?;
    check_activation_cancellation(is_cancelled)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file));
    check_activation_cancellation(is_cancelled)?;
    let certificates = certificates.map_err(|_| TlsActivationError::CaInvalid)?;
    if certificates.is_empty() {
        return Err(TlsActivationError::CaEmpty);
    }
    Ok(certificates)
}

fn check_activation_cancellation(
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<(), TlsActivationError> {
    if is_cancelled() {
        Err(TlsActivationError::ActivationCancelled)
    } else {
        Ok(())
    }
}

struct NoVerifyServerCert;

impl ServerCertVerifier for NoVerifyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
}
