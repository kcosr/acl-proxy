use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};

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
    #[error("TLS client configuration is unavailable")]
    Configuration,
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
) -> Result<ClientConfig, TlsActivationError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsActivationError::Configuration)?;
    let mut config = match trust {
        ClientTrust::Roots(roots) => builder
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
        ClientTrust::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifyServerCert {
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
    };
    config.alpn_protocols = alpn.protocols();
    config.enable_sni = enable_sni;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

fn root_store_with_native_roots(
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<RootCertStore, TlsActivationError> {
    let mut roots = RootCertStore::empty();
    check_activation_cancellation(is_cancelled)?;
    let certificates = rustls_native_certs::load_native_certs();
    check_activation_cancellation(is_cancelled)?;
    if !certificates.errors.is_empty() || certificates.certs.is_empty() {
        return Err(TlsActivationError::NativeRoots);
    }
    for certificate in certificates.certs {
        roots
            .add(certificate)
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
            .add(CertificateDer::from(certificate.clone()))
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
    let certificates =
        CertificateDer::pem_reader_iter(BufReader::new(file)).collect::<Result<Vec<_>, _>>();
    check_activation_cancellation(is_cancelled)?;
    let certificates = certificates.map_err(|_| TlsActivationError::CaInvalid)?;
    if certificates.is_empty() {
        return Err(TlsActivationError::CaEmpty);
    }
    Ok(certificates
        .into_iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect())
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

#[derive(Debug)]
struct NoVerifyServerCert {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoVerifyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
