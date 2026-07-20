use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;

use http_access_runtime::{
    RuntimeError, TlsRootCertificate, TlsRootSet, MAX_TLS_ROOT_CERTIFICATES,
    MAX_TLS_ROOT_CERTIFICATE_BYTES, MAX_TLS_ROOT_SET_BYTES,
};
use http_access_types::PolicyGeneration;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};

use crate::config::compiler::CompiledTlsTrust;

const MAX_CUSTOM_CA_PEM_BYTES: usize = MAX_TLS_ROOT_SET_BYTES * 2 + MAX_TLS_ROOT_CERTIFICATES * 128;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
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
    #[error("custom CA certificate bundle exceeds the shared TLS root limits")]
    CaLimit,
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
    generation: PolicyGeneration,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<ClientTrust, TlsActivationError> {
    match trust {
        CompiledTlsTrust::System => {
            root_store_with_native_roots(is_cancelled).map(ClientTrust::Roots)
        }
        CompiledTlsTrust::Custom => {
            let custom_ca_der = load_bounded_custom_ca(
                ca_certificate.ok_or(TlsActivationError::CaUnavailable)?,
                generation,
                is_cancelled,
            )?;
            root_store_from_custom_ca(&custom_ca_der).map(ClientTrust::Roots)
        }
        CompiledTlsTrust::SystemPlusCustom => {
            let custom_ca_der = load_bounded_custom_ca(
                ca_certificate.ok_or(TlsActivationError::CaUnavailable)?,
                generation,
                is_cancelled,
            )?;
            let mut roots = root_store_with_native_roots(is_cancelled)?;
            add_custom_ca(&mut roots, &custom_ca_der)?;
            Ok(ClientTrust::Roots(roots))
        }
        CompiledTlsTrust::Insecure => Ok(ClientTrust::Insecure),
    }
}

fn load_bounded_custom_ca(
    path: &Path,
    generation: PolicyGeneration,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<Vec<Vec<u8>>, TlsActivationError> {
    let certificates = load_custom_ca_der(path, is_cancelled)?;
    validate_custom_ca_der(generation, &certificates)?;
    Ok(certificates)
}

pub(crate) fn validate_custom_ca_der(
    generation: PolicyGeneration,
    certificates: &[Vec<u8>],
) -> Result<(), TlsActivationError> {
    let certificates = certificates
        .iter()
        .cloned()
        .map(TlsRootCertificate::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_shared_root_error)?;
    TlsRootSet::new(generation, certificates)
        .map(drop)
        .map_err(map_shared_root_error)
}

fn map_shared_root_error(error: RuntimeError) -> TlsActivationError {
    match error {
        RuntimeError::LimitExceeded => TlsActivationError::CaLimit,
        _ => TlsActivationError::CaInvalid,
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
    let mut pem = Vec::new();
    let read_result = file
        .take(
            u64::try_from(MAX_CUSTOM_CA_PEM_BYTES + 1)
                .expect("custom CA PEM byte bound is representable as u64"),
        )
        .read_to_end(&mut pem);
    check_activation_cancellation(is_cancelled)?;
    read_result.map_err(|_| TlsActivationError::CaInvalid)?;
    if pem.len() > MAX_CUSTOM_CA_PEM_BYTES {
        return Err(TlsActivationError::CaLimit);
    }
    let mut certificates = Vec::new();
    let mut total_der_bytes = 0_usize;
    for certificate in CertificateDer::pem_reader_iter(BufReader::new(pem.as_slice())) {
        check_activation_cancellation(is_cancelled)?;
        let certificate = certificate.map_err(|_| TlsActivationError::CaInvalid)?;
        if certificates.len() == MAX_TLS_ROOT_CERTIFICATES
            || certificate.len() > MAX_TLS_ROOT_CERTIFICATE_BYTES
        {
            return Err(TlsActivationError::CaLimit);
        }
        total_der_bytes = total_der_bytes
            .checked_add(certificate.len())
            .ok_or(TlsActivationError::CaLimit)?;
        if total_der_bytes > MAX_TLS_ROOT_SET_BYTES {
            return Err(TlsActivationError::CaLimit);
        }
        certificates.push(certificate.as_ref().to_vec());
    }
    check_activation_cancellation(is_cancelled)?;
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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use tempfile::TempDir;

    use super::*;
    use crate::test_certificates::TestTlsIdentity;

    fn write_bundle(directory: &TempDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = directory.path().join(name);
        crate::filesystem::write_public_file(&path, contents).unwrap();
        path
    }

    fn pem_certificate(der: &[u8]) -> Vec<u8> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n").into_bytes()
    }

    fn trust_error(trust: CompiledTlsTrust, path: &Path) -> TlsActivationError {
        load_client_trust(
            trust,
            Some(path),
            PolicyGeneration::new(7).unwrap(),
            &mut || false,
        )
        .err()
        .expect("invalid custom roots must fail")
    }

    #[test]
    fn valid_custom_bundle_activates_in_both_custom_trust_modes() {
        let directory = TempDir::new().unwrap();
        let identity = TestTlsIdentity::new("bounded-roots.example");
        let path = write_bundle(&directory, "valid.pem", &identity.root_certificate_pem());

        for trust in [CompiledTlsTrust::Custom, CompiledTlsTrust::SystemPlusCustom] {
            let activated = load_client_trust(
                trust,
                Some(&path),
                PolicyGeneration::new(7).unwrap(),
                &mut || false,
            )
            .unwrap();
            let ClientTrust::Roots(roots) = activated else {
                panic!("custom trust modes must activate a root store")
            };
            assert!(!roots.is_empty());
        }
    }

    #[test]
    fn custom_trust_modes_share_duplicate_count_and_byte_bounds() {
        let directory = TempDir::new().unwrap();
        let identity = TestTlsIdentity::new("bounded-roots.example");
        let pem = identity.root_certificate_pem();

        let duplicate = write_bundle(
            &directory,
            "duplicate.pem",
            &[pem.clone(), pem.clone()].concat(),
        );
        let too_many = write_bundle(
            &directory,
            "too-many.pem",
            &pem.repeat(MAX_TLS_ROOT_CERTIFICATES + 1),
        );
        let oversized = write_bundle(
            &directory,
            "oversized.pem",
            &pem_certificate(&vec![0x5a; MAX_TLS_ROOT_CERTIFICATE_BYTES + 1]),
        );
        let aggregate_certificate = pem_certificate(&vec![0x5b; 1024]);
        let repeats = MAX_TLS_ROOT_SET_BYTES / 1024 + 1;
        assert!(repeats <= MAX_TLS_ROOT_CERTIFICATES);
        let aggregate = write_bundle(
            &directory,
            "aggregate.pem",
            &aggregate_certificate.repeat(repeats),
        );
        let oversized_container = write_bundle(
            &directory,
            "oversized-container.pem",
            &vec![b' '; MAX_CUSTOM_CA_PEM_BYTES + 1],
        );

        for trust in [CompiledTlsTrust::Custom, CompiledTlsTrust::SystemPlusCustom] {
            assert_eq!(
                trust_error(trust, &duplicate),
                TlsActivationError::CaInvalid
            );
            assert_eq!(trust_error(trust, &too_many), TlsActivationError::CaLimit);
            assert_eq!(trust_error(trust, &oversized), TlsActivationError::CaLimit);
            assert_eq!(trust_error(trust, &aggregate), TlsActivationError::CaLimit);
            assert_eq!(
                trust_error(trust, &oversized_container),
                TlsActivationError::CaLimit
            );
        }

        for path in [
            &duplicate,
            &too_many,
            &oversized,
            &aggregate,
            &oversized_container,
        ] {
            assert!(!trust_error(CompiledTlsTrust::Custom, path)
                .to_string()
                .contains(path.to_str().unwrap()));
        }
    }

    #[test]
    fn cancellation_precedes_concurrent_read_and_parse_failures() {
        let directory = TempDir::new().unwrap();

        let read_checks = std::cell::Cell::new(0_usize);
        let read_error = load_custom_ca_der(directory.path(), &mut || {
            let next = read_checks.get() + 1;
            read_checks.set(next);
            next == 4
        })
        .expect_err("cancellation must win over a directory read failure");
        assert_eq!(read_error, TlsActivationError::ActivationCancelled);
        assert_eq!(read_checks.get(), 4);

        let malformed = write_bundle(
            &directory,
            "malformed.pem",
            b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n",
        );
        let parse_checks = std::cell::Cell::new(0_usize);
        let parse_error = load_custom_ca_der(&malformed, &mut || {
            let next = parse_checks.get() + 1;
            parse_checks.set(next);
            next == 5
        })
        .expect_err("cancellation must win over a PEM parse failure");
        assert_eq!(parse_error, TlsActivationError::ActivationCancelled);
        assert_eq!(parse_checks.get(), 5);
    }
}
