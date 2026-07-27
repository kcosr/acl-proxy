//! Pure-Rust certificate fixtures shared by product tests.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey as _;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject as _;
use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, ObjectIdentifier};
use x509_cert::der::Encode as _;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const SERVER_AUTH_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const NOT_BEFORE_UNIX_SECONDS: u64 = 1_577_836_800;
const NOT_AFTER_UNIX_SECONDS: u64 = 4_102_444_800;
static NEXT_SERIAL: AtomicU32 = AtomicU32::new(1);

pub(crate) struct TestTlsIdentity {
    root_certificate_der: Vec<u8>,
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_pkcs8_der: Vec<u8>,
}

impl TestTlsIdentity {
    pub(crate) fn new(host: &str) -> Self {
        Self::new_between(
            host,
            UNIX_EPOCH
                .checked_add(Duration::from_secs(NOT_BEFORE_UNIX_SECONDS))
                .expect("test certificate not-before fits SystemTime"),
            UNIX_EPOCH
                .checked_add(Duration::from_secs(NOT_AFTER_UNIX_SECONDS))
                .expect("test certificate not-after fits SystemTime"),
        )
    }

    pub(crate) fn new_expiring_after(host: &str, lifetime: Duration) -> Self {
        let now = SystemTime::now();
        Self::new_between(
            host,
            now.checked_sub(Duration::from_secs(60))
                .expect("short-lived test certificate not-before fits SystemTime"),
            now.checked_add(lifetime)
                .expect("short-lived test certificate not-after fits SystemTime"),
        )
    }

    fn new_between(host: &str, not_before: SystemTime, not_after: SystemTime) -> Self {
        let validity = || Validity {
            not_before: Time::try_from(not_before).expect("encode test certificate not-before"),
            not_after: Time::try_from(not_after).expect("encode test certificate not-after"),
        };
        let root_key = SigningKey::random(&mut OsRng);
        let root_subject = name("acl-proxy test root");
        let root = CertificateBuilder::new(
            Profile::Root,
            next_serial(),
            validity(),
            root_subject.clone(),
            subject_public_key_info(&root_key),
            &root_key,
        )
        .expect("construct test root certificate")
        .build::<DerSignature>()
        .expect("sign test root certificate");
        let root_certificate_der = root.to_der().expect("encode test root certificate");

        let leaf_key = SigningKey::random(&mut OsRng);
        let mut leaf = CertificateBuilder::new(
            Profile::Manual {
                issuer: Some(root_subject),
            },
            next_serial(),
            validity(),
            name(host),
            subject_public_key_info(&leaf_key),
            &root_key,
        )
        .expect("construct test server certificate");
        leaf.add_extension(&BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })
        .expect("add test server basic constraints");
        leaf.add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
            .expect("add test server key usage");
        leaf.add_extension(&ExtendedKeyUsage(vec![SERVER_AUTH_OID]))
            .expect("add test server extended key usage");
        leaf.add_extension(&SubjectAltName(vec![general_name(host)]))
            .expect("add test server subject alternative name");
        let leaf_certificate_der = leaf
            .build::<DerSignature>()
            .expect("sign test server certificate")
            .to_der()
            .expect("encode test server certificate");
        let private_key_pkcs8_der = leaf_key
            .to_pkcs8_der()
            .expect("encode test server private key")
            .as_bytes()
            .to_vec();

        Self {
            root_certificate_der: root_certificate_der.clone(),
            certificate_chain_der: vec![leaf_certificate_der, root_certificate_der],
            private_key_pkcs8_der,
        }
    }

    pub(crate) fn certificate_chain_pem(&self) -> Vec<u8> {
        self.certificate_chain_der
            .iter()
            .flat_map(|certificate| pem("CERTIFICATE", certificate))
            .collect()
    }

    pub(crate) fn private_key_pem(&self) -> Vec<u8> {
        pem("PRIVATE KEY", &self.private_key_pkcs8_der)
    }

    pub(crate) fn root_certificate_pem(&self) -> Vec<u8> {
        pem("CERTIFICATE", &self.root_certificate_der)
    }

    pub(crate) fn root_certificate_der(&self) -> Vec<u8> {
        self.root_certificate_der.clone()
    }

    pub(crate) fn certificate_chain_der(&self) -> Vec<Vec<u8>> {
        self.certificate_chain_der.clone()
    }

    pub(crate) fn private_key_pkcs8_der(&self) -> Vec<u8> {
        self.private_key_pkcs8_der.clone()
    }

    pub(crate) fn server_config(&self, alpn: &[&[u8]]) -> ServerConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("test TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                self.certificate_chain_der
                    .iter()
                    .cloned()
                    .map(CertificateDer::from)
                    .collect(),
                PrivatePkcs8KeyDer::from(self.private_key_pkcs8_der.clone()).into(),
            )
            .expect("test TLS server identity");
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        config
    }

    pub(crate) fn client_config(&self, alpn: &[&[u8]]) -> ClientConfig {
        client_config_for_roots([self.root_certificate_der()], alpn)
    }
}

pub(crate) fn client_config_for_roots(
    certificates: impl IntoIterator<Item = Vec<u8>>,
    alpn: &[&[u8]],
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(CertificateDer::from(certificate))
            .expect("valid test TLS root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

pub(crate) fn client_config_for_pem_roots(pem: &[u8], alpn: &[&[u8]]) -> ClientConfig {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .map(|certificate| {
            certificate
                .expect("valid test TLS root PEM")
                .as_ref()
                .to_vec()
        })
        .collect::<Vec<_>>();
    client_config_for_roots(certificates, alpn)
}

fn name(common_name: &str) -> Name {
    Name::from_str(&format!("CN={common_name}")).expect("test certificate common name is valid")
}

fn subject_public_key_info(signing_key: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key().to_owned())
        .expect("encode test certificate public key")
}

fn general_name(host: &str) -> GeneralName {
    match host.parse::<IpAddr>() {
        Ok(ip) => GeneralName::from(ip),
        Err(_) => GeneralName::DnsName(Ia5String::new(host).expect("test DNS name is IA5")),
    }
}

fn next_serial() -> SerialNumber {
    SerialNumber::from(NEXT_SERIAL.fetch_add(1, Ordering::Relaxed))
}

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        output.push('\n');
    }
    output.push_str("-----END ");
    output.push_str(label);
    output.push_str("-----\n");
    output.into_bytes()
}

#[test]
fn fixture_exposes_matching_pem_der_and_rustls_configs() {
    let identity = TestTlsIdentity::new("localhost");
    assert!(identity
        .certificate_chain_pem()
        .starts_with(b"-----BEGIN CERTIFICATE-----\n"));
    assert!(identity
        .private_key_pem()
        .starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
    assert!(identity
        .root_certificate_pem()
        .starts_with(b"-----BEGIN CERTIFICATE-----\n"));
    assert_eq!(identity.certificate_chain_der().len(), 2);
    assert!(!identity.private_key_pkcs8_der().is_empty());
    assert_eq!(
        identity.server_config(&[b"http/1.1"]).alpn_protocols,
        vec![b"http/1.1".to_vec()]
    );
    assert_eq!(
        identity.client_config(&[b"http/1.1"]).alpn_protocols,
        vec![b"http/1.1".to_vec()]
    );
}
