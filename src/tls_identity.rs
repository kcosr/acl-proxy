use rustls::{Certificate, PrivateKey, SignatureScheme};

pub(crate) fn validate_certificate_key_match(
    cert_chain: &[Certificate],
    private_key: &PrivateKey,
) -> Result<(), String> {
    let certificate = cert_chain
        .first()
        .ok_or_else(|| "certificate chain is empty".to_string())?;
    let end_entity = webpki::EndEntityCert::try_from(certificate.0.as_slice())
        .map_err(|err| format!("failed to parse end-entity certificate: {err}"))?;
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
