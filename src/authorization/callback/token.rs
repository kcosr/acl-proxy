use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(super) const RESUME_TOKEN_RANDOM_BYTES: usize = 32;
pub(crate) const RESUME_TOKEN_ENCODED_BYTES: usize = 43;

pub(crate) struct ResumeToken {
    encoded: Zeroizing<[u8; RESUME_TOKEN_ENCODED_BYTES]>,
    #[cfg(test)]
    drop_observer: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ResumeToken {
    pub(crate) fn as_bytes(&self) -> &[u8; RESUME_TOKEN_ENCODED_BYTES] {
        &self.encoded
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("base64url output is ASCII")
    }

    pub(crate) fn digest(&self) -> ResumeTokenDigest {
        ResumeTokenDigest::from_encoded(self.as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn from_encoded_for_test(encoded: [u8; RESUME_TOKEN_ENCODED_BYTES]) -> Self {
        Self {
            encoded: Zeroizing::new(encoded),
            drop_observer: None,
        }
    }

    #[cfg(test)]
    fn with_drop_observer(
        encoded: [u8; RESUME_TOKEN_ENCODED_BYTES],
        observer: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            encoded: Zeroizing::new(encoded),
            drop_observer: Some(observer),
        }
    }
}

impl fmt::Debug for ResumeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResumeToken([REDACTED])")
    }
}

impl Drop for ResumeToken {
    fn drop(&mut self) {
        self.encoded.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.store(
                self.encoded.iter().all(|byte| *byte == 0),
                std::sync::atomic::Ordering::Release,
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ResumeTokenDigest([u8; 32]);

impl ResumeTokenDigest {
    pub(crate) fn from_encoded(encoded: &[u8; RESUME_TOKEN_ENCODED_BYTES]) -> Self {
        Self(Sha256::digest(encoded).into())
    }
}

impl fmt::Debug for ResumeTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResumeTokenDigest([REDACTED])")
    }
}

pub(super) trait ResumeTokenSource {
    fn fill(&mut self, bytes: &mut [u8; RESUME_TOKEN_RANDOM_BYTES]) -> Result<(), ()>;
}

pub(super) struct OsResumeTokenSource;

impl ResumeTokenSource for OsResumeTokenSource {
    fn fill(&mut self, bytes: &mut [u8; RESUME_TOKEN_RANDOM_BYTES]) -> Result<(), ()> {
        OsRng.try_fill_bytes(bytes).map_err(|_| ())
    }
}

pub(super) fn generate_resume_token(
    source: &mut impl ResumeTokenSource,
) -> Result<ResumeToken, ()> {
    let mut random = Zeroizing::new([0u8; RESUME_TOKEN_RANDOM_BYTES]);
    source.fill(&mut random)?;
    let mut encoded = Zeroizing::new([0u8; RESUME_TOKEN_ENCODED_BYTES]);
    let encoded_len = URL_SAFE_NO_PAD
        .encode_slice(&random[..], &mut encoded[..])
        .expect("43 bytes hold the unpadded encoding of 32 bytes");
    debug_assert_eq!(encoded_len, RESUME_TOKEN_ENCODED_BYTES);
    Ok(ResumeToken {
        encoded,
        #[cfg(test)]
        drop_observer: None,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;

    struct FixedSource([u8; RESUME_TOKEN_RANDOM_BYTES]);

    impl ResumeTokenSource for FixedSource {
        fn fill(&mut self, bytes: &mut [u8; RESUME_TOKEN_RANDOM_BYTES]) -> Result<(), ()> {
            *bytes = self.0;
            Ok(())
        }
    }

    #[test]
    fn resume_token_is_exact_base64url_without_padding_and_digest_is_encoded_wire_digest() {
        let token = generate_resume_token(&mut FixedSource([0xff; 32])).unwrap();
        assert_eq!(token.as_bytes().len(), RESUME_TOKEN_ENCODED_BYTES);
        assert_eq!(
            token.as_str(),
            "__________________________________________8"
        );
        assert!(!token.as_str().contains('='));
        assert_eq!(
            token.digest(),
            ResumeTokenDigest::from_encoded(token.as_bytes())
        );
        assert_eq!(
            token.digest().0,
            <[u8; 32]>::from(Sha256::digest(token.as_bytes()))
        );
    }

    #[test]
    fn resume_token_debug_and_drop_do_not_disclose_or_retain_wire_value() {
        let encoded = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let observer = Arc::new(AtomicBool::new(false));
        let token = ResumeToken::with_drop_observer(encoded, observer.clone());
        let debug = format!("{token:?}");
        assert!(!debug.contains("AAAA"));
        drop(token);
        assert!(observer.load(Ordering::Acquire));
    }
}
