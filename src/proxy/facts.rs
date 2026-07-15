use http::header::{
    HeaderMap, HeaderName as ProductHeaderName, HeaderValue as ProductHeaderValue, CONTENT_LENGTH,
    TRANSFER_ENCODING,
};
use http::{Method, Request, Version};
use http_access_types::{
    BodyFraming, BodyMetadata, CanonicalUrl, HeaderField, HeaderName, HeaderValue, HttpMethod,
    HttpVersion, IngressMode, InterceptedRequestFacts, UpgradeIntent as NeutralUpgradeIntent,
    UpgradeProtocol, ValueError,
};

use hyper::Body;

use crate::proxy::headers::{
    sanitize_untrusted_ingress_request, HeaderPreparationError, SanitizedIngressRequest,
    UpgradeIntent as ProductUpgradeIntent,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum FactsError {
    #[error("the ingress HTTP version is unsupported")]
    UnsupportedVersion,
    #[error("request fact allocation failed")]
    Capacity,
    #[error("request body framing sources conflict")]
    AmbiguousBodyFraming,
    #[error("request contains duplicate Content-Length fields")]
    DuplicateContentLength,
    #[error("request Content-Length is invalid")]
    InvalidContentLength,
    #[error("request Transfer-Encoding is invalid")]
    InvalidTransferEncoding,
    #[error("request upgrade protocol is invalid")]
    InvalidUpgrade,
    #[error("neutral facts contain a header name the product cannot represent")]
    InvalidProductHeaderName,
    #[error("neutral facts contain a header value the product cannot represent")]
    InvalidProductHeaderValue,
    #[error("request facts contain an invalid checked value")]
    Value(#[from] ValueError),
}

/// A request identity whose transport-owned components have been checked before
/// any product credential processing occurs. Header values are deliberately not
/// retained here because configured inbound fields may contain secrets.
pub(crate) struct ValidatedRequestFactShape {
    ingress_mode: IngressMode,
    version: HttpVersion,
    method: HttpMethod,
    url: CanonicalUrl,
    body: BodyMetadata,
    upgrade: Option<NeutralUpgradeIntent>,
}

/// One fact shape and transport owner derived atomically from the same ingress
/// request before product credential extraction.
pub(crate) struct ValidatedStandaloneIngress {
    shape: ValidatedRequestFactShape,
    ingress: SanitizedIngressRequest,
}

impl ValidatedStandaloneIngress {
    #[allow(
        dead_code,
        reason = "P06 C03 preflights this owner only in focused tests before C04 listener cutover"
    )]
    pub(crate) fn ingress(&self) -> &SanitizedIngressRequest {
        &self.ingress
    }

    pub(crate) fn into_parts(self) -> (ValidatedRequestFactShape, SanitizedIngressRequest) {
        (self.shape, self.ingress)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidatedStandaloneIngressError {
    #[error("request framing or facts are invalid")]
    Facts(#[from] FactsError),
    #[error("request headers are invalid")]
    Headers(#[from] HeaderPreparationError),
}

#[allow(
    dead_code,
    reason = "P06 C03 lands the atomic ingress validator before the mandatory C04 listener cutover"
)]
pub(crate) fn validate_standalone_ingress_request(
    ingress_mode: IngressMode,
    canonical: CanonicalUrl,
    request: Request<Body>,
) -> Result<ValidatedStandaloneIngress, ValidatedStandaloneIngressError> {
    let framing = body_metadata(request.version(), request.headers())?;
    let ingress = sanitize_untrusted_ingress_request(request)?;
    let shape = validate_request_fact_shape(
        ingress_mode,
        ingress.version(),
        ingress.method(),
        canonical,
        ingress.headers(),
        framing,
        ingress.upgrade_intent(),
    )?;
    Ok(ValidatedStandaloneIngress { shape, ingress })
}

pub(crate) fn http_version(version: Version) -> Result<HttpVersion, FactsError> {
    match version {
        Version::HTTP_10 => Ok(HttpVersion::Http10),
        Version::HTTP_11 => Ok(HttpVersion::Http11),
        Version::HTTP_2 => Ok(HttpVersion::Http2),
        _ => Err(FactsError::UnsupportedVersion),
    }
}

pub(crate) fn http_method(method: &Method) -> Result<HttpMethod, FactsError> {
    HttpMethod::new(method.as_str()).map_err(Into::into)
}

pub(crate) fn neutral_headers(headers: &HeaderMap) -> Result<Vec<HeaderField>, FactsError> {
    let mut names: Vec<_> = headers.keys().cloned().collect();
    names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));

    let mut fields = Vec::new();
    fields
        .try_reserve(headers.len())
        .map_err(|_| FactsError::Capacity)?;
    for name in names {
        let checked_name = HeaderName::new(name.as_str())?;
        for value in headers.get_all(&name).iter() {
            fields.push(HeaderField::new(
                checked_name.clone(),
                HeaderValue::new(value.as_bytes().to_vec())?,
            ));
        }
    }
    Ok(fields)
}

pub(crate) fn product_headers(fields: &[HeaderField]) -> Result<HeaderMap, FactsError> {
    let mut headers = HeaderMap::new();
    headers
        .try_reserve(fields.len())
        .map_err(|_| FactsError::Capacity)?;
    for field in fields {
        let name = ProductHeaderName::from_bytes(field.name().as_str().as_bytes())
            .map_err(|_| FactsError::InvalidProductHeaderName)?;
        let value = ProductHeaderValue::from_bytes(field.value().as_bytes())
            .map_err(|_| FactsError::InvalidProductHeaderValue)?;
        headers
            .try_append(name, value)
            .map_err(|_| FactsError::Capacity)?;
    }
    Ok(headers)
}

pub(crate) fn body_metadata(
    version: Version,
    headers: &HeaderMap,
) -> Result<BodyMetadata, FactsError> {
    let version = http_version(version)?;
    let content_length = single_content_length(headers)?;
    let transfer_encoding = headers.get_all(TRANSFER_ENCODING);
    let transfer_encoding_count = transfer_encoding.iter().count();

    if content_length.is_some() && transfer_encoding_count != 0 {
        return Err(FactsError::AmbiguousBodyFraming);
    }

    let framing = match version {
        HttpVersion::Http2 => {
            if transfer_encoding_count != 0 {
                return Err(FactsError::InvalidTransferEncoding);
            }
            BodyFraming::Http2Stream
        }
        HttpVersion::Http10 | HttpVersion::Http11 => {
            if transfer_encoding_count != 0 {
                if version != HttpVersion::Http11 || transfer_encoding_count != 1 {
                    return Err(FactsError::InvalidTransferEncoding);
                }
                let value = transfer_encoding
                    .iter()
                    .next()
                    .expect("a nonzero field count has a first value");
                if !value.as_bytes().eq_ignore_ascii_case(b"chunked") {
                    return Err(FactsError::InvalidTransferEncoding);
                }
                BodyFraming::Chunked
            } else if let Some(length) = content_length {
                BodyFraming::ContentLength(length)
            } else {
                BodyFraming::None
            }
        }
    };
    Ok(BodyMetadata::new(framing))
}

fn single_content_length(headers: &HeaderMap) -> Result<Option<u64>, FactsError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(FactsError::DuplicateContentLength);
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(FactsError::InvalidContentLength);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FactsError::InvalidContentLength)?;
    text.parse::<u64>()
        .map(Some)
        .map_err(|_| FactsError::InvalidContentLength)
}

pub(crate) fn upgrade_intent(
    intent: Option<&ProductUpgradeIntent>,
) -> Result<Option<NeutralUpgradeIntent>, FactsError> {
    intent
        .map(|intent| {
            let protocol = intent
                .protocol()
                .to_str()
                .map_err(|_| FactsError::InvalidUpgrade)?;
            Ok(if protocol.eq_ignore_ascii_case("websocket") {
                NeutralUpgradeIntent::WebSocket
            } else {
                NeutralUpgradeIntent::Other(UpgradeProtocol::new(protocol)?)
            })
        })
        .transpose()
}

pub(crate) fn validate_request_fact_shape(
    ingress_mode: IngressMode,
    version: Version,
    method: &Method,
    url: CanonicalUrl,
    headers: &HeaderMap,
    body: BodyMetadata,
    upgrade: Option<&ProductUpgradeIntent>,
) -> Result<ValidatedRequestFactShape, FactsError> {
    for (name, value) in headers {
        HeaderName::new(name.as_str())?;
        HeaderValue::validate(value.as_bytes())?;
    }
    let version = http_version(version)?;
    let method = http_method(method)?;
    let upgrade = upgrade_intent(upgrade)?;
    InterceptedRequestFacts::new(
        ingress_mode,
        version,
        method.clone(),
        url.clone(),
        Vec::new(),
        body,
        upgrade.clone(),
    )?;
    Ok(ValidatedRequestFactShape {
        ingress_mode,
        version,
        method,
        url,
        body,
        upgrade,
    })
}

impl ValidatedRequestFactShape {
    pub(crate) fn into_facts(
        self,
        policy_visible_headers: &HeaderMap,
    ) -> Result<InterceptedRequestFacts, FactsError> {
        Ok(InterceptedRequestFacts::new(
            self.ingress_mode,
            self.version,
            self.method,
            self.url,
            neutral_headers(policy_visible_headers)?,
            self.body,
            self.upgrade,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{CONNECTION, UPGRADE};
    use http::{HeaderValue as HttpHeaderValue, Request};
    use http_access_url::canonicalize_http_url;
    use hyper::Body;

    use crate::proxy::headers::sanitize_untrusted_request;

    fn headers(entries: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in entries {
            headers.append(*name, HttpHeaderValue::from_static(value));
        }
        headers
    }

    fn framing(version: Version, entries: &[(&'static str, &'static str)]) -> BodyFraming {
        body_metadata(version, &headers(entries)).unwrap().framing()
    }

    #[test]
    fn versions_and_extension_methods_are_checked() {
        assert_eq!(http_version(Version::HTTP_10).unwrap(), HttpVersion::Http10);
        assert_eq!(http_version(Version::HTTP_11).unwrap(), HttpVersion::Http11);
        assert_eq!(http_version(Version::HTTP_2).unwrap(), HttpVersion::Http2);
        assert_eq!(
            http_version(Version::HTTP_3),
            Err(FactsError::UnsupportedVersion)
        );

        let extension = Method::from_bytes(b"PURGE-CACHE").unwrap();
        assert_eq!(http_method(&extension).unwrap().as_str(), "PURGE-CACHE");
        let lowercase = Method::from_bytes(b"custom").unwrap();
        assert!(matches!(http_method(&lowercase), Err(FactsError::Value(_))));
    }

    #[test]
    fn body_metadata_distinguishes_none_zero_length_length_chunked_and_h2() {
        assert_eq!(framing(Version::HTTP_11, &[]), BodyFraming::None);
        assert_eq!(
            framing(Version::HTTP_11, &[("content-length", "0")]),
            BodyFraming::ContentLength(0)
        );
        assert_eq!(
            framing(Version::HTTP_10, &[("content-length", "42")]),
            BodyFraming::ContentLength(42)
        );
        assert_eq!(
            framing(Version::HTTP_11, &[("transfer-encoding", "ChUnKeD")]),
            BodyFraming::Chunked
        );
        assert_eq!(
            framing(Version::HTTP_2, &[("content-length", "42")]),
            BodyFraming::Http2Stream
        );
    }

    #[test]
    fn body_metadata_rejects_ambiguous_duplicate_and_invalid_framing() {
        assert_eq!(
            body_metadata(
                Version::HTTP_11,
                &headers(&[("content-length", "4"), ("transfer-encoding", "chunked")])
            ),
            Err(FactsError::AmbiguousBodyFraming)
        );
        assert_eq!(
            body_metadata(
                Version::HTTP_11,
                &headers(&[("content-length", "1"), ("content-length", "1")])
            ),
            Err(FactsError::DuplicateContentLength)
        );
        for value in ["", "01", "+1", "18446744073709551616"] {
            assert_eq!(
                body_metadata(Version::HTTP_11, &headers(&[("content-length", value)])),
                Err(FactsError::InvalidContentLength),
                "{value:?}"
            );
        }
        assert_eq!(
            body_metadata(
                Version::HTTP_10,
                &headers(&[("transfer-encoding", "chunked")])
            ),
            Err(FactsError::InvalidTransferEncoding)
        );
        assert_eq!(
            body_metadata(
                Version::HTTP_11,
                &headers(&[("transfer-encoding", "gzip, chunked")])
            ),
            Err(FactsError::InvalidTransferEncoding)
        );
        assert_eq!(
            body_metadata(
                Version::HTTP_2,
                &headers(&[("transfer-encoding", "chunked")])
            ),
            Err(FactsError::InvalidTransferEncoding)
        );
    }

    #[test]
    fn standalone_ingress_atomically_binds_method_version_framing_and_upgrade_transport() {
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri("/resource")
            .header("host", "example.test")
            .header("content-length", "3")
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "chat/1")
            .body(Body::from("abc"))
            .unwrap();
        let canonical = canonicalize_http_url("http://example.test/resource").unwrap();

        let validated =
            validate_standalone_ingress_request(IngressMode::ExplicitHttp, canonical, request)
                .unwrap();
        let (shape, ingress) = validated.into_parts();
        let (mut parts, _body, protocol, downstream_upgrade) = ingress.into_parts();
        let headers = std::mem::take(&mut parts.headers);
        let facts = shape.into_facts(&headers).unwrap();

        assert_eq!(facts.method().as_str(), "POST");
        assert_eq!(facts.version(), HttpVersion::Http11);
        assert_eq!(facts.body().framing(), BodyFraming::ContentLength(3));
        assert!(matches!(
            facts.upgrade(),
            Some(NeutralUpgradeIntent::Other(protocol)) if protocol.as_str() == "chat/1"
        ));
        assert_eq!(parts.method, Method::POST);
        assert_eq!(parts.version, Version::HTTP_11);
        assert_eq!(protocol, crate::egress::OriginProtocol::Http1);
        assert!(parts.extensions.get::<ProductUpgradeIntent>().is_some());
        assert!(downstream_upgrade.is_some());
    }

    #[test]
    fn neutral_headers_sort_names_and_preserve_duplicate_value_order() {
        let headers = headers(&[
            ("z-last", "z"),
            ("x-repeat", "first"),
            ("a-first", "a"),
            ("x-repeat", "second"),
        ]);
        let actual: Vec<_> = neutral_headers(&headers)
            .unwrap()
            .into_iter()
            .map(|field| {
                (
                    field.name().as_str().to_owned(),
                    field.value().as_bytes().to_vec(),
                )
            })
            .collect();
        assert_eq!(
            actual,
            [
                ("a-first".to_owned(), b"a".to_vec()),
                ("x-repeat".to_owned(), b"first".to_vec()),
                ("x-repeat".to_owned(), b"second".to_vec()),
                ("z-last".to_owned(), b"z".to_vec()),
            ]
        );
    }

    #[test]
    fn product_headers_preserve_duplicate_value_order() {
        let neutral = neutral_headers(&headers(&[
            ("x-repeat", "first"),
            ("x-other", "value"),
            ("x-repeat", "second"),
        ]))
        .unwrap();
        let product = product_headers(&neutral).unwrap();
        let repeated: Vec<_> = product
            .get_all("x-repeat")
            .iter()
            .map(|value| value.as_bytes())
            .collect();
        assert_eq!(repeated, [b"first".as_slice(), b"second".as_slice()]);
        assert_eq!(product["x-other"], "value");
    }

    fn sanitized_upgrade(protocol: &'static str) -> crate::proxy::headers::SanitizedRequest {
        sanitize_untrusted_request(
            Request::builder()
                .version(Version::HTTP_11)
                .uri("http://example.test/socket")
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, protocol)
                .body(Body::empty())
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn upgrade_intent_distinguishes_websocket_and_other_protocols() {
        let websocket = sanitized_upgrade("WebSocket");
        assert_eq!(
            upgrade_intent(websocket.upgrade_intent()).unwrap(),
            Some(NeutralUpgradeIntent::WebSocket)
        );
        let opaque = sanitized_upgrade("test-echo/1");
        assert_eq!(
            upgrade_intent(opaque.upgrade_intent()).unwrap(),
            Some(NeutralUpgradeIntent::Other(
                UpgradeProtocol::new("test-echo/1").unwrap()
            ))
        );
        assert_eq!(upgrade_intent(None).unwrap(), None);
    }

    #[test]
    fn assembly_produces_one_complete_checked_facts_value() {
        let sanitized = sanitized_upgrade("websocket");
        let headers = headers(&[("host", "example.test"), ("x-test", "one")]);
        let shape = validate_request_fact_shape(
            IngressMode::ExplicitHttp,
            Version::HTTP_11,
            &Method::GET,
            canonicalize_http_url("http://example.test/socket").unwrap(),
            &headers,
            BodyMetadata::new(BodyFraming::ContentLength(0)),
            sanitized.upgrade_intent(),
        )
        .unwrap();
        let facts = shape.into_facts(&headers).unwrap();
        assert_eq!(facts.ingress_mode(), IngressMode::ExplicitHttp);
        assert_eq!(facts.version(), HttpVersion::Http11);
        assert_eq!(facts.method().as_str(), "GET");
        assert_eq!(facts.url().as_str(), "http://example.test/socket");
        assert_eq!(facts.body().framing(), BodyFraming::ContentLength(0));
        assert_eq!(facts.upgrade(), Some(&NeutralUpgradeIntent::WebSocket));
        assert_eq!(facts.headers().len(), 2);
    }
}
