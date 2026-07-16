use http::header::{HeaderMap, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{Method, Request, Version};
use http_access_types::{
    apply_header_mutation_batches, BodyFraming, BodyMetadata, CanonicalUrl, HeaderField,
    HeaderMutationBatch, HttpMethod, HttpScheme, HttpVersion, IngressMode, InterceptedRequestFacts,
    UpgradeIntent as NeutralUpgradeIntent, UpgradeProtocol, ValueError,
};

use hyper::body::HttpBody;
use hyper::Body;

use crate::credentials::{InboundCredentialSnapshot, InboundCredentials};
use crate::proxy::headers::{
    sanitize_untrusted_connect_ingress_request, sanitize_untrusted_ingress_request,
    HeaderAdapterError, SanitizedConnectIngressRequest, SanitizedIngressRequest,
};
use crate::runtime::GenerationLease;

pub(crate) struct IngressPartitionPolicy<'a> {
    inbound: &'a InboundCredentialSnapshot,
    internal_context: &'a [http::HeaderName],
    sensitive: &'a [http_access_types::HeaderName],
    observation_sensitive: &'a [http_access_types::HeaderName],
}

impl<'a> IngressPartitionPolicy<'a> {
    pub(crate) fn from_lease(lease: &'a GenerationLease) -> Self {
        Self {
            inbound: lease.credentials(),
            internal_context: lease.authorization().internal_context_headers(),
            sensitive: lease.standalone().sensitive_headers(),
            observation_sensitive: lease.standalone().sensitive_header_policy().names(),
        }
    }

    #[cfg(test)]
    pub(crate) fn empty_for_test() -> IngressPartitionPolicy<'static> {
        static EMPTY: std::sync::OnceLock<InboundCredentialSnapshot> = std::sync::OnceLock::new();
        IngressPartitionPolicy {
            inbound: EMPTY.get_or_init(InboundCredentialSnapshot::empty_for_test),
            internal_context: &[],
            sensitive: &[],
            observation_sensitive: &[],
        }
    }
}

pub(crate) struct PartitionedIngressHeaders {
    pub(crate) inbound: InboundCredentials,
    pub(crate) internal_context: HeaderMap,
    pub(crate) sensitive_presence: Vec<http_access_types::HeaderName>,
    pub(crate) audit_sensitive_presence: Vec<http_access_types::HeaderName>,
}

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
    #[error("neutral facts contain a header name the product cannot represent")]
    InvalidProductHeaderName,
    #[error("neutral facts contain a header value the product cannot represent")]
    InvalidProductHeaderValue,
    #[error("request contains an invalid header value")]
    InvalidHeaderValue,
    #[error("request sensitive-header partition is incomplete")]
    SensitivePartition,
    #[error("request facts contain an invalid checked value")]
    Value(#[from] ValueError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResponseMutationError {
    #[error("response headers cannot be represented by the neutral contract")]
    Facts(#[from] FactsError),
    #[error("response header mutations are invalid")]
    Mutation(#[from] http_access_types::MutationError),
}

/// A request identity derived after product-specific sensitive values have been
/// partitioned out of the original product header map.
pub(crate) struct ValidatedRequestFactShape {
    ingress_mode: IngressMode,
    version: HttpVersion,
    method: HttpMethod,
    url: CanonicalUrl,
    body: BodyMetadata,
    upgrade: Option<NeutralUpgradeIntent>,
}

/// One fact shape, sanitized transport owner, and sensitive partition derived
/// atomically from the same ingress request.
pub(crate) struct ValidatedStandaloneIngress {
    shape: ValidatedRequestFactShape,
    ingress: SanitizedStandaloneIngress,
    partitioned: PartitionedIngressHeaders,
}

pub(crate) enum SanitizedStandaloneIngress {
    Ordinary(SanitizedIngressRequest),
    OuterConnect(SanitizedConnectIngressRequest),
}

impl SanitizedStandaloneIngress {
    pub(crate) fn protocol(&self) -> http_access_types::HttpProtocol {
        match self {
            Self::Ordinary(ingress) => {
                crate::proxy::headers::product_protocol(ingress.head().ingress_version())
            }
            Self::OuterConnect(ingress) => {
                crate::proxy::headers::product_protocol(ingress.head().ingress_version())
            }
        }
    }
}

impl ValidatedStandaloneIngress {
    pub(crate) fn ingress(&self) -> &SanitizedStandaloneIngress {
        &self.ingress
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ValidatedRequestFactShape,
        SanitizedStandaloneIngress,
        PartitionedIngressHeaders,
    ) {
        (self.shape, self.ingress, self.partitioned)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidatedStandaloneIngressError {
    #[error("request framing or facts are invalid")]
    Facts(#[from] FactsError),
    #[error("request headers are invalid")]
    Headers(#[from] HeaderAdapterError),
    #[error("inbound credential partition failed")]
    Credential(#[from] crate::credentials::CredentialError),
    #[error("outer CONNECT is valid only on an explicit listener")]
    ConnectIngressMode,
    #[error("outer CONNECT requires a canonical HTTPS root target")]
    ConnectTarget,
    #[error("outer CONNECT cannot carry a request body")]
    ConnectBody,
}

pub(crate) fn validate_standalone_ingress_request(
    partition_policy: IngressPartitionPolicy<'_>,
    ingress_mode: IngressMode,
    canonical: CanonicalUrl,
    mut request: Request<Body>,
) -> Result<ValidatedStandaloneIngress, ValidatedStandaloneIngressError> {
    validate_raw_ingress_headers(request.headers())?;
    let framing = body_metadata(request.version(), request.headers())?;
    let partitioned = partition_ingress_headers(&partition_policy, request.headers_mut())?;
    let ingress = sanitize_untrusted_ingress_request(request)?;
    let shape = validate_request_fact_shape(
        ingress_mode,
        ingress.head().ingress_version(),
        ingress.head().method(),
        canonical,
        ingress.head().headers(),
        framing,
        ingress.head().upgrade_protocol(),
    )?;
    Ok(ValidatedStandaloneIngress {
        shape,
        ingress: SanitizedStandaloneIngress::Ordinary(ingress),
        partitioned,
    })
}

pub(crate) fn validate_standalone_connect_ingress_request(
    partition_policy: IngressPartitionPolicy<'_>,
    ingress_mode: IngressMode,
    canonical: CanonicalUrl,
    mut request: Request<Body>,
) -> Result<ValidatedStandaloneIngress, ValidatedStandaloneIngressError> {
    if !matches!(
        ingress_mode,
        IngressMode::ExplicitHttp | IngressMode::ExplicitHttps
    ) {
        return Err(ValidatedStandaloneIngressError::ConnectIngressMode);
    }
    if canonical.scheme() != HttpScheme::Https
        || canonical.path() != "/"
        || canonical.query().is_some()
    {
        return Err(ValidatedStandaloneIngressError::ConnectTarget);
    }
    validate_raw_ingress_headers(request.headers())?;
    let framing = body_metadata(request.version(), request.headers())?;
    if !matches!(
        framing.framing(),
        BodyFraming::None | BodyFraming::ContentLength(0)
    ) || !request.body().is_end_stream()
    {
        return Err(ValidatedStandaloneIngressError::ConnectBody);
    }
    let partitioned = partition_ingress_headers(&partition_policy, request.headers_mut())?;
    let ingress = sanitize_untrusted_connect_ingress_request(request)?;
    let shape = validate_request_fact_shape(
        ingress_mode,
        ingress.head().ingress_version(),
        ingress.head().method(),
        canonical,
        ingress.head().headers(),
        framing,
        None,
    )?;
    Ok(ValidatedStandaloneIngress {
        shape,
        ingress: SanitizedStandaloneIngress::OuterConnect(ingress),
        partitioned,
    })
}

fn partition_ingress_headers(
    policy: &IngressPartitionPolicy<'_>,
    headers: &mut HeaderMap,
) -> Result<PartitionedIngressHeaders, ValidatedStandaloneIngressError> {
    let connection_values = headers.get_all(http::header::CONNECTION);
    let nominations = http_access_runtime::prepartition_connection_nominations(
        connection_values.iter().map(http::HeaderValue::as_bytes),
    )
    .map_err(HeaderAdapterError::from)?;
    for nomination in nominations {
        headers.remove(nomination.as_str());
    }
    let mut audit_sensitive_presence = Vec::new();
    audit_sensitive_presence
        .try_reserve_exact(policy.observation_sensitive.len())
        .map_err(|_| FactsError::Capacity)?;
    for name in policy.observation_sensitive {
        if headers.contains_key(name.as_str()) {
            audit_sensitive_presence.push(name.clone());
        }
    }
    let mut sensitive_presence = Vec::new();
    sensitive_presence
        .try_reserve_exact(policy.sensitive.len())
        .map_err(|_| FactsError::Capacity)?;
    for name in policy.sensitive {
        if headers.contains_key(name.as_str()) {
            sensitive_presence.push(name.clone());
        }
    }
    while let Some(name) = headers
        .keys()
        .find(|name| http_access_runtime::is_prepartition_caller_credential_header(name.as_str()))
        .cloned()
    {
        headers.remove(name);
    }
    let inbound = policy.inbound.extract(headers)?;
    let internal_context = partition_internal_context(headers, policy.internal_context)?;
    if policy
        .sensitive
        .iter()
        .any(|name| headers.contains_key(name.as_str()))
    {
        return Err(FactsError::SensitivePartition.into());
    }
    Ok(PartitionedIngressHeaders {
        inbound,
        internal_context,
        sensitive_presence,
        audit_sensitive_presence,
    })
}

fn validate_raw_ingress_headers(
    headers: &HeaderMap,
) -> Result<(), ValidatedStandaloneIngressError> {
    let name_value_bytes = headers
        .iter()
        .try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
        })
        .ok_or(HeaderAdapterError::Hygiene(
            http_access_runtime::HeaderHygieneError::LimitExceeded,
        ))?;
    http_access_runtime::validate_header_projection(headers.len(), name_value_bytes)
        .map_err(HeaderAdapterError::from)?;
    for value in headers.values() {
        http_access_types::HeaderValue::validate(value.as_bytes())
            .map_err(|_| FactsError::InvalidHeaderValue)?;
    }
    Ok(())
}

fn partition_internal_context(
    headers: &mut HeaderMap,
    names: &[http::HeaderName],
) -> Result<HeaderMap, FactsError> {
    let mut ordinary = HeaderMap::new();
    ordinary
        .try_reserve(headers.len())
        .map_err(|_| FactsError::Capacity)?;
    let mut internal = HeaderMap::new();
    internal
        .try_reserve(names.len())
        .map_err(|_| FactsError::Capacity)?;
    let mut current_name = None;
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            current_name = Some(name);
        }
        let name = current_name.as_ref().ok_or(FactsError::Capacity)?;
        let target = if names.contains(name) {
            &mut internal
        } else {
            &mut ordinary
        };
        target
            .try_append(name.clone(), value)
            .map_err(|_| FactsError::Capacity)?;
    }
    *headers = ordinary;
    Ok(internal)
}

#[cfg(test)]
pub(crate) fn partition_internal_context_for_test(
    headers: &mut HeaderMap,
    names: &[http::HeaderName],
) -> Result<HeaderMap, FactsError> {
    partition_internal_context(headers, names)
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
    crate::proxy::headers::neutral_headers(headers).map_err(|error| match error {
        HeaderAdapterError::Capacity => FactsError::Capacity,
        HeaderAdapterError::Value(error) => FactsError::Value(error),
        _ => FactsError::InvalidProductHeaderValue,
    })
}

pub(crate) fn product_headers(fields: &[HeaderField]) -> Result<HeaderMap, FactsError> {
    crate::proxy::headers::product_headers(fields).map_err(|error| match error {
        HeaderAdapterError::Capacity => FactsError::Capacity,
        HeaderAdapterError::HeaderName => FactsError::InvalidProductHeaderName,
        _ => FactsError::InvalidProductHeaderValue,
    })
}

pub(crate) fn apply_response_mutations(
    headers: &HeaderMap,
    batches: &[HeaderMutationBatch],
) -> Result<HeaderMap, ResponseMutationError> {
    let neutral = neutral_headers(headers)?;
    let mutated = apply_header_mutation_batches(&neutral, batches)?;
    product_headers(&mutated).map_err(Into::into)
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
    intent: Option<&UpgradeProtocol>,
) -> Result<Option<NeutralUpgradeIntent>, FactsError> {
    intent
        .map(|intent| {
            let protocol = intent.as_str();
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
    version: HttpVersion,
    method: &HttpMethod,
    url: CanonicalUrl,
    _headers: &[HeaderField],
    body: BodyMetadata,
    upgrade: Option<&UpgradeProtocol>,
) -> Result<ValidatedRequestFactShape, FactsError> {
    let method = method.clone();
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

    use crate::proxy::headers::sanitize_product_request;

    fn validate_standalone_ingress_request(
        ingress_mode: IngressMode,
        canonical: CanonicalUrl,
        request: Request<Body>,
    ) -> Result<ValidatedStandaloneIngress, ValidatedStandaloneIngressError> {
        super::validate_standalone_ingress_request(
            IngressPartitionPolicy::empty_for_test(),
            ingress_mode,
            canonical,
            request,
        )
    }

    fn validate_standalone_connect_ingress_request(
        ingress_mode: IngressMode,
        canonical: CanonicalUrl,
        request: Request<Body>,
    ) -> Result<ValidatedStandaloneIngress, ValidatedStandaloneIngressError> {
        super::validate_standalone_connect_ingress_request(
            IngressPartitionPolicy::empty_for_test(),
            ingress_mode,
            canonical,
            request,
        )
    }

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
        let (shape, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::Ordinary(ingress) = ingress else {
            panic!("ordinary validation returned CONNECT ingress");
        };
        let (parts, _body, head, downstream_upgrade) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();
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
        assert_eq!(
            crate::proxy::headers::product_protocol(head.ingress_version()),
            http_access_types::HttpProtocol::Http1
        );
        assert_eq!(head.upgrade_protocol().unwrap().as_str(), "chat/1");
        assert!(downstream_upgrade.is_some());
        assert!(partitioned.internal_context.is_empty());
        assert!(partitioned.sensitive_presence.is_empty());
        assert!(partitioned.audit_sensitive_presence.is_empty());
    }

    #[test]
    fn standalone_connect_ingress_atomically_binds_empty_facts_and_tunnel_transport() {
        for ingress_mode in [IngressMode::ExplicitHttp, IngressMode::ExplicitHttps] {
            let request = Request::builder()
                .method(Method::CONNECT)
                .version(Version::HTTP_11)
                .uri("example.test:443")
                .header("host", "example.test:443")
                .header("content-length", "0")
                .body(Body::empty())
                .unwrap();
            let canonical = canonicalize_http_url("https://example.test/").unwrap();

            let validated =
                validate_standalone_connect_ingress_request(ingress_mode, canonical, request)
                    .unwrap();
            let (shape, ingress, partitioned) = validated.into_parts();
            let SanitizedStandaloneIngress::OuterConnect(ingress) = ingress else {
                panic!("CONNECT validation returned ordinary ingress");
            };
            let (parts, body, head, downstream_upgrade) = ingress.into_parts();
            let headers = product_headers(head.headers()).unwrap();
            let facts = shape.into_facts(&headers).unwrap();

            assert_eq!(facts.ingress_mode(), ingress_mode);
            assert_eq!(facts.method().as_str(), "CONNECT");
            assert_eq!(facts.version(), HttpVersion::Http11);
            assert_eq!(facts.body().framing(), BodyFraming::ContentLength(0));
            assert!(facts.upgrade().is_none());
            assert_eq!(facts.url().as_str(), "https://example.test/");
            assert_eq!(parts.method, Method::CONNECT);
            assert_eq!(parts.version, Version::HTTP_11);
            assert!(body.is_end_stream());
            assert_eq!(
                crate::proxy::headers::product_protocol(head.ingress_version()),
                http_access_types::HttpProtocol::Http1
            );
            drop(downstream_upgrade);
            assert!(partitioned.internal_context.is_empty());
            assert!(partitioned.sensitive_presence.is_empty());
            assert!(partitioned.audit_sensitive_presence.is_empty());
        }
    }

    fn sensitive_partition_fixture() -> (
        InboundCredentialSnapshot,
        [http::HeaderName; 1],
        [http_access_types::HeaderName; 2],
    ) {
        let authorization = http::header::AUTHORIZATION;
        let internal = http::HeaderName::from_static("x-internal-context");
        let snapshot = InboundCredentialSnapshot::for_test([authorization.clone()]);
        let sensitive = [
            http_access_types::HeaderName::new(authorization.as_str()).unwrap(),
            http_access_types::HeaderName::new(internal.as_str()).unwrap(),
        ];
        (snapshot, [internal], sensitive)
    }

    #[test]
    fn ordinary_ingress_partitions_authorization_and_custom_internal_before_neutralization() {
        let (snapshot, internal, sensitive) = sensitive_partition_fixture();
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &internal,
            sensitive: &sensitive,
            observation_sensitive: &sensitive,
        };
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("http://example.test/resource")
            .header("host", "example.test")
            .header("authorization", "Bearer inbound-secret")
            .header("x-internal-context", "internal-secret")
            .header("x-visible", "ordinary")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("http://example.test/resource").unwrap();

        let validated = super::validate_standalone_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        )
        .unwrap();
        let (_, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::Ordinary(ingress) = ingress else {
            panic!("ordinary validation returned CONNECT ingress");
        };
        let (_, _, head, _) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();

        assert!(!headers.contains_key(http::header::AUTHORIZATION));
        assert!(!headers.contains_key("x-internal-context"));
        assert_eq!(headers["x-visible"], "ordinary");
        assert!(partitioned.inbound.is_present(&http::header::AUTHORIZATION));
        assert!(partitioned
            .internal_context
            .contains_key("x-internal-context"));
        assert_eq!(partitioned.sensitive_presence, sensitive);
        assert_eq!(partitioned.audit_sensitive_presence.as_slice(), sensitive);
    }

    #[test]
    fn outer_connect_partitions_sensitive_values_before_neutralization() {
        let (snapshot, internal, sensitive) = sensitive_partition_fixture();
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &internal,
            sensitive: &sensitive,
            observation_sensitive: &sensitive,
        };
        let request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri("example.test:443")
            .header("host", "example.test:443")
            .header("authorization", "Bearer tunnel-secret")
            .header("x-internal-context", "tunnel-internal-secret")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("https://example.test/").unwrap();

        let validated = super::validate_standalone_connect_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        )
        .unwrap();
        let (_, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::OuterConnect(ingress) = ingress else {
            panic!("CONNECT validation returned ordinary ingress");
        };
        let (_, _, head, _) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();

        assert!(!headers.contains_key(http::header::AUTHORIZATION));
        assert!(!headers.contains_key("x-internal-context"));
        assert!(partitioned.inbound.is_present(&http::header::AUTHORIZATION));
        assert!(partitioned
            .internal_context
            .contains_key("x-internal-context"));
        assert_eq!(partitioned.sensitive_presence, sensitive);
        assert_eq!(partitioned.audit_sensitive_presence.as_slice(), sensitive);
    }

    #[test]
    fn prepartition_consumes_nominated_sensitive_fields_and_preserves_valid_upgrade_control() {
        let (snapshot, internal, _) = sensitive_partition_fixture();
        let observation = [http_access_types::HeaderName::new("x-observation-secret").unwrap()];
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &internal,
            sensitive: &observation,
            observation_sensitive: &observation,
        };
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("http://example.test/resource")
            .header("host", "example.test")
            .header(
                "connection",
                "connection, upgrade, Authorization, X-Internal-Context, X-Observation-Secret",
            )
            .header("upgrade", "websocket")
            .header("authorization", "Bearer nominated-secret")
            .header("x-internal-context", "nominated-internal-secret")
            .header("x-observation-secret", "nominated-observation-secret")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("http://example.test/resource").unwrap();

        let validated = super::validate_standalone_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        )
        .unwrap();
        let (_, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::Ordinary(ingress) = ingress else {
            panic!("ordinary validation returned CONNECT ingress");
        };
        let (_, _, head, _) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();

        assert!(!headers.contains_key(http::header::AUTHORIZATION));
        assert!(!headers.contains_key("x-internal-context"));
        assert!(!headers.contains_key("x-observation-secret"));
        assert_eq!(head.upgrade_protocol().unwrap().as_str(), "websocket");
        assert!(!partitioned.inbound.is_present(&http::header::AUTHORIZATION));
        assert!(partitioned.internal_context.is_empty());
        assert!(partitioned.sensitive_presence.is_empty());
        assert!(partitioned.audit_sensitive_presence.is_empty());
    }

    #[test]
    fn h2_invalid_te_remains_for_shared_validation_after_prepartition() {
        let snapshot = InboundCredentialSnapshot::empty_for_test();
        let observation = [http_access_types::HeaderName::new("x-observation-secret").unwrap()];
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &[],
            sensitive: &observation,
            observation_sensitive: &observation,
        };
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_2)
            .uri("http://example.test/resource")
            .header("host", "example.test")
            .header("connection", "te, x-observation-secret")
            .header("te", "gzip")
            .header("x-observation-secret", "nominated-observation-secret")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("http://example.test/resource").unwrap();

        let error = expect_ingress_error(super::validate_standalone_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        ));
        assert!(matches!(
            error,
            ValidatedStandaloneIngressError::Headers(HeaderAdapterError::Hygiene(
                http_access_runtime::HeaderHygieneError::InvalidTe
            ))
        ));
    }

    #[test]
    fn connection_nominated_partition_owners_are_removed_before_connect_extraction() {
        let (snapshot, internal, sensitive) = sensitive_partition_fixture();
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &internal,
            sensitive: &sensitive,
            observation_sensitive: &sensitive,
        };
        let request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri("example.test:443")
            .header("host", "example.test:443")
            .header("connection", "authorization, x-internal-context")
            .header("authorization", "Bearer nominated-secret")
            .header("x-internal-context", "nominated-internal-secret")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("https://example.test/").unwrap();

        let validated = super::validate_standalone_connect_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        )
        .unwrap();
        let (_, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::OuterConnect(ingress) = ingress else {
            panic!("CONNECT validation returned ordinary ingress");
        };
        let (_, _, head, _) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();

        assert!(!headers.contains_key(http::header::AUTHORIZATION));
        assert!(!headers.contains_key("x-internal-context"));
        assert!(!partitioned.inbound.is_present(&http::header::AUTHORIZATION));
        assert!(partitioned.internal_context.is_empty());
        assert!(partitioned.sensitive_presence.is_empty());
        assert!(partitioned.audit_sensitive_presence.is_empty());
    }

    fn proxy_authorization_policy() -> [http_access_types::HeaderName; 1] {
        [http_access_types::HeaderName::new("proxy-authorization").unwrap()]
    }

    #[test]
    fn ordinary_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral() {
        let snapshot = InboundCredentialSnapshot::empty_for_test();
        let sensitive = proxy_authorization_policy();
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &[],
            sensitive: &sensitive,
            observation_sensitive: &sensitive,
        };
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("http://example.test/resource")
            .header("host", "example.test")
            .header("proxy-authorization", "Basic caller-secret")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("http://example.test/resource").unwrap();

        let validated = super::validate_standalone_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        )
        .unwrap();
        let (_, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::Ordinary(ingress) = ingress else {
            panic!("ordinary validation returned CONNECT ingress");
        };
        let (_, _, head, _) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();

        assert!(!headers.contains_key("proxy-authorization"));
        assert_eq!(partitioned.sensitive_presence, sensitive);
        assert_eq!(partitioned.audit_sensitive_presence, sensitive);
    }

    #[test]
    fn connect_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral() {
        let snapshot = InboundCredentialSnapshot::empty_for_test();
        let sensitive = proxy_authorization_policy();
        let policy = IngressPartitionPolicy {
            inbound: &snapshot,
            internal_context: &[],
            sensitive: &sensitive,
            observation_sensitive: &sensitive,
        };
        let request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri("example.test:443")
            .header("host", "example.test:443")
            .header("proxy-authorization", "Basic caller-secret")
            .body(Body::empty())
            .unwrap();
        let canonical = canonicalize_http_url("https://example.test/").unwrap();

        let validated = super::validate_standalone_connect_ingress_request(
            policy,
            IngressMode::ExplicitHttp,
            canonical,
            request,
        )
        .unwrap();
        let (_, ingress, partitioned) = validated.into_parts();
        let SanitizedStandaloneIngress::OuterConnect(ingress) = ingress else {
            panic!("CONNECT validation returned ordinary ingress");
        };
        let (_, _, head, _) = ingress.into_parts();
        let headers = product_headers(head.headers()).unwrap();

        assert!(!headers.contains_key("proxy-authorization"));
        assert_eq!(partitioned.sensitive_presence, sensitive);
        assert_eq!(partitioned.audit_sensitive_presence, sensitive);
    }

    fn internal_partition_policy<'a>(
        snapshot: &'a InboundCredentialSnapshot,
        internal: &'a [http::HeaderName],
        sensitive: &'a [http_access_types::HeaderName],
    ) -> IngressPartitionPolicy<'a> {
        IngressPartitionPolicy {
            inbound: snapshot,
            internal_context: internal,
            sensitive,
            observation_sensitive: sensitive,
        }
    }

    fn raw_internal_request(
        method: Method,
        uri: &'static str,
        host: &'static str,
        values: usize,
        value_len: usize,
    ) -> Request<Body> {
        let mut request = Request::new(Body::empty());
        *request.method_mut() = method;
        *request.version_mut() = Version::HTTP_11;
        *request.uri_mut() = uri.parse().unwrap();
        request
            .headers_mut()
            .insert("host", HttpHeaderValue::from_static(host));
        let value = HttpHeaderValue::from_bytes(&vec![b'a'; value_len]).unwrap();
        for _ in 0..values {
            request
                .headers_mut()
                .append("x-internal-context", value.clone());
        }
        request
    }

    fn is_header_limit(error: &ValidatedStandaloneIngressError) -> bool {
        matches!(
            error,
            ValidatedStandaloneIngressError::Headers(HeaderAdapterError::Hygiene(
                http_access_runtime::HeaderHygieneError::LimitExceeded
            ))
        )
    }

    fn expect_ingress_error(
        result: Result<ValidatedStandaloneIngress, ValidatedStandaloneIngressError>,
    ) -> ValidatedStandaloneIngressError {
        match result {
            Ok(_) => panic!("ingress validation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn ordinary_raw_projection_bounds_precede_internal_partition() {
        let snapshot = InboundCredentialSnapshot::empty_for_test();
        let internal = [http::HeaderName::from_static("x-internal-context")];
        let sensitive = [http_access_types::HeaderName::new("x-internal-context").unwrap()];
        let canonical = || canonicalize_http_url("http://example.test/resource").unwrap();
        let exact_count = raw_internal_request(
            Method::GET,
            "http://example.test/resource",
            "example.test",
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1,
            0,
        );
        let validated = super::validate_standalone_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            exact_count,
        )
        .unwrap();
        assert_eq!(
            validated.into_parts().2.internal_context.len(),
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1
        );

        let count_over = raw_internal_request(
            Method::GET,
            "http://example.test/resource",
            "example.test",
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS,
            0,
        );
        let error = expect_ingress_error(super::validate_standalone_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            count_over,
        ));
        assert!(is_header_limit(&error));

        let fixed_bytes = "host".len() + "example.test".len() + "x-internal-context".len();
        let exact_value_len = http_access_runtime::MAX_HEADER_HYGIENE_BYTES - fixed_bytes;
        let exact_bytes = raw_internal_request(
            Method::GET,
            "http://example.test/resource",
            "example.test",
            1,
            exact_value_len,
        );
        super::validate_standalone_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            exact_bytes,
        )
        .unwrap();
        let byte_over = raw_internal_request(
            Method::GET,
            "http://example.test/resource",
            "example.test",
            1,
            exact_value_len + 1,
        );
        let error = expect_ingress_error(super::validate_standalone_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            byte_over,
        ));
        assert!(is_header_limit(&error));
    }

    #[test]
    fn connect_raw_projection_bounds_precede_internal_partition() {
        let snapshot = InboundCredentialSnapshot::empty_for_test();
        let internal = [http::HeaderName::from_static("x-internal-context")];
        let sensitive = [http_access_types::HeaderName::new("x-internal-context").unwrap()];
        let canonical = || canonicalize_http_url("https://example.test/").unwrap();
        let exact_count = raw_internal_request(
            Method::CONNECT,
            "example.test:443",
            "example.test:443",
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1,
            0,
        );
        let validated = super::validate_standalone_connect_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            exact_count,
        )
        .unwrap();
        assert_eq!(
            validated.into_parts().2.internal_context.len(),
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1
        );

        let count_over = raw_internal_request(
            Method::CONNECT,
            "example.test:443",
            "example.test:443",
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS,
            0,
        );
        let error = expect_ingress_error(super::validate_standalone_connect_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            count_over,
        ));
        assert!(is_header_limit(&error));

        let fixed_bytes = "host".len() + "example.test:443".len() + "x-internal-context".len();
        let exact_value_len = http_access_runtime::MAX_HEADER_HYGIENE_BYTES - fixed_bytes;
        let exact_bytes = raw_internal_request(
            Method::CONNECT,
            "example.test:443",
            "example.test:443",
            1,
            exact_value_len,
        );
        super::validate_standalone_connect_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            exact_bytes,
        )
        .unwrap();
        let byte_over = raw_internal_request(
            Method::CONNECT,
            "example.test:443",
            "example.test:443",
            1,
            exact_value_len + 1,
        );
        let error = expect_ingress_error(super::validate_standalone_connect_ingress_request(
            internal_partition_policy(&snapshot, &internal, &sensitive),
            IngressMode::ExplicitHttp,
            canonical(),
            byte_over,
        ));
        assert!(is_header_limit(&error));
    }

    #[test]
    fn standalone_connect_ingress_rejects_wrong_mode_target_framing_or_body() {
        fn request(body: Body) -> Request<Body> {
            Request::builder()
                .method(Method::CONNECT)
                .version(Version::HTTP_11)
                .uri("example.test:443")
                .header("host", "example.test:443")
                .body(body)
                .unwrap()
        }

        let https = || canonicalize_http_url("https://example.test/").unwrap();
        assert!(matches!(
            validate_standalone_connect_ingress_request(
                IngressMode::TransparentHttp,
                https(),
                request(Body::empty()),
            ),
            Err(ValidatedStandaloneIngressError::ConnectIngressMode)
        ));
        assert!(matches!(
            validate_standalone_connect_ingress_request(
                IngressMode::ExplicitHttp,
                canonicalize_http_url("http://example.test/").unwrap(),
                request(Body::empty()),
            ),
            Err(ValidatedStandaloneIngressError::ConnectTarget)
        ));

        let framed = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri("example.test:443")
            .header("host", "example.test:443")
            .header("content-length", "1")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            validate_standalone_connect_ingress_request(IngressMode::ExplicitHttp, https(), framed,),
            Err(ValidatedStandaloneIngressError::ConnectBody)
        ));
        assert!(matches!(
            validate_standalone_connect_ingress_request(
                IngressMode::ExplicitHttp,
                https(),
                request(Body::from("x")),
            ),
            Err(ValidatedStandaloneIngressError::ConnectBody)
        ));

        let (sender, pending) = Body::channel();
        assert!(matches!(
            validate_standalone_connect_ingress_request(
                IngressMode::ExplicitHttp,
                https(),
                request(pending),
            ),
            Err(ValidatedStandaloneIngressError::ConnectBody)
        ));
        drop(sender);

        let ordinary_connect = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri("example.test:443")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            validate_standalone_ingress_request(
                IngressMode::ExplicitHttp,
                https(),
                ordinary_connect,
            ),
            Err(ValidatedStandaloneIngressError::Headers(
                HeaderAdapterError::Hygiene(
                    http_access_runtime::HeaderHygieneError::ConnectUnsupported
                )
            ))
        ));
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

    fn sanitized_upgrade(
        protocol: &'static str,
    ) -> crate::proxy::headers::PendingForwardRequest<Body> {
        sanitize_product_request(
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
            upgrade_intent(websocket.upgrade_protocol()).unwrap(),
            Some(NeutralUpgradeIntent::WebSocket)
        );
        let opaque = sanitized_upgrade("test-echo/1");
        assert_eq!(
            upgrade_intent(opaque.upgrade_protocol()).unwrap(),
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
            HttpVersion::Http11,
            &HttpMethod::new("GET").unwrap(),
            canonicalize_http_url("http://example.test/socket").unwrap(),
            &neutral_headers(&headers).unwrap(),
            BodyMetadata::new(BodyFraming::ContentLength(0)),
            sanitized.upgrade_protocol(),
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
