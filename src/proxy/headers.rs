use std::collections::HashSet;

use http::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, TE, UPGRADE};
use http::{Request, StatusCode, Uri, Version};
use http_access_types::CanonicalUrl;
use hyper::Body;

use crate::egress::OriginProtocol;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestTargetForm {
    Origin,
    Absolute,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HeaderPreparationError {
    #[error("the canonical request target cannot be represented on the wire")]
    Target,
    #[error("the canonical authority cannot be represented as an HTTP header")]
    Authority,
    #[error("the ingress HTTP version cannot be forwarded")]
    UnsupportedVersion,
    #[error("HTTP upgrade requests require the dedicated upgrade executor")]
    UpgradeUnsupported,
    #[error("the HTTP upgrade handshake is malformed or unsupported")]
    InvalidUpgrade,
    #[error("CONNECT requests require the dedicated CONNECT executor")]
    ConnectUnsupported,
    #[error("trusted request effects introduced a forbidden hop-by-hop header")]
    Unsanitized,
    #[error("the Connection header contains an invalid nominated field name")]
    InvalidConnection,
}

pub(crate) struct SanitizedRequest<B = Body> {
    request: Request<B>,
    protocol: OriginProtocol,
    upgrade_intent: Option<UpgradeIntent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeIntent {
    protocol: HeaderValue,
}

impl UpgradeIntent {
    pub(crate) fn protocol(&self) -> &HeaderValue {
        &self.protocol
    }
}

impl<B> SanitizedRequest<B> {
    pub(crate) fn headers_mut(&mut self) -> &mut HeaderMap {
        self.request.headers_mut()
    }

    pub(crate) fn protocol(&self) -> OriginProtocol {
        self.protocol
    }

    pub(crate) fn version(&self) -> Version {
        self.request.version()
    }

    pub(crate) fn method(&self) -> &http::Method {
        self.request.method()
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        self.request.headers()
    }

    pub(crate) fn upgrade_intent(&self) -> Option<&UpgradeIntent> {
        self.upgrade_intent.as_ref()
    }

    pub(crate) fn into_parts(self) -> (http::request::Parts, B, OriginProtocol) {
        let (mut parts, body) = self.request.into_parts();
        if let Some(intent) = self.upgrade_intent {
            parts.extensions.insert(intent);
        }
        (parts, body, self.protocol)
    }

    pub(crate) fn from_parts(
        mut parts: http::request::Parts,
        body: B,
        protocol: OriginProtocol,
    ) -> Self {
        let upgrade_intent = parts.extensions.remove::<UpgradeIntent>();
        Self {
            request: Request::from_parts(parts, body),
            protocol,
            upgrade_intent,
        }
    }
}

/// Removes attacker-controlled hop-by-hop headers before any trusted request
/// effect, credential, identity, or loop-marker mutation is applied.
pub(crate) fn sanitize_untrusted_request<B>(
    mut request: Request<B>,
) -> Result<SanitizedRequest<B>, HeaderPreparationError> {
    if request.method() == http::Method::CONNECT {
        return Err(HeaderPreparationError::ConnectUnsupported);
    }
    let protocol = match request.version() {
        Version::HTTP_10 | Version::HTTP_11 => OriginProtocol::Http1,
        Version::HTTP_2 => OriginProtocol::Http2,
        _ => return Err(HeaderPreparationError::UnsupportedVersion),
    };
    let connection_tokens = strict_connection_header_tokens(request.headers())?;
    let upgrade_intent =
        extract_upgrade_intent(request.version(), request.headers(), &connection_tokens)?;
    strip_request_hop_by_hop(request.headers_mut(), protocol.is_http2());
    Ok(SanitizedRequest {
        request,
        protocol,
        upgrade_intent,
    })
}

/// Sanitizes the outer HTTP/1 CONNECT control request before policy evaluation.
/// CONNECT is never forwarded as an origin request, so it cannot carry an
/// upgrade intent or retain caller-controlled hop-by-hop fields.
pub(crate) fn sanitize_untrusted_connect_request<B>(
    mut request: Request<B>,
) -> Result<SanitizedRequest<B>, HeaderPreparationError> {
    if request.method() != http::Method::CONNECT {
        return Err(HeaderPreparationError::ConnectUnsupported);
    }
    if !matches!(request.version(), Version::HTTP_10 | Version::HTTP_11) {
        return Err(HeaderPreparationError::UnsupportedVersion);
    }
    let connection_tokens = strict_connection_header_tokens(request.headers())?;
    if extract_upgrade_intent(request.version(), request.headers(), &connection_tokens)?.is_some() {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    strip_request_hop_by_hop(request.headers_mut(), false);
    Ok(SanitizedRequest {
        request,
        protocol: OriginProtocol::Http1,
        upgrade_intent: None,
    })
}

fn extract_upgrade_intent(
    version: Version,
    headers: &HeaderMap,
    connection_tokens: &HashSet<HeaderName>,
) -> Result<Option<UpgradeIntent>, HeaderPreparationError> {
    let has_upgrade_header = headers.contains_key(UPGRADE);
    let nominates_upgrade = connection_tokens.contains(&UPGRADE);
    if !has_upgrade_header && !nominates_upgrade {
        return Ok(None);
    }
    if version != Version::HTTP_11 || !has_upgrade_header || !nominates_upgrade {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    let protocol = single_upgrade_protocol(headers)?;
    Ok(Some(UpgradeIntent { protocol }))
}

fn single_upgrade_protocol(headers: &HeaderMap) -> Result<HeaderValue, HeaderPreparationError> {
    let mut values = headers.get_all(UPGRADE).iter();
    let value = values
        .next()
        .ok_or(HeaderPreparationError::InvalidUpgrade)?;
    if values.next().is_some() {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    let protocol = value
        .to_str()
        .map_err(|_| HeaderPreparationError::InvalidUpgrade)?;
    if !valid_upgrade_protocol(protocol) {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    Ok(value.clone())
}

fn valid_upgrade_protocol(value: &str) -> bool {
    let mut parts = value.split('/');
    let Some(name) = parts.next() else {
        return false;
    };
    if !is_http_token(name) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(version), None) => is_http_token(version),
        _ => false,
    }
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn strict_connection_header_tokens(
    headers: &HeaderMap,
) -> Result<HashSet<HeaderName>, HeaderPreparationError> {
    let mut tokens = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION).iter() {
        let value = value
            .to_str()
            .map_err(|_| HeaderPreparationError::InvalidConnection)?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(HeaderPreparationError::InvalidConnection);
            }
            tokens.insert(
                HeaderName::from_bytes(token.as_bytes())
                    .map_err(|_| HeaderPreparationError::InvalidConnection)?,
            );
        }
    }
    Ok(tokens)
}

pub(crate) fn prepare_origin_request<B>(
    sanitized: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    target_form: RequestTargetForm,
    protocol: OriginProtocol,
) -> Result<Request<B>, HeaderPreparationError> {
    if sanitized.upgrade_intent.is_some() {
        return Err(HeaderPreparationError::UpgradeUnsupported);
    }
    prepare_origin_request_head(sanitized, canonical, target_form, protocol)
}

pub(crate) fn prepare_origin_upgrade_request<B>(
    sanitized: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    target_form: RequestTargetForm,
    protocol: OriginProtocol,
) -> Result<Request<B>, HeaderPreparationError> {
    if protocol.is_http2() {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    let intent = sanitized
        .upgrade_intent
        .clone()
        .ok_or(HeaderPreparationError::InvalidUpgrade)?;
    let mut request = prepare_origin_request_head(sanitized, canonical, target_form, protocol)?;
    request
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    request
        .headers_mut()
        .insert(UPGRADE, intent.protocol().clone());
    Ok(request)
}

fn prepare_origin_request_head<B>(
    mut sanitized: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    target_form: RequestTargetForm,
    protocol: OriginProtocol,
) -> Result<Request<B>, HeaderPreparationError> {
    let use_http2 = protocol.is_http2();
    if !use_http2 && te_is_trailers_only(sanitized.request.headers()) {
        sanitized.request.headers_mut().remove(TE);
    }
    if sanitized.request.headers().keys().any(|name| {
        is_hop_by_hop(name)
            && !(use_http2 && *name == TE && te_is_trailers_only(sanitized.request.headers()))
    }) {
        return Err(HeaderPreparationError::Unsanitized);
    }
    let request = &mut sanitized.request;
    request.headers_mut().remove(HOST);

    if use_http2 {
        *request.uri_mut() = parse_uri(canonical.as_str())?;
        *request.version_mut() = Version::HTTP_2;
    } else {
        *request.uri_mut() = match target_form {
            RequestTargetForm::Origin => parse_uri(&canonical_path_and_query(canonical))?,
            RequestTargetForm::Absolute => parse_uri(canonical.as_str())?,
        };
        *request.version_mut() = Version::HTTP_11;
        request.headers_mut().insert(
            HOST,
            HeaderValue::from_str(canonical.authority().as_str())
                .map_err(|_| HeaderPreparationError::Authority)?,
        );
    }
    Ok(sanitized.request)
}

/// Validates a `101 Switching Protocols` head and replaces its hop headers
/// with the canonical downstream handshake for the accepted request intent.
pub(crate) fn prepare_downstream_upgrade_response(
    status: StatusCode,
    headers: &mut HeaderMap,
    request_intent: &UpgradeIntent,
) -> Result<(), HeaderPreparationError> {
    if status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    let connection_tokens = strict_connection_header_tokens(headers)?;
    if !connection_tokens.contains(&UPGRADE) {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    let response_protocol = single_upgrade_protocol(headers)?;
    let response_protocol = response_protocol
        .to_str()
        .map_err(|_| HeaderPreparationError::InvalidUpgrade)?;
    let request_protocol = request_intent
        .protocol()
        .to_str()
        .map_err(|_| HeaderPreparationError::InvalidUpgrade)?;
    if !response_protocol.eq_ignore_ascii_case(request_protocol) {
        return Err(HeaderPreparationError::InvalidUpgrade);
    }
    strip_response_hop_by_hop(headers);
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, request_intent.protocol().clone());
    Ok(())
}

pub(crate) fn strip_response_hop_by_hop(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers, false);
}

fn strip_request_hop_by_hop(headers: &mut HeaderMap, use_http2: bool) {
    let retain_h2_trailers = use_http2 && te_is_trailers_only(headers);
    strip_hop_by_hop(headers, retain_h2_trailers);
    if retain_h2_trailers {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap, retain_h2_trailers: bool) {
    let connection_tokens = connection_header_tokens(headers);
    let names = headers
        .keys()
        .filter(|name| {
            !(retain_h2_trailers && *name == TE)
                && (is_hop_by_hop(name) || connection_tokens.contains(*name))
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        headers.remove(name);
    }
}

fn te_is_trailers_only(headers: &HeaderMap) -> bool {
    let mut saw_value = false;
    for value in headers.get_all(TE).iter() {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for token in value.split(',') {
            saw_value = true;
            if !token.trim().eq_ignore_ascii_case("trailers") {
                return false;
            }
        }
    }
    saw_value
}

fn canonical_path_and_query(canonical: &CanonicalUrl) -> String {
    match canonical.query() {
        Some(query) => format!("{}?{query}", canonical.path()),
        None => canonical.path().to_owned(),
    }
}

fn parse_uri(value: &str) -> Result<Uri, HeaderPreparationError> {
    value.parse().map_err(|_| HeaderPreparationError::Target)
}

fn connection_header_tokens(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use http::header::{AUTHORIZATION, CONNECTION, HOST};

    use super::*;
    use http_access_url::canonicalize_http_url;

    fn request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(HOST, "client-spelling.example")
            .header(CONNECTION, "keep-alive, x-private")
            .header("keep-alive", "timeout=10")
            .header("x-private", "remove-me")
            .header("proxy-authorization", "Basic parent-secret")
            .header(AUTHORIZATION, "Bearer origin-secret")
            .header("x-end-to-end", "preserve-me")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn h1_origin_form_rebuilds_authority_and_preserves_canonical_encoding() {
        let canonical =
            canonicalize_http_url("https://EXAMPLE.com:8443/a%2fb/../c?project=group%2fproject")
                .unwrap();
        let sanitized = sanitize_untrusted_request(request("/untrusted")).unwrap();
        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();

        assert_eq!(prepared.uri().to_string(), "/c?project=group%2Fproject");
        assert_eq!(prepared.headers()[HOST], "example.com:8443");
        assert_eq!(prepared.headers()[AUTHORIZATION], "Bearer origin-secret");
        assert_eq!(prepared.headers()["x-end-to-end"], "preserve-me");
        assert!(!prepared.headers().contains_key(CONNECTION));
        assert!(!prepared.headers().contains_key("keep-alive"));
        assert!(!prepared.headers().contains_key("x-private"));
        assert!(!prepared.headers().contains_key("proxy-authorization"));
    }

    #[test]
    fn h1_parent_uses_exact_absolute_form() {
        let canonical = canonicalize_http_url("http://example.com/a%2fb?q=%7e").unwrap();
        let sanitized = sanitize_untrusted_request(request("/untrusted")).unwrap();
        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Absolute,
            OriginProtocol::Http1,
        )
        .unwrap();

        assert_eq!(prepared.uri().to_string(), canonical.as_str());
        assert_eq!(prepared.headers()[HOST], canonical.authority().as_str());
    }

    #[test]
    fn h2_rebuilds_pseudo_authority_without_a_host_header() {
        let canonical = canonicalize_http_url("https://example.com:8443/resource").unwrap();
        let mut request = request("/untrusted");
        *request.version_mut() = Version::HTTP_2;
        let sanitized = sanitize_untrusted_request(request).unwrap();
        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http2,
        )
        .unwrap();

        assert_eq!(prepared.uri().to_string(), canonical.as_str());
        assert_eq!(prepared.version(), Version::HTTP_2);
        assert!(!prepared.headers().contains_key(HOST));
    }

    #[test]
    fn response_hygiene_removes_connection_nominated_and_proxy_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("x-private"));
        headers.insert("x-private", HeaderValue::from_static("secret"));
        headers.insert(
            "proxy-authenticate",
            HeaderValue::from_static("Basic realm=parent"),
        );
        headers.insert("x-end-to-end", HeaderValue::from_static("visible"));

        strip_response_hop_by_hop(&mut headers);

        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-private"));
        assert!(!headers.contains_key("proxy-authenticate"));
        assert_eq!(headers["x-end-to-end"], "visible");
    }

    #[test]
    fn h1_strips_te_even_when_the_client_only_offers_trailers() {
        let canonical = canonicalize_http_url("http://example.com/resource").unwrap();
        let mut request = request("/untrusted");
        request
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers"));

        let sanitized = sanitize_untrusted_request(request).unwrap();
        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();

        assert!(!prepared.headers().contains_key(TE));
    }

    #[test]
    fn h2_retains_only_the_normalized_trailers_te_value() {
        let canonical = canonicalize_http_url("https://example.com/resource").unwrap();
        let mut trailers = request("/untrusted");
        trailers
            .headers_mut()
            .insert(TE, HeaderValue::from_static("Trailers"));
        *trailers.version_mut() = Version::HTTP_2;
        let trailers = sanitize_untrusted_request(trailers).unwrap();
        let trailers = prepare_origin_request(
            trailers,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http2,
        )
        .unwrap();
        assert_eq!(trailers.headers()[TE], "trailers");

        let mut invalid = request("/untrusted");
        invalid
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers, deflate"));
        *invalid.version_mut() = Version::HTTP_2;
        let invalid = sanitize_untrusted_request(invalid).unwrap();
        let invalid = prepare_origin_request(
            invalid,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http2,
        )
        .unwrap();
        assert!(!invalid.headers().contains_key(TE));
    }

    #[test]
    fn attacker_connection_tokens_are_consumed_before_trusted_injection() {
        let canonical = canonicalize_http_url("http://example.com/resource").unwrap();
        let mut request = request("/untrusted");
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("x-injected"));
        request
            .headers_mut()
            .insert("x-injected", HeaderValue::from_static("attacker"));
        let mut sanitized = sanitize_untrusted_request(request).unwrap();
        assert!(!sanitized.headers_mut().contains_key("x-injected"));

        sanitized
            .headers_mut()
            .insert("x-injected", HeaderValue::from_static("trusted"));
        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();
        assert_eq!(prepared.headers()["x-injected"], "trusted");
    }

    #[test]
    fn trusted_hop_header_mutation_fails_closed() {
        let canonical = canonicalize_http_url("http://example.com/resource").unwrap();
        let mut sanitized = sanitize_untrusted_request(request("/untrusted")).unwrap();
        sanitized
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));

        assert!(matches!(
            prepare_origin_request(
                sanitized,
                &canonical,
                RequestTargetForm::Origin,
                OriginProtocol::Http1,
            ),
            Err(HeaderPreparationError::Unsanitized)
        ));
    }

    #[test]
    fn h2_trailers_te_is_removed_when_selected_origin_is_h1() {
        let canonical = canonicalize_http_url("http://example.com/resource").unwrap();
        let mut request = request("/untrusted");
        *request.version_mut() = Version::HTTP_2;
        request
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers"));
        let sanitized = sanitize_untrusted_request(request).unwrap();

        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();

        assert_eq!(prepared.version(), Version::HTTP_11);
        assert_eq!(prepared.uri(), "/resource");
        assert_eq!(prepared.headers()[HOST], "example.com");
        assert!(!prepared.headers().contains_key(TE));
    }

    #[test]
    fn trusted_trailers_te_is_retained_when_selected_origin_is_h2() {
        let canonical = canonicalize_http_url("https://example.com/resource").unwrap();
        let mut sanitized = sanitize_untrusted_request(request("/untrusted")).unwrap();
        sanitized
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers"));

        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http2,
        )
        .unwrap();

        assert_eq!(prepared.version(), Version::HTTP_2);
        assert_eq!(prepared.uri().to_string(), canonical.as_str());
        assert!(!prepared.headers().contains_key(HOST));
        assert_eq!(prepared.headers()[TE], "trailers");
    }

    #[test]
    fn trusted_trailers_te_is_removed_when_selected_origin_is_h1() {
        let canonical = canonicalize_http_url("http://example.com/resource").unwrap();
        let mut sanitized = sanitize_untrusted_request(request("/untrusted")).unwrap();
        sanitized
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers"));

        let prepared = prepare_origin_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();

        assert_eq!(prepared.version(), Version::HTTP_11);
        assert_eq!(prepared.uri(), "/resource");
        assert_eq!(prepared.headers()[HOST], "example.com");
        assert!(!prepared.headers().contains_key(TE));
    }

    #[test]
    fn valid_upgrade_intent_is_typed_before_hop_header_sanitization() {
        let request = Request::builder()
            .version(Version::HTTP_11)
            .header(CONNECTION, "keep-alive, Upgrade, x-private")
            .header(UPGRADE, "WebSocket/13")
            .header("x-private", "remove-me")
            .body(Body::empty())
            .unwrap();

        let sanitized = sanitize_untrusted_request(request).unwrap();
        assert_eq!(
            sanitized.upgrade_intent().unwrap().protocol(),
            "WebSocket/13"
        );
        assert!(!sanitized.request.headers().contains_key(CONNECTION));
        assert!(!sanitized.request.headers().contains_key(UPGRADE));
        assert!(!sanitized.request.headers().contains_key("x-private"));

        let (parts, body, protocol) = sanitized.into_parts();
        let sanitized = SanitizedRequest::from_parts(parts, body, protocol);
        assert_eq!(
            sanitized.upgrade_intent().unwrap().protocol(),
            "WebSocket/13"
        );
    }

    #[test]
    fn malformed_and_h2_upgrade_intents_fail_closed() {
        for request in [
            Request::builder()
                .version(Version::HTTP_11)
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "websocket, h2c")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .version(Version::HTTP_11)
                .header(UPGRADE, "custom")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .version(Version::HTTP_11)
                .header(CONNECTION, "upgrade")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .version(Version::HTTP_2)
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "websocket")
                .body(Body::empty())
                .unwrap(),
        ] {
            assert!(matches!(
                sanitize_untrusted_request(request),
                Err(HeaderPreparationError::InvalidUpgrade)
            ));
        }
    }

    #[test]
    fn dedicated_upgrade_request_restores_only_canonical_handshake_headers() {
        let canonical = canonicalize_http_url("https://example.com/socket").unwrap();
        let request = Request::builder()
            .version(Version::HTTP_11)
            .header(CONNECTION, "Upgrade, x-private")
            .header(UPGRADE, "WebSocket")
            .header("x-private", "attacker")
            .body(Body::empty())
            .unwrap();
        let sanitized = sanitize_untrusted_request(request).unwrap();

        let prepared = prepare_origin_upgrade_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();

        assert_eq!(prepared.uri(), "/socket");
        assert_eq!(prepared.headers()[HOST], "example.com");
        assert_eq!(prepared.headers()[CONNECTION], "upgrade");
        assert_eq!(prepared.headers()[UPGRADE], "WebSocket");
        assert!(!prepared.headers().contains_key("x-private"));
    }

    #[test]
    fn upgrade_response_is_validated_and_canonicalized() {
        let request = Request::builder()
            .version(Version::HTTP_11)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "WebSocket")
            .body(Body::empty())
            .unwrap();
        let intent = sanitize_untrusted_request(request)
            .unwrap()
            .upgrade_intent()
            .unwrap()
            .clone();
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("x-private, Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert("x-private", HeaderValue::from_static("remove-me"));

        prepare_downstream_upgrade_response(StatusCode::SWITCHING_PROTOCOLS, &mut headers, &intent)
            .unwrap();

        assert_eq!(headers[CONNECTION], "upgrade");
        assert_eq!(headers[UPGRADE], "WebSocket");
        assert!(!headers.contains_key("x-private"));

        assert!(matches!(
            prepare_downstream_upgrade_response(StatusCode::OK, &mut headers, &intent),
            Err(HeaderPreparationError::InvalidUpgrade)
        ));
    }

    #[test]
    fn h1_and_h2_connect_require_the_dedicated_executor() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let request = Request::builder()
                .method(http::Method::CONNECT)
                .version(version)
                .uri("example.com:443")
                .body(Body::empty())
                .unwrap();
            assert!(matches!(
                sanitize_untrusted_request(request),
                Err(HeaderPreparationError::ConnectUnsupported)
            ));
        }
    }

    #[test]
    fn malformed_connection_token_list_fails_closed() {
        let request = Request::builder()
            .version(Version::HTTP_11)
            .header(CONNECTION, "keep-alive,,x-private")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            sanitize_untrusted_request(request),
            Err(HeaderPreparationError::InvalidConnection)
        ));
    }
}
