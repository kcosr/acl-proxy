use http::{HeaderMap, Request, Uri, Version};
use http_access_runtime::{
    prepare_upgrade_response_headers, sanitize_connect_request_head, sanitize_request_head,
    sanitize_response_headers, HeaderHygieneError, PreparedRequestHead,
    SanitizedConnectRequestHead, SanitizedRequestHead,
};
use http_access_types::{
    HeaderField, HeaderName, HeaderValue, HttpMethod, HttpProtocol, HttpVersion, ValueError,
};
use hyper::Body;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HeaderAdapterError {
    #[error(transparent)]
    Hygiene(#[from] HeaderHygieneError),
    #[error("the HTTP adapter cannot represent the checked method")]
    Method,
    #[error("the HTTP adapter cannot represent the checked request target")]
    Target,
    #[error("the HTTP adapter cannot represent a checked header name")]
    HeaderName,
    #[error("the HTTP adapter cannot represent a checked header value")]
    HeaderValue,
    #[error("request fact allocation failed")]
    Capacity,
    #[error("the HTTP adapter cannot represent this protocol version")]
    Version,
    #[error("request headers contain an invalid checked value")]
    Value(#[from] ValueError),
}

/// One runtime-sanitized request head and its original Hyper-owned transport
/// state. The body and extensions are never polled or copied by this adapter.
pub(crate) struct SanitizedIngressRequest {
    head: SanitizedRequestHead,
    parts: Box<http::request::Parts>,
    body: Body,
    downstream_upgrade: Option<hyper::upgrade::OnUpgrade>,
}

/// One runtime-sanitized outer CONNECT head and its original upgrade owner.
pub(crate) struct SanitizedConnectIngressRequest {
    head: SanitizedConnectRequestHead,
    parts: Box<http::request::Parts>,
    body: Body,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
}

pub(crate) struct PendingForwardRequest<B> {
    pub(crate) head: SanitizedRequestHead,
    pub(crate) parts: Box<http::request::Parts>,
    pub(crate) body: B,
}

impl<B> PendingForwardRequest<B> {
    pub(crate) fn ingress_protocol(&self) -> HttpProtocol {
        product_protocol(self.head.ingress_version())
    }

    pub(crate) fn upgrade_protocol(&self) -> Option<&http_access_types::UpgradeProtocol> {
        self.head.upgrade_protocol()
    }

    pub(crate) fn into_parts(self) -> (Box<http::request::Parts>, B, SanitizedRequestHead) {
        (self.parts, self.body, self.head)
    }
}

impl SanitizedIngressRequest {
    pub(crate) fn head(&self) -> &SanitizedRequestHead {
        &self.head
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<http::request::Parts>,
        Body,
        SanitizedRequestHead,
        Option<hyper::upgrade::OnUpgrade>,
    ) {
        (self.parts, self.body, self.head, self.downstream_upgrade)
    }
}

impl SanitizedConnectIngressRequest {
    pub(crate) fn head(&self) -> &SanitizedConnectRequestHead {
        &self.head
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<http::request::Parts>,
        Body,
        SanitizedConnectRequestHead,
        hyper::upgrade::OnUpgrade,
    ) {
        (self.parts, self.body, self.head, self.downstream_upgrade)
    }
}

/// Captures Hyper upgrade ownership before splitting the ingress request and
/// delegates all request-head semantics to the shared runtime.
pub(crate) fn sanitize_untrusted_ingress_request(
    mut request: Request<Body>,
) -> Result<SanitizedIngressRequest, HeaderAdapterError> {
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    let sanitized = sanitize_product_request(request)?;
    let downstream_upgrade = sanitized
        .head
        .upgrade_protocol()
        .is_some()
        .then_some(downstream_upgrade);
    Ok(SanitizedIngressRequest {
        head: sanitized.head,
        parts: sanitized.parts,
        body: sanitized.body,
        downstream_upgrade,
    })
}

pub(crate) fn sanitize_product_request<B>(
    request: Request<B>,
) -> Result<PendingForwardRequest<B>, HeaderAdapterError> {
    let (mut parts, body) = request.into_parts();
    let head = sanitize_request_head(
        neutral_version(parts.version)?,
        neutral_method(&parts.method)?,
        neutral_headers(&parts.headers)?,
    )?;
    parts.headers = HeaderMap::new();
    Ok(PendingForwardRequest {
        head,
        parts: Box::new(parts),
        body,
    })
}

pub(crate) fn sanitize_untrusted_connect_ingress_request(
    mut request: Request<Body>,
) -> Result<SanitizedConnectIngressRequest, HeaderAdapterError> {
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    let (mut parts, body) = request.into_parts();
    let head = sanitize_connect_request_head(
        neutral_version(parts.version)?,
        neutral_method(&parts.method)?,
        neutral_headers(&parts.headers)?,
    )?;
    parts.headers = HeaderMap::new();
    Ok(SanitizedConnectIngressRequest {
        head,
        parts: Box::new(parts),
        body,
        downstream_upgrade,
    })
}

pub(crate) fn neutral_version(version: Version) -> Result<HttpVersion, HeaderAdapterError> {
    match version {
        Version::HTTP_10 => Ok(HttpVersion::Http10),
        Version::HTTP_11 => Ok(HttpVersion::Http11),
        Version::HTTP_2 => Ok(HttpVersion::Http2),
        _ => Err(HeaderAdapterError::Version),
    }
}

pub(crate) fn product_protocol(version: HttpVersion) -> HttpProtocol {
    match version {
        HttpVersion::Http10 | HttpVersion::Http11 => HttpProtocol::Http1,
        HttpVersion::Http2 => HttpProtocol::Http2,
    }
}

pub(crate) fn neutral_method(method: &http::Method) -> Result<HttpMethod, HeaderAdapterError> {
    HttpMethod::new(method.as_str()).map_err(Into::into)
}

pub(crate) fn neutral_headers(headers: &HeaderMap) -> Result<Vec<HeaderField>, HeaderAdapterError> {
    let mut names: Vec<_> = headers.keys().cloned().collect();
    names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut fields = Vec::new();
    fields
        .try_reserve(headers.len())
        .map_err(|_| HeaderAdapterError::Capacity)?;
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

pub(crate) fn product_headers(fields: &[HeaderField]) -> Result<HeaderMap, HeaderAdapterError> {
    let mut headers = HeaderMap::new();
    headers
        .try_reserve(fields.len())
        .map_err(|_| HeaderAdapterError::Capacity)?;
    for field in fields {
        let name = http::HeaderName::from_bytes(field.name().as_str().as_bytes())
            .map_err(|_| HeaderAdapterError::HeaderName)?;
        let value = http::HeaderValue::from_bytes(field.value().as_bytes())
            .map_err(|_| HeaderAdapterError::HeaderValue)?;
        headers
            .try_append(name, value)
            .map_err(|_| HeaderAdapterError::Capacity)?;
    }
    Ok(headers)
}

pub(crate) fn replace_sanitized_headers(
    head: &mut SanitizedRequestHead,
    headers: &HeaderMap,
) -> Result<(), HeaderAdapterError> {
    *head.headers_mut() = neutral_headers(headers)?;
    Ok(())
}

pub(crate) fn sanitize_product_response_headers(
    headers: &mut HeaderMap,
) -> Result<(), HeaderAdapterError> {
    let sanitized = sanitize_response_headers(neutral_headers(headers)?)?;
    *headers = product_headers(&sanitized)?;
    Ok(())
}

pub(crate) fn prepare_product_upgrade_response(
    status: http::StatusCode,
    headers: &mut HeaderMap,
    protocol: &http_access_types::UpgradeProtocol,
) -> Result<(), HeaderAdapterError> {
    let prepared =
        prepare_upgrade_response_headers(status.as_u16(), neutral_headers(headers)?, protocol)?;
    *headers = product_headers(&prepared)?;
    Ok(())
}

/// Rebuilds a Hyper request from the runtime's final prepared head while
/// preserving body, extensions, and the reserved header-map allocation.
/// Credential publication occurs only after this conversion, so secret values
/// never enter neutral `HeaderValue` storage.
pub(crate) fn apply_prepared_head<B>(
    request: Request<B>,
    prepared: PreparedRequestHead,
) -> Result<Request<B>, HeaderAdapterError> {
    let (mut parts, body) = request.into_parts();
    let (method, protocol, target, headers, _upgrade) = prepared.into_parts();
    parts.method = http::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|_| HeaderAdapterError::Method)?;
    parts.version = match protocol {
        HttpProtocol::Http1 => Version::HTTP_11,
        HttpProtocol::Http2 => Version::HTTP_2,
    };
    parts.uri = target
        .rendered()
        .parse::<Uri>()
        .map_err(|_| HeaderAdapterError::Target)?;
    parts.headers.clear();
    parts
        .headers
        .try_reserve(headers.len())
        .map_err(|_| HeaderAdapterError::Capacity)?;
    for field in &headers {
        let name = http::HeaderName::from_bytes(field.name().as_str().as_bytes())
            .map_err(|_| HeaderAdapterError::HeaderName)?;
        let value = http::HeaderValue::from_bytes(field.value().as_bytes())
            .map_err(|_| HeaderAdapterError::HeaderValue)?;
        parts
            .headers
            .try_append(name, value)
            .map_err(|_| HeaderAdapterError::Capacity)?;
    }
    Ok(Request::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use http::header::{CONNECTION, UPGRADE};
    use hyper::body::HttpBody;

    use super::*;

    #[test]
    fn ingress_adapter_preserves_body_extensions_and_upgrade_owner() {
        #[derive(Clone, Copy)]
        struct Marker;

        let mut request = Request::builder()
            .method("GET")
            .version(Version::HTTP_11)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "WebSocket")
            .body(Body::from("payload"))
            .unwrap();
        request.extensions_mut().insert(Marker);

        let sanitized = sanitize_untrusted_ingress_request(request).unwrap();
        assert_eq!(
            sanitized.head().upgrade_protocol().unwrap().as_str(),
            "WebSocket"
        );
        let (parts, body, _, on_upgrade) = sanitized.into_parts();
        assert!(parts.extensions.get::<Marker>().is_some());
        assert_eq!(body.size_hint().exact(), Some(7));
        assert!(on_upgrade.is_some());
    }

    #[test]
    fn neutral_product_conversion_preserves_duplicate_order() {
        let mut headers = HeaderMap::new();
        headers.append("x-test", http::HeaderValue::from_static("one"));
        headers.append("x-test", http::HeaderValue::from_static("two"));
        let neutral = neutral_headers(&headers).unwrap();
        let product = product_headers(&neutral).unwrap();
        let values = product
            .get_all("x-test")
            .iter()
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>();
        assert_eq!(values, vec![b"one".as_slice(), b"two".as_slice()]);
    }
}
