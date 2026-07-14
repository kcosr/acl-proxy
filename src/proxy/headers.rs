use std::collections::HashSet;

use http::header::{HeaderMap, HeaderName, HeaderValue, HOST, TE};
use http::{Request, Uri, Version};
use hyper::Body;

use crate::url::CanonicalUrl;

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
}

pub(crate) fn prepare_origin_request(
    mut request: Request<Body>,
    canonical: &CanonicalUrl,
    target_form: RequestTargetForm,
    use_http2: bool,
) -> Result<Request<Body>, HeaderPreparationError> {
    strip_request_hop_by_hop(request.headers_mut(), use_http2);
    request.headers_mut().remove(HOST);

    if use_http2 {
        *request.uri_mut() = parse_uri(&canonical.url)?;
        *request.version_mut() = Version::HTTP_2;
    } else {
        *request.uri_mut() = match target_form {
            RequestTargetForm::Origin => parse_uri(&canonical_path_and_query(canonical))?,
            RequestTargetForm::Absolute => parse_uri(&canonical.url)?,
        };
        *request.version_mut() = Version::HTTP_11;
        request.headers_mut().insert(
            HOST,
            HeaderValue::from_str(&canonical.authority)
                .map_err(|_| HeaderPreparationError::Authority)?,
        );
    }
    Ok(request)
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
    match &canonical.query {
        Some(query) => format!("{}?{query}", canonical.path),
        None => canonical.path.clone(),
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
    use crate::url::canonicalize_http_url;

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
        let prepared = prepare_origin_request(
            request("/untrusted"),
            &canonical,
            RequestTargetForm::Origin,
            false,
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
        let prepared = prepare_origin_request(
            request("/untrusted"),
            &canonical,
            RequestTargetForm::Absolute,
            false,
        )
        .unwrap();

        assert_eq!(prepared.uri().to_string(), canonical.url);
        assert_eq!(prepared.headers()[HOST], canonical.authority);
    }

    #[test]
    fn h2_rebuilds_pseudo_authority_without_a_host_header() {
        let canonical = canonicalize_http_url("https://example.com:8443/resource").unwrap();
        let prepared = prepare_origin_request(
            request("/untrusted"),
            &canonical,
            RequestTargetForm::Origin,
            true,
        )
        .unwrap();

        assert_eq!(prepared.uri().to_string(), canonical.url);
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

        let prepared =
            prepare_origin_request(request, &canonical, RequestTargetForm::Origin, false).unwrap();

        assert!(!prepared.headers().contains_key(TE));
    }

    #[test]
    fn h2_retains_only_the_normalized_trailers_te_value() {
        let canonical = canonicalize_http_url("https://example.com/resource").unwrap();
        let mut trailers = request("/untrusted");
        trailers
            .headers_mut()
            .insert(TE, HeaderValue::from_static("Trailers"));
        let trailers =
            prepare_origin_request(trailers, &canonical, RequestTargetForm::Origin, true).unwrap();
        assert_eq!(trailers.headers()[TE], "trailers");

        let mut invalid = request("/untrusted");
        invalid
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers, deflate"));
        let invalid =
            prepare_origin_request(invalid, &canonical, RequestTargetForm::Origin, true).unwrap();
        assert!(!invalid.headers().contains_key(TE));
    }
}
