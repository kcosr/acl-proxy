use http::header::{HeaderMap, HeaderValue, HOST};
use http::{Method, Request, Uri, Version};

use crate::url::{
    canonicalize_http_authority, canonicalize_http_url_from_parts, canonicalize_tls_server_name,
    CanonicalAuthority, CanonicalUrl,
};

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityError {
    #[error("invalid request target")]
    InvalidRequestTarget,
    #[error("request target has the wrong form for this listener")]
    RequestTargetForm,
    #[error("request target has the wrong scheme for this listener")]
    SchemeMismatch,
    #[error("required authority is missing")]
    MissingAuthority,
    #[error("Host header is missing")]
    MissingHost,
    #[error("Host header is duplicated")]
    DuplicateHost,
    #[error("authority is invalid")]
    InvalidAuthority,
    #[error("authority sources conflict")]
    ConflictingAuthority,
    #[error("CONNECT requires an explicit nonzero port")]
    MissingConnectPort,
    #[error("CONNECT is not supported for this HTTP version")]
    UnsupportedConnectVersion,
    #[error("CONNECT must use the dedicated CONNECT reconciliation path")]
    ConnectMethod,
    #[error("TLS SNI is missing")]
    MissingSni,
    #[error("TLS SNI is invalid")]
    InvalidSni,
    #[error("transparent TLS destination port must be nonzero")]
    InvalidDestinationPort,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) struct CanonicalRequestTarget {
    pub(crate) url: CanonicalUrl,
    pub(crate) uri: Uri,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) struct CanonicalConnectTarget {
    pub(crate) authority: CanonicalAuthority,
    pub(crate) url: CanonicalUrl,
}

pub(crate) fn reconcile_explicit_request<B>(
    request: &mut Request<B>,
) -> Result<CanonicalRequestTarget, AuthorityError> {
    reject_connect_method(request)?;
    let canonical = canonical_absolute_request_target(request.uri())?;
    let host = read_host(
        request.headers(),
        &canonical.scheme,
        HostRequirement::Optional,
    )?;
    require_equal(host.as_ref(), &canonical_authority(&canonical))?;
    let target = request_target(canonical)?;
    rebuild_request(request, &target)?;
    Ok(target)
}

pub(crate) fn reconcile_transparent_http_request<B>(
    request: &mut Request<B>,
) -> Result<CanonicalRequestTarget, AuthorityError> {
    reject_connect_method(request)?;
    let canonical = if request.version() == Version::HTTP_2 {
        let canonical = canonical_absolute_request_target(request.uri())?;
        if canonical.scheme != "http" {
            return Err(AuthorityError::SchemeMismatch);
        }
        let host = read_host(request.headers(), "http", HostRequirement::Optional)?;
        require_equal(host.as_ref(), &canonical_authority(&canonical))?;
        canonical
    } else {
        require_origin_form(request.uri())?;
        let host = read_host(request.headers(), "http", HostRequirement::Required)?
            .ok_or(AuthorityError::MissingHost)?;
        canonicalize_http_url_from_parts("http", &host.authority, path_and_query(request.uri()))
            .map_err(|_| AuthorityError::InvalidRequestTarget)?
    };

    let target = request_target(canonical)?;
    rebuild_request(request, &target)?;
    Ok(target)
}

pub(crate) fn reconcile_connect_outer_request<B>(
    request: &mut Request<B>,
) -> Result<CanonicalConnectTarget, AuthorityError> {
    if request.method() != Method::CONNECT {
        return Err(AuthorityError::RequestTargetForm);
    }
    if request.version() == Version::HTTP_2 {
        return Err(AuthorityError::UnsupportedConnectVersion);
    }
    if request.uri().scheme().is_some() || request.uri().path_and_query().is_some() {
        return Err(AuthorityError::RequestTargetForm);
    }
    let raw_authority = request
        .uri()
        .authority()
        .ok_or(AuthorityError::MissingAuthority)?;
    if raw_authority.port_u16().is_none() {
        return Err(AuthorityError::MissingConnectPort);
    }

    let authority = canonicalize_http_authority("https", raw_authority.as_str())
        .map_err(|_| AuthorityError::InvalidAuthority)?;
    let host = read_host(request.headers(), "https", HostRequirement::Required)?
        .ok_or(AuthorityError::MissingHost)?;
    require_equal(Some(&host), &authority)?;

    let canonical_url = canonicalize_http_url_from_parts("https", &authority.authority, "/")
        .map_err(|_| AuthorityError::InvalidRequestTarget)?;
    let connect_authority = authority.connect_authority();
    let uri = connect_authority
        .parse::<Uri>()
        .map_err(|_| AuthorityError::InvalidRequestTarget)?;
    let host =
        HeaderValue::from_str(&connect_authority).map_err(|_| AuthorityError::InvalidAuthority)?;

    *request.uri_mut() = uri.clone();
    request.headers_mut().remove(HOST);
    request.headers_mut().insert(HOST, host);

    Ok(CanonicalConnectTarget {
        authority,
        url: canonical_url,
    })
}

pub(crate) fn reconcile_connect_sni(
    target: &CanonicalConnectTarget,
    sni: Option<&str>,
) -> Result<(), AuthorityError> {
    let Some(sni) = sni else {
        return Ok(());
    };
    let host = canonicalize_tls_server_name(sni).map_err(|_| AuthorityError::InvalidSni)?;
    if host != target.authority.host {
        return Err(AuthorityError::ConflictingAuthority);
    }
    Ok(())
}

pub(crate) fn reconcile_connect_inner_request<B>(
    request: &mut Request<B>,
    connect: &CanonicalConnectTarget,
) -> Result<CanonicalRequestTarget, AuthorityError> {
    reject_connect_method(request)?;
    let canonical = if request.version() == Version::HTTP_2 {
        let canonical = canonical_absolute_request_target(request.uri())?;
        if canonical.scheme != "https" {
            return Err(AuthorityError::SchemeMismatch);
        }
        require_equal_authority(&canonical, &connect.authority)?;
        let host = read_host(request.headers(), "https", HostRequirement::Optional)?;
        require_equal(host.as_ref(), &connect.authority)?;
        canonical
    } else {
        let host = read_host(request.headers(), "https", HostRequirement::Required)?
            .ok_or(AuthorityError::MissingHost)?;
        require_equal(Some(&host), &connect.authority)?;
        if request.uri().scheme().is_some() || request.uri().authority().is_some() {
            let canonical = canonical_absolute_request_target(request.uri())?;
            if canonical.scheme != "https" {
                return Err(AuthorityError::SchemeMismatch);
            }
            require_equal_authority(&canonical, &connect.authority)?;
            canonical
        } else {
            require_origin_form(request.uri())?;
            canonicalize_http_url_from_parts(
                "https",
                &connect.authority.authority,
                path_and_query(request.uri()),
            )
            .map_err(|_| AuthorityError::InvalidRequestTarget)?
        }
    };

    let target = request_target(canonical)?;
    rebuild_request(request, &target)?;
    Ok(target)
}

pub(crate) fn reconcile_transparent_https_request<B>(
    request: &mut Request<B>,
    destination_port: u16,
    sni: Option<&str>,
) -> Result<CanonicalRequestTarget, AuthorityError> {
    reject_connect_method(request)?;
    if destination_port == 0 {
        return Err(AuthorityError::InvalidDestinationPort);
    }
    let sni = sni.ok_or(AuthorityError::MissingSni)?;
    let sni_host = canonicalize_tls_server_name(sni).map_err(|_| AuthorityError::InvalidSni)?;
    let primary = canonicalize_http_authority("https", &format!("{sni_host}:{destination_port}"))
        .map_err(|_| AuthorityError::InvalidDestinationPort)?;

    let canonical = if request.version() == Version::HTTP_2 {
        let canonical = canonical_absolute_request_target(request.uri())?;
        if canonical.scheme != "https" {
            return Err(AuthorityError::SchemeMismatch);
        }
        require_equal_authority(&canonical, &primary)?;
        let host = read_host(request.headers(), "https", HostRequirement::Optional)?;
        require_equal(host.as_ref(), &primary)?;
        canonical
    } else {
        require_origin_form(request.uri())?;
        let host = read_host(request.headers(), "https", HostRequirement::Required)?
            .ok_or(AuthorityError::MissingHost)?;
        require_equal(Some(&host), &primary)?;
        canonicalize_http_url_from_parts("https", &primary.authority, path_and_query(request.uri()))
            .map_err(|_| AuthorityError::InvalidRequestTarget)?
    };
    let target = request_target(canonical)?;
    rebuild_request(request, &target)?;
    Ok(target)
}

#[derive(Clone, Copy)]
enum HostRequirement {
    Optional,
    Required,
}

fn reject_connect_method<B>(request: &Request<B>) -> Result<(), AuthorityError> {
    if request.method() == Method::CONNECT {
        return Err(AuthorityError::ConnectMethod);
    }
    Ok(())
}

fn read_host(
    headers: &HeaderMap,
    scheme: &str,
    requirement: HostRequirement,
) -> Result<Option<CanonicalAuthority>, AuthorityError> {
    let mut values = headers.get_all(HOST).iter();
    let Some(value) = values.next() else {
        return match requirement {
            HostRequirement::Optional => Ok(None),
            HostRequirement::Required => Err(AuthorityError::MissingHost),
        };
    };
    if values.next().is_some() {
        return Err(AuthorityError::DuplicateHost);
    }
    let value = value
        .to_str()
        .map_err(|_| AuthorityError::InvalidAuthority)?;
    canonicalize_http_authority(scheme, value)
        .map(Some)
        .map_err(|_| AuthorityError::InvalidAuthority)
}

fn canonical_absolute_request_target(uri: &Uri) -> Result<CanonicalUrl, AuthorityError> {
    let scheme = uri.scheme_str().ok_or(AuthorityError::MissingAuthority)?;
    let authority = uri.authority().ok_or(AuthorityError::MissingAuthority)?;
    canonicalize_http_url_from_parts(scheme, authority.as_str(), path_and_query(uri))
        .map_err(|_| AuthorityError::InvalidRequestTarget)
}

fn require_origin_form(uri: &Uri) -> Result<(), AuthorityError> {
    if uri.scheme().is_some() || uri.authority().is_some() || !path_and_query(uri).starts_with('/')
    {
        return Err(AuthorityError::RequestTargetForm);
    }
    Ok(())
}

fn path_and_query(uri: &Uri) -> &str {
    uri.path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
}

fn canonical_authority(url: &CanonicalUrl) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: url.authority.clone(),
        host: url.host.clone(),
        host_for_capture: url.host_for_capture.clone(),
        port: url.port,
    }
}

fn require_equal(
    candidate: Option<&CanonicalAuthority>,
    primary: &CanonicalAuthority,
) -> Result<(), AuthorityError> {
    if candidate.is_some_and(|candidate| candidate != primary) {
        return Err(AuthorityError::ConflictingAuthority);
    }
    Ok(())
}

fn require_equal_authority(
    candidate: &CanonicalUrl,
    primary: &CanonicalAuthority,
) -> Result<(), AuthorityError> {
    require_equal(Some(&canonical_authority(candidate)), primary)
}

fn request_target(canonical: CanonicalUrl) -> Result<CanonicalRequestTarget, AuthorityError> {
    let uri = canonical
        .url
        .parse::<Uri>()
        .map_err(|_| AuthorityError::InvalidRequestTarget)?;
    Ok(CanonicalRequestTarget {
        url: canonical,
        uri,
    })
}

fn rebuild_request<B>(
    request: &mut Request<B>,
    target: &CanonicalRequestTarget,
) -> Result<(), AuthorityError> {
    let host = HeaderValue::from_str(&target.url.authority)
        .map_err(|_| AuthorityError::InvalidAuthority)?;
    *request.uri_mut() = target.uri.clone();
    request.headers_mut().remove(HOST);
    request.headers_mut().insert(HOST, host);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: Method, version: Version, uri: &str, host: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().method(method).version(version).uri(uri);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        builder.body(()).expect("request")
    }

    fn append_host(request: &mut Request<()>, host: &'static str) {
        request
            .headers_mut()
            .append(HOST, HeaderValue::from_static(host));
    }

    fn host(request: &Request<()>) -> &str {
        request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .expect("canonical Host")
    }

    fn assert_connect_rejected_without_mutation(
        mut request: Request<()>,
        reconcile: impl FnOnce(&mut Request<()>) -> Result<CanonicalRequestTarget, AuthorityError>,
    ) {
        let method = request.method().clone();
        let version = request.version();
        let uri = request.uri().clone();
        let headers = request.headers().clone();

        assert_eq!(reconcile(&mut request), Err(AuthorityError::ConnectMethod));
        assert_eq!(request.method(), &method);
        assert_eq!(request.version(), version);
        assert_eq!(request.uri(), &uri);
        assert_eq!(request.headers(), &headers);
    }

    #[test]
    fn explicit_h1_and_h2_reject_connect_without_mutation() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            assert_connect_rejected_without_mutation(
                request(
                    Method::CONNECT,
                    version,
                    "https://example.com:443/path",
                    Some("example.com:443"),
                ),
                reconcile_explicit_request,
            );
        }
    }

    #[test]
    fn transparent_http_h1_and_h2_reject_connect_without_mutation() {
        assert_connect_rejected_without_mutation(
            request(
                Method::CONNECT,
                Version::HTTP_11,
                "/path",
                Some("example.com"),
            ),
            reconcile_transparent_http_request,
        );
        assert_connect_rejected_without_mutation(
            request(
                Method::CONNECT,
                Version::HTTP_2,
                "http://example.com/path",
                Some("example.com"),
            ),
            reconcile_transparent_http_request,
        );
    }

    #[test]
    fn connect_inner_h1_and_h2_reject_nested_connect_without_mutation() {
        let mut outer = request(
            Method::CONNECT,
            Version::HTTP_11,
            "example.com:443",
            Some("example.com:443"),
        );
        let connect = reconcile_connect_outer_request(&mut outer).unwrap();

        assert_connect_rejected_without_mutation(
            request(
                Method::CONNECT,
                Version::HTTP_11,
                "https://example.com/path",
                Some("example.com"),
            ),
            |request| reconcile_connect_inner_request(request, &connect),
        );
        assert_connect_rejected_without_mutation(
            request(
                Method::CONNECT,
                Version::HTTP_2,
                "https://example.com/path",
                Some("example.com"),
            ),
            |request| reconcile_connect_inner_request(request, &connect),
        );
    }

    #[test]
    fn transparent_https_h1_and_h2_reject_connect_without_mutation() {
        assert_connect_rejected_without_mutation(
            request(
                Method::CONNECT,
                Version::HTTP_11,
                "/path",
                Some("example.com"),
            ),
            |request| reconcile_transparent_https_request(request, 443, Some("example.com")),
        );
        assert_connect_rejected_without_mutation(
            request(
                Method::CONNECT,
                Version::HTTP_2,
                "https://example.com/path",
                Some("example.com"),
            ),
            |request| reconcile_transparent_https_request(request, 443, Some("example.com")),
        );
    }

    #[test]
    fn explicit_h1_uses_absolute_authority_and_rebuilds_canonical_inputs() {
        let mut explicit = request(
            Method::GET,
            Version::HTTP_11,
            "HTTPS://EXAMPLE.com.:443/a/../ok?q=%61",
            Some("example.com:443"),
        );

        let target = reconcile_explicit_request(&mut explicit).unwrap();
        assert_eq!(target.url.url, "https://example.com/ok?q=a");
        assert_eq!(explicit.uri(), &target.uri);
        assert_eq!(host(&explicit), "example.com");

        let mut no_host = request(
            Method::GET,
            Version::HTTP_11,
            "http://example.com/path",
            None,
        );
        reconcile_explicit_request(&mut no_host).unwrap();
        assert_eq!(host(&no_host), "example.com");
    }

    #[test]
    fn explicit_h1_rejects_conflict_duplicate_and_origin_form_without_mutation() {
        let mut conflict = request(
            Method::GET,
            Version::HTTP_11,
            "http://one.example/path",
            Some("two.example"),
        );
        let original_uri = conflict.uri().clone();
        assert_eq!(
            reconcile_explicit_request(&mut conflict),
            Err(AuthorityError::ConflictingAuthority)
        );
        assert_eq!(conflict.uri(), &original_uri);
        assert_eq!(host(&conflict), "two.example");

        let mut duplicate = request(
            Method::GET,
            Version::HTTP_11,
            "http://one.example/path",
            Some("one.example"),
        );
        append_host(&mut duplicate, "one.example");
        assert_eq!(
            reconcile_explicit_request(&mut duplicate),
            Err(AuthorityError::DuplicateHost)
        );
        assert_eq!(duplicate.headers().get_all(HOST).iter().count(), 2);

        let mut origin = request(Method::GET, Version::HTTP_11, "/path", Some("one.example"));
        assert_eq!(
            reconcile_explicit_request(&mut origin),
            Err(AuthorityError::MissingAuthority)
        );
    }

    #[test]
    fn explicit_h2_uses_scheme_and_authority_and_checks_optional_host() {
        let mut equal = request(
            Method::GET,
            Version::HTTP_2,
            "https://XN--BCHER-KVA.example.:443/a",
            Some("xn--bcher-kva.example"),
        );
        let target = reconcile_explicit_request(&mut equal).unwrap();
        assert_eq!(target.url.url, "https://xn--bcher-kva.example/a");
        assert_eq!(host(&equal), "xn--bcher-kva.example");

        let mut conflict = request(
            Method::GET,
            Version::HTTP_2,
            "https://one.example/a",
            Some("two.example"),
        );
        assert_eq!(
            reconcile_explicit_request(&mut conflict),
            Err(AuthorityError::ConflictingAuthority)
        );
    }

    #[test]
    fn transparent_http_h1_requires_one_host_and_origin_form() {
        let mut valid = request(
            Method::GET,
            Version::HTTP_11,
            "/a/../ok",
            Some("EXAMPLE.com.:80"),
        );
        let target = reconcile_transparent_http_request(&mut valid).unwrap();
        assert_eq!(target.url.url, "http://example.com/ok");
        assert_eq!(host(&valid), "example.com");

        let mut missing = request(Method::GET, Version::HTTP_11, "/", None);
        assert_eq!(
            reconcile_transparent_http_request(&mut missing),
            Err(AuthorityError::MissingHost)
        );

        let mut duplicate = request(Method::GET, Version::HTTP_11, "/", Some("example.com"));
        append_host(&mut duplicate, "example.com");
        assert_eq!(
            reconcile_transparent_http_request(&mut duplicate),
            Err(AuthorityError::DuplicateHost)
        );

        let mut absolute = request(
            Method::GET,
            Version::HTTP_11,
            "http://example.com/",
            Some("example.com"),
        );
        assert_eq!(
            reconcile_transparent_http_request(&mut absolute),
            Err(AuthorityError::RequestTargetForm)
        );
    }

    #[test]
    fn transparent_http_h2_uses_authority_and_requires_http_scheme() {
        let mut valid = request(
            Method::GET,
            Version::HTTP_2,
            "http://[::ffff:192.0.2.1]:80/a",
            Some("192.0.2.1"),
        );
        let target = reconcile_transparent_http_request(&mut valid).unwrap();
        assert_eq!(target.url.authority, "192.0.2.1");
        assert_eq!(host(&valid), "192.0.2.1");

        let mut conflict = request(
            Method::GET,
            Version::HTTP_2,
            "http://one.example/",
            Some("two.example"),
        );
        assert_eq!(
            reconcile_transparent_http_request(&mut conflict),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut https = request(Method::GET, Version::HTTP_2, "https://example.com/", None);
        assert_eq!(
            reconcile_transparent_http_request(&mut https),
            Err(AuthorityError::SchemeMismatch)
        );
    }

    #[test]
    fn connect_outer_requires_authority_port_and_equal_single_host() {
        let mut valid = request(
            Method::CONNECT,
            Version::HTTP_11,
            "EXAMPLE.com.:443",
            Some("example.com"),
        );
        let target = reconcile_connect_outer_request(&mut valid).unwrap();
        assert_eq!(target.authority.authority, "example.com");
        assert_eq!(target.authority.port, 443);
        assert_eq!(target.url.url, "https://example.com/");
        assert_eq!(valid.uri().to_string(), "example.com:443");
        assert_eq!(host(&valid), "example.com:443");

        let mut missing_port = request(
            Method::CONNECT,
            Version::HTTP_11,
            "example.com",
            Some("example.com"),
        );
        assert_eq!(
            reconcile_connect_outer_request(&mut missing_port),
            Err(AuthorityError::MissingConnectPort)
        );

        let mut missing_host = request(Method::CONNECT, Version::HTTP_11, "example.com:443", None);
        assert_eq!(
            reconcile_connect_outer_request(&mut missing_host),
            Err(AuthorityError::MissingHost)
        );

        let mut conflict = request(
            Method::CONNECT,
            Version::HTTP_11,
            "example.com:443",
            Some("other.example:443"),
        );
        assert_eq!(
            reconcile_connect_outer_request(&mut conflict),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut duplicate = request(
            Method::CONNECT,
            Version::HTTP_11,
            "example.com:443",
            Some("example.com:443"),
        );
        append_host(&mut duplicate, "example.com:443");
        assert_eq!(
            reconcile_connect_outer_request(&mut duplicate),
            Err(AuthorityError::DuplicateHost)
        );

        let mut h2 = request(
            Method::CONNECT,
            Version::HTTP_2,
            "example.com:443",
            Some("example.com:443"),
        );
        assert_eq!(
            reconcile_connect_outer_request(&mut h2),
            Err(AuthorityError::UnsupportedConnectVersion)
        );
    }

    #[test]
    fn connect_outer_preserves_bracketed_ipv6_and_nondefault_port() {
        let mut request = request(
            Method::CONNECT,
            Version::HTTP_11,
            "[2001:0db8::1]:8443",
            Some("[2001:db8::1]:8443"),
        );
        let target = reconcile_connect_outer_request(&mut request).unwrap();
        assert_eq!(target.authority.host, "2001:db8::1");
        assert_eq!(target.authority.authority, "[2001:db8::1]:8443");
        assert_eq!(host(&request), "[2001:db8::1]:8443");
    }

    #[test]
    fn connect_sni_comparison_is_host_only() {
        let mut request = request(
            Method::CONNECT,
            Version::HTTP_11,
            "EXAMPLE.com.:8443",
            Some("example.com:8443"),
        );
        let target = reconcile_connect_outer_request(&mut request).unwrap();

        reconcile_connect_sni(&target, None).unwrap();
        reconcile_connect_sni(&target, Some("EXAMPLE.com.")).unwrap();
        assert_eq!(
            reconcile_connect_sni(&target, Some("other.example")),
            Err(AuthorityError::ConflictingAuthority)
        );
        assert_eq!(
            reconcile_connect_sni(&target, Some("example.com:8443")),
            Err(AuthorityError::InvalidSni)
        );
    }

    #[test]
    fn connect_sni_ipv4_reconciles_mapped_targets_and_rejects_native_mismatches() {
        let mut mapped = request(
            Method::CONNECT,
            Version::HTTP_11,
            "[::ffff:192.0.2.10]:8443",
            Some("192.0.2.10:8443"),
        );
        let mapped = reconcile_connect_outer_request(&mut mapped).unwrap();
        assert_eq!(mapped.authority.host, "192.0.2.10");
        reconcile_connect_sni(&mapped, Some("192.0.2.10")).unwrap();
        assert_eq!(
            reconcile_connect_sni(&mapped, Some("192.0.2.11")),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut native = request(
            Method::CONNECT,
            Version::HTTP_11,
            "[2001:db8::1]:8443",
            Some("[2001:db8::1]:8443"),
        );
        let native = reconcile_connect_outer_request(&mut native).unwrap();
        assert_eq!(
            reconcile_connect_sni(&native, Some("192.0.2.10")),
            Err(AuthorityError::ConflictingAuthority)
        );
        assert_eq!(
            reconcile_connect_sni(&native, Some("2001:db8::1")),
            Err(AuthorityError::InvalidSni)
        );
    }

    #[test]
    fn connect_inner_h1_reconciles_every_authority_source() {
        let mut outer = request(
            Method::CONNECT,
            Version::HTTP_11,
            "example.com:8443",
            Some("example.com:8443"),
        );
        let connect = reconcile_connect_outer_request(&mut outer).unwrap();

        let mut origin = request(
            Method::GET,
            Version::HTTP_11,
            "/a/../ok",
            Some("EXAMPLE.com.:8443"),
        );
        let target = reconcile_connect_inner_request(&mut origin, &connect).unwrap();
        assert_eq!(target.url.url, "https://example.com:8443/ok");
        assert_eq!(host(&origin), "example.com:8443");

        let mut absolute = request(
            Method::GET,
            Version::HTTP_11,
            "https://example.com:8443/path",
            Some("example.com:8443"),
        );
        reconcile_connect_inner_request(&mut absolute, &connect).unwrap();

        let mut conflict = request(
            Method::GET,
            Version::HTTP_11,
            "/path",
            Some("other.example:8443"),
        );
        assert_eq!(
            reconcile_connect_inner_request(&mut conflict, &connect),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut absolute_conflict = request(
            Method::GET,
            Version::HTTP_11,
            "https://other.example:8443/path",
            Some("example.com:8443"),
        );
        assert_eq!(
            reconcile_connect_inner_request(&mut absolute_conflict, &connect),
            Err(AuthorityError::ConflictingAuthority)
        );
    }

    #[test]
    fn connect_inner_h2_requires_https_and_connect_authority() {
        let mut outer = request(
            Method::CONNECT,
            Version::HTTP_11,
            "example.com:443",
            Some("example.com:443"),
        );
        let connect = reconcile_connect_outer_request(&mut outer).unwrap();

        let mut valid = request(
            Method::GET,
            Version::HTTP_2,
            "https://EXAMPLE.com.:443/path",
            None,
        );
        reconcile_connect_inner_request(&mut valid, &connect).unwrap();
        assert_eq!(host(&valid), "example.com");

        let mut wrong_scheme = request(
            Method::GET,
            Version::HTTP_2,
            "http://example.com/path",
            None,
        );
        assert_eq!(
            reconcile_connect_inner_request(&mut wrong_scheme, &connect),
            Err(AuthorityError::SchemeMismatch)
        );

        let mut wrong_authority = request(
            Method::GET,
            Version::HTTP_2,
            "https://other.example/path",
            None,
        );
        assert_eq!(
            reconcile_connect_inner_request(&mut wrong_authority, &connect),
            Err(AuthorityError::ConflictingAuthority)
        );
    }

    #[test]
    fn transparent_https_h1_uses_required_sni_as_primary() {
        let mut valid = request(
            Method::GET,
            Version::HTTP_11,
            "/path",
            Some("xn--bcher-kva.example:443"),
        );
        let target =
            reconcile_transparent_https_request(&mut valid, 443, Some("B\u{dc}CHER.example."))
                .unwrap();
        assert_eq!(target.url.url, "https://xn--bcher-kva.example/path");
        assert_eq!(host(&valid), "xn--bcher-kva.example");

        let mut intercepted_nondefault = request(
            Method::GET,
            Version::HTTP_11,
            "/path",
            Some("example.com:8443"),
        );
        let target = reconcile_transparent_https_request(
            &mut intercepted_nondefault,
            8443,
            Some("example.com"),
        )
        .unwrap();
        assert_eq!(target.url.url, "https://example.com:8443/path");
        assert_eq!(host(&intercepted_nondefault), "example.com:8443");

        let mut missing_sni = request(Method::GET, Version::HTTP_11, "/", Some("example.com"));
        assert_eq!(
            reconcile_transparent_https_request(&mut missing_sni, 443, None),
            Err(AuthorityError::MissingSni)
        );

        let mut invalid_port = request(Method::GET, Version::HTTP_11, "/", Some("example.com"));
        assert_eq!(
            reconcile_transparent_https_request(&mut invalid_port, 0, Some("example.com")),
            Err(AuthorityError::InvalidDestinationPort)
        );

        let mut nondefault = request(Method::GET, Version::HTTP_11, "/", Some("example.com:8443"));
        assert_eq!(
            reconcile_transparent_https_request(&mut nondefault, 443, Some("example.com")),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut absolute = request(
            Method::GET,
            Version::HTTP_11,
            "https://example.com/",
            Some("example.com"),
        );
        assert_eq!(
            reconcile_transparent_https_request(&mut absolute, 443, Some("example.com")),
            Err(AuthorityError::RequestTargetForm)
        );
    }

    #[test]
    fn transparent_https_h2_reconciles_sni_authority_and_optional_host() {
        let mut valid = request(
            Method::GET,
            Version::HTTP_2,
            "https://EXAMPLE.com.:443/path",
            None,
        );
        let target =
            reconcile_transparent_https_request(&mut valid, 443, Some("example.com")).unwrap();
        assert_eq!(target.url.url, "https://example.com/path");
        assert_eq!(host(&valid), "example.com");

        let mut nondefault = request(
            Method::GET,
            Version::HTTP_2,
            "https://EXAMPLE.com.:8443/path",
            None,
        );
        let target =
            reconcile_transparent_https_request(&mut nondefault, 8443, Some("example.com"))
                .unwrap();
        assert_eq!(target.url.url, "https://example.com:8443/path");
        assert_eq!(host(&nondefault), "example.com:8443");

        let mut mapped = request(
            Method::GET,
            Version::HTTP_2,
            "https://[::ffff:192.0.2.10]:8443/path",
            Some("192.0.2.10:8443"),
        );
        let target =
            reconcile_transparent_https_request(&mut mapped, 8443, Some("192.0.2.10")).unwrap();
        assert_eq!(target.url.url, "https://192.0.2.10:8443/path");

        let mut host_conflict = request(
            Method::GET,
            Version::HTTP_2,
            "https://example.com/path",
            Some("other.example"),
        );
        assert_eq!(
            reconcile_transparent_https_request(&mut host_conflict, 443, Some("example.com")),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut duplicate_host = request(
            Method::GET,
            Version::HTTP_2,
            "https://example.com/path",
            Some("example.com"),
        );
        append_host(&mut duplicate_host, "example.com");
        assert_eq!(
            reconcile_transparent_https_request(&mut duplicate_host, 443, Some("example.com")),
            Err(AuthorityError::DuplicateHost)
        );

        let mut authority_conflict = request(
            Method::GET,
            Version::HTTP_2,
            "https://other.example/path",
            None,
        );
        assert_eq!(
            reconcile_transparent_https_request(&mut authority_conflict, 443, Some("example.com")),
            Err(AuthorityError::ConflictingAuthority)
        );

        let mut scheme_conflict = request(
            Method::GET,
            Version::HTTP_2,
            "http://example.com/path",
            None,
        );
        assert_eq!(
            reconcile_transparent_https_request(&mut scheme_conflict, 443, Some("example.com")),
            Err(AuthorityError::SchemeMismatch)
        );
    }
}

#[cfg(test)]
mod conformance_adapter {
    use super::*;
    use http_access_conformance::{
        load_authority_suite, AuthorityErrorCode, AuthorityEvidence, AuthorityOutcome,
        FixtureHttpVersion, FixtureIngressMode, FixtureRequestMethod, OuterConnectEvidence,
        ReconciledAuthority,
    };
    use http_access_types::{HttpVersion as SharedHttpVersion, IngressMode as SharedIngressMode};
    use http_access_url::{
        canonicalize_tls_server_name as shared_canonicalize_tls_server_name,
        reconcile_connect_target as shared_reconcile_connect_target,
        reconcile_request_target as shared_reconcile_request_target,
        AuthorityError as SharedAuthorityError, ConnectTargetEvidence, RequestAuthorityEvidence,
        RequestMethod, RequestTargetEvidence,
    };

    const INTENTIONAL_AUTHORITY_DIFFERENCES: &[&str] = &[];

    // Hyper's Request cannot represent duplicate pseudo-fields, so the adapter
    // rejects their ordered fixture evidence before either reconciler runs.
    fn prevalidate_pseudo_fields(
        input: &AuthorityEvidence,
    ) -> Result<Option<(&str, &str)>, AuthorityErrorCode> {
        if input.http_version != FixtureHttpVersion::Http2 {
            return Ok(None);
        }
        let authority = match input.authority_fields.as_slice() {
            [] => return Err(AuthorityErrorCode::MissingAuthority),
            [authority] => authority.as_str(),
            [_, _, ..] => return Err(AuthorityErrorCode::DuplicateAuthority),
        };
        let scheme = match input.scheme_fields.as_slice() {
            [] => return Err(AuthorityErrorCode::MissingAuthority),
            [scheme] => scheme.as_str(),
            [_, _, ..] => return Err(AuthorityErrorCode::DuplicateAuthority),
        };
        Ok(Some((scheme, authority)))
    }

    fn shared_version(version: FixtureHttpVersion) -> SharedHttpVersion {
        match version {
            FixtureHttpVersion::Http10 => SharedHttpVersion::Http10,
            FixtureHttpVersion::Http11 => SharedHttpVersion::Http11,
            FixtureHttpVersion::Http2 => SharedHttpVersion::Http2,
        }
    }

    fn shared_ingress(mode: FixtureIngressMode) -> SharedIngressMode {
        match mode {
            FixtureIngressMode::ExplicitHttp => SharedIngressMode::ExplicitHttp,
            FixtureIngressMode::ExplicitHttps => SharedIngressMode::ExplicitHttps,
            FixtureIngressMode::TransparentHttp => SharedIngressMode::TransparentHttp,
            FixtureIngressMode::ConnectMitmInner => SharedIngressMode::ConnectMitmInner,
            FixtureIngressMode::TransparentHttps => SharedIngressMode::TransparentHttps,
        }
    }

    fn shared_method(method: FixtureRequestMethod) -> RequestMethod {
        match method {
            FixtureRequestMethod::Connect => RequestMethod::Connect,
            FixtureRequestMethod::Other => RequestMethod::Other,
        }
    }

    fn shared_target<'a>(
        input: &'a AuthorityEvidence,
        pseudo: Option<(&'a str, &'a str)>,
    ) -> RequestTargetEvidence<'a> {
        if let Some((scheme, authority)) = pseudo {
            return RequestTargetEvidence::Http2 {
                scheme,
                authority,
                path_and_query: &input.request_target,
            };
        }
        match input.ingress_mode {
            FixtureIngressMode::ExplicitHttp | FixtureIngressMode::ExplicitHttps => {
                RequestTargetEvidence::Http1Absolute {
                    url: &input.request_target,
                }
            }
            FixtureIngressMode::TransparentHttp | FixtureIngressMode::TransparentHttps => {
                RequestTargetEvidence::Http1Origin {
                    path_and_query: &input.request_target,
                }
            }
            FixtureIngressMode::ConnectMitmInner
                if input.request_target.starts_with("http://")
                    || input.request_target.starts_with("https://") =>
            {
                RequestTargetEvidence::Http1Absolute {
                    url: &input.request_target,
                }
            }
            FixtureIngressMode::ConnectMitmInner => RequestTargetEvidence::Http1Origin {
                path_and_query: &input.request_target,
            },
        }
    }

    fn shared_outer(
        outer: &OuterConnectEvidence,
    ) -> Result<http_access_url::CanonicalConnectTarget, SharedAuthorityError> {
        let hosts: Vec<&str> = outer.host_fields.iter().map(String::as_str).collect();
        shared_reconcile_connect_target(ConnectTargetEvidence {
            version: shared_version(outer.http_version),
            method: RequestMethod::Connect,
            target: RequestTargetEvidence::Http1Authority {
                authority: &outer.target,
            },
            hosts: &hosts,
        })
    }

    fn shared_result(input: &AuthorityEvidence) -> Result<ReconciledAuthority, AuthorityErrorCode> {
        let pseudo = prevalidate_pseudo_fields(input)?;
        let hosts: Vec<&str> = input.host_fields.iter().map(String::as_str).collect();
        let sni = input.tls_server_name.as_deref().map(|raw| {
            shared_canonicalize_tls_server_name(raw)
                .expect("authority fixture SNI must pass shared prevalidation")
        });
        let outer = input
            .outer_connect
            .as_ref()
            .map(shared_outer)
            .transpose()
            .map_err(shared_error_code)?;
        let target = shared_reconcile_request_target(RequestAuthorityEvidence {
            ingress_mode: shared_ingress(input.ingress_mode),
            version: shared_version(input.http_version),
            method: shared_method(input.method),
            target: shared_target(input, pseudo),
            hosts: &hosts,
            connect_authority: outer.as_ref().map(|target| target.authority()),
            sni: sni.as_ref(),
            destination_port: input.destination_port,
        })
        .map_err(shared_error_code)?;
        let url = target.url();
        Ok(ReconciledAuthority {
            scheme: url.scheme().as_str().to_owned(),
            authority: url.authority().as_str().to_owned(),
            host: url.authority().host().as_str().to_owned(),
            port: url.authority().effective_port(),
        })
    }

    fn shared_error_code(error: SharedAuthorityError) -> AuthorityErrorCode {
        match error {
            SharedAuthorityError::MissingAuthority | SharedAuthorityError::MissingHost => {
                AuthorityErrorCode::MissingAuthority
            }
            SharedAuthorityError::DuplicateHost => AuthorityErrorCode::DuplicateAuthority,
            SharedAuthorityError::AuthorityMismatch => AuthorityErrorCode::AuthorityMismatch,
            SharedAuthorityError::TlsServerNameMismatch => {
                AuthorityErrorCode::TlsServerNameMismatch
            }
            SharedAuthorityError::OuterConnectMismatch => AuthorityErrorCode::OuterConnectMismatch,
            SharedAuthorityError::DestinationPortMismatch => {
                AuthorityErrorCode::DestinationPortMismatch
            }
            SharedAuthorityError::ConnectMethod => AuthorityErrorCode::ConnectMethod,
            SharedAuthorityError::UnsupportedConnectVersion => {
                AuthorityErrorCode::UnsupportedConnectVersion
            }
            other => panic!("authority corpus produced unsupported shared error {other:?}"),
        }
    }

    fn old_version(version: FixtureHttpVersion) -> Version {
        match version {
            FixtureHttpVersion::Http10 => Version::HTTP_10,
            FixtureHttpVersion::Http11 => Version::HTTP_11,
            FixtureHttpVersion::Http2 => Version::HTTP_2,
        }
    }

    fn old_request(input: &AuthorityEvidence, pseudo: Option<(&str, &str)>) -> Request<()> {
        let uri = match pseudo {
            Some((scheme, authority)) => {
                format!("{scheme}://{authority}{}", input.request_target)
            }
            None => input.request_target.clone(),
        };
        let mut request = Request::builder()
            .method(match input.method {
                FixtureRequestMethod::Connect => Method::CONNECT,
                FixtureRequestMethod::Other => Method::GET,
            })
            .version(old_version(input.http_version))
            .uri(uri)
            .body(())
            .expect("prevalidated authority fixture request");
        for host in &input.host_fields {
            request.headers_mut().append(
                HOST,
                HeaderValue::from_str(host).expect("prevalidated fixture Host"),
            );
        }
        request
    }

    fn old_outer(outer: &OuterConnectEvidence) -> Result<CanonicalConnectTarget, AuthorityError> {
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .version(old_version(outer.http_version))
            .uri(&outer.target)
            .body(())
            .expect("prevalidated outer CONNECT fixture");
        for host in &outer.host_fields {
            request.headers_mut().append(
                HOST,
                HeaderValue::from_str(host).expect("prevalidated outer Host"),
            );
        }
        reconcile_connect_outer_request(&mut request)
    }

    fn old_result(input: &AuthorityEvidence) -> Result<ReconciledAuthority, AuthorityErrorCode> {
        let pseudo = prevalidate_pseudo_fields(input)?;
        let outer = input
            .outer_connect
            .as_ref()
            .map(old_outer)
            .transpose()
            .map_err(|error| old_error_code(error, input))?;
        if let Some(outer) = outer.as_ref() {
            reconcile_connect_sni(outer, input.tls_server_name.as_deref())
                .map_err(|error| old_error_code(error, input))?;
        }
        let mut request = old_request(input, pseudo);
        let target = match input.ingress_mode {
            FixtureIngressMode::ExplicitHttp | FixtureIngressMode::ExplicitHttps => {
                reconcile_explicit_request(&mut request)
            }
            FixtureIngressMode::TransparentHttp => reconcile_transparent_http_request(&mut request),
            FixtureIngressMode::ConnectMitmInner => reconcile_connect_inner_request(
                &mut request,
                outer
                    .as_ref()
                    .expect("connect fixture must carry outer evidence"),
            ),
            FixtureIngressMode::TransparentHttps => reconcile_transparent_https_request(
                &mut request,
                input.destination_port.unwrap_or(0),
                input.tls_server_name.as_deref(),
            ),
        }
        .map_err(|error| old_error_code(error, input))?;
        Ok(ReconciledAuthority {
            scheme: target.url.scheme,
            authority: target.url.authority,
            host: target.url.host,
            port: target.url.port,
        })
    }

    fn old_error_code(error: AuthorityError, input: &AuthorityEvidence) -> AuthorityErrorCode {
        match error {
            AuthorityError::MissingAuthority | AuthorityError::MissingHost => {
                AuthorityErrorCode::MissingAuthority
            }
            AuthorityError::DuplicateHost => AuthorityErrorCode::DuplicateAuthority,
            AuthorityError::ConnectMethod => AuthorityErrorCode::ConnectMethod,
            AuthorityError::UnsupportedConnectVersion => {
                AuthorityErrorCode::UnsupportedConnectVersion
            }
            AuthorityError::ConflictingAuthority => match input.ingress_mode {
                FixtureIngressMode::ConnectMitmInner => AuthorityErrorCode::OuterConnectMismatch,
                FixtureIngressMode::TransparentHttps => transparent_https_conflict(input),
                _ => AuthorityErrorCode::AuthorityMismatch,
            },
            other => panic!("authority corpus produced unsupported old error {other:?}"),
        }
    }

    fn transparent_https_conflict(input: &AuthorityEvidence) -> AuthorityErrorCode {
        let raw_authority = if input.http_version == FixtureHttpVersion::Http2 {
            input.authority_fields.first()
        } else {
            input.host_fields.first()
        }
        .expect("prevalidated transparent HTTPS authority");
        let request = canonicalize_http_authority("https", raw_authority)
            .expect("prevalidated transparent HTTPS authority");
        let sni = canonicalize_tls_server_name(
            input
                .tls_server_name
                .as_deref()
                .expect("prevalidated transparent HTTPS SNI"),
        )
        .expect("prevalidated transparent HTTPS SNI");
        if request.host == sni {
            AuthorityErrorCode::DestinationPortMismatch
        } else {
            AuthorityErrorCode::TlsServerNameMismatch
        }
    }

    #[test]
    fn shared_authority_reconciliation_is_exactly_compatible_with_the_committed_corpus() {
        assert!(
            INTENTIONAL_AUTHORITY_DIFFERENCES.is_empty(),
            "P03 requires an empty intentional-change list"
        );
        let suite = load_authority_suite().expect("committed authority suite must prevalidate");

        for case in suite.into_cases() {
            let old = old_result(&case.input);
            let shared = shared_result(&case.input);
            assert_eq!(old, shared, "{}: old/shared parity", case.id);
            match case.expected {
                AuthorityOutcome::Accepted { value } => {
                    assert_eq!(old, Ok(value), "{}: fixture result", case.id);
                }
                AuthorityOutcome::Rejected { error } => {
                    assert_eq!(old, Err(error), "{}: fixture error", case.id);
                }
            }
        }
    }
}
