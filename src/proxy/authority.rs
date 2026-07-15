use http::header::{HeaderMap, HeaderValue, HOST};
use http::{Request, Uri, Version};
use http_access_types::{CanonicalHost, HttpVersion, IngressMode};
use http_access_url::{
    reconcile_connect_target, reconcile_request_target, AuthorityError, CanonicalConnectTarget,
    CanonicalRequestTarget, ConnectTargetEvidence, RequestAuthorityEvidence, RequestMethod,
    RequestTargetEvidence,
};

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AuthorityAdapterError {
    #[error("request authority reconciliation failed")]
    Reconciliation(#[from] AuthorityError),
    #[error("unsupported HTTP version")]
    UnsupportedHttpVersion,
    #[error("required HTTP/2 pseudo-field evidence is missing")]
    MissingHttp2PseudoField,
    #[error("Host field is not valid HTTP text")]
    InvalidHostField,
    #[error("canonical request target cannot be represented as an HTTP URI")]
    CanonicalUri,
    #[error("canonical authority cannot be represented as a Host field")]
    CanonicalHostField,
}

/// Adapts one framed Hyper request to the shared authority contract and then
/// replaces its URI and Host field with the resulting canonical spellings.
pub(crate) fn reconcile_request<B>(
    request: &mut Request<B>,
    ingress_mode: IngressMode,
    connect_target: Option<&CanonicalConnectTarget>,
    sni: Option<&CanonicalHost>,
    destination_port: Option<u16>,
) -> Result<CanonicalRequestTarget, AuthorityAdapterError> {
    let version = http_version(request.version())?;
    let absolute_target = request.uri().to_string();
    let target = request_target_evidence(request.uri(), version, &absolute_target)?;
    let hosts = host_fields(request.headers())?;
    let canonical = reconcile_request_target(RequestAuthorityEvidence {
        ingress_mode,
        version,
        method: request_method(request.method()),
        target,
        hosts: &hosts,
        connect_authority: connect_target.map(CanonicalConnectTarget::authority),
        sni,
        destination_port,
    })?;
    rebuild_request(request, &canonical)?;
    Ok(canonical)
}

/// Adapts an outer CONNECT request to the shared CONNECT authority contract and
/// replaces its authority-form target and Host field with canonical spellings.
pub(crate) fn reconcile_connect_outer_request<B>(
    request: &mut Request<B>,
) -> Result<CanonicalConnectTarget, AuthorityAdapterError> {
    let version = http_version(request.version())?;
    let absolute_target = request.uri().to_string();
    let target = if version == HttpVersion::Http2 {
        // The shared reconciler rejects H2 CONNECT before inspecting its target.
        RequestTargetEvidence::Http2 {
            scheme: "",
            authority: "",
            path_and_query: "",
        }
    } else {
        request_target_evidence(request.uri(), version, &absolute_target)?
    };
    let hosts = host_fields(request.headers())?;
    let canonical = reconcile_connect_target(ConnectTargetEvidence {
        version,
        method: request_method(request.method()),
        target,
        hosts: &hosts,
    })?;
    rebuild_connect_request(request, &canonical)?;
    Ok(canonical)
}

fn http_version(version: Version) -> Result<HttpVersion, AuthorityAdapterError> {
    match version {
        Version::HTTP_10 => Ok(HttpVersion::Http10),
        Version::HTTP_11 => Ok(HttpVersion::Http11),
        Version::HTTP_2 => Ok(HttpVersion::Http2),
        _ => Err(AuthorityAdapterError::UnsupportedHttpVersion),
    }
}

fn request_method(method: &http::Method) -> RequestMethod {
    if method == http::Method::CONNECT {
        RequestMethod::Connect
    } else {
        RequestMethod::Other
    }
}

fn request_target_evidence<'a>(
    uri: &'a Uri,
    version: HttpVersion,
    absolute_target: &'a str,
) -> Result<RequestTargetEvidence<'a>, AuthorityAdapterError> {
    if version == HttpVersion::Http2 {
        return Ok(RequestTargetEvidence::Http2 {
            scheme: uri
                .scheme_str()
                .ok_or(AuthorityAdapterError::MissingHttp2PseudoField)?,
            authority: uri
                .authority()
                .map(http::uri::Authority::as_str)
                .ok_or(AuthorityAdapterError::MissingHttp2PseudoField)?,
            path_and_query: uri
                .path_and_query()
                .map(http::uri::PathAndQuery::as_str)
                .ok_or(AuthorityAdapterError::MissingHttp2PseudoField)?,
        });
    }

    if uri.scheme().is_none() && uri.authority().is_some() && uri.path_and_query().is_none() {
        return Ok(RequestTargetEvidence::Http1Authority {
            authority: uri
                .authority()
                .expect("authority-form classification requires authority")
                .as_str(),
        });
    }
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Ok(RequestTargetEvidence::Http1Absolute {
            url: absolute_target,
        });
    }
    Ok(RequestTargetEvidence::Http1Origin {
        path_and_query: uri
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            .unwrap_or("/"),
    })
}

fn host_fields(headers: &HeaderMap) -> Result<Vec<&str>, AuthorityAdapterError> {
    headers
        .get_all(HOST)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| AuthorityAdapterError::InvalidHostField)
        })
        .collect()
}

fn rebuild_request<B>(
    request: &mut Request<B>,
    target: &CanonicalRequestTarget,
) -> Result<(), AuthorityAdapterError> {
    let uri = target
        .url()
        .as_str()
        .parse::<Uri>()
        .map_err(|_| AuthorityAdapterError::CanonicalUri)?;
    let host = HeaderValue::from_str(target.host_header())
        .map_err(|_| AuthorityAdapterError::CanonicalHostField)?;
    *request.uri_mut() = uri;
    request.headers_mut().remove(HOST);
    request.headers_mut().insert(HOST, host);
    Ok(())
}

fn rebuild_connect_request<B>(
    request: &mut Request<B>,
    target: &CanonicalConnectTarget,
) -> Result<(), AuthorityAdapterError> {
    let uri = target
        .authority_form()
        .parse::<Uri>()
        .map_err(|_| AuthorityAdapterError::CanonicalUri)?;
    let host = HeaderValue::from_str(target.authority_form())
        .map_err(|_| AuthorityAdapterError::CanonicalHostField)?;
    *request.uri_mut() = uri;
    request.headers_mut().remove(HOST);
    request.headers_mut().insert(HOST, host);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_access_url::{canonicalize_tls_server_name, reconcile_connect_sni};

    fn request(method: http::Method, version: Version, uri: &str, hosts: &[&str]) -> Request<()> {
        let mut request = Request::builder()
            .method(method)
            .version(version)
            .uri(uri)
            .body(())
            .expect("request");
        for host in hosts {
            request
                .headers_mut()
                .append(HOST, HeaderValue::from_str(host).expect("test Host field"));
        }
        request
    }

    #[test]
    fn explicit_modes_are_supplied_exactly_and_rebuild_canonical_target() {
        for ingress_mode in [IngressMode::ExplicitHttp, IngressMode::ExplicitHttps] {
            let mut request = request(
                http::Method::GET,
                Version::HTTP_11,
                "HTTPS://EXAMPLE.com.:443/a/../ok?q=%61",
                &["example.com:443"],
            );
            let target = reconcile_request(&mut request, ingress_mode, None, None, None).unwrap();
            assert_eq!(target.url().as_str(), "https://example.com/ok?q=a");
            assert_eq!(request.uri().to_string(), "https://example.com/ok?q=a");
            assert_eq!(request.headers()[HOST], "example.com");
        }
    }

    #[test]
    fn reconciliation_failure_does_not_mutate_request() {
        let mut request = request(
            http::Method::GET,
            Version::HTTP_11,
            "http://allowed.example/path",
            &["other.example"],
        );
        let original_uri = request.uri().clone();
        let original_headers = request.headers().clone();
        assert!(matches!(
            reconcile_request(&mut request, IngressMode::ExplicitHttp, None, None, None),
            Err(AuthorityAdapterError::Reconciliation(
                AuthorityError::AuthorityMismatch
            ))
        ));
        assert_eq!(request.uri(), &original_uri);
        assert_eq!(request.headers(), &original_headers);
    }

    #[test]
    fn connect_outer_and_inner_use_shared_checked_identity() {
        let mut outer = request(
            http::Method::CONNECT,
            Version::HTTP_11,
            "EXAMPLE.com.:443",
            &["example.com"],
        );
        let connect = reconcile_connect_outer_request(&mut outer).unwrap();
        assert_eq!(connect.authority_form(), "example.com:443");
        assert_eq!(outer.uri().to_string(), "example.com:443");
        assert_eq!(outer.headers()[HOST], "example.com:443");

        let sni = canonicalize_tls_server_name("EXAMPLE.com.").unwrap();
        reconcile_connect_sni(&connect, Some(&sni)).unwrap();
        let mut inner = request(
            http::Method::GET,
            Version::HTTP_11,
            "/inside/../resource",
            &["example.com:443"],
        );
        let target = reconcile_request(
            &mut inner,
            IngressMode::ConnectMitmInner,
            Some(&connect),
            Some(&sni),
            None,
        )
        .unwrap();
        assert_eq!(target.url().as_str(), "https://example.com/resource");
        assert_eq!(inner.headers()[HOST], "example.com");
    }

    #[test]
    fn transparent_https_uses_checked_sni_and_destination_port() {
        let sni = canonicalize_tls_server_name("B\u{fc}CHER.example.").unwrap();
        let mut request = request(
            http::Method::GET,
            Version::HTTP_2,
            "https://xn--bcher-kva.example:8443/a/../resource",
            &["xn--bcher-kva.example:8443"],
        );
        let target = reconcile_request(
            &mut request,
            IngressMode::TransparentHttps,
            None,
            Some(&sni),
            Some(8443),
        )
        .unwrap();
        assert_eq!(
            target.url().as_str(),
            "https://xn--bcher-kva.example:8443/resource"
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
    use http_access_url::{canonicalize_tls_server_name, reconcile_connect_sni};

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

    fn version(version: FixtureHttpVersion) -> Version {
        match version {
            FixtureHttpVersion::Http10 => Version::HTTP_10,
            FixtureHttpVersion::Http11 => Version::HTTP_11,
            FixtureHttpVersion::Http2 => Version::HTTP_2,
        }
    }

    fn ingress_mode(mode: FixtureIngressMode) -> IngressMode {
        match mode {
            FixtureIngressMode::ExplicitHttp => IngressMode::ExplicitHttp,
            FixtureIngressMode::ExplicitHttps => IngressMode::ExplicitHttps,
            FixtureIngressMode::TransparentHttp => IngressMode::TransparentHttp,
            FixtureIngressMode::ConnectMitmInner => IngressMode::ConnectMitmInner,
            FixtureIngressMode::TransparentHttps => IngressMode::TransparentHttps,
        }
    }

    fn fixture_request(input: &AuthorityEvidence, pseudo: Option<(&str, &str)>) -> Request<()> {
        let uri = match pseudo {
            Some((scheme, authority)) => {
                format!("{scheme}://{authority}{}", input.request_target)
            }
            None => input.request_target.clone(),
        };
        let mut request = Request::builder()
            .method(match input.method {
                FixtureRequestMethod::Connect => http::Method::CONNECT,
                FixtureRequestMethod::Other => http::Method::GET,
            })
            .version(version(input.http_version))
            .uri(uri)
            .body(())
            .expect("prevalidated authority fixture request");
        append_hosts(&mut request, &input.host_fields);
        request
    }

    fn outer_connect(
        outer: &OuterConnectEvidence,
    ) -> Result<CanonicalConnectTarget, AuthorityAdapterError> {
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .version(version(outer.http_version))
            .uri(&outer.target)
            .body(())
            .expect("prevalidated outer CONNECT fixture");
        append_hosts(&mut request, &outer.host_fields);
        reconcile_connect_outer_request(&mut request)
    }

    fn append_hosts(request: &mut Request<()>, hosts: &[String]) {
        for host in hosts {
            request.headers_mut().append(
                HOST,
                HeaderValue::from_str(host).expect("prevalidated fixture Host"),
            );
        }
    }

    fn adapter_result(
        input: &AuthorityEvidence,
    ) -> Result<ReconciledAuthority, AuthorityErrorCode> {
        let pseudo = prevalidate_pseudo_fields(input)?;
        let outer = input
            .outer_connect
            .as_ref()
            .map(outer_connect)
            .transpose()
            .map_err(adapter_error_code)?;
        let sni = input
            .tls_server_name
            .as_deref()
            .map(canonicalize_tls_server_name)
            .transpose()
            .expect("authority fixture SNI must pass prevalidation");
        if let Some(outer) = outer.as_ref() {
            reconcile_connect_sni(outer, sni.as_ref()).map_err(shared_error_code)?;
        }
        let mut request = fixture_request(input, pseudo);
        let target = reconcile_request(
            &mut request,
            ingress_mode(input.ingress_mode),
            outer.as_ref(),
            sni.as_ref(),
            input.destination_port,
        )
        .map_err(adapter_error_code)?;
        let url = target.url();
        Ok(ReconciledAuthority {
            scheme: url.scheme().as_str().to_owned(),
            authority: url.authority().as_str().to_owned(),
            host: url.authority().host().as_str().to_owned(),
            port: url.authority().effective_port(),
        })
    }

    fn adapter_error_code(error: AuthorityAdapterError) -> AuthorityErrorCode {
        match error {
            AuthorityAdapterError::Reconciliation(error) => shared_error_code(error),
            AuthorityAdapterError::MissingHttp2PseudoField => AuthorityErrorCode::MissingAuthority,
            other => panic!("authority corpus produced unsupported adapter error {other:?}"),
        }
    }

    fn shared_error_code(error: AuthorityError) -> AuthorityErrorCode {
        match error {
            AuthorityError::MissingAuthority | AuthorityError::MissingHost => {
                AuthorityErrorCode::MissingAuthority
            }
            AuthorityError::DuplicateHost => AuthorityErrorCode::DuplicateAuthority,
            AuthorityError::AuthorityMismatch => AuthorityErrorCode::AuthorityMismatch,
            AuthorityError::TlsServerNameMismatch => AuthorityErrorCode::TlsServerNameMismatch,
            AuthorityError::OuterConnectMismatch => AuthorityErrorCode::OuterConnectMismatch,
            AuthorityError::DestinationPortMismatch => AuthorityErrorCode::DestinationPortMismatch,
            AuthorityError::ConnectMethod => AuthorityErrorCode::ConnectMethod,
            AuthorityError::UnsupportedConnectVersion => {
                AuthorityErrorCode::UnsupportedConnectVersion
            }
            other => panic!("authority corpus produced unsupported shared error {other:?}"),
        }
    }

    #[test]
    fn hyper_adapter_conforms_to_the_committed_authority_corpus() {
        let suite = load_authority_suite().expect("committed authority suite must prevalidate");
        for case in suite.into_cases() {
            let actual = adapter_result(&case.input);
            match case.expected {
                AuthorityOutcome::Accepted { value } => {
                    assert_eq!(actual, Ok(value), "{}: fixture result", case.id);
                }
                AuthorityOutcome::Rejected { error } => {
                    assert_eq!(actual, Err(error), "{}: fixture error", case.id);
                }
            }
        }
    }
}
