use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalUrl {
    pub url: String,
    pub authority: String,
    pub host_for_capture: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CanonicalUrlError {
    #[error("failed to parse URL: {0}")]
    Parse(#[from] url::ParseError),
    #[error("unsupported URL scheme '{0}'")]
    UnsupportedScheme(String),
    #[error("URL is missing host")]
    MissingHost,
    #[error("URL host is empty after normalization")]
    EmptyHost,
    #[error("URL userinfo is not allowed")]
    UserInfo,
}

pub(crate) fn canonicalize_http_url(raw: &str) -> Result<CanonicalUrl, CanonicalUrlError> {
    let url = Url::parse(raw)?;
    let scheme = url.scheme();
    if !matches!(scheme, "http" | "https") {
        return Err(CanonicalUrlError::UnsupportedScheme(scheme.to_string()));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(CanonicalUrlError::UserInfo);
    }

    let raw_host = url.host_str().ok_or(CanonicalUrlError::MissingHost)?;
    let host = canonical_host(raw_host)?;
    let host_for_url = host_for_url_authority(&host);
    let port = url
        .port_or_known_default()
        .ok_or_else(|| CanonicalUrlError::UnsupportedScheme(scheme.to_string()))?;
    let authority = match url.port() {
        Some(port) => format!("{host_for_url}:{port}"),
        None => host_for_url.clone(),
    };

    let path = normalize_path_percent_encoding(if url.path().is_empty() {
        "/"
    } else {
        url.path()
    });
    let query = match url.query() {
        Some(query) => format!("?{query}"),
        None => String::new(),
    };

    Ok(CanonicalUrl {
        url: format!("{scheme}://{authority}{path}{query}"),
        authority,
        host_for_capture: host_for_url,
        port,
    })
}

fn canonical_host(raw_host: &str) -> Result<String, CanonicalUrlError> {
    let host = raw_host.trim_end_matches('.');
    if host.is_empty() {
        return Err(CanonicalUrlError::EmptyHost);
    }
    Ok(host.to_ascii_lowercase())
}

fn normalize_path_percent_encoding(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut normalized = String::with_capacity(path.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                let decoded = (high << 4) | low;
                if is_unreserved(decoded) {
                    normalized.push(decoded as char);
                    index += 3;
                    continue;
                }
            }
        }

        normalized.push(bytes[index] as char);
        index += 1;
    }

    normalized
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn host_for_url_authority(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_host_path_and_default_port() {
        let canonical =
            canonicalize_http_url("https://EXAMPLE.COM.:443/a/../admin?q=1").expect("canonical");

        assert_eq!(canonical.url, "https://example.com/admin?q=1");
        assert_eq!(canonical.authority, "example.com");
        assert_eq!(canonical.host_for_capture, "example.com");
        assert_eq!(canonical.port, 443);
    }

    #[test]
    fn keeps_non_default_ports_and_brackets_ipv6() {
        let canonical =
            canonicalize_http_url("http://[::1]:8080/relative/path").expect("canonical");

        assert_eq!(canonical.url, "http://[::1]:8080/relative/path");
        assert_eq!(canonical.authority, "[::1]:8080");
        assert_eq!(canonical.host_for_capture, "[::1]");
        assert_eq!(canonical.port, 8080);
    }

    #[test]
    fn decodes_unreserved_path_percent_encoding_only() {
        let canonical = canonicalize_http_url("https://example.com/%61dmin/%7Eme/%2F?q=%61")
            .expect("canonical");

        assert_eq!(canonical.url, "https://example.com/admin/~me/%2F?q=%61");
    }

    #[test]
    fn rejects_userinfo_and_non_http_schemes() {
        assert!(matches!(
            canonicalize_http_url("http://user:pass@example.com/"),
            Err(CanonicalUrlError::UserInfo)
        ));
        assert!(matches!(
            canonicalize_http_url("ftp://example.com/"),
            Err(CanonicalUrlError::UnsupportedScheme(_))
        ));
    }
}
