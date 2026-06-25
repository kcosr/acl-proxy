use url::Url;

pub(crate) const REDACTED: &str = "[REDACTED]";
const REDACTED_URL: &str = "[REDACTED_URL]";
const REDACTED_QUERY: &str = "REDACTED";

pub(crate) fn is_sensitive_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

pub(crate) fn redact_url_for_sink(raw: &str) -> String {
    let mut url = match Url::parse(raw) {
        Ok(url) => url,
        Err(_) => {
            if raw.contains('?') || raw.contains('@') {
                return REDACTED_URL.to_string();
            }
            return raw.to_string();
        }
    };

    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_fragment(None);
    if url.query().is_some() {
        url.set_query(Some(REDACTED_QUERY));
    }

    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_header_names_match_credentials_case_insensitively() {
        assert!(is_sensitive_header_name("Authorization"));
        assert!(is_sensitive_header_name("proxy-authorization"));
        assert!(is_sensitive_header_name("COOKIE"));
        assert!(is_sensitive_header_name("Set-Cookie"));
        assert!(!is_sensitive_header_name("content-type"));
    }

    #[test]
    fn redact_url_for_sink_removes_userinfo_query_and_fragment() {
        let redacted = redact_url_for_sink(
            "https://user:pass@example.com:8443/path?token=secret&other=value#fragment",
        );

        assert_eq!(redacted, "https://example.com:8443/path?REDACTED");
    }

    #[test]
    fn redact_url_for_sink_keeps_non_sensitive_url_shape() {
        assert_eq!(
            redact_url_for_sink("http://example.com/path"),
            "http://example.com/path"
        );
    }

    #[test]
    fn redact_url_for_sink_does_not_echo_unparseable_secret_bearing_url() {
        assert_eq!(redact_url_for_sink("not a url?token=secret"), REDACTED_URL);
    }
}
