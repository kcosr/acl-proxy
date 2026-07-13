use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use idna::domain_to_ascii_strict;
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalUrl {
    pub url: String,
    pub scheme: String,
    pub authority: String,
    pub host: String,
    pub host_for_capture: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalAuthority {
    pub authority: String,
    pub host: String,
    pub host_for_capture: String,
    pub port: u16,
}

impl CanonicalAuthority {
    pub(crate) fn connect_authority(&self) -> String {
        format!("{}:{}", self.host_for_capture, self.port)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UrlError {
    #[error("invalid absolute HTTP/HTTPS URL")]
    Parse,
    #[error("URL scheme must be http or https")]
    Scheme,
    #[error("URL userinfo is not allowed")]
    UserInfo,
    #[error("URL fragments are not allowed")]
    Fragment,
    #[error("URL is missing a valid host")]
    Host,
    #[error("URL port must be a nonzero integer")]
    Port,
    #[error("URL contains an invalid percent escape")]
    PercentEscape,
    #[error("URL contains a forbidden raw component byte")]
    ComponentByte,
    #[error("invalid_url_ambiguous_double_encoding")]
    AmbiguousDoubleEncoding,
    #[error("invalid URL glob: {0}")]
    Glob(String),
}

pub(crate) fn canonicalize_http_url(raw: &str) -> Result<CanonicalUrl, UrlError> {
    if raw.trim() != raw || raw.contains('\\') || raw.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(UrlError::ComponentByte);
    }
    if raw.contains('#') {
        return Err(UrlError::Fragment);
    }
    let (raw_scheme, remainder) = raw.split_once("://").ok_or(UrlError::Parse)?;
    let scheme = canonical_scheme(&raw_scheme.to_ascii_lowercase())?;
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let raw_authority = &remainder[..authority_end];
    if raw_authority.is_empty() {
        return Err(UrlError::Host);
    }
    if raw_authority.contains('@') {
        return Err(UrlError::UserInfo);
    }
    let authority = canonicalize_http_authority(scheme, raw_authority)?;

    let target = &remainder[authority_end..];
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let path = normalize_path(if raw_path.is_empty() { "/" } else { raw_path })?;
    let query = raw_query
        .map(|query| normalize_component(query, ComponentKind::Query))
        .transpose()?;
    let query_suffix = query
        .as_ref()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();

    Ok(CanonicalUrl {
        url: format!("{scheme}://{}{path}{query_suffix}", authority.authority),
        scheme: scheme.to_string(),
        authority: authority.authority,
        host: authority.host,
        host_for_capture: authority.host_for_capture,
        port: authority.port,
        path,
        query,
    })
}

pub(crate) fn canonicalize_http_authority(
    scheme: &str,
    raw: &str,
) -> Result<CanonicalAuthority, UrlError> {
    let scheme = canonical_scheme(&scheme.to_ascii_lowercase())?;
    if raw.contains('@') {
        return Err(UrlError::UserInfo);
    }
    if raw.contains('#') {
        return Err(UrlError::Fragment);
    }
    if raw.trim() != raw
        || raw.is_empty()
        || raw.contains(['/', '?', '\\'])
        || raw.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(UrlError::Host);
    }

    let (raw_host, authored_port) = split_pattern_authority(raw)?;
    let host = canonical_host(raw_host)?;
    let default_port = if scheme == "http" { 80 } else { 443 };
    let port = authored_port.unwrap_or(default_port);
    let host_for_capture = authority_host(&host);
    let authority = if authored_port.is_some_and(|port| port != default_port) {
        format!("{host_for_capture}:{port}")
    } else {
        host_for_capture.clone()
    };

    Ok(CanonicalAuthority {
        authority,
        host,
        host_for_capture,
        port,
    })
}

pub(crate) fn canonicalize_tls_server_name(raw: &str) -> Result<String, UrlError> {
    if raw.trim() != raw
        || raw.is_empty()
        || raw.contains(['/', '?', '#', '\\', '@', '[', ']', ':'])
        || raw.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(UrlError::Host);
    }
    canonical_host(raw)
}

pub(crate) fn canonicalize_http_url_from_parts(
    scheme: &str,
    raw_authority: &str,
    raw_path_and_query: &str,
) -> Result<CanonicalUrl, UrlError> {
    let scheme = canonical_scheme(&scheme.to_ascii_lowercase())?;
    let authority = canonicalize_http_authority(scheme, raw_authority)?;
    if raw_path_and_query.contains('#') {
        return Err(UrlError::Fragment);
    }
    let target = if raw_path_and_query.is_empty() {
        "/"
    } else {
        raw_path_and_query
    };
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let path = normalize_path(raw_path)?;
    let query = raw_query
        .map(|query| normalize_component(query, ComponentKind::Query))
        .transpose()?;
    let query_suffix = query
        .as_ref()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();

    Ok(CanonicalUrl {
        url: format!("{scheme}://{}{path}{query_suffix}", authority.authority),
        scheme: scheme.to_string(),
        authority: authority.authority,
        host: authority.host,
        host_for_capture: authority.host_for_capture,
        port: authority.port,
        path,
        query,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledUrlPattern {
    match_all: bool,
    scheme: String,
    port: u16,
    host: HostPattern,
    path: Regex,
    query: Option<Regex>,
}

#[derive(Debug, Clone)]
enum HostPattern {
    Exact(String),
    Labels {
        patterns: Vec<HostLabelPattern>,
        has_recursive: bool,
    },
}

#[derive(Debug, Clone)]
enum HostLabelPattern {
    Exact(String),
    One,
    Recursive,
    Local(Regex),
}

impl CompiledUrlPattern {
    pub(crate) fn compile(raw: &str) -> Result<Self, UrlError> {
        if raw == "**" {
            return Ok(Self {
                match_all: true,
                scheme: String::new(),
                port: 0,
                host: HostPattern::Exact(String::new()),
                path: Regex::new("^$").expect("constant regex"),
                query: None,
            });
        }
        if raw.is_empty() || raw.contains('\\') || raw.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(UrlError::Glob(
                "pattern must be nonempty and contain no backslash".into(),
            ));
        }
        if raw.contains('#') {
            return Err(UrlError::Fragment);
        }

        let (raw_scheme, remainder) = raw.split_once("://").ok_or(UrlError::Parse)?;
        if raw_scheme.contains('*') {
            return Err(UrlError::Glob("scheme cannot contain a wildcard".into()));
        }
        let scheme = canonical_scheme(&raw_scheme.to_ascii_lowercase())?.to_string();
        let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let raw_authority = &remainder[..authority_end];
        if raw_authority.is_empty() {
            return Err(UrlError::Host);
        }
        if raw_authority.contains('@') {
            return Err(UrlError::UserInfo);
        }
        let (raw_host, authored_port) = split_pattern_authority(raw_authority)?;
        let default_port = if scheme == "http" { 80 } else { 443 };
        let port = authored_port.unwrap_or(default_port);
        let host = compile_host_pattern(raw_host)?;

        let target = &remainder[authority_end..];
        let (raw_path, raw_query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target, None),
        };
        let path = normalize_pattern_path(if raw_path.is_empty() { "/" } else { raw_path })?;
        let path = compile_component_glob(&path, ComponentKind::Path)?;
        let query = raw_query
            .map(|query| {
                normalize_component(query, ComponentKind::Query)
                    .and_then(|query| compile_component_glob(&query, ComponentKind::Query))
            })
            .transpose()?;

        Ok(Self {
            match_all: false,
            scheme,
            port,
            host,
            path,
            query,
        })
    }

    pub(crate) fn is_match(&self, url: &CanonicalUrl) -> bool {
        if self.match_all {
            return true;
        }
        if self.scheme != url.scheme || self.port != url.port || !self.host.is_match(&url.host) {
            return false;
        }
        if !self.path.is_match(&url.path) {
            return false;
        }
        match (&self.query, &url.query) {
            (None, _) => true,
            (Some(pattern), Some(query)) => pattern.is_match(query),
            (Some(_), None) => false,
        }
    }
}

impl HostPattern {
    fn is_match(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == host,
            Self::Labels {
                patterns,
                has_recursive,
            } => {
                if host.parse::<IpAddr>().is_ok() {
                    return false;
                }
                if !has_recursive {
                    let labels = host.split('.');
                    return patterns.len() == labels.clone().count()
                        && patterns
                            .iter()
                            .zip(labels)
                            .all(|(pattern, label)| host_label_matches(pattern, label));
                }
                let labels: Vec<&str> = host.split('.').collect();
                let memo_width = labels.len() + 1;
                let mut memo = vec![None; (patterns.len() + 1) * memo_width];
                match_host_labels(patterns, &labels, 0, 0, memo_width, &mut memo)
            }
        }
    }
}

fn host_label_matches(pattern: &HostLabelPattern, label: &str) -> bool {
    match pattern {
        HostLabelPattern::Exact(expected) => expected == label,
        HostLabelPattern::One => true,
        HostLabelPattern::Local(regex) => regex.is_match(label),
        HostLabelPattern::Recursive => false,
    }
}

fn match_host_labels(
    patterns: &[HostLabelPattern],
    labels: &[&str],
    pattern_index: usize,
    label_index: usize,
    memo_width: usize,
    memo: &mut [Option<bool>],
) -> bool {
    let memo_index = pattern_index * memo_width + label_index;
    if let Some(result) = memo[memo_index] {
        return result;
    }
    let result = if pattern_index == patterns.len() {
        label_index == labels.len()
    } else {
        match &patterns[pattern_index] {
            HostLabelPattern::Recursive => ((label_index + 1)..=labels.len()).any(|next| {
                match_host_labels(patterns, labels, pattern_index + 1, next, memo_width, memo)
            }),
            pattern if label_index < labels.len() => {
                host_label_matches(pattern, labels[label_index])
                    && match_host_labels(
                        patterns,
                        labels,
                        pattern_index + 1,
                        label_index + 1,
                        memo_width,
                        memo,
                    )
            }
            _ => false,
        }
    };
    memo[memo_index] = Some(result);
    result
}

fn canonical_scheme(raw: &str) -> Result<&'static str, UrlError> {
    match raw {
        "http" => Ok("http"),
        "https" => Ok("https"),
        _ => Err(UrlError::Scheme),
    }
}

fn canonical_host(raw: &str) -> Result<String, UrlError> {
    let host = raw.strip_suffix('.').unwrap_or(raw);
    if host.is_empty() {
        return Err(UrlError::Host);
    }
    if let Some(literal) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        let address = literal.parse::<Ipv6Addr>().map_err(|_| UrlError::Host)?;
        if is_deprecated_ipv4_compatible(address) {
            return Err(UrlError::Host);
        }
        return Ok(address
            .to_ipv4_mapped()
            .map(|mapped| mapped.to_string())
            .unwrap_or_else(|| address.to_string()));
    }
    if host.contains(':') {
        return Err(UrlError::Host);
    }
    if is_strict_ipv4_shape(host) {
        return host
            .parse::<Ipv4Addr>()
            .map(|address| address.to_string())
            .map_err(|_| UrlError::Host);
    }
    if is_legacy_ipv4_spelling(host) {
        return Err(UrlError::Host);
    }
    let domain = domain_to_ascii_strict(host).map_err(|_| UrlError::Host)?;
    let domain = domain.to_ascii_lowercase();
    validate_dns_name(&domain)?;
    Ok(domain)
}

fn is_deprecated_ipv4_compatible(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[..12].iter().all(|octet| *octet == 0)
        && address != Ipv6Addr::UNSPECIFIED
        && address != Ipv6Addr::LOCALHOST
}

fn is_strict_ipv4_shape(host: &str) -> bool {
    host.split('.').count() == 4
        && host
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_legacy_ipv4_spelling(host: &str) -> bool {
    let parts: Vec<_> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    let Some(numbers) = parts
        .iter()
        .map(|part| parse_legacy_ipv4_number(part))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if numbers[..numbers.len() - 1]
        .iter()
        .any(|number| *number > 255)
    {
        return false;
    }
    let last_limit = 1u64 << (8 * (5 - numbers.len()));
    numbers[numbers.len() - 1] < last_limit
}

fn parse_legacy_ipv4_number(raw: &str) -> Option<u64> {
    let (digits, radix) =
        if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            (hex, 16)
        } else if raw.len() > 1 && raw.starts_with('0') {
            (&raw[1..], 8)
        } else {
            (raw, 10)
        };
    if digits.is_empty() {
        return (raw == "0").then_some(0);
    }
    u64::from_str_radix(digits, radix).ok()
}

fn validate_dns_name(host: &str) -> Result<(), UrlError> {
    if host.is_empty() || host.len() > 253 {
        return Err(UrlError::Host);
    }
    for label in host.split('.') {
        validate_dns_label(label)?;
    }
    Ok(())
}

fn validate_dns_label(label: &str) -> Result<(), UrlError> {
    let bytes = label.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(UrlError::Host);
    }
    Ok(())
}

fn authority_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn split_pattern_authority(authority: &str) -> Result<(&str, Option<u16>), UrlError> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or(UrlError::Host)?;
        let host = &authority[..=end];
        let suffix = &authority[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            let raw = suffix.strip_prefix(':').ok_or(UrlError::Port)?;
            Some(parse_port(raw)?)
        };
        return Ok((host, port));
    }
    if authority.matches(':').count() > 1 {
        return Err(UrlError::Host);
    }
    match authority.rsplit_once(':') {
        Some((host, raw_port)) => Ok((host, Some(parse_port(raw_port)?))),
        None => Ok((authority, None)),
    }
}

fn parse_port(raw: &str) -> Result<u16, UrlError> {
    if raw.contains('*') {
        return Err(UrlError::Glob("port cannot contain a wildcard".into()));
    }
    let port = raw.parse::<u16>().map_err(|_| UrlError::Port)?;
    if port == 0 {
        return Err(UrlError::Port);
    }
    Ok(port)
}

fn compile_host_pattern(raw: &str) -> Result<HostPattern, UrlError> {
    if !raw.contains('*') {
        return Ok(HostPattern::Exact(canonical_host(raw)?));
    }
    if raw.starts_with('[') {
        return Err(UrlError::Glob(
            "IP literals cannot contain host wildcards".into(),
        ));
    }
    let host = raw.strip_suffix('.').unwrap_or(raw);
    if host.is_empty() || host.len() > 253 {
        return Err(UrlError::Host);
    }
    if is_ipv4_shaped_glob(host) {
        return Err(UrlError::Glob(
            "IP literals cannot be expressed with host wildcards".into(),
        ));
    }
    let mut labels = Vec::new();
    let mut canonical_length = 0usize;
    for raw_label in host.split('.') {
        if raw_label.is_empty() {
            return Err(UrlError::Host);
        }
        let (label, label_length) = match raw_label {
            "*" => (HostLabelPattern::One, 1),
            "**" => (HostLabelPattern::Recursive, 1),
            label if label.contains("**") => {
                return Err(UrlError::Glob(
                    "recursive host wildcard must occupy a complete label".into(),
                ));
            }
            label if label.contains('*') => (
                HostLabelPattern::Local(compile_local_label(label)?),
                label.len(),
            ),
            label => {
                let label = canonical_literal_label(label)?;
                let length = label.len();
                (HostLabelPattern::Exact(label), length)
            }
        };
        labels.push(label);
        canonical_length = canonical_length
            .checked_add(label_length)
            .and_then(|length| length.checked_add(usize::from(labels.len() > 1)))
            .ok_or(UrlError::Host)?;
    }
    if canonical_length > 253 {
        return Err(UrlError::Host);
    }
    let has_recursive = labels
        .iter()
        .any(|label| matches!(label, HostLabelPattern::Recursive));
    Ok(HostPattern::Labels {
        patterns: labels,
        has_recursive,
    })
}

fn is_ipv4_shaped_glob(host: &str) -> bool {
    let labels: Vec<_> = host.split('.').collect();
    (1..=4).contains(&labels.len())
        && host.contains('*')
        && host.bytes().any(|byte| byte.is_ascii_digit())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'*')
        })
}

fn canonical_literal_label(raw: &str) -> Result<String, UrlError> {
    let label = domain_to_ascii_strict(raw).map_err(|_| UrlError::Host)?;
    if label.contains('.') {
        return Err(UrlError::Host);
    }
    let label = label.to_ascii_lowercase();
    validate_dns_label(&label)?;
    Ok(label)
}

fn compile_local_label(raw: &str) -> Result<Regex, UrlError> {
    if !raw.is_ascii()
        || raw.len() > 63
        || raw.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'*')
        })
    {
        return Err(UrlError::Glob(
            "label-local wildcards require lowercase ASCII DNS-label bytes".into(),
        ));
    }
    let expression = glob_regex(raw, "[^.]*", "[^.]*");
    Regex::new(&format!("^{expression}$")).map_err(|error| UrlError::Glob(error.to_string()))
}

#[derive(Debug, Clone, Copy)]
enum ComponentKind {
    Path,
    Query,
}

fn compile_component_glob(raw: &str, kind: ComponentKind) -> Result<Regex, UrlError> {
    let (single, recursive) = match kind {
        ComponentKind::Path => ("[^/]*", ".*"),
        ComponentKind::Query => ("[^&]*", ".*"),
    };
    let expression = if matches!(kind, ComponentKind::Path) && raw.ends_with("/**") {
        let base = &raw[..raw.len() - 3];
        format!("{}(?:/.*)?", glob_regex(base, single, recursive))
    } else {
        glob_regex(raw, single, recursive)
    };
    Regex::new(&format!("^{expression}$")).map_err(|error| UrlError::Glob(error.to_string()))
}

fn normalize_pattern_path(path: &str) -> Result<String, UrlError> {
    let normalized = normalize_component(
        if path.is_empty() { "/" } else { path },
        ComponentKind::Path,
    )?;
    if !normalized.starts_with('/') {
        return Err(UrlError::Parse);
    }
    if normalized
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(UrlError::Glob(
            "path patterns cannot contain dot or dot-dot segments".into(),
        ));
    }
    Ok(normalized)
}

fn glob_regex(raw: &str, single: &str, recursive: &str) -> String {
    let mut expression = String::new();
    let mut literals = String::new();
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'*' {
            expression.push_str(&regex::escape(&literals));
            literals.clear();
            if index + 1 < bytes.len() && bytes[index + 1] == b'*' {
                expression.push_str(recursive);
                index += 2;
            } else {
                expression.push_str(single);
                index += 1;
            }
        } else {
            literals.push(bytes[index] as char);
            index += 1;
        }
    }
    expression.push_str(&regex::escape(&literals));
    expression
}

fn normalize_path(path: &str) -> Result<String, UrlError> {
    let normalized = normalize_component(
        if path.is_empty() { "/" } else { path },
        ComponentKind::Path,
    )?;
    if !normalized.starts_with('/') {
        return Err(UrlError::Parse);
    }
    let mut segments = Vec::new();
    let segment_count = normalized.split('/').count();
    for (index, segment) in normalized.split('/').enumerate() {
        let last = index + 1 == segment_count;
        match segment {
            "." => {
                if last {
                    segments.push("");
                }
            }
            ".." => {
                if segments.len() > 1 {
                    segments.pop();
                }
                if last {
                    segments.push("");
                }
            }
            segment => segments.push(segment),
        }
    }
    let result = segments.join("/");
    if result.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(result)
    }
}

fn normalize_component(component: &str, kind: ComponentKind) -> Result<String, UrlError> {
    let bytes = component.as_bytes();
    let mut normalized = String::with_capacity(component.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' || byte.is_ascii_control() {
            return Err(UrlError::ComponentByte);
        }
        if byte != b'%' {
            if byte.is_ascii() && is_allowed_raw_component_byte(byte, kind) {
                normalized.push(byte as char);
            } else {
                normalized.push('%');
                normalized.push(hex_digit(byte >> 4));
                normalized.push(hex_digit(byte & 0x0f));
            }
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(UrlError::PercentEscape);
        }
        let high = hex_value(bytes[index + 1]).ok_or(UrlError::PercentEscape)?;
        let low = hex_value(bytes[index + 2]).ok_or(UrlError::PercentEscape)?;
        let decoded = (high << 4) | low;
        if decoded == 0 || decoded == b'\\' || decoded.is_ascii_control() {
            return Err(UrlError::ComponentByte);
        }
        if decoded == b'%'
            && index + 4 < bytes.len()
            && hex_value(bytes[index + 3]).is_some()
            && hex_value(bytes[index + 4]).is_some()
        {
            return Err(UrlError::AmbiguousDoubleEncoding);
        }
        if is_unreserved(decoded) {
            normalized.push(decoded as char);
        } else {
            normalized.push('%');
            normalized.push(hex_digit(high));
            normalized.push(hex_digit(low));
        }
        index += 3;
    }
    if contains_ambiguous_percent_shape(&normalized) {
        return Err(UrlError::AmbiguousDoubleEncoding);
    }
    Ok(normalized)
}

fn is_allowed_raw_component_byte(byte: u8, kind: ComponentKind) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
        || byte == b'/'
        || (matches!(kind, ComponentKind::Query) && byte == b'?')
}

fn contains_ambiguous_percent_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    (0..bytes.len().saturating_sub(4)).any(|index| {
        bytes[index] == b'%'
            && bytes[index + 1..index + 3].eq_ignore_ascii_case(b"25")
            && hex_value(bytes[index + 3]).is_some()
            && hex_value(bytes[index + 4]).is_some()
    })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    HEX[value as usize] as char
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct GoldenCase {
        input: String,
        url: Option<String>,
        authority: Option<String>,
        host_for_capture: Option<String>,
        port: Option<u16>,
        error: Option<String>,
    }

    fn matches(pattern: &str, url: &str) -> bool {
        let pattern = CompiledUrlPattern::compile(pattern).unwrap();
        let url = canonicalize_http_url(url).unwrap();
        pattern.is_match(&url)
    }

    #[test]
    fn canonicalization_matches_the_end_state_golden_corpus() {
        let cases: Vec<GoldenCase> = serde_json::from_str(include_str!(
            "../tests/fixtures/golden/normalized-urls.json"
        ))
        .expect("parse URL golden corpus");

        for case in cases {
            match canonicalize_http_url(&case.input) {
                Ok(actual) => {
                    actual
                        .url
                        .parse::<http::Uri>()
                        .expect("canonical URL must be a legal HTTP request target");
                    assert_eq!(Some(actual.url), case.url, "{}: URL", case.input);
                    assert_eq!(
                        Some(actual.authority),
                        case.authority,
                        "{}: authority",
                        case.input
                    );
                    assert_eq!(
                        Some(actual.host_for_capture),
                        case.host_for_capture,
                        "{}: capture host",
                        case.input
                    );
                    assert_eq!(Some(actual.port), case.port, "{}: port", case.input);
                    assert_eq!(case.error, None, "{}: unexpected success", case.input);
                }
                Err(error) => {
                    assert_eq!(Some(error.to_string()), case.error, "{}: error", case.input);
                    assert_eq!(case.url, None, "{}: expected URL", case.input);
                }
            }
        }
    }

    #[test]
    fn canonicalization_honors_scheme_authority_path_and_query() {
        let url =
            canonicalize_http_url("https://EXAMPLE.com.:443/a/%2e%2e/admin/%7eme/%3a?q=%61&x=%2f")
                .unwrap();
        assert_eq!(url.url, "https://example.com/admin/~me/%3A?q=a&x=%2F");
        assert_eq!(url.authority, "example.com");
        assert_eq!(url.path, "/admin/~me/%3A");
        assert_eq!(url.query.as_deref(), Some("q=a&x=%2F"));

        let empty_segments = canonicalize_http_url("https://example.com/a//b/../c").unwrap();
        assert_eq!(empty_segments.path, "/a//c");

        let mapped = canonicalize_http_url("http://[::ffff:127.0.0.1]/").unwrap();
        assert_eq!(mapped.host, "127.0.0.1");
        assert_eq!(mapped.authority, "127.0.0.1");

        let query = canonicalize_http_url("HTTPS://example.com:443/path?Key=One&key=two&Key=Three")
            .unwrap();
        assert_eq!(
            query.url,
            "https://example.com/path?Key=One&key=two&Key=Three"
        );

        let structural =
            canonicalize_http_url("https://example.com/a%2fb%3fc%23d?q=%2f%3f%23").unwrap();
        assert_eq!(
            structural.url,
            "https://example.com/a%2Fb%3Fc%23d?q=%2F%3F%23"
        );
    }

    #[test]
    fn standalone_authority_canonicalization_matches_full_urls() {
        let cases = [
            ("http", "EXAMPLE.com.:80", "example.com", "example.com", 80),
            (
                "https",
                "b\u{fc}cher.example.:443",
                "xn--bcher-kva.example",
                "xn--bcher-kva.example",
                443,
            ),
            (
                "https",
                "[2001:0db8::1]:8443",
                "[2001:db8::1]:8443",
                "2001:db8::1",
                8443,
            ),
            (
                "https",
                "[::ffff:192.0.2.1]:443",
                "192.0.2.1",
                "192.0.2.1",
                443,
            ),
        ];

        for (scheme, raw, expected_authority, expected_host, expected_port) in cases {
            let authority = canonicalize_http_authority(scheme, raw).unwrap();
            assert_eq!(authority.authority, expected_authority);
            assert_eq!(authority.host, expected_host);
            assert_eq!(authority.port, expected_port);

            let url = canonicalize_http_url(&format!("{scheme}://{raw}/")).unwrap();
            assert_eq!(url.authority, authority.authority);
            assert_eq!(url.host, authority.host);
            assert_eq!(url.host_for_capture, authority.host_for_capture);
            assert_eq!(url.port, authority.port);
        }
    }

    #[test]
    fn authority_and_sni_canonicalizers_reject_non_authority_shapes() {
        for raw in [
            "",
            " example.com",
            "example.com ",
            "user@example.com",
            "example.com/path",
            "example.com?x=1",
            "example.com#fragment",
            "example.com:0",
            "[2001:db8::1",
            "127.1",
        ] {
            assert!(canonicalize_http_authority("https", raw).is_err(), "{raw}");
        }

        assert_eq!(
            canonicalize_tls_server_name("B\u{dc}CHER.example.").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            canonicalize_tls_server_name("192.0.2.1").unwrap(),
            "192.0.2.1"
        );
        for raw in ["", "example.com:443", "[2001:db8::1]", "a/b", " user.test"] {
            assert!(canonicalize_tls_server_name(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn url_from_parts_uses_the_exact_canonical_component_contract() {
        let from_parts = canonicalize_http_url_from_parts(
            "HTTPS",
            "EXAMPLE.com.:443",
            "/a/%2e%2e/b%2fc?Key=%61&x=%2f",
        )
        .unwrap();
        let full =
            canonicalize_http_url("HTTPS://EXAMPLE.com.:443/a/%2e%2e/b%2fc?Key=%61&x=%2f").unwrap();
        assert_eq!(from_parts, full);

        let ipv6 = canonicalize_http_authority("https", "[2001:db8::1]").unwrap();
        assert_eq!(ipv6.connect_authority(), "[2001:db8::1]:443");
    }

    #[test]
    fn canonicalization_rejects_ambiguous_or_unsafe_inputs() {
        for raw in [
            "ftp://example.com/",
            "https://user@example.com/",
            "https://example.com/path#fragment",
            "https://example.com/%252fadmin",
            "https://example.com/%25%32%65",
            "https://example.com/%00/..",
            "https://example.com/%252f/..",
            "https://example.com/%ZZ/..",
            "https://example.com/%00",
            "https://example.com/path\nignored",
            " https://example.com/",
            "https://bad_host.example/",
            "https://example.com../",
            "https://xn--/",
            "https://-leading.example/",
            "https://trailing-.example/",
        ] {
            assert!(canonicalize_http_url(raw).is_err(), "{raw}");
        }
        assert!(matches!(
            canonicalize_http_url("https://example.com/%252fadmin"),
            Err(UrlError::AmbiguousDoubleEncoding)
        ));
    }

    #[test]
    fn excluded_raw_ascii_is_percent_encoded_symmetrically() {
        for (raw, encoded) in [
            ('[', "%5B"),
            (']', "%5D"),
            ('{', "%7B"),
            ('}', "%7D"),
            ('|', "%7C"),
            ('^', "%5E"),
            (' ', "%20"),
            ('<', "%3C"),
            ('>', "%3E"),
            ('"', "%22"),
            ('`', "%60"),
        ] {
            let raw_url = format!("https://example.com/p{raw}ath?q={raw}value");
            let canonical = canonicalize_http_url(&raw_url).unwrap();
            assert_eq!(
                canonical.url,
                format!("https://example.com/p{encoded}ath?q={encoded}value")
            );
            canonical
                .url
                .parse::<http::Uri>()
                .expect("canonical URL must remain a legal HTTP request target");

            let pattern = CompiledUrlPattern::compile(&raw_url).unwrap();
            assert!(pattern.is_match(&canonical));
        }
    }

    #[test]
    fn strict_dns_and_ip_paths_reject_resolver_ipv4_coercions() {
        let numeric_dns = canonicalize_http_url("https://example.123/").unwrap();
        assert_eq!(numeric_dns.host, "example.123");
        let out_of_range_numeric_dns = canonicalize_http_url("https://4294967296/").unwrap();
        assert_eq!(out_of_range_numeric_dns.host, "4294967296");
        let canonical_ipv4 = canonicalize_http_url("http://192.0.2.1/").unwrap();
        assert_eq!(canonical_ipv4.host, "192.0.2.1");

        for host in [
            "127.1",
            "127.0.1",
            "2130706433",
            "0x7f000001",
            "017700000001",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "127.0.0x1",
        ] {
            assert!(matches!(
                canonicalize_http_url(&format!("http://{host}/")),
                Err(UrlError::Host)
            ));
        }

        assert!(matches(
            "https://*.example.123/**",
            "https://api.example.123/path"
        ));
    }

    #[test]
    fn deprecated_ipv4_compatible_ipv6_literals_are_rejected() {
        for raw in [
            "http://[::192.0.2.1]/",
            "http://[::c000:201]/",
            "https://[::0.0.0.2]:8443/",
        ] {
            assert!(matches!(canonicalize_http_url(raw), Err(UrlError::Host)));
        }

        assert_eq!(canonicalize_http_url("http://[::]/").unwrap().host, "::");
        assert_eq!(canonicalize_http_url("http://[::1]/").unwrap().host, "::1");
        assert_eq!(
            canonicalize_http_url("http://[::ffff:192.0.2.1]/")
                .unwrap()
                .host,
            "192.0.2.1"
        );
    }

    #[test]
    fn ipv4_shaped_host_globs_are_rejected_instead_of_becoming_dns_patterns() {
        for pattern in [
            "http://169.254.*.*/**",
            "http://127.*/**",
            "http://10.**/**",
            "http://192.168.*/**",
            "http://1*/**",
            "https://*.0.2.1/**",
            "https://192.0.2.*/**",
            "https://1*.2.3.4/**",
            "https://**.2.3.4/**",
        ] {
            assert!(matches!(
                CompiledUrlPattern::compile(pattern),
                Err(UrlError::Glob(_))
            ));
        }

        CompiledUrlPattern::compile("https://build-*.2.3.4/**")
            .expect("a visibly nonnumeric DNS label remains a hostname glob");
        CompiledUrlPattern::compile("https://**/**")
            .expect("a pure wildcard remains a DNS hostname glob");
    }

    #[test]
    fn dns_host_globs_never_match_canonical_ip_targets() {
        let pattern = CompiledUrlPattern::compile("http://**/**").unwrap();
        for target in [
            "http://192.0.2.1/path",
            "http://[::ffff:192.0.2.1]/path",
            "http://[2001:db8::1]/path",
        ] {
            let target = canonicalize_http_url(target).unwrap();
            assert!(!pattern.is_match(&target), "{target:?}");
        }
    }

    #[test]
    fn host_globs_preserve_recursive_one_label_and_label_local_intent() {
        assert!(!matches(
            "https://**.chatgpt.com/**",
            "https://chatgpt.com/"
        ));
        assert!(matches(
            "https://**.chatgpt.com/**",
            "https://a.chatgpt.com/"
        ));
        assert!(matches(
            "https://**.chatgpt.com/**",
            "https://a.b.chatgpt.com/path"
        ));
        assert!(matches("https://*.cursor.sh/**", "https://api.cursor.sh/"));
        assert!(!matches(
            "https://*.cursor.sh/**",
            "https://a.api.cursor.sh/"
        ));
        assert!(matches(
            "https://rocky-linux-*.production.gcp.mirrors.ctrliq.cloud/**",
            "https://rocky-linux-9.production.gcp.mirrors.ctrliq.cloud/pkg"
        ));
        assert!(matches!(
            CompiledUrlPattern::compile(
                "https://ROCKY-LINUX-*.PRODUCTION.GCP.MIRRORS.CTRLIQ.CLOUD/**"
            ),
            Err(UrlError::Glob(_))
        ));
        assert!(!matches(
            "https://rocky-linux-*.production.gcp.mirrors.ctrliq.cloud/**",
            "https://rocky-linux.evil.production.gcp.mirrors.ctrliq.cloud/pkg"
        ));

        assert!(matches(
            "https://api.**.example.com/**",
            "https://api.us.example.com/"
        ));
        assert!(matches(
            "https://api.**.example.com/**",
            "https://api.us.central.example.com/"
        ));
        assert!(!matches(
            "https://api.**.example.com/**",
            "https://api.example.com/"
        ));
        assert!(matches(
            "https://api-*.example.com/**",
            "https://api-v1.example.com/"
        ));
        assert!(!matches(
            "https://api-*.example.com/**",
            "https://api.v1.example.com/"
        ));
        assert!(matches!(
            CompiledUrlPattern::compile("https://api**prod.example.com/**"),
            Err(UrlError::Glob(_))
        ));
    }

    #[test]
    fn production_hostname_glob_corpus_preserves_label_boundaries() {
        for suffix in ["chatgpt.com", "sentry.io", "datadoghq.com"] {
            let pattern = format!("https://**.{suffix}/**");
            assert!(!matches(&pattern, &format!("https://{suffix}/")));
            assert!(matches(&pattern, &format!("https://api.{suffix}/")));
            assert!(matches(
                &pattern,
                &format!("https://us.api.{suffix}/v1/items")
            ));
            assert!(!matches(
                &pattern,
                &format!("https://api.{suffix}.attacker.test/")
            ));
        }

        for suffix in ["cursor.sh", "vailsys.com", "vailsys.net"] {
            let pattern = format!("https://*.{suffix}/**");
            assert!(!matches(&pattern, &format!("https://{suffix}/")));
            assert!(matches(&pattern, &format!("https://api.{suffix}/")));
            assert!(!matches(&pattern, &format!("https://us.api.{suffix}/")));
        }

        let rocky = "https://rocky-linux-*.production.gcp.mirrors.ctrliq.cloud/**";
        assert!(matches(
            rocky,
            "https://rocky-linux-9.production.gcp.mirrors.ctrliq.cloud/packages"
        ));
        assert!(matches(
            rocky,
            "https://rocky-linux-9-stream.production.gcp.mirrors.ctrliq.cloud/packages"
        ));
        assert!(!matches(
            rocky,
            "https://rocky-linux-9.evil.production.gcp.mirrors.ctrliq.cloud/packages"
        ));
    }

    #[test]
    fn component_globs_do_not_cross_boundaries_and_terminal_recursive_includes_prefix() {
        assert!(matches(
            "https://example.com/api/*",
            "https://example.com/api/item"
        ));
        assert!(!matches(
            "https://example.com/api/*",
            "https://example.com/api/a/b"
        ));
        assert!(matches(
            "https://example.com/api/**",
            "https://example.com/api"
        ));
        assert!(matches(
            "https://example.com/api/**",
            "https://example.com/api/"
        ));
        assert!(matches(
            "https://example.com/api/**",
            "https://example.com/api/a/b"
        ));
        assert!(matches(
            "https://example.com/deny",
            "https://example.com/deny?added=1"
        ));
        assert!(!matches(
            "https://example.com/deny?key=*",
            "https://example.com/deny?other=1"
        ));
        assert!(matches(
            "https://example.com/café?q=é",
            "https://example.com/café?q=é"
        ));
        assert!(matches(
            "https://example.com/empty?",
            "https://example.com/empty?"
        ));
        assert!(!matches(
            "https://example.com/empty?",
            "https://example.com/empty"
        ));
        assert!(matches(
            "https://example.com/search?key=*",
            "https://example.com/search?key=one"
        ));
        assert!(!matches(
            "https://example.com/search?key=*",
            "https://example.com/search?key=one&admin=true"
        ));
        assert!(matches(
            "https://example.com/search?key=**",
            "https://example.com/search?key=one&admin=true"
        ));
        assert!(matches(
            "https://example.com/search?key=*&mode=safe",
            "https://example.com/search?key=one&mode=safe"
        ));
        assert!(!matches(
            "https://example.com/search?key=*&mode=safe",
            "https://example.com/search?key=one&admin=true&mode=safe"
        ));
    }

    #[test]
    fn authored_pattern_paths_reject_dot_segments_before_canonicalization() {
        for pattern in [
            "https://example.com/a/../admin",
            "https://example.com/a/./admin",
            "https://example.com/a/%2e%2e/admin",
            "https://example.com/a/.%2e/admin",
        ] {
            assert!(matches!(
                CompiledUrlPattern::compile(pattern),
                Err(UrlError::Glob(_))
            ));
        }

        assert_eq!(
            canonicalize_http_url("https://example.com/a/../admin")
                .unwrap()
                .path,
            "/admin"
        );
    }

    #[test]
    fn recursive_host_matching_is_bounded_for_adversarial_patterns() {
        let pattern =
            CompiledUrlPattern::compile("https://**.**.**.**.**.**.expected.example/**").unwrap();
        let url =
            canonicalize_http_url("https://a.b.c.d.e.f.g.h.i.j.k.l.m.n.wrong.example/").unwrap();
        assert!(!pattern.is_match(&url));
    }

    #[test]
    fn scheme_port_and_encoded_asterisk_are_literal_boundaries() {
        assert!(!matches("http://example.com/**", "https://example.com/"));
        assert!(!matches(
            "https://example.com:8443/**",
            "https://example.com/"
        ));
        assert!(matches(
            "https://example.com/%2a",
            "https://example.com/%2A"
        ));
        assert!(!matches(
            "https://example.com/%2a",
            "https://example.com/anything"
        ));
        assert!(!matches("https://example.com/%2a", "https://example.com/*"));
        assert!(matches(
            "https://example.com:443/path?Key=*&key=two&Key=*",
            "https://example.com/path?Key=One&key=two&Key=Three"
        ));
        assert!(!matches(
            "https://example.com/path?key=two&Key=One&Key=Three",
            "https://example.com/path?Key=One&key=two&Key=Three"
        ));
    }
}
