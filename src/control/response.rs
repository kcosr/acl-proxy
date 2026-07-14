const NO_STORE: &str = "no-store";
const APPLICATION_JSON: &str = "application/json";
const READY_BODY: &[u8] = br#"{"status":"ready"}"#;
const NOT_READY_BODY: &[u8] = br#"{"status":"not_ready"}"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmptyResponseStatus {
    NoContent,
    BadRequest,
    NotFound,
    PayloadTooLarge,
    UnsupportedMediaType,
    ServiceUnavailable,
}

impl EmptyResponseStatus {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::NoContent => 204,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::PayloadTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::ServiceUnavailable => 503,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllowedMethod {
    Get,
    Post,
}

impl AllowedMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// Complete application response metadata for the control HTTP/1 encoder.
///
/// Constructors keep the response shapes fixed: callback and routing outcomes
/// are empty and readiness outcomes carry only their canonical JSON entity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlResponse {
    status: u16,
    content_length: usize,
    cache_control: &'static str,
    content_type: Option<&'static str>,
    allow: Option<AllowedMethod>,
    body: &'static [u8],
}

impl ControlResponse {
    pub(crate) const fn empty(status: EmptyResponseStatus) -> Self {
        Self {
            status: status.code(),
            content_length: 0,
            cache_control: NO_STORE,
            content_type: None,
            allow: None,
            body: b"",
        }
    }

    pub(crate) const fn method_not_allowed(allow: AllowedMethod) -> Self {
        Self {
            status: 405,
            content_length: 0,
            cache_control: NO_STORE,
            content_type: None,
            allow: Some(allow),
            body: b"",
        }
    }

    pub(crate) const fn readiness(ready: bool) -> Self {
        let (status, body) = if ready {
            (200, READY_BODY)
        } else {
            (503, NOT_READY_BODY)
        };
        Self {
            status,
            content_length: body.len(),
            cache_control: NO_STORE,
            content_type: Some(APPLICATION_JSON),
            allow: None,
            body,
        }
    }

    pub(crate) const fn status(self) -> u16 {
        self.status
    }

    pub(crate) const fn content_length(self) -> usize {
        self.content_length
    }

    pub(crate) const fn cache_control(self) -> &'static str {
        self.cache_control
    }

    pub(crate) const fn content_type(self) -> Option<&'static str> {
        self.content_type
    }

    pub(crate) const fn allow(self) -> Option<AllowedMethod> {
        self.allow
    }

    pub(crate) const fn body(self) -> &'static [u8] {
        self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_success_metadata_is_fixed_and_empty() {
        let response = ControlResponse::empty(EmptyResponseStatus::NoContent);

        assert_eq!(response.status(), 204);
        assert_eq!(response.content_length(), 0);
        assert_eq!(response.cache_control(), "no-store");
        assert_eq!(response.content_type(), None);
        assert_eq!(response.allow(), None);
        assert_eq!(response.body(), b"");
    }

    #[test]
    fn readiness_metadata_has_exact_json_entities() {
        let ready = ControlResponse::readiness(true);
        assert_eq!(ready.status(), 200);
        assert_eq!(ready.content_type(), Some("application/json"));
        assert_eq!(ready.body(), br#"{"status":"ready"}"#);
        assert_eq!(ready.content_length(), ready.body().len());
        assert_eq!(ready.cache_control(), "no-store");

        let not_ready = ControlResponse::readiness(false);
        assert_eq!(not_ready.status(), 503);
        assert_eq!(not_ready.content_type(), Some("application/json"));
        assert_eq!(not_ready.body(), br#"{"status":"not_ready"}"#);
        assert_eq!(not_ready.content_length(), not_ready.body().len());
        assert_eq!(not_ready.cache_control(), "no-store");
    }
}
