use std::fmt;

use crate::http1::head::{ContentType, RequestHead, RequestMethod, MAX_REQUEST_TARGET_BYTES};

use super::response::{AllowedMethod, ControlResponse, EmptyResponseStatus};

const CALLBACK_SUFFIX: &[u8] = b"/external-auth/callback";
const READINESS_SUFFIX: &[u8] = b"/ready";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControlRouter {
    callback_target: Box<[u8]>,
    readiness_target: Box<[u8]>,
}

impl ControlRouter {
    pub(crate) fn try_new(base_path: &str) -> Result<Self, ControlRouterError> {
        Ok(Self {
            callback_target: exact_target(base_path, CALLBACK_SUFFIX)?,
            readiness_target: exact_target(base_path, READINESS_SUFFIX)?,
        })
    }

    pub(crate) fn classify(&self, head: &RequestHead) -> ControlRoute {
        if head.target.as_bytes() == self.callback_target.as_ref() {
            return self.classify_callback(head);
        }
        if head.target.as_bytes() == self.readiness_target.as_ref() {
            return self.classify_readiness(head);
        }
        ControlRoute::Respond(ControlResponse::empty(EmptyResponseStatus::NotFound))
    }

    fn classify_callback(&self, head: &RequestHead) -> ControlRoute {
        if head.method != RequestMethod::Post {
            return ControlRoute::Respond(ControlResponse::method_not_allowed(AllowedMethod::Post));
        }
        if head.content_type != ContentType::ApplicationJson || head.content_encoding_present {
            return ControlRoute::Respond(ControlResponse::empty(
                EmptyResponseStatus::UnsupportedMediaType,
            ));
        }
        ControlRoute::Callback
    }

    fn classify_readiness(&self, head: &RequestHead) -> ControlRoute {
        if head.method == RequestMethod::Get {
            ControlRoute::Readiness
        } else {
            ControlRoute::Respond(ControlResponse::method_not_allowed(AllowedMethod::Get))
        }
    }
}

fn exact_target(base_path: &str, suffix: &[u8]) -> Result<Box<[u8]>, ControlRouterError> {
    let length = base_path
        .len()
        .checked_add(suffix.len())
        .ok_or(ControlRouterError::TargetTooLong)?;
    if length > MAX_REQUEST_TARGET_BYTES {
        return Err(ControlRouterError::TargetTooLong);
    }
    let mut target = Vec::new();
    target
        .try_reserve_exact(length)
        .map_err(|_| ControlRouterError::Allocation)?;
    target.extend_from_slice(base_path.as_bytes());
    target.extend_from_slice(suffix);
    Ok(target.into_boxed_slice())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlRoute {
    Callback,
    Readiness,
    Respond(ControlResponse),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlRouterError {
    Allocation,
    TargetTooLong,
}

impl fmt::Display for ControlRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("could not allocate control route targets"),
            Self::TargetTooLong => {
                formatter.write_str("control route target exceeds the 8 KiB parser limit")
            }
        }
    }
}

impl std::error::Error for ControlRouterError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::head::{parse_request_head, HeadParse};
    use crate::http1::store::ParserStore;

    fn classify(request: &[u8]) -> ControlRoute {
        let router = ControlRouter::try_new("/_acl-proxy").unwrap();
        let mut store = ParserStore::try_new().unwrap();
        store.append(request).unwrap();
        let HeadParse::Complete(head) = parse_request_head(&mut store).unwrap() else {
            panic!("test request head must be complete");
        };
        router.classify(&head)
    }

    #[test]
    fn callback_route_requires_one_exact_target() {
        let exact = classify(
            b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(exact, ControlRoute::Callback);

        for target in [
            "/_acl-proxy/external-auth/callback/",
            "/_acl-proxy/external-auth/callback?request=1",
            "/_acl-proxy//external-auth/callback",
            "/external-auth/callback",
            "http://control.test/_acl-proxy/external-auth/callback",
        ] {
            let request = format!(
                "POST {target} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"
            );
            let ControlRoute::Respond(response) = classify(request.as_bytes()) else {
                panic!("mismatched target must be rejected");
            };
            assert_eq!(response.status(), 404, "target {target}");
            assert_eq!(response.content_length(), 0);
            assert_eq!(response.cache_control(), "no-store");
        }
    }

    #[test]
    fn callback_method_precedes_media_validation() {
        let ControlRoute::Respond(response) = classify(
            b"GET /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n",
        ) else {
            panic!("wrong callback method must be rejected");
        };
        assert_eq!(response.status(), 405);
        assert_eq!(response.allow(), Some(AllowedMethod::Post));
        assert_eq!(response.allow().unwrap().as_str(), "POST");
    }

    #[test]
    fn callback_media_type_and_encoding_are_exact() {
        for headers in [
            "",
            "Content-Type: text/plain\r\n",
            "Content-Type: application/json; charset=utf-8\r\n",
            "Content-Type: application/json, application/json\r\n",
            "Content-Type: application/json\r\nContent-Type: application/json\r\n",
            "Content-Type: application/json\r\nContent-Encoding: identity\r\n",
        ] {
            let request = format!(
                "POST /_acl-proxy/external-auth/callback HTTP/1.1\r\n{headers}Content-Length: 0\r\n\r\n"
            );
            let ControlRoute::Respond(response) = classify(request.as_bytes()) else {
                panic!("invalid callback media headers must be rejected");
            };
            assert_eq!(response.status(), 415, "headers {headers:?}");
            assert_eq!(response.content_length(), 0);
            assert_eq!(response.cache_control(), "no-store");
        }

        assert_eq!(
            classify(
                b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type:\tApPlIcAtIoN/JsOn \t\r\nContent-Length: 0\r\n\r\n"
            ),
            ControlRoute::Callback
        );
    }

    #[test]
    fn readiness_route_is_exact_and_get_only() {
        assert_eq!(
            classify(b"GET /_acl-proxy/ready HTTP/1.1\r\n\r\n"),
            ControlRoute::Readiness
        );

        let ControlRoute::Respond(wrong_method) =
            classify(b"POST /_acl-proxy/ready HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
        else {
            panic!("wrong readiness method must be rejected");
        };
        assert_eq!(wrong_method.status(), 405);
        assert_eq!(wrong_method.allow(), Some(AllowedMethod::Get));
        assert_eq!(wrong_method.allow().unwrap().as_str(), "GET");

        for target in ["/_acl-proxy/ready/", "/_acl-proxy/ready?full=true"] {
            let request = format!("GET {target} HTTP/1.1\r\n\r\n");
            let ControlRoute::Respond(response) = classify(request.as_bytes()) else {
                panic!("mismatched readiness target must be rejected");
            };
            assert_eq!(response.status(), 404, "target {target}");
        }
    }

    #[test]
    fn route_targets_are_precomputed_with_the_parser_bound() {
        let maximum_base = "a".repeat(MAX_REQUEST_TARGET_BYTES - CALLBACK_SUFFIX.len() - 1);
        let maximum_base = format!("/{maximum_base}");
        ControlRouter::try_new(&maximum_base).unwrap();

        let oversized_base = format!("{maximum_base}a");
        assert_eq!(
            ControlRouter::try_new(&oversized_base).unwrap_err(),
            ControlRouterError::TargetTooLong
        );
    }
}
