use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http_access_runtime::{RuntimeError, StandaloneExchange};
use http_access_types::{BodyFraming, TrailerPolicy};
use hyper::body::{HttpBody, SizeHint};

use super::ingress::CaptureSubmission;
use crate::standalone_provider_result::StandaloneRequestSidecar;

/// Product transport body retaining the exact checked exchange and its
/// request-scoped resources until Hyper releases the outbound body.
pub(crate) struct StandaloneExchangeBody {
    exchange: StandaloneExchange,
    _sidecar: StandaloneRequestSidecar,
    state: BodyState,
    exact_remaining: Option<u64>,
    trailers_allowed: bool,
    capture: Option<CaptureSubmission>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyState {
    Data,
    Trailers,
    Complete,
    Failed,
}

/// Sanitized failures emitted while adapting a checked standalone exchange to
/// Hyper's request-body contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StandaloneExchangeBodyError {
    #[error("standalone request body failed")]
    Runtime(#[source] RuntimeError),
    #[error("standalone request body length is inconsistent")]
    Length,
    #[error("standalone request trailers were polled before body EOF")]
    TrailerOrder,
    #[error("standalone request trailer capacity is unavailable")]
    TrailerCapacity,
    #[error("standalone request trailer name is invalid")]
    TrailerName,
    #[error("standalone request trailer value is invalid")]
    TrailerValue,
}

impl StandaloneExchangeBody {
    pub(crate) fn new(exchange: StandaloneExchange, sidecar: StandaloneRequestSidecar) -> Self {
        let exact_remaining = match exchange.facts().body().framing() {
            BodyFraming::None => Some(0),
            BodyFraming::ContentLength(length) => Some(length),
            BodyFraming::Chunked | BodyFraming::Http2Stream => None,
        };
        let trailers_allowed = matches!(
            exchange.plan().request_body().trailer_policy(),
            TrailerPolicy::Allow
        );
        Self {
            exchange,
            _sidecar: sidecar,
            state: BodyState::Data,
            exact_remaining,
            trailers_allowed,
            capture: None,
        }
    }

    pub(super) fn set_capture(&mut self, capture: Option<CaptureSubmission>) {
        self.capture = capture;
        if self.exact_remaining == Some(0) {
            if let Some(capture) = self.capture.as_mut() {
                capture.finish_data_if_complete(true);
            }
        }
    }

    fn fail(&mut self, error: StandaloneExchangeBodyError) -> StandaloneExchangeBodyError {
        self.state = BodyState::Failed;
        self.exact_remaining = None;
        error
    }
}

impl HttpBody for StandaloneExchangeBody {
    type Data = Bytes;
    type Error = StandaloneExchangeBodyError;

    fn poll_data(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        if self.state != BodyState::Data {
            return Poll::Ready(None);
        }

        match self.exchange.poll_body_chunk(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(chunk))) => {
                let chunk_len = u64::try_from(chunk.as_bytes().len()).unwrap_or(u64::MAX);
                if let Some(remaining) = self.exact_remaining.as_mut() {
                    let Some(next) = remaining.checked_sub(chunk_len) else {
                        let error = self.fail(StandaloneExchangeBodyError::Length);
                        return Poll::Ready(Some(Err(error)));
                    };
                    *remaining = next;
                }
                let complete = self.exact_remaining == Some(0);
                if let Some(capture) = self.capture.as_mut() {
                    capture.push(chunk.as_bytes());
                    capture.finish_data_if_complete(complete);
                }
                Poll::Ready(Some(Ok(Bytes::copy_from_slice(chunk.as_bytes()))))
            }
            Poll::Ready(Ok(None)) => {
                if self.exact_remaining.is_some_and(|remaining| remaining != 0) {
                    let error = self.fail(StandaloneExchangeBodyError::Length);
                    return Poll::Ready(Some(Err(error)));
                }
                if let Some(capture) = self.capture.as_mut() {
                    capture.finish_data_if_complete(true);
                }
                self.state = if self.trailers_allowed {
                    BodyState::Trailers
                } else {
                    BodyState::Complete
                };
                Poll::Ready(None)
            }
            Poll::Ready(Err(error)) => {
                if let Some(capture) = self.capture.as_mut() {
                    capture.abandon();
                }
                let error = self.fail(StandaloneExchangeBodyError::Runtime(error));
                Poll::Ready(Some(Err(error)))
            }
        }
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        match self.state {
            BodyState::Data => {
                let error = self.fail(StandaloneExchangeBodyError::TrailerOrder);
                Poll::Ready(Err(error))
            }
            BodyState::Complete | BodyState::Failed => Poll::Ready(Ok(None)),
            BodyState::Trailers => match self.exchange.poll_trailers(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Some(trailers))) => {
                    let converted = checked_trailers(
                        trailers.iter().map(|field| (field.name(), field.value())),
                    );
                    match converted {
                        Ok(trailers) => {
                            if let Some(capture) = self.capture.as_mut() {
                                capture.finish();
                            }
                            self.state = BodyState::Complete;
                            Poll::Ready(Ok(Some(trailers)))
                        }
                        Err(error) => {
                            if let Some(capture) = self.capture.as_mut() {
                                capture.abandon();
                            }
                            let error = self.fail(error);
                            Poll::Ready(Err(error))
                        }
                    }
                }
                Poll::Ready(Ok(None)) => {
                    if let Some(capture) = self.capture.as_mut() {
                        capture.finish();
                    }
                    self.state = BodyState::Complete;
                    Poll::Ready(Ok(None))
                }
                Poll::Ready(Err(error)) => {
                    if let Some(capture) = self.capture.as_mut() {
                        capture.abandon();
                    }
                    let error = self.fail(StandaloneExchangeBodyError::Runtime(error));
                    Poll::Ready(Err(error))
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.state, BodyState::Complete | BodyState::Failed)
            || (self.state == BodyState::Data && self.exact_remaining == Some(0))
    }

    fn size_hint(&self) -> SizeHint {
        self.exact_remaining
            .map(SizeHint::with_exact)
            .unwrap_or_default()
    }
}

fn checked_trailers<'a>(
    fields: impl ExactSizeIterator<Item = (&'a str, &'a [u8])>,
) -> Result<HeaderMap, StandaloneExchangeBodyError> {
    let mut trailers = HeaderMap::new();
    trailers
        .try_reserve(fields.len())
        .map_err(|_| StandaloneExchangeBodyError::TrailerCapacity)?;
    for (name, value) in fields {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| StandaloneExchangeBodyError::TrailerName)?;
        let value = HeaderValue::from_bytes(value)
            .map_err(|_| StandaloneExchangeBodyError::TrailerValue)?;
        trailers.append(name, value);
    }
    Ok(trailers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_trailer_conversion_preserves_duplicate_value_order() {
        let fields = [
            ("x-check", b"first".as_slice()),
            ("x-other", b"middle".as_slice()),
            ("x-check", b"last".as_slice()),
        ];

        let trailers = checked_trailers(fields.into_iter()).unwrap();
        let values = trailers
            .get_all("x-check")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(values, [b"first".as_slice(), b"last".as_slice()]);
        assert_eq!(trailers.get("x-other").unwrap(), "middle");
    }

    #[test]
    fn checked_trailer_conversion_rejects_invalid_fields_without_echoing_them() {
        let invalid_name = [("bad name", b"value".as_slice())];
        let invalid_value = [("x-check", b"bad\r\nvalue".as_slice())];

        let name_error = checked_trailers(invalid_name.into_iter()).unwrap_err();
        let value_error = checked_trailers(invalid_value.into_iter()).unwrap_err();

        assert_eq!(name_error, StandaloneExchangeBodyError::TrailerName);
        assert_eq!(value_error, StandaloneExchangeBodyError::TrailerValue);
        assert!(!name_error.to_string().contains("bad name"));
        assert!(!value_error.to_string().contains("bad"));
    }
}
