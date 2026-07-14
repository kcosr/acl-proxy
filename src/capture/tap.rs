use std::sync::Arc;

use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::HeaderMap;

use super::{CaptureArtifactJob, CaptureRecord};
use crate::http_body::{parse_capture_content_encoding, CaptureContentEncoding};
use crate::observation::{CaptureBodyBuilder, CaptureEpoch, CaptureEvent};

/// Wire-path state for one best-effort HTTP capture. All methods are
/// synchronous, and capture failure permanently reduces the outcome to
/// metadata only.
pub(crate) struct HttpCaptureTap {
    job: CaptureArtifactJob,
    body: Option<CaptureBodyBuilder>,
    encoding: Option<CaptureContentEncoding>,
    content_type: Option<String>,
    content_encoding_present: bool,
}

impl HttpCaptureTap {
    pub(crate) fn try_begin(
        epoch: Arc<CaptureEpoch>,
        event: CaptureEvent,
        metadata: impl FnOnce() -> CaptureRecord,
        headers: &HeaderMap,
        max_expansion_ratio: usize,
    ) -> Option<Self> {
        let operation = epoch.capture()?.try_admit(event)?;
        // Parse and copy the narrow, noncredential header state before the tap
        // can outlive the caller's complete header map.
        let encoding = parse_capture_content_encoding(headers).ok();
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let content_encoding_present = headers.contains_key(CONTENT_ENCODING);

        let job = match CaptureArtifactJob::begin_admitted(
            epoch,
            operation,
            metadata(),
            max_expansion_ratio,
        ) {
            Ok(job) => job,
            Err(error) => {
                tracing::debug!(error = %error, "capture tap omitted invalid metadata");
                return None;
            }
        };
        let body = encoding.map(|_| job.operation().body_buffer());
        Some(Self {
            job,
            body,
            encoding,
            content_type,
            content_encoding_present,
        })
    }

    /// Copies bytes opportunistically. Failure is observation-only and makes
    /// all subsequent pushes no-ops.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        let Some(body) = self.body.as_mut() else {
            return;
        };
        if body.try_extend_from_slice(bytes).is_err() {
            self.body = None;
        }
    }

    /// Completes the tap and returns its job exactly once. A failed tap becomes
    /// a metadata-only job.
    pub(crate) fn finish(mut self) -> CaptureArtifactJob {
        let Some(body) = self.body.take() else {
            self.job.omit_body();
            return self.job;
        };
        let Some(encoding) = self.encoding else {
            self.job.omit_body();
            return self.job;
        };
        if self
            .job
            .complete_http_body(
                body.finish(),
                encoding,
                self.content_type,
                self.content_encoding_present,
            )
            .is_err()
        {
            self.job.omit_body();
        }
        self.job
    }

    /// Abandons an incomplete body without retaining its buffered prefix.
    pub(crate) fn abandon(mut self) -> CaptureArtifactJob {
        self.body = None;
        self.job.omit_body();
        self.job
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use http::HeaderValue;

    use super::*;
    use crate::capture::{
        CaptureArtifactPayload, CaptureDecision, CaptureEndpoint, CaptureKind, CaptureMode,
        CaptureSinkSpec,
    };
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, CompiledLogLevel,
        CompiledRedactionPayloads, ObservationPlan, PolicyDecisionLoggingPlan, RedactionPlan,
        RedactionProfilePlan, RedactionRulePlan, ReloadableLoggingPlan,
    };
    use crate::observation::{CapturePool, ProductObservationSnapshot};
    use crate::redaction::RedactionSnapshot;
    use crate::runtime::GenerationOwner;

    fn epoch_with_limit(
        directory: &Path,
        limit: usize,
    ) -> (
        Arc<CaptureEpoch>,
        Arc<CapturePool>,
        Arc<dyn GenerationOwner>,
    ) {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "capture".to_owned(),
            RedactionProfilePlan {
                replacement: b"REDACTED".to_vec(),
                max_body_bytes: 1024,
                max_decoded_body_bytes: 1024,
                max_frame_bytes: 1024,
                max_message_bytes: 1024,
                allow_permessage_deflate: false,
                max_environment_literal_sources: 0,
                max_environment_literal_bytes: 0,
                max_environment_literal_total_bytes: 0,
                rules: vec![RedactionRulePlan {
                    literals: Vec::new(),
                    literal_environment_variables: Vec::new(),
                    expressions: Vec::new(),
                    payloads: CompiledRedactionPayloads::Both,
                }],
            },
        );
        let redaction = RedactionSnapshot::activate(RedactionPlan { profiles }, || false)
            .expect("redaction activation");
        let pool = CapturePool::new();
        let activation = ProductObservationSnapshot::activate(
            ObservationPlan {
                logging: ReloadableLoggingPlan {
                    level: CompiledLogLevel::Info,
                    policy_decisions: PolicyDecisionLoggingPlan {
                        allows: false,
                        denies: false,
                        allow_level: CompiledLogLevel::Info,
                        deny_level: CompiledLogLevel::Warn,
                    },
                },
                capture: Some(CapturePlan {
                    events: vec![CompiledCaptureEvent::RequestAllowed],
                    redaction_profile: "capture".to_owned(),
                    sink: CaptureSinkSpec::new(
                        directory.to_path_buf(),
                        "{requestId}-{suffix}.json".to_owned(),
                        4,
                        1024,
                    )
                    .expect("capture sink"),
                    max_body_bytes: 1024,
                    max_inflight_body_bytes: limit,
                    working_set: CaptureWorkingSetPlan::default(),
                }),
            },
            &redaction,
            pool.clone(),
        )
        .expect("observation activation");
        let (_snapshot, owner) = activation.into_parts();
        owner
            .publication_guard()
            .expect("capture publication")
            .commit();
        (pool.current_epoch(), pool, owner)
    }

    fn metadata() -> CaptureRecord {
        CaptureRecord {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            request_id: "tap".to_owned(),
            kind: CaptureKind::Request,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "http://example.test/".to_owned(),
            method: "POST".to_owned(),
            status_code: None,
            status_message: None,
            client: CaptureEndpoint::default(),
            target: None,
            http_version: Some("1.1".to_owned()),
            headers: None,
            body: None,
            body_truncated: None,
            provider_replacement_omitted: None,
            provider_replacement_size: None,
        }
    }

    fn body_bytes(body: &crate::observation::CaptureBody) -> Vec<u8> {
        body.segments().flatten().copied().collect()
    }

    #[test]
    fn successful_tap_finishes_complete_body() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _pool, _owner) = epoch_with_limit(directory.path(), 128 * 1024);
        let mut tap = HttpCaptureTap::try_begin(
            epoch,
            CaptureEvent::RequestAllowed,
            metadata,
            &HeaderMap::new(),
            16,
        )
        .expect("capture tap");

        tap.push(b"first-");
        tap.push(b"second");

        match tap.finish().payload {
            CaptureArtifactPayload::Http { encoded, .. } => {
                assert_eq!(body_bytes(&encoded), b"first-second");
            }
            _ => panic!("complete tap must retain its HTTP body"),
        }
    }

    #[test]
    fn allocation_failure_permanently_degrades_to_metadata_only() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, pool, _owner) = epoch_with_limit(directory.path(), 1);
        let mut tap = HttpCaptureTap::try_begin(
            epoch,
            CaptureEvent::RequestAllowed,
            metadata,
            &HeaderMap::new(),
            16,
        )
        .expect("capture tap");

        tap.push(b"cannot allocate a chunk");
        tap.push(b"ignored after failure");

        assert!(matches!(
            tap.finish().payload,
            CaptureArtifactPayload::Unavailable
        ));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn abandoning_incomplete_body_returns_metadata_only_job() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, pool, _owner) = epoch_with_limit(directory.path(), 128 * 1024);
        let mut tap = HttpCaptureTap::try_begin(
            epoch,
            CaptureEvent::RequestAllowed,
            metadata,
            &HeaderMap::new(),
            16,
        )
        .expect("capture tap");
        tap.push(b"incomplete prefix");

        assert!(matches!(
            tap.abandon().payload,
            CaptureArtifactPayload::Unavailable
        ));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn constructor_parses_and_retains_http_encoding_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _pool, _owner) = epoch_with_limit(directory.path(), 128 * 1024);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut tap =
            HttpCaptureTap::try_begin(epoch, CaptureEvent::RequestAllowed, metadata, &headers, 23)
                .expect("capture tap");
        tap.push(b"encoded");

        match tap.finish().payload {
            CaptureArtifactPayload::Http {
                encoding,
                content_type,
                content_encoding_present,
                ..
            } => {
                assert_eq!(encoding, CaptureContentEncoding::Gzip);
                assert_eq!(content_type.as_deref(), Some("application/json"));
                assert!(content_encoding_present);
            }
            _ => panic!("valid encoding must produce an HTTP payload"),
        }
    }

    #[test]
    fn invalid_encoding_degrades_to_metadata_only() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _pool, _owner) = epoch_with_limit(directory.path(), 128 * 1024);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip, br"));
        let mut tap =
            HttpCaptureTap::try_begin(epoch, CaptureEvent::RequestAllowed, metadata, &headers, 16)
                .expect("capture tap");
        tap.push(b"ignored");

        assert!(matches!(
            tap.finish().payload,
            CaptureArtifactPayload::Unavailable
        ));
    }

    #[test]
    fn disabled_event_does_not_create_a_tap() {
        use std::cell::Cell;

        let directory = tempfile::tempdir().unwrap();
        let (epoch, _pool, _owner) = epoch_with_limit(directory.path(), 128 * 1024);
        let materialized = Cell::new(false);
        assert!(HttpCaptureTap::try_begin(
            epoch,
            CaptureEvent::ResponseAllowed,
            || {
                materialized.set(true);
                metadata()
            },
            &HeaderMap::new(),
            16,
        )
        .is_none());
        assert!(!materialized.get());
    }
}
