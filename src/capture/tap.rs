use std::sync::Arc;

use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::HeaderMap;

use super::{CaptureArtifactJob, CaptureBodyOmission, SanitizedCaptureMetadata};
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
    max_encoded_body_bytes: usize,
}

impl HttpCaptureTap {
    pub(crate) fn try_begin(
        epoch: Arc<CaptureEpoch>,
        event: CaptureEvent,
        metadata: impl FnOnce() -> Option<SanitizedCaptureMetadata>,
        headers: &HeaderMap,
        max_expansion_ratio: usize,
    ) -> Option<Self> {
        let policy = epoch.capture()?;
        let operation = policy.try_admit(event)?;
        let max_encoded_body_bytes = policy
            .max_body_bytes()
            .min(policy.profile().limits().max_body_bytes());
        // Parse and copy the narrow, noncredential header state before the tap
        // can outlive the caller's complete header map.
        let encoding = parse_capture_content_encoding(headers).ok();
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let content_encoding_present = headers.contains_key(CONTENT_ENCODING);
        let metadata = metadata()?;

        let mut job = match CaptureArtifactJob::begin_admitted(
            epoch,
            operation,
            metadata,
            max_expansion_ratio,
        ) {
            Ok(job) => job,
            Err(error) => {
                tracing::debug!(error = %error, "capture tap omitted invalid metadata");
                return None;
            }
        };
        let body = if encoding.is_some() {
            Some(job.operation().body_buffer())
        } else {
            job.omit_body(CaptureBodyOmission::DecodingFailed);
            None
        };
        Some(Self {
            job,
            body,
            encoding,
            content_type,
            content_encoding_present,
            max_encoded_body_bytes,
        })
    }

    /// Copies bytes opportunistically. Failure is observation-only and makes
    /// all subsequent pushes no-ops.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        let Some(body) = self.body.as_mut() else {
            return;
        };
        let Some(next_len) = body.len().checked_add(bytes.len()) else {
            self.body = None;
            self.job.omit_body(CaptureBodyOmission::LimitExceeded);
            return;
        };
        if next_len > self.max_encoded_body_bytes {
            self.body = None;
            self.job.omit_body(CaptureBodyOmission::LimitExceeded);
            return;
        }
        if body.try_extend_from_slice(bytes).is_err() {
            self.body = None;
            self.job.omit_body(CaptureBodyOmission::ResourceExhausted);
        }
    }

    pub(crate) fn mark_trailers_omitted(&mut self) {
        self.job.metadata.mark_trailers_omitted();
    }

    /// Completes the tap and returns its job exactly once. A failed tap becomes
    /// a metadata-only job.
    pub(crate) fn finish(mut self) -> CaptureArtifactJob {
        let Some(body) = self.body.take() else {
            return self.job;
        };
        let Some(encoding) = self.encoding else {
            self.job.omit_body(CaptureBodyOmission::DecodingFailed);
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
            self.job.omit_body(CaptureBodyOmission::ResourceExhausted);
        }
        self.job
    }

    /// Abandons an incomplete body without retaining its buffered prefix.
    pub(crate) fn abandon(mut self) -> CaptureArtifactJob {
        self.body = None;
        self.job.omit_body(CaptureBodyOmission::Incomplete);
        self.job
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use http::HeaderValue;

    use super::*;
    use crate::capture::{
        CaptureArtifactPayload, CaptureDecision, CaptureEndpoint, CaptureKind, CaptureMode,
        CaptureRecord, CaptureSinkSpec,
    };
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, ObservationPlan,
    };
    use crate::observation::{CapturePool, ProductObservationSnapshot};
    use crate::redaction::{test_snapshot, TestProfile};
    use crate::runtime::GenerationOwner;

    fn epoch_with_limit(
        directory: &Path,
        limit: usize,
    ) -> (
        Arc<CaptureEpoch>,
        Arc<CapturePool>,
        Arc<dyn GenerationOwner>,
    ) {
        epoch_with_limits(directory, limit, 1024)
    }

    fn epoch_with_limits(
        directory: &Path,
        limit: usize,
        max_body_bytes: usize,
    ) -> (
        Arc<CaptureEpoch>,
        Arc<CapturePool>,
        Arc<dyn GenerationOwner>,
    ) {
        let (redaction, references) = test_snapshot(vec![TestProfile {
            name: "capture".to_owned(),
            replacement: b"REDACTED".to_vec(),
            max_body_bytes: 1024,
            max_decoded_body_bytes: 1024,
            max_frame_bytes: 1024,
            max_message_bytes: 1024,
            allow_permessage_deflate: false,
            literals: Vec::new(),
        }]);
        let pool = CapturePool::new();
        let activation = ProductObservationSnapshot::activate(
            ObservationPlan {
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
                    max_body_bytes,
                    max_inflight_body_bytes: limit,
                    working_set: CaptureWorkingSetPlan::default(),
                }),
                ..ObservationPlan::default()
            },
            &redaction,
            references.get("capture"),
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

    fn metadata() -> Option<SanitizedCaptureMetadata> {
        Some(SanitizedCaptureMetadata::from_test_record(CaptureRecord {
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
            body_omission: None,
            trailers_omitted: None,
        }))
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
            CaptureArtifactPayload::Omitted(CaptureBodyOmission::ResourceExhausted)
        ));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn encoded_profile_limit_is_checked_before_growth_and_releases_the_prefix() {
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

        tap.push(&vec![b'a'; 1024]);
        assert!(pool.used() > 0);
        tap.push(b"x");

        assert_eq!(pool.used(), 0, "overflow must release the captured prefix");
        assert!(matches!(
            tap.finish().payload,
            CaptureArtifactPayload::Omitted(CaptureBodyOmission::LimitExceeded)
        ));
    }

    #[test]
    fn lower_capture_limit_is_checked_before_growth_and_releases_the_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, pool, _owner) = epoch_with_limits(directory.path(), 128 * 1024, 8);
        let mut tap = HttpCaptureTap::try_begin(
            epoch,
            CaptureEvent::RequestAllowed,
            metadata,
            &HeaderMap::new(),
            16,
        )
        .expect("capture tap");

        tap.push(b"12345678");
        assert!(pool.used() > 0);
        tap.push(b"9");

        assert_eq!(pool.used(), 0, "overflow must release the captured prefix");
        assert!(matches!(
            tap.finish().payload,
            CaptureArtifactPayload::Omitted(CaptureBodyOmission::LimitExceeded)
        ));
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
            CaptureArtifactPayload::Omitted(CaptureBodyOmission::Incomplete)
        ));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn trailer_marker_is_retained_on_the_capture_job() {
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
        tap.mark_trailers_omitted();

        let job = tap.finish();
        assert_eq!(job.metadata.record.trailers_omitted, Some(true));
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
            CaptureArtifactPayload::Omitted(CaptureBodyOmission::DecodingFailed)
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

    #[test]
    fn omitted_metadata_releases_admission_for_the_next_capture() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _pool, _owner) = epoch_with_limit(directory.path(), 128 * 1024);

        assert!(HttpCaptureTap::try_begin(
            epoch.clone(),
            CaptureEvent::RequestAllowed,
            || None,
            &HeaderMap::new(),
            16,
        )
        .is_none());
        assert!(HttpCaptureTap::try_begin(
            epoch,
            CaptureEvent::RequestAllowed,
            metadata,
            &HeaderMap::new(),
            16,
        )
        .is_some());
    }
}
