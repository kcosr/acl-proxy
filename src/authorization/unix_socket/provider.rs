use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use access_flow_unix::{
    unix_access_flow_capability, unix_peer_uid_capability, UnixAccessFlowCapability,
    UnixPeerUidCapability,
};
use access_rpc_framing::{
    check_operation_live, ClientFrameError, FrameError, FrameKind, FrameProtocol,
};
use http::HeaderName;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::time::Instant;

#[cfg(unix)]
use tokio::net::UnixStream;

use super::{parse_sensitive_response, AwapRequest, AwapRequestError, AwapResponseError};
use crate::authorization::protocol::{ProviderDecision, ProviderOutputRegistry, ProviderRequest};
use crate::config::compiler::{CompiledProviderFailureMode, UnixSocketProviderPlan};
use crate::runtime::AuthorizationInvocationMode;
use crate::safety::wire_body::guarded_body_allocation_bytes;
use crate::safety::HttpWireBodyGuard;

pub(crate) struct UnixSocketProvider {
    socket_path: PathBuf,
    timeout: Duration,
    failure_mode: CompiledProviderFailureMode,
    include_headers: Box<[HeaderName]>,
    include_identity: bool,
    frame_protocol: FrameProtocol,
    response_allocation_bytes: usize,
    peer_uid: Option<u32>,
    admission: Semaphore,
    next_request_id: AtomicU64,
    outputs: ProviderOutputRegistry,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum UnixSocketActivationError {
    #[error("Unix authorization providers are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("Unix authorization peer UID validation is unsupported on this platform")]
    PeerUidUnsupported,
    #[error("Unix authorization provider activation plan is inconsistent")]
    InvalidPlan,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum UnixSocketRequestError {
    #[error("Unix authorization provider has reached its pending-request limit")]
    AtCapacity,
    #[error("Unix authorization provider is unavailable")]
    Unavailable,
    #[error("Unix authorization peer UID does not match")]
    PeerUidMismatch,
    #[error("Unix authorization request is invalid")]
    InvalidRequest(#[source] AwapRequestError),
    #[error("Unix authorization request storage could not be admitted")]
    FrameAdmission,
    #[error("Unix authorization response is invalid")]
    InvalidResponse(#[source] AwapResponseError),
    #[error("Unix authorization request was cancelled")]
    Cancelled,
    #[error("Unix authorization request timed out")]
    Timeout,
    #[error("Unix authorization frame exchange failed")]
    Frame {
        category: FrameError,
        request_may_have_been_written: bool,
    },
    #[error("Unix authorization request ID space is exhausted")]
    RequestIdExhausted,
    #[cfg(not(unix))]
    #[error("Unix authorization providers are unsupported on this platform")]
    UnsupportedPlatform,
}

impl UnixSocketRequestError {
    pub(crate) const fn is_timeout(self) -> bool {
        matches!(self, Self::Timeout)
    }

    pub(crate) const fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }

    #[cfg(test)]
    pub(crate) const fn request_may_have_been_written(self) -> bool {
        match self {
            Self::Frame {
                request_may_have_been_written,
                ..
            } => request_may_have_been_written,
            _ => false,
        }
    }
}

impl UnixSocketProvider {
    pub(crate) fn activate(
        plan: UnixSocketProviderPlan,
    ) -> Result<Arc<Self>, UnixSocketActivationError> {
        validate_capabilities(plan.peer_uid)?;
        validate_plan_projections(&plan)?;
        let UnixSocketProviderPlan {
            socket_path,
            timeout,
            on_failure,
            include_headers,
            include_identity,
            frame_protocol,
            request_frame_bytes: _,
            response_frame_bytes: _,
            request_allocation_bytes: _,
            response_allocation_bytes,
            max_pending_requests,
            max_inflight_allocation_bytes: _,
            peer_uid,
            outputs,
        } = plan;
        Ok(Arc::new(Self {
            socket_path,
            timeout,
            failure_mode: on_failure,
            include_headers: include_headers.into_boxed_slice(),
            include_identity,
            frame_protocol,
            response_allocation_bytes,
            peer_uid,
            admission: Semaphore::new(max_pending_requests),
            next_request_id: AtomicU64::new(1),
            outputs: ProviderOutputRegistry::activate(outputs),
        }))
    }

    pub(crate) fn include_headers(&self) -> &[HeaderName] {
        &self.include_headers
    }

    pub(crate) const fn include_identity(&self) -> bool {
        self.include_identity
    }

    pub(crate) const fn failure_mode(&self) -> CompiledProviderFailureMode {
        self.failure_mode
    }

    pub(crate) const fn outputs(&self) -> &ProviderOutputRegistry {
        &self.outputs
    }

    #[cfg(unix)]
    pub(crate) async fn decide(
        &self,
        request: ProviderRequest<'_>,
        invocation: AuthorizationInvocationMode,
        cancellation: &http_access_runtime::ForwardingCancellation,
        guard: &HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> Result<ProviderDecision, UnixSocketRequestError> {
        let operation_deadline = operation_deadline(Instant::now(), request_deadline, self.timeout);
        check_live(operation_deadline, cancellation)?;
        let _permit = self.admission.try_acquire().map_err(map_admission_error)?;
        check_live(operation_deadline, cancellation)?;

        let request_id = self.next_request_id()?;
        let request_body_limit = usize::try_from(self.frame_protocol.request_limit().get())
            .map_err(|_| UnixSocketRequestError::InvalidRequest(AwapRequestError::TooLarge))?;
        let request = AwapRequest::new(request_id.as_str(), request, invocation)
            .prepare(request_body_limit, guard)
            .map_err(map_request_error)?;
        let response_allocation = guard
            .charge_exact_allocation(self.response_allocation_bytes)
            .map_err(|_| UnixSocketRequestError::FrameAdmission)?;
        check_live(operation_deadline, cancellation)?;

        let stream = connect_unix(&self.socket_path, operation_deadline, cancellation).await?;
        check_live(operation_deadline, cancellation)?;
        self.validate_peer(&stream)?;
        check_live(operation_deadline, cancellation)?;

        let response = access_rpc_framing::client_exchange_sensitive_response(
            stream,
            self.frame_protocol,
            request.body(),
            operation_deadline.into_std(),
            cancellation,
        )
        .await
        .map_err(map_frame_error)?;
        check_live(operation_deadline, cancellation)?;
        let decision = parse_sensitive_response(
            &response,
            request_id.as_str(),
            invocation,
            &self.outputs,
            &guard.provider_response_charge(),
        )
        .map_err(map_response_error)?;
        check_live(operation_deadline, cancellation)?;

        drop(response);
        drop(response_allocation);
        check_live(operation_deadline, cancellation)?;
        Ok(decision)
    }

    #[cfg(not(unix))]
    pub(crate) async fn decide(
        &self,
        _request: ProviderRequest<'_>,
        _invocation: AuthorizationInvocationMode,
        _cancellation: &http_access_runtime::ForwardingCancellation,
        _guard: &HttpWireBodyGuard,
        _request_deadline: Instant,
    ) -> Result<ProviderDecision, UnixSocketRequestError> {
        Err(UnixSocketRequestError::UnsupportedPlatform)
    }

    fn next_request_id(&self) -> Result<ProtocolRequestId, UnixSocketRequestError> {
        let value = self
            .next_request_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| UnixSocketRequestError::RequestIdExhausted)?;
        Ok(ProtocolRequestId::new(value))
    }

    #[cfg(unix)]
    fn validate_peer(&self, stream: &UnixStream) -> Result<(), UnixSocketRequestError> {
        let Some(expected) = self.peer_uid else {
            return Ok(());
        };
        let actual = stream
            .peer_cred()
            .map_err(|_| UnixSocketRequestError::Unavailable)?
            .uid();
        if actual == expected {
            Ok(())
        } else {
            Err(UnixSocketRequestError::PeerUidMismatch)
        }
    }
}

impl fmt::Debug for UnixSocketProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixSocketProvider")
            .field("include_header_count", &self.include_headers.len())
            .field("include_identity", &self.include_identity)
            .field("output_count", &self.outputs.len())
            .field("available_permits", &self.admission.available_permits())
            .finish()
    }
}

fn validate_capabilities(peer_uid: Option<u32>) -> Result<(), UnixSocketActivationError> {
    validate_capability_values(
        unix_access_flow_capability(),
        unix_peer_uid_capability(),
        peer_uid,
    )
}

fn validate_capability_values(
    access_flow: UnixAccessFlowCapability,
    peer_uid_capability: UnixPeerUidCapability,
    peer_uid: Option<u32>,
) -> Result<(), UnixSocketActivationError> {
    if access_flow != UnixAccessFlowCapability::Supported {
        return Err(UnixSocketActivationError::UnsupportedPlatform);
    }
    if peer_uid.is_some() && peer_uid_capability != UnixPeerUidCapability::Available {
        return Err(UnixSocketActivationError::PeerUidUnsupported);
    }
    Ok(())
}

fn validate_plan_projections(
    plan: &UnixSocketProviderPlan,
) -> Result<(), UnixSocketActivationError> {
    let request_limit = usize::try_from(plan.frame_protocol.request_limit().get())
        .map_err(|_| UnixSocketActivationError::InvalidPlan)?;
    let response_limit = usize::try_from(plan.frame_protocol.response_limit().get())
        .map_err(|_| UnixSocketActivationError::InvalidPlan)?;
    let request_allocation = guarded_body_allocation_bytes(request_limit)
        .ok_or(UnixSocketActivationError::InvalidPlan)?;
    let response_allocation = guarded_body_allocation_bytes(response_limit)
        .ok_or(UnixSocketActivationError::InvalidPlan)?;
    let minimum_inflight = request_allocation
        .checked_add(response_allocation)
        .and_then(|bytes| bytes.checked_mul(plan.max_pending_requests))
        .ok_or(UnixSocketActivationError::InvalidPlan)?;
    if plan.max_pending_requests == 0
        || plan
            .frame_protocol
            .projected_frame_bytes(FrameKind::Request)
            != Ok(plan.request_frame_bytes)
        || plan
            .frame_protocol
            .projected_frame_bytes(FrameKind::Response)
            != Ok(plan.response_frame_bytes)
        || plan.request_allocation_bytes != request_allocation
        || plan.response_allocation_bytes != response_allocation
        || plan.max_inflight_allocation_bytes < minimum_inflight
    {
        return Err(UnixSocketActivationError::InvalidPlan);
    }
    Ok(())
}

fn operation_deadline(now: Instant, request_deadline: Instant, timeout: Duration) -> Instant {
    now.checked_add(timeout)
        .map_or(request_deadline, |provider_deadline| {
            provider_deadline.min(request_deadline)
        })
}

fn check_live(
    deadline: Instant,
    cancellation: &http_access_runtime::ForwardingCancellation,
) -> Result<(), UnixSocketRequestError> {
    check_operation_live(deadline.into_std(), cancellation).map_err(map_live_error)
}

#[cfg(unix)]
async fn connect_unix(
    path: &std::path::Path,
    deadline: Instant,
    cancellation: &http_access_runtime::ForwardingCancellation,
) -> Result<UnixStream, UnixSocketRequestError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(UnixSocketRequestError::Cancelled),
        () = tokio::time::sleep_until(deadline) => Err(UnixSocketRequestError::Timeout),
        result = UnixStream::connect(path) => {
            result.map_err(|_| UnixSocketRequestError::Unavailable)
        }
    }
}

fn map_admission_error(error: TryAcquireError) -> UnixSocketRequestError {
    match error {
        TryAcquireError::NoPermits => UnixSocketRequestError::AtCapacity,
        TryAcquireError::Closed => UnixSocketRequestError::Unavailable,
    }
}

fn map_request_error(error: AwapRequestError) -> UnixSocketRequestError {
    match error {
        AwapRequestError::Allocation => UnixSocketRequestError::FrameAdmission,
        AwapRequestError::InvalidShape
        | AwapRequestError::BodyNotAllowed
        | AwapRequestError::LengthOverflow
        | AwapRequestError::TooLarge => UnixSocketRequestError::InvalidRequest(error),
    }
}

fn map_response_error(error: AwapResponseError) -> UnixSocketRequestError {
    UnixSocketRequestError::InvalidResponse(error)
}

fn map_frame_error(error: ClientFrameError) -> UnixSocketRequestError {
    match error.error() {
        FrameError::Cancelled => UnixSocketRequestError::Cancelled,
        FrameError::DeadlineExceeded => UnixSocketRequestError::Timeout,
        category => UnixSocketRequestError::Frame {
            category,
            request_may_have_been_written: error.request_may_have_been_written(),
        },
    }
}

fn map_live_error(error: FrameError) -> UnixSocketRequestError {
    match error {
        FrameError::Cancelled => UnixSocketRequestError::Cancelled,
        FrameError::DeadlineExceeded => UnixSocketRequestError::Timeout,
        category => UnixSocketRequestError::Frame {
            category,
            request_may_have_been_written: false,
        },
    }
}

struct ProtocolRequestId([u8; 17]);

impl ProtocolRequestId {
    fn new(value: u64) -> Self {
        let mut bytes = [b'0'; 17];
        bytes[0] = b'u';
        for index in 0..16 {
            let shift = (15 - index) * 4;
            bytes[index + 1] = hex_nibble(((value >> shift) & 0x0f) as u8);
        }
        Self(bytes)
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("protocol request IDs are ASCII")
    }
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + value - 10,
        _ => unreachable!("request ID nibble is in range"),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use access_rpc_framing::{
        receive_request, FrameBodyLimit, SensitiveFrameBody, FRAME_HEADER_LEN,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    use super::*;
    use crate::config::compiler::{CompiledTransportSecurity, ProviderOutputPlan};
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    const REQUEST_LIMIT: usize = 4096;
    const RESPONSE_LIMIT: usize = 4096;
    const TEST_PEAK: usize = 2 * 1024 * 1024;

    fn provider_plan(
        socket_path: PathBuf,
        timeout: Duration,
        max_pending_requests: usize,
        peer_uid: Option<u32>,
        with_output: bool,
    ) -> UnixSocketProviderPlan {
        let frame_protocol = FrameProtocol::new(
            *b"AWAP",
            1,
            FrameBodyLimit::new(REQUEST_LIMIT).unwrap(),
            FrameBodyLimit::new(RESPONSE_LIMIT).unwrap(),
        );
        let request_allocation_bytes = guarded_body_allocation_bytes(REQUEST_LIMIT).unwrap();
        let response_allocation_bytes = guarded_body_allocation_bytes(RESPONSE_LIMIT).unwrap();
        let minimum_inflight =
            (request_allocation_bytes + response_allocation_bytes) * max_pending_requests;
        let outputs = if with_output {
            BTreeMap::from([(
                "api_token".to_owned(),
                ProviderOutputPlan::Bearer {
                    required: true,
                    transport_security: CompiledTransportSecurity::TlsRequired,
                },
            )])
        } else {
            BTreeMap::new()
        };
        UnixSocketProviderPlan {
            socket_path,
            timeout,
            on_failure: CompiledProviderFailureMode::Deny,
            include_headers: Vec::new(),
            include_identity: false,
            frame_protocol,
            request_frame_bytes: frame_protocol
                .projected_frame_bytes(FrameKind::Request)
                .unwrap(),
            response_frame_bytes: frame_protocol
                .projected_frame_bytes(FrameKind::Response)
                .unwrap(),
            request_allocation_bytes,
            response_allocation_bytes,
            max_pending_requests,
            max_inflight_allocation_bytes: minimum_inflight + RESPONSE_LIMIT,
            peer_uid,
            outputs,
        }
    }

    fn request() -> ProviderRequest<'static> {
        ProviderRequest {
            request_id: "logical-1",
            rule_id: "rule-1",
            url: "https://example.test/a",
            method: "GET",
            client_ip: "203.0.113.10",
            headers: None,
            identity: None,
            body: None,
        }
    }

    fn guard() -> (Arc<WireBodyPool>, HttpWireBodyGuard) {
        let pool = WireBodyPool::new(TEST_PEAK, TEST_PEAK);
        let guard = pool.begin_for_test(
            TEST_PEAK,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        (pool, guard)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn capability_validation_is_closed_and_peer_uid_is_opt_in() {
        assert_eq!(
            validate_capability_values(
                UnixAccessFlowCapability::Unsupported,
                UnixPeerUidCapability::Unsupported,
                None,
            ),
            Err(UnixSocketActivationError::UnsupportedPlatform)
        );
        assert_eq!(
            validate_capability_values(
                UnixAccessFlowCapability::Supported,
                UnixPeerUidCapability::Unsupported,
                Some(501),
            ),
            Err(UnixSocketActivationError::PeerUidUnsupported)
        );
        assert_eq!(
            validate_capability_values(
                UnixAccessFlowCapability::Supported,
                UnixPeerUidCapability::Unsupported,
                None,
            ),
            Ok(())
        );
    }

    #[tokio::test]
    async fn activation_does_not_probe_and_later_socket_restart_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let plan = provider_plan(path.clone(), Duration::from_secs(1), 1, None, false);
        let protocol = plan.frame_protocol;
        let provider = UnixSocketProvider::activate(plan).unwrap();
        let (pool, guard) = guard();
        let cancellation = http_access_runtime::ForwardingCancellation::new();

        assert_eq!(
            provider
                .decide(
                    request(),
                    AuthorizationInvocationMode::EffectsAllowed,
                    &cancellation,
                    &guard,
                    deadline(),
                )
                .await
                .err(),
            Some(UnixSocketRequestError::Unavailable)
        );
        assert_eq!(pool.global_charge(), 0);

        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cancellation = http_access_runtime::ForwardingCancellation::new();
            let received = receive_request(
                stream,
                protocol,
                std::time::Instant::now() + Duration::from_secs(2),
                &cancellation,
            )
            .await
            .unwrap();
            let response = SensitiveFrameBody::new(
                br#"{"id":"u0000000000000002","type":"response","decision":"deny"}"#.to_vec(),
            )
            .unwrap();
            received.respond_sensitive(&response).await.unwrap();
        });
        let decision = provider
            .decide(
                request(),
                AuthorizationInvocationMode::EffectsAllowed,
                &cancellation,
                &guard,
                deadline(),
            )
            .await
            .unwrap();
        assert!(matches!(decision, ProviderDecision::Deny));
        server.await.unwrap();
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn canonical_round_trip_checks_peer_and_rehomes_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let uid = unsafe { libc::geteuid() };
        let plan = provider_plan(path.clone(), Duration::from_secs(1), 1, Some(uid), true);
        let protocol = plan.frame_protocol;
        let provider = UnixSocketProvider::activate(plan).unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cancellation = http_access_runtime::ForwardingCancellation::new();
            let received = receive_request(
                stream,
                protocol,
                std::time::Instant::now() + Duration::from_secs(2),
                &cancellation,
            )
            .await
            .unwrap();
            assert_eq!(
                received.body().as_bytes(),
                br#"{"id":"u0000000000000001","type":"request","requestId":"logical-1","ruleId":"rule-1","invocation":"effects_allowed","url":"https://example.test/a","method":"GET","client":"127.0.0.1:0","headers":{}}"#
            );
            let response = SensitiveFrameBody::new(
                br#"{"id":"u0000000000000001","type":"response","decision":"allow","values":{"api_token":"secret"}}"#.to_vec(),
            )
            .unwrap();
            received.respond_sensitive(&response).await.unwrap();
        });
        let (pool, guard) = guard();
        let cancellation = http_access_runtime::ForwardingCancellation::new();
        let decision = provider
            .decide(
                request(),
                AuthorizationInvocationMode::EffectsAllowed,
                &cancellation,
                &guard,
                deadline(),
            )
            .await
            .unwrap();
        let ProviderDecision::Allow { credentials, .. } = decision else {
            panic!("expected allow with credentials");
        };
        let output = provider.outputs().index("api_token").unwrap();
        assert_eq!(
            credentials.unix_contiguous(output),
            Some(b"secret".as_slice())
        );
        let compact = provider
            .outputs()
            .compact_provider_credential_wire(&credentials, &guard)
            .unwrap();
        assert_eq!(compact.present_count(), 1);
        assert_eq!(compact.output_len(output), Some(6));
        let mut copied = [0_u8; 6];
        compact.copy_output(output, &mut copied).unwrap();
        assert_eq!(&copied, b"secret");
        server.await.unwrap();
        assert!(pool.global_charge() > 0);
        drop(compact);
        drop(credentials);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn peer_mismatch_precedes_request_publication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let provider = UnixSocketProvider::activate(provider_plan(
            path.clone(),
            Duration::from_secs(1),
            1,
            Some(u32::MAX),
            false,
        ))
        .unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).await.unwrap()
        });
        let (_, guard) = guard();
        let cancellation = http_access_runtime::ForwardingCancellation::new();
        assert_eq!(
            provider
                .decide(
                    request(),
                    AuthorizationInvocationMode::EffectsAllowed,
                    &cancellation,
                    &guard,
                    deadline(),
                )
                .await
                .err(),
            Some(UnixSocketRequestError::PeerUidMismatch)
        );
        assert_eq!(server.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn admission_is_non_queuing_and_cancellation_releases_every_charge() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let provider = UnixSocketProvider::activate(provider_plan(
            path.clone(),
            Duration::from_secs(5),
            1,
            None,
            false,
        ))
        .unwrap();
        let listener = Arc::new(UnixListener::bind(&path).unwrap());
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server_listener = listener.clone();
        let server = tokio::spawn(async move {
            let (_stream, _) = server_listener.accept().await.unwrap();
            let _ = accepted_tx.send(());
            std::future::pending::<()>().await;
        });

        let (pool, first_guard) = guard();
        let first_provider = provider.clone();
        let first_cancellation = http_access_runtime::ForwardingCancellation::new();
        let task_cancellation = first_cancellation.clone();
        let first = tokio::spawn(async move {
            first_provider
                .decide(
                    request(),
                    AuthorizationInvocationMode::EffectsAllowed,
                    &task_cancellation,
                    &first_guard,
                    deadline(),
                )
                .await
        });
        accepted_rx.await.unwrap();

        let (_, second_guard) = guard();
        let second_cancellation = http_access_runtime::ForwardingCancellation::new();
        assert_eq!(
            provider
                .decide(
                    request(),
                    AuthorizationInvocationMode::EffectsAllowed,
                    &second_cancellation,
                    &second_guard,
                    deadline(),
                )
                .await
                .err(),
            Some(UnixSocketRequestError::AtCapacity)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );

        first_cancellation.cancel();
        assert_eq!(
            first.await.unwrap().err(),
            Some(UnixSocketRequestError::Cancelled)
        );
        assert_eq!(pool.global_charge(), 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn malformed_response_is_sanitized_and_never_retried() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let provider = UnixSocketProvider::activate(provider_plan(
            path.clone(),
            Duration::from_secs(1),
            1,
            None,
            false,
        ))
        .unwrap();
        let listener = Arc::new(UnixListener::bind(&path).unwrap());
        let server_listener = listener.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = server_listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert!(request.len() > FRAME_HEADER_LEN);
            let mut response = b"NOPE".to_vec();
            response.extend_from_slice(&[1, 2, 0, 0, 0, 2]);
            response.extend_from_slice(b"{}");
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (_, guard) = guard();
        let cancellation = http_access_runtime::ForwardingCancellation::new();
        let result = provider
            .decide(
                request(),
                AuthorizationInvocationMode::EffectsAllowed,
                &cancellation,
                &guard,
                deadline(),
            )
            .await;
        let Err(error) = result else {
            panic!("malformed response unexpectedly succeeded");
        };
        assert_eq!(
            error,
            UnixSocketRequestError::Frame {
                category: FrameError::WrongMagic,
                request_may_have_been_written: true,
            }
        );
        assert!(error.request_may_have_been_written());
        assert!(!error
            .to_string()
            .contains(&path.to_string_lossy().to_string()));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn provider_timeout_uses_the_single_bound_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let provider = UnixSocketProvider::activate(provider_plan(
            path.clone(),
            Duration::from_millis(30),
            1,
            None,
            false,
        ))
        .unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let (pool, guard) = guard();
        let cancellation = http_access_runtime::ForwardingCancellation::new();
        assert_eq!(
            provider
                .decide(
                    request(),
                    AuthorizationInvocationMode::EffectsAllowed,
                    &cancellation,
                    &guard,
                    deadline(),
                )
                .await
                .err(),
            Some(UnixSocketRequestError::Timeout)
        );
        assert_eq!(pool.global_charge(), 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn request_deadline_can_be_shorter_than_provider_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.sock");
        let provider = UnixSocketProvider::activate(provider_plan(
            path.clone(),
            Duration::from_secs(5),
            1,
            None,
            false,
        ))
        .unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let (pool, guard) = guard();
        let cancellation = http_access_runtime::ForwardingCancellation::new();
        assert_eq!(
            provider
                .decide(
                    request(),
                    AuthorizationInvocationMode::EffectsAllowed,
                    &cancellation,
                    &guard,
                    Instant::now() + Duration::from_millis(30),
                )
                .await
                .err(),
            Some(UnixSocketRequestError::Timeout)
        );
        assert_eq!(pool.global_charge(), 0);
        server.abort();
        let _ = server.await;
    }
}
