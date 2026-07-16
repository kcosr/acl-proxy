use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use http::header::{CONTENT_ENCODING, TRAILER};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use hyper::Body;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::capture::CaptureDecision;
use crate::http1::ingress::RequestDisposition;
use crate::observation::CaptureEvent;
use crate::proxy::forward::{
    forward_request, forward_upgrade_request, ForwardError, ForwardUpgradeResult,
    ForwardedDownstreamBody, ForwardingTimeouts, ResolvedForwardingTarget,
};
use crate::proxy::h2_stream_cancellation::H2StreamCancellation;
use crate::proxy::headers::SanitizedRequest;
use crate::proxy::ingress::{
    HandledResponse, ProxyResponseBody, StandaloneHttpTerminal, TerminalRequestBodyProvenance,
};
use crate::proxy::standalone_body::StandaloneExchangeBody;
use crate::proxy::upgrade_relay::{
    EstablishedUpgradeKind, UpgradeCaptureContext, UpgradeRelayDeadlines,
};
use crate::runtime::GenerationRetention;
use crate::standalone_policy_provider::{StandaloneForwardDispatch, StandaloneIngressTransport};
use crate::standalone_provider_result::{StandaloneCaptureBody, StandaloneUpgradeBinding};
use crate::upgrade::{
    UpgradeEntryPlan, UpgradeRuntime, UpgradeTerminalCause, UpgradeTerminalControl,
};
use http_access_types::{apply_header_mutation_batches, UpgradePolicy};

pub(super) struct ForwardingExecutor;

impl ForwardingExecutor {
    pub(super) async fn execute(
        terminal: StandaloneHttpTerminal,
        mut dispatch: StandaloneForwardDispatch,
    ) -> HandledResponse {
        let StandaloneIngressTransport::Ordinary {
            mut parts,
            protocol,
            downstream_upgrade,
        } = dispatch.transport
        else {
            return terminal.capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        };
        let h2_stream = parts.extensions.remove::<H2StreamCancellation>();
        let plan = dispatch.exchange.plan();
        let origin = plan.origin().clone();
        let plan_binding = plan.binding();
        let response_mutations = plan.response_mutation_batches().to_vec();
        let response_policy = plan.response();
        let stage_timeouts = plan.timeouts();
        let forwarding_timeouts = ForwardingTimeouts::new(
            dispatch.deadline,
            Duration::from_millis(stage_timeouts.connect_ms()),
            Duration::from_millis(stage_timeouts.response_head_ms()),
        );
        let upgrade_deadlines = UpgradeRelayDeadlines::new(
            Duration::from_millis(stage_timeouts.upgrade_idle_ms()),
            dispatch.deadline,
        );
        let upgrade = plan.upgrade().clone();
        let upgrade_binding = match dispatch.sidecar.take_upgrade_binding(plan_binding) {
            Ok(binding) => binding,
            Err(_) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "request failed\n",
                    true,
                )
            }
        };
        let neutral_headers = match apply_header_mutation_batches(
            dispatch.exchange.facts().headers(),
            plan.request_mutation_batches(),
        ) {
            Ok(headers) => headers,
            Err(_) => {
                if let Ok(headers) =
                    crate::proxy::facts::product_headers(dispatch.exchange.facts().headers())
                {
                    let body_headers = body_headers(&headers);
                    if let Some(mut submission) = terminal.capture.begin_allowed_request(
                        &headers,
                        &body_headers,
                        TerminalRequestBodyProvenance::Unconsumed,
                    ) {
                        submission.abandon();
                    }
                }
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "request failed\n",
                    true,
                );
            }
        };
        let mut headers = match crate::proxy::facts::product_headers(&neutral_headers) {
            Ok(headers) => headers,
            Err(_) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "request failed\n",
                    true,
                )
            }
        };
        let capture_headers = headers.clone();
        let mut capture_body_headers = body_headers(&headers);
        let provenance = match dispatch.sidecar.capture_body() {
            StandaloneCaptureBody::ProviderReplacement { size } => {
                TerminalRequestBodyProvenance::ProviderReplacement { size }
            }
            StandaloneCaptureBody::Stream { canonical_identity } => {
                if canonical_identity {
                    capture_body_headers
                        .insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
                }
                if plan.redaction().is_some() {
                    TerminalRequestBodyProvenance::CompleteWireRedacted
                } else {
                    TerminalRequestBodyProvenance::CompleteOriginal
                }
            }
        };
        let request_capture = terminal.capture.begin_allowed_request(
            &capture_headers,
            &capture_body_headers,
            provenance,
        );

        dispatch.decision.submit_now();
        let program = match dispatch.sidecar.take_credential_program(plan_binding) {
            Ok(program) => program,
            Err(_) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "request failed\n",
                    true,
                )
            }
        };
        if program
            .apply(dispatch.exchange.plan(), &dispatch.services, &mut headers)
            .is_err()
            || dispatch
                .services
                .inject_loop_marker(&mut headers, &dispatch.request_id)
                .is_err()
        {
            return terminal.capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        }
        parts.headers = headers;
        let request_headers = capture_headers;
        let mut body = StandaloneExchangeBody::new(dispatch.exchange, dispatch.sidecar);
        body.set_capture(request_capture);
        let request = SanitizedRequest::from_parts(*parts, body, protocol);
        let response_admission = match dispatch.services.begin_response(dispatch.quota_key) {
            Ok(admission) => admission,
            Err(_) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service unavailable\n",
                    true,
                )
            }
        };

        if !matches!(upgrade, UpgradePolicy::Deny) {
            let (Some(binding), Some(downstream_upgrade), Some(upgrade_protocol)) = (
                upgrade_binding,
                downstream_upgrade,
                request
                    .upgrade_intent()
                    .map(|intent| intent.protocol().clone()),
            ) else {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "upgrade failed\n",
                    true,
                );
            };
            let upgrade_capture = terminal.capture.upgrade_capture_context(&origin);
            let outcome = execute_standalone_upgrade(StandaloneUpgradeExecution {
                runtime: terminal.upgrade_runtime,
                capture: upgrade_capture,
                binding,
                request,
                canonical: origin,
                resolved: dispatch.resolved,
                destinations: dispatch.destinations,
                retention: dispatch.retention,
                downstream_upgrade,
                deadline: dispatch.deadline,
                response_mutations,
                request_headers,
                protocol: upgrade_protocol,
                response_admission,
                response_policy,
                h2_stream: h2_stream.clone(),
                forwarding_timeouts,
                upgrade_deadlines,
            })
            .await;
            return match outcome {
                Ok(UpgradeHandshakeResponse::Ordinary(response)) => {
                    let response = *response;
                    let response_capture = terminal.capture.begin(
                        CaptureEvent::ResponseAllowed,
                        || {
                            terminal.capture.response_record(
                                CaptureDecision::Allow,
                                response.version(),
                                Some(response.headers()),
                                response.status(),
                                false,
                            )
                        },
                        response.headers(),
                    );
                    HandledResponse {
                        response: response
                            .map(|body| ProxyResponseBody::forwarded(body, response_capture)),
                        close_connection: false,
                        request_disposition: RequestDisposition::ContinueHttp,
                    }
                }
                Ok(UpgradeHandshakeResponse::SwitchingProtocols(response)) => {
                    if let Some(mut submission) = terminal.capture.begin(
                        CaptureEvent::ResponseAllowed,
                        || {
                            terminal.capture.response_record(
                                CaptureDecision::Allow,
                                response.version(),
                                Some(response.headers()),
                                response.status(),
                                false,
                            )
                        },
                        response.headers(),
                    ) {
                        submission.finish();
                    }
                    HandledResponse {
                        response: response.map(ProxyResponseBody::Local),
                        close_connection: false,
                        request_disposition: RequestDisposition::SwitchProtocol,
                    }
                }
                Ok(UpgradeHandshakeResponse::Failed(status)) | Err(status) => terminal
                    .capture
                    .fixed_response(CaptureDecision::Allow, status, "upgrade failed\n", true),
            };
        }
        if upgrade_binding.is_some() || downstream_upgrade.is_some() {
            return terminal.capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        }
        let mut response = match tokio::time::timeout_at(
            dispatch.deadline,
            forward_request(
                request,
                &origin,
                dispatch.services.egress(),
                &dispatch.destinations,
                dispatch.resolved,
                forwarding_timeouts,
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(ForwardError::ConnectTimeout | ForwardError::ResponseHeadTimeout)) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::GATEWAY_TIMEOUT,
                    "request timed out\n",
                    true,
                );
            }
            Ok(Err(error)) => {
                tracing::error!(error = ?error, "upstream request failed");
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::BAD_GATEWAY,
                    "upstream failed\n",
                    true,
                );
            }
            Err(_) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::GATEWAY_TIMEOUT,
                    "request timed out\n",
                    true,
                )
            }
        };
        if apply_standalone_response_mutations(&response_mutations, response.headers_mut()).is_err()
        {
            return terminal.capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::INTERNAL_SERVER_ERROR,
                "response failed\n",
                true,
            );
        }
        let response_capture = terminal.capture.begin(
            CaptureEvent::ResponseAllowed,
            || {
                terminal.capture.response_record(
                    CaptureDecision::Allow,
                    response.version(),
                    Some(response.headers()),
                    response.status(),
                    false,
                )
            },
            response.headers(),
        );
        let (parts, body) = response.into_parts();
        let body = body
            .bind_response_lifetime(
                dispatch.deadline,
                dispatch.retention,
                response_admission,
                response_policy,
                h2_stream,
            )
            .await;
        let response = Response::from_parts(parts, body);
        HandledResponse {
            response: response.map(|body| ProxyResponseBody::forwarded(body, response_capture)),
            close_connection: false,
            request_disposition: RequestDisposition::ContinueHttp,
        }
    }
}

struct StandaloneUpgradeExecution {
    runtime: Arc<UpgradeRuntime>,
    capture: Option<UpgradeCaptureContext>,
    binding: StandaloneUpgradeBinding,
    request: SanitizedRequest<StandaloneExchangeBody>,
    canonical: http_access_url::CanonicalUrl,
    resolved: ResolvedForwardingTarget,
    destinations: Arc<crate::destination::DestinationGuard>,
    retention: GenerationRetention,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
    deadline: Instant,
    response_mutations: Vec<http_access_types::HeaderMutationBatch>,
    request_headers: HeaderMap,
    protocol: HeaderValue,
    response_admission: crate::safety::ForwardResponseAdmission,
    response_policy: http_access_types::ResponsePolicy,
    h2_stream: Option<H2StreamCancellation>,
    forwarding_timeouts: ForwardingTimeouts,
    upgrade_deadlines: UpgradeRelayDeadlines,
}

enum UpgradeHandshakeResponse {
    Ordinary(Box<Response<ForwardedDownstreamBody>>),
    SwitchingProtocols(Response<Body>),
    Failed(StatusCode),
}

struct UpgradeHandshakeCancellation(Option<oneshot::Sender<()>>);

impl UpgradeHandshakeCancellation {
    fn new(sender: oneshot::Sender<()>) -> Self {
        Self(Some(sender))
    }
}

impl Drop for UpgradeHandshakeCancellation {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

async fn run_cancellable_upgrade_handshake<Task>(cancelled: oneshot::Receiver<()>, task: Task)
where
    Task: Future<Output = ()>,
{
    tokio::select! {
        biased;
        _ = cancelled => {}
        _ = task => {}
    }
}

async fn complete_upgrade_setup<Downstream, Upstream, DownstreamTask, UpstreamTask>(
    deadline: Instant,
    downstream: DownstreamTask,
    upstream: UpstreamTask,
) -> Result<(Downstream, Upstream), UpgradeTerminalCause>
where
    DownstreamTask: Future<Output = Result<Downstream, UpgradeTerminalCause>>,
    UpstreamTask: Future<Output = Result<Upstream, UpgradeTerminalCause>>,
{
    match tokio::time::timeout_at(deadline, async { tokio::try_join!(downstream, upstream) }).await
    {
        Ok(result) => result,
        Err(_) => Err(UpgradeTerminalCause::LifetimeExpired),
    }
}

async fn execute_standalone_upgrade(
    execution: StandaloneUpgradeExecution,
) -> Result<UpgradeHandshakeResponse, StatusCode> {
    let StandaloneUpgradeExecution {
        runtime: upgrade_runtime,
        capture: upgrade_capture,
        binding,
        request,
        canonical,
        resolved,
        destinations,
        retention,
        downstream_upgrade,
        deadline,
        response_mutations,
        request_headers,
        protocol,
        response_admission,
        response_policy,
        h2_stream,
        forwarding_timeouts,
        upgrade_deadlines,
    } = execution;
    let (response_tx, response_rx) = oneshot::channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let cancellation = UpgradeHandshakeCancellation::new(cancel_tx);
    let allocation = binding.allocation;
    let wire_redaction = binding.wire_redaction;
    let task_profile = wire_redaction.clone();
    let runtime_for_task = upgrade_runtime.clone();
    upgrade_runtime
        .try_spawn_handshake(allocation, move |handshake| {
            run_cancellable_upgrade_handshake(cancel_rx, async move {
                let forwarded = tokio::time::timeout_at(
                    deadline,
                    forward_upgrade_request(
                        request,
                        &canonical,
                        &retention,
                        destinations,
                        resolved,
                        forwarding_timeouts,
                    ),
                )
                .await;
                match forwarded {
                    Ok(Ok(ForwardUpgradeResult::Response(mut response))) => {
                        if apply_standalone_response_mutations(
                            &response_mutations,
                            response.headers_mut(),
                        )
                        .is_err()
                        {
                            let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                                StatusCode::INTERNAL_SERVER_ERROR,
                            ));
                            return;
                        }
                        let (parts, body) = (*response).into_parts();
                        let body = body
                            .bind_response_lifetime(
                                deadline,
                                retention,
                                response_admission,
                                response_policy,
                                h2_stream,
                            )
                            .await;
                        let response = Response::from_parts(parts, body);
                        let _ = response_tx
                            .send(UpgradeHandshakeResponse::Ordinary(Box::new(response)));
                    }
                    Ok(Ok(ForwardUpgradeResult::SwitchingProtocols(upgrade))) => {
                        let (mut response, upstream_upgrade) = upgrade.into_parts();
                        if apply_standalone_response_mutations(
                            &response_mutations,
                            response.headers_mut(),
                        )
                        .is_err()
                        {
                            let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                                StatusCode::INTERNAL_SERVER_ERROR,
                            ));
                            return;
                        }
                        let kind = match EstablishedUpgradeKind::from_handshake(
                            &protocol,
                            &request_headers,
                            response.headers(),
                            task_profile.as_ref(),
                        ) {
                            Ok(kind) => kind,
                            Err(_) => {
                                let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                                    StatusCode::BAD_GATEWAY,
                                ));
                                return;
                            }
                        };
                        let prepared_relay = match kind.prepare(
                            runtime_for_task.limits().relay_buffer_bytes(),
                            upgrade_capture,
                        ) {
                            Ok(prepared_relay) => prepared_relay,
                            Err(_) => {
                                let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                ));
                                return;
                            }
                        };
                        let terminal_control =
                            UpgradeTerminalControl::new(std::future::pending::<()>, |_| async {});
                        let entry_plan =
                            UpgradeEntryPlan::new(terminal_control, move |snapshot| async move {
                                response_tx
                                    .send(UpgradeHandshakeResponse::SwitchingProtocols(response))
                                    .map_err(|_| UpgradeTerminalCause::DownstreamWriteFailed)?;
                                let (downstream, upstream) = complete_upgrade_setup(
                                    deadline,
                                    async {
                                        downstream_upgrade.await.map_err(|_| {
                                            UpgradeTerminalCause::DownstreamWriteFailed
                                        })
                                    },
                                    async {
                                        upstream_upgrade
                                            .complete()
                                            .await
                                            .map_err(|_| UpgradeTerminalCause::SetupFailed)
                                    },
                                )
                                .await?;
                                Ok(prepared_relay.establish(
                                    downstream,
                                    upstream,
                                    snapshot,
                                    upgrade_deadlines,
                                ))
                            });
                        if handshake.commit(wire_redaction, entry_plan).is_err() {
                            return;
                        }
                        drop(retention);
                    }
                    Ok(Err(ForwardError::ConnectTimeout | ForwardError::ResponseHeadTimeout)) => {
                        let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                            StatusCode::GATEWAY_TIMEOUT,
                        ));
                    }
                    Ok(Err(_)) => {
                        let _ = response_tx
                            .send(UpgradeHandshakeResponse::Failed(StatusCode::BAD_GATEWAY));
                    }
                    Err(_) => {
                        let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                            StatusCode::GATEWAY_TIMEOUT,
                        ));
                    }
                }
            })
        })
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let outcome = match tokio::time::timeout_at(deadline, response_rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => Err(StatusCode::GATEWAY_TIMEOUT),
    };
    drop(cancellation);
    outcome
}

fn apply_standalone_response_mutations(
    batches: &[http_access_types::HeaderMutationBatch],
    headers: &mut HeaderMap,
) -> Result<(), ()> {
    *headers = crate::proxy::facts::apply_response_mutations(headers, batches).map_err(|_| ())?;
    Ok(())
}

fn body_headers(headers: &HeaderMap) -> HeaderMap {
    let mut selected = HeaderMap::new();
    for name in [CONTENT_ENCODING, TRAILER] {
        for value in headers.get_all(&name).iter() {
            selected.append(name.clone(), value.clone());
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::{UpgradeAllocation, UpgradeRuntimeLimits};

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn caller_cancellation_releases_runtime_owned_uncommitted_handshake() {
        let runtime =
            UpgradeRuntime::try_new(UpgradeRuntimeLimits::new(1, 8, 2, Duration::from_secs(60)))
                .unwrap();
        let allocation = UpgradeAllocation::from_compiled_rule(0, Some(4)).unwrap();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let cancellation = UpgradeHandshakeCancellation::new(cancel_tx);
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        runtime
            .try_spawn_handshake(allocation, move |handshake| {
                run_cancellable_upgrade_handshake(cancel_rx, async move {
                    let _handshake = handshake;
                    let _signal = signal;
                    std::future::pending::<()>().await;
                })
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let counts = runtime.counts();
                if counts.reserved_slots == 1
                    && counts.reserved_bytes == 8
                    && counts.uncommitted == 1
                    && counts.tracked_tasks == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        drop(cancellation);
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let counts = runtime.counts();
                if counts.reserved_slots == 0
                    && counts.reserved_bytes == 0
                    && counts.uncommitted == 0
                    && counts.tracked_tasks == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        runtime.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    async fn absolute_deadline_bounds_committed_upgrade_setup() {
        let error = complete_upgrade_setup(
            Instant::now() + Duration::from_millis(20),
            std::future::ready(Ok::<_, UpgradeTerminalCause>(())),
            std::future::pending::<Result<(), UpgradeTerminalCause>>(),
        )
        .await
        .unwrap_err();

        assert_eq!(error, UpgradeTerminalCause::LifetimeExpired);
    }
}
