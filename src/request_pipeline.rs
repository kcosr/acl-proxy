#![allow(
    dead_code,
    reason = "P06 C01 adds the pipeline before the mandatory C04 listener cutover"
)]

use http_access_runtime::{
    prepare_standalone_exchange, BoxFuture, DecisionProvider, ProviderOutcome, RuntimeRequest,
    RuntimeResponse, StandaloneExchange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RequestPipelineError {
    #[error("standalone provider returned an invalid forwarding result")]
    InvalidProviderOutput,
}

pub(crate) trait StandaloneDispatch: Send + Sync {
    type Output;

    fn fail_closed(&self, error: RequestPipelineError) -> BoxFuture<'_, Self::Output>;

    fn respond(&self, response: RuntimeResponse) -> BoxFuture<'_, Self::Output>;

    fn forward(&self, exchange: StandaloneExchange) -> BoxFuture<'_, Self::Output>;
}

pub(crate) trait StandaloneRequestContext: DecisionProvider + StandaloneDispatch {}

impl<T> StandaloneRequestContext for T where T: DecisionProvider + StandaloneDispatch {}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RequestPipeline;

impl RequestPipeline {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) async fn execute<C>(&self, context: C, request: RuntimeRequest) -> C::Output
    where
        C: StandaloneRequestContext,
    {
        let facts = request.facts().clone();
        let lineage = request.begin_provider_invocation();
        match context.decide(&facts, request).await {
            ProviderOutcome::Respond(response) => context.respond(response).await,
            ProviderOutcome::Forward { plan, request } => {
                match prepare_standalone_exchange(lineage, plan, request) {
                    Ok(exchange) => context.forward(exchange).await,
                    Err(_) => {
                        context
                            .fail_closed(RequestPipelineError::InvalidProviderOutput)
                            .await
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::task::{Context, Poll};

    use http_access_runtime::{
        BodyBudget, BodySource, BodySourceEvent, BoxFuture, Clock, DecisionProvider,
        ProviderOutcome, RuntimeBody, RuntimeError, RuntimeRequest, RuntimeResourceLimits,
        RuntimeResponse, RuntimeTrailers, SnapshotLease, SnapshotRegistries, StandaloneExchange,
        StandaloneTrusted,
    };
    use http_access_types::{
        BodyFraming, BodyLimits, BodyMetadata, BodyRepresentation, CanonicalAuthority,
        CanonicalHost, CanonicalUrl, DecisionProvenance, DecisionReason, DecisionReasonCategory,
        EffectivePolicy, ForwardingPlan, ForwardingPlanInput, HttpMethod, HttpScheme, HttpVersion,
        IngressMode, PolicyGeneration, PolicyHeaderFacts, RedirectPolicy, RequestBinding,
        RequestBodyPolicy, ResponsePolicy, Route, SnapshotIdentity, StageTimeouts, TlsIntent,
        TrailerPolicy, UpgradePolicy,
    };

    use super::{
        RequestPipeline, RequestPipelineError, StandaloneDispatch, StandaloneRequestContext,
    };

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct FakeClock {
        monotonic_millis: AtomicU64,
    }

    impl FakeClock {
        fn new(monotonic_millis: u64) -> Self {
            Self {
                monotonic_millis: AtomicU64::new(monotonic_millis),
            }
        }
    }

    impl Clock for FakeClock {
        fn monotonic_millis(&self) -> u64 {
            self.monotonic_millis.load(Ordering::SeqCst)
        }

        fn unix_millis(&self) -> u64 {
            0
        }

        fn sleep_until(&self, _deadline_millis: u64) -> BoxFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
    }

    struct DropProbe {
        drops: Arc<AtomicUsize>,
    }

    impl DropProbe {
        fn new(drops: Arc<AtomicUsize>) -> Self {
            Self { drops }
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct DropBodySource {
        _drop_probe: DropProbe,
    }

    impl BodySource for DropBodySource {
        fn poll_next(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
            Poll::Pending
        }

        fn poll_trailers(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
            Poll::Pending
        }
    }

    #[derive(Clone, Copy)]
    enum DecisionMode {
        ForwardInput,
        ForeignCompletePair,
        StalePlanForRevisedInput,
        Respond(u16),
    }

    enum DispatchMode {
        Ready,
        Pending(Arc<AtomicUsize>),
    }

    #[derive(Default)]
    struct Observed {
        decide_calls: AtomicUsize,
        response_calls: AtomicUsize,
        forward_calls: AtomicUsize,
        fail_closed_calls: AtomicUsize,
        facts_match_request: AtomicBool,
        events: Mutex<Vec<&'static str>>,
    }

    struct FakeContext {
        decision: DecisionMode,
        dispatch: DispatchMode,
        clock: Arc<FakeClock>,
        observed: Arc<Observed>,
        _context_drop: DropProbe,
        _sidecar_drop: DropProbe,
        response_body_drops: Option<Arc<AtomicUsize>>,
    }

    impl FakeContext {
        fn new(decision: DecisionMode, observed: Arc<Observed>) -> (Self, DropCounters) {
            Self::with_dispatch(decision, DispatchMode::Ready, observed, None)
        }

        fn pending(
            decision: DecisionMode,
            observed: Arc<Observed>,
            pending_future_drops: Arc<AtomicUsize>,
            response_body_drops: Option<Arc<AtomicUsize>>,
        ) -> (Self, DropCounters) {
            Self::with_dispatch(
                decision,
                DispatchMode::Pending(pending_future_drops),
                observed,
                response_body_drops,
            )
        }

        fn with_dispatch(
            decision: DecisionMode,
            dispatch: DispatchMode,
            observed: Arc<Observed>,
            response_body_drops: Option<Arc<AtomicUsize>>,
        ) -> (Self, DropCounters) {
            let counters = DropCounters::default();
            (
                Self {
                    decision,
                    dispatch,
                    clock: Arc::new(FakeClock::new(1)),
                    observed,
                    _context_drop: DropProbe::new(counters.context.clone()),
                    _sidecar_drop: DropProbe::new(counters.sidecar.clone()),
                    response_body_drops,
                },
                counters,
            )
        }

        fn terminal_future<T: Send + 'static>(
            &self,
            owned: T,
            ready: Terminal,
        ) -> BoxFuture<'_, Terminal> {
            match &self.dispatch {
                DispatchMode::Ready => Box::pin(async move {
                    drop(owned);
                    ready
                }),
                DispatchMode::Pending(drops) => Box::pin(PendingOwned {
                    _owned: owned,
                    drops: drops.clone(),
                }),
            }
        }
    }

    impl DecisionProvider for FakeContext {
        fn decide<'a>(
            &'a self,
            facts: &'a http_access_types::InterceptedRequestFacts,
            mut request: RuntimeRequest,
        ) -> BoxFuture<'a, ProviderOutcome> {
            self.observed.decide_calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.observed.events).push("decide");
            self.observed.facts_match_request.store(
                facts.url().as_str() == request.facts().url().as_str()
                    && facts.method() == request.facts().method()
                    && facts.ingress_mode() == request.facts().ingress_mode(),
                Ordering::SeqCst,
            );
            let outcome = match self.decision {
                DecisionMode::ForwardInput => forward_outcome(request),
                DecisionMode::ForeignCompletePair => {
                    drop(request);
                    forward_outcome(runtime_request(Arc::new(FakeClock::new(1))))
                }
                DecisionMode::StalePlanForRevisedInput => {
                    let plan = standalone_plan(&request);
                    request
                        .apply_header_mutation_batches(&[])
                        .expect("the test mutation advances the request revision");
                    ProviderOutcome::Forward { plan, request }
                }
                DecisionMode::Respond(status) => {
                    let response = match &self.response_body_drops {
                        Some(drops) => {
                            tracked_response(self.clock.clone(), &request, status, drops)
                        }
                        None => response(self.clock.clone(), &request, status),
                    };
                    ProviderOutcome::Respond(response)
                }
            };
            Box::pin(async move { outcome })
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Terminal {
        Response(u16),
        Forward(String),
        FailClosed(RequestPipelineError),
    }

    impl StandaloneDispatch for FakeContext {
        type Output = Terminal;

        fn fail_closed(&self, error: RequestPipelineError) -> BoxFuture<'_, Self::Output> {
            self.observed
                .fail_closed_calls
                .fetch_add(1, Ordering::SeqCst);
            lock(&self.observed.events).push("fail_closed");
            Box::pin(async move { Terminal::FailClosed(error) })
        }

        fn respond(&self, response: RuntimeResponse) -> BoxFuture<'_, Self::Output> {
            self.observed.response_calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.observed.events).push("respond");
            let status = response.status();
            self.terminal_future(response, Terminal::Response(status))
        }

        fn forward(&self, exchange: StandaloneExchange) -> BoxFuture<'_, Self::Output> {
            self.observed.forward_calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.observed.events).push("forward");
            let path = exchange.facts().url().path().to_owned();
            self.terminal_future(exchange, Terminal::Forward(path))
        }
    }

    #[derive(Default)]
    struct DropCounters {
        context: Arc<AtomicUsize>,
        sidecar: Arc<AtomicUsize>,
    }

    struct PendingOwned<T> {
        _owned: T,
        drops: Arc<AtomicUsize>,
    }

    impl<T> Future for PendingOwned<T> {
        type Output = Terminal;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl<T> Drop for PendingOwned<T> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn response_dispatches_once_without_forwarding() {
        let observed = Arc::new(Observed::default());
        let (context, drops) = FakeContext::new(DecisionMode::Respond(403), observed.clone());

        let result = RequestPipeline::new()
            .execute(context, runtime_request(Arc::new(FakeClock::new(1))))
            .await;

        assert_eq!(result, Terminal::Response(403));
        assert_counts(&observed, 1, 1, 0, 0);
        assert_eq!(*lock(&observed.events), ["decide", "respond"]);
        assert!(observed.facts_match_request.load(Ordering::SeqCst));
        assert_drop_counts(&drops, 1, 1);
    }

    #[tokio::test]
    async fn valid_forward_pair_is_built_from_its_actual_input_and_dispatched_once() {
        let observed = Arc::new(Observed::default());
        let (context, drops) = FakeContext::new(DecisionMode::ForwardInput, observed.clone());

        let result = RequestPipeline::new()
            .execute(context, runtime_request(Arc::new(FakeClock::new(1))))
            .await;

        assert_eq!(result, Terminal::Forward("/resource".to_owned()));
        assert_counts(&observed, 1, 0, 1, 0);
        assert_eq!(*lock(&observed.events), ["decide", "forward"]);
        assert!(observed.facts_match_request.load(Ordering::SeqCst));
        assert_drop_counts(&drops, 1, 1);
    }

    #[tokio::test]
    async fn semantically_identical_foreign_complete_pair_fails_closed() {
        let observed = Arc::new(Observed::default());
        let (context, drops) =
            FakeContext::new(DecisionMode::ForeignCompletePair, observed.clone());

        let result = RequestPipeline::new()
            .execute(context, runtime_request(Arc::new(FakeClock::new(1))))
            .await;

        assert_eq!(
            result,
            Terminal::FailClosed(RequestPipelineError::InvalidProviderOutput)
        );
        assert_counts(&observed, 1, 0, 0, 1);
        assert_eq!(*lock(&observed.events), ["decide", "fail_closed"]);
        assert_drop_counts(&drops, 1, 1);
    }

    #[tokio::test]
    async fn stale_plan_and_newer_same_lineage_request_fail_closed() {
        let observed = Arc::new(Observed::default());
        let (context, drops) =
            FakeContext::new(DecisionMode::StalePlanForRevisedInput, observed.clone());

        let result = RequestPipeline::new()
            .execute(context, runtime_request(Arc::new(FakeClock::new(1))))
            .await;

        assert_eq!(
            result,
            Terminal::FailClosed(RequestPipelineError::InvalidProviderOutput)
        );
        assert_counts(&observed, 1, 0, 0, 1);
        assert_eq!(*lock(&observed.events), ["decide", "fail_closed"]);
        assert_drop_counts(&drops, 1, 1);
    }

    struct PendingDecisionContext {
        observed: Arc<Observed>,
        future_drops: Arc<AtomicUsize>,
        _context_drop: DropProbe,
        _sidecar_drop: DropProbe,
    }

    impl DecisionProvider for PendingDecisionContext {
        fn decide<'a>(
            &'a self,
            facts: &'a http_access_types::InterceptedRequestFacts,
            request: RuntimeRequest,
        ) -> BoxFuture<'a, ProviderOutcome> {
            self.observed.decide_calls.fetch_add(1, Ordering::SeqCst);
            self.observed.facts_match_request.store(
                facts.url().as_str() == request.facts().url().as_str(),
                Ordering::SeqCst,
            );
            Box::pin(PendingDecision {
                _request: request,
                drops: self.future_drops.clone(),
            })
        }
    }

    impl StandaloneDispatch for PendingDecisionContext {
        type Output = Terminal;

        fn fail_closed(&self, error: RequestPipelineError) -> BoxFuture<'_, Self::Output> {
            self.observed
                .fail_closed_calls
                .fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Terminal::FailClosed(error) })
        }

        fn respond(&self, _response: RuntimeResponse) -> BoxFuture<'_, Self::Output> {
            self.observed.response_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }

        fn forward(&self, _exchange: StandaloneExchange) -> BoxFuture<'_, Self::Output> {
            self.observed.forward_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }
    }

    struct PendingDecision {
        _request: RuntimeRequest,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PendingDecision {
        type Output = ProviderOutcome;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingDecision {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn dropping_pending_decision_drops_request_context_and_sidecar() {
        let observed = Arc::new(Observed::default());
        let drops = DropCounters::default();
        let future_drops = Arc::new(AtomicUsize::new(0));
        let body_drops = Arc::new(AtomicUsize::new(0));
        let context = PendingDecisionContext {
            observed: observed.clone(),
            future_drops: future_drops.clone(),
            _context_drop: DropProbe::new(drops.context.clone()),
            _sidecar_drop: DropProbe::new(drops.sidecar.clone()),
        };
        let pipeline = RequestPipeline::new();
        let mut execution = Box::pin(pipeline.execute(
            context,
            tracked_request(Arc::new(FakeClock::new(1)), &body_drops),
        ));

        assert_pending(execution.as_mut());
        assert_eq!(observed.decide_calls.load(Ordering::SeqCst), 1);
        assert!(observed.facts_match_request.load(Ordering::SeqCst));
        assert_eq!(body_drops.load(Ordering::SeqCst), 0);
        assert_drop_counts(&drops, 0, 0);

        drop(execution);

        assert_eq!(future_drops.load(Ordering::SeqCst), 1);
        assert_eq!(body_drops.load(Ordering::SeqCst), 1);
        assert_counts(&observed, 1, 0, 0, 0);
        assert_drop_counts(&drops, 1, 1);
    }

    #[test]
    fn dropping_pending_response_drops_response_context_and_sidecar() {
        let observed = Arc::new(Observed::default());
        let pending_future_drops = Arc::new(AtomicUsize::new(0));
        let request_body_drops = Arc::new(AtomicUsize::new(0));
        let response_body_drops = Arc::new(AtomicUsize::new(0));
        let (context, drops) = FakeContext::pending(
            DecisionMode::Respond(202),
            observed.clone(),
            pending_future_drops.clone(),
            Some(response_body_drops.clone()),
        );
        let pipeline = RequestPipeline::new();
        let mut execution = Box::pin(pipeline.execute(
            context,
            tracked_request(Arc::new(FakeClock::new(1)), &request_body_drops),
        ));

        assert_pending(execution.as_mut());
        assert_eq!(request_body_drops.load(Ordering::SeqCst), 1);
        assert_eq!(response_body_drops.load(Ordering::SeqCst), 0);
        assert_eq!(pending_future_drops.load(Ordering::SeqCst), 0);
        assert_counts(&observed, 1, 1, 0, 0);
        assert_drop_counts(&drops, 0, 0);

        drop(execution);

        assert_eq!(response_body_drops.load(Ordering::SeqCst), 1);
        assert_eq!(pending_future_drops.load(Ordering::SeqCst), 1);
        assert_drop_counts(&drops, 1, 1);
    }

    #[test]
    fn dropping_pending_forward_drops_exchange_context_and_sidecar() {
        let observed = Arc::new(Observed::default());
        let pending_future_drops = Arc::new(AtomicUsize::new(0));
        let request_body_drops = Arc::new(AtomicUsize::new(0));
        let (context, drops) = FakeContext::pending(
            DecisionMode::ForwardInput,
            observed.clone(),
            pending_future_drops.clone(),
            None,
        );
        let pipeline = RequestPipeline::new();
        let mut execution = Box::pin(pipeline.execute(
            context,
            tracked_request(Arc::new(FakeClock::new(1)), &request_body_drops),
        ));

        assert_pending(execution.as_mut());
        assert_eq!(request_body_drops.load(Ordering::SeqCst), 0);
        assert_eq!(pending_future_drops.load(Ordering::SeqCst), 0);
        assert_counts(&observed, 1, 0, 1, 0);
        assert_drop_counts(&drops, 0, 0);

        drop(execution);

        assert_eq!(request_body_drops.load(Ordering::SeqCst), 1);
        assert_eq!(pending_future_drops.load(Ordering::SeqCst), 1);
        assert_drop_counts(&drops, 1, 1);
    }

    #[test]
    fn execution_consumes_one_non_clone_context_by_signature() {
        fn execute_once<C: StandaloneRequestContext>(
            pipeline: &RequestPipeline,
            context: C,
            request: RuntimeRequest,
        ) {
            drop(pipeline.execute(context, request));
        }

        let observed = Arc::new(Observed::default());
        let (context, drops) = FakeContext::new(DecisionMode::ForwardInput, observed.clone());
        execute_once(
            &RequestPipeline::new(),
            context,
            runtime_request(Arc::new(FakeClock::new(1))),
        );

        assert_counts(&observed, 0, 0, 0, 0);
        assert_drop_counts(&drops, 1, 1);
    }

    fn assert_pending<T>(mut future: Pin<&mut T>)
    where
        T: Future,
    {
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop())),
            Poll::Pending
        ));
    }

    fn assert_counts(
        observed: &Observed,
        decide: usize,
        respond: usize,
        forward: usize,
        fail_closed: usize,
    ) {
        assert_eq!(observed.decide_calls.load(Ordering::SeqCst), decide);
        assert_eq!(observed.response_calls.load(Ordering::SeqCst), respond);
        assert_eq!(observed.forward_calls.load(Ordering::SeqCst), forward);
        assert_eq!(
            observed.fail_closed_calls.load(Ordering::SeqCst),
            fail_closed
        );
    }

    fn assert_drop_counts(counters: &DropCounters, context: usize, sidecar: usize) {
        assert_eq!(counters.context.load(Ordering::SeqCst), context);
        assert_eq!(counters.sidecar.load(Ordering::SeqCst), sidecar);
    }

    fn runtime_request(clock: Arc<FakeClock>) -> RuntimeRequest {
        let body_bounds = body_bounds();
        let body = RuntimeBody::from_chunks(
            Vec::new(),
            body_bounds,
            clock,
            BodyBudget::new(4_096).unwrap(),
            1_000,
        )
        .unwrap();
        request_with_body(body)
    }

    fn tracked_request(clock: Arc<FakeClock>, drops: &Arc<AtomicUsize>) -> RuntimeRequest {
        let body = RuntimeBody::new(
            Box::pin(DropBodySource {
                _drop_probe: DropProbe::new(drops.clone()),
            }),
            body_bounds(),
            clock,
            BodyBudget::new(4_096).unwrap(),
            1_000,
        )
        .unwrap();
        request_with_body(body)
    }

    fn request_with_body(body: RuntimeBody) -> RuntimeRequest {
        let facts = facts();
        RuntimeRequest::new(
            facts.clone(),
            "127.0.0.1".parse().unwrap(),
            PolicyHeaderFacts::new(facts.headers().to_vec(), Vec::new()).unwrap(),
            BodyRepresentation::PreservedContentCoded,
            body,
            1_000,
        )
        .unwrap()
    }

    fn response(clock: Arc<FakeClock>, request: &RuntimeRequest, status: u16) -> RuntimeResponse {
        let policy = request
            .local_response_policy(body_bounds(), 16, 4_096)
            .unwrap();
        let body = RuntimeBody::from_chunks(
            Vec::new(),
            body_bounds(),
            clock,
            BodyBudget::new(4_096).unwrap(),
            1_000,
        )
        .unwrap();
        RuntimeResponse::new(status, Vec::new(), body, policy).unwrap()
    }

    fn tracked_response(
        clock: Arc<FakeClock>,
        request: &RuntimeRequest,
        status: u16,
        drops: &Arc<AtomicUsize>,
    ) -> RuntimeResponse {
        let policy = request
            .local_response_policy(body_bounds(), 16, 4_096)
            .unwrap();
        let body = RuntimeBody::new(
            Box::pin(DropBodySource {
                _drop_probe: DropProbe::new(drops.clone()),
            }),
            body_bounds(),
            clock,
            BodyBudget::new(4_096).unwrap(),
            1_000,
        )
        .unwrap();
        RuntimeResponse::new(status, Vec::new(), body, policy).unwrap()
    }

    fn body_bounds() -> http_access_runtime::BodyBounds {
        http_access_runtime::BodyBounds::new(1_024, 1_024, 512, 0, 0, 100).unwrap()
    }

    fn facts() -> http_access_types::InterceptedRequestFacts {
        http_access_types::InterceptedRequestFacts::new(
            IngressMode::ExplicitHttps,
            HttpVersion::Http11,
            HttpMethod::new("GET").unwrap(),
            canonical_url(),
            Vec::new(),
            BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap()
    }

    fn canonical_url() -> CanonicalUrl {
        let authority = CanonicalAuthority::new(
            HttpScheme::Https,
            CanonicalHost::new("example.test").unwrap(),
            443,
        )
        .unwrap();
        CanonicalUrl::new(HttpScheme::Https, authority, "/resource", None).unwrap()
    }

    fn forward_outcome(request: RuntimeRequest) -> ProviderOutcome {
        let plan = standalone_plan(&request);
        ProviderOutcome::Forward { plan, request }
    }

    fn standalone_plan(request: &RuntimeRequest) -> http_access_runtime::StandalonePlan {
        let identity = SnapshotIdentity::new();
        let generation = PolicyGeneration::new(1).unwrap();
        let plan = forwarding_plan(identity.clone(), generation, request.binding().unwrap());
        let snapshot = snapshot(identity, generation);
        StandaloneTrusted::validate(plan, request, &snapshot).unwrap()
    }

    fn snapshot(identity: SnapshotIdentity, generation: PolicyGeneration) -> SnapshotLease {
        SnapshotLease::new(
            identity.clone(),
            generation,
            Vec::new(),
            SnapshotRegistries::empty(&identity),
            RuntimeResourceLimits::new(1_024 * 1_024, 1_024 * 1_024, 1_024 * 1_024).unwrap(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    fn forwarding_plan(
        identity: SnapshotIdentity,
        generation: PolicyGeneration,
        request_binding: RequestBinding,
    ) -> ForwardingPlan {
        let limits = BodyLimits::new(1_024, 1_024, 1, 1, 512, 0, 0).unwrap();
        ForwardingPlan::new(ForwardingPlanInput {
            snapshot_identity: identity,
            request_binding,
            origin: canonical_url(),
            route: Route::Direct,
            origin_tls: TlsIntent::SystemRoots,
            timeouts: StageTimeouts::new(100, 100, 100, 100).unwrap(),
            request_body: RequestBodyPolicy::new(
                BodyRepresentation::PreservedContentCoded,
                limits,
                TrailerPolicy::Deny,
            )
            .unwrap(),
            response: ResponsePolicy::new(limits, 100, RedirectPolicy::ReturnToCaller).unwrap(),
            request_mutation_batches: Vec::new(),
            response_mutation_batches: Vec::new(),
            redaction: None,
            capture: None,
            upgrade: UpgradePolicy::Deny,
            provenance: DecisionProvenance::new(
                generation,
                EffectivePolicy::Default,
                DecisionReason::new(DecisionReasonCategory::Policy, 1),
                None,
            ),
            credential_mutations: Vec::new(),
        })
        .unwrap()
    }
}
