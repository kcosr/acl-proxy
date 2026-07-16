use std::collections::VecDeque;
#[cfg(unix)]
use std::ffi::OsString;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, Notify, Semaphore};

use crate::authorization::callback::{
    CallbackClaimResult, PendingCapabilityStore, PendingDeadline, ResumeTokenDigest,
};
use crate::authorization::protocol::{ProviderDecision, ProviderRequest};
use crate::authorization::webhook::runtime::WebhookAuthorizationRuntime;
use crate::authorization::ProductAuthorizationSnapshot;
use crate::config::compiler::{
    AuthorizationCallbackPlan, AuthorizationPlan, AuthorizationProviderPlan,
    CompiledProviderFailureMode, PendingOperationLimit, WebhookProviderPlan,
};
use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput};
use crate::destination::{
    DestinationFacts, DestinationGuard, DestinationResolver, LocalAddressSnapshot,
    LocalAddressSource, ResolveFuture,
};
use crate::safety::{WireBodyPool, WireBodyQuotaKey};
use crate::upgrade::{
    UpgradeAllocation, UpgradeEntryPlan, UpgradeRelayPair, UpgradeRuntime, UpgradeRuntimeLimits,
    UpgradeTerminalCause, UpgradeTerminalControl,
};

use super::*;

struct EmptySnapshot;

struct FixedDestinationResolver(SocketAddr);

impl DestinationResolver for FixedDestinationResolver {
    fn resolve(&self, _host: &str, _port: u16, _max_addresses: usize) -> ResolveFuture<'_> {
        let endpoint = self.0;
        Box::pin(async move { Ok(vec![endpoint]) })
    }
}

struct EmptyLocalAddressSource;

impl LocalAddressSource for EmptyLocalAddressSource {
    fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
        Ok(LocalAddressSnapshot::default())
    }
}

impl EgressSnapshot for EmptySnapshot {
    fn identity(&self) -> &Arc<()> {
        static IDENTITY: std::sync::OnceLock<Arc<()>> = std::sync::OnceLock::new();
        IDENTITY.get_or_init(|| Arc::new(()))
    }

    fn route(&self) -> &crate::egress::EgressRoute {
        panic!("empty test egress has no route")
    }

    fn origin_tls(&self) -> &crate::egress::OriginTls {
        panic!("empty test egress has no origin TLS policy")
    }
}
impl AuthorizationSnapshot for EmptySnapshot {
    fn internal_context_headers(&self) -> &[http::HeaderName] {
        &[]
    }

    fn provider_metadata(
        &self,
        _provider: ProviderIndex,
    ) -> Option<crate::authorization::AuthorizationProviderMetadata<'_>> {
        None
    }

    fn stage_provider_credentials(
        &self,
        _provider: ProviderIndex,
        _credentials: &crate::authorization::protocol::ProviderCredentialSet,
        _guard: &crate::safety::HttpWireBodyGuard,
    ) -> Result<
        crate::authorization::protocol::StagedProviderCredentialMutation,
        crate::authorization::protocol::ProviderCredentialInjectionError,
    > {
        Err(crate::authorization::protocol::ProviderCredentialInjectionError::UnknownProvider)
    }

    fn consume_allow_output(
        &self,
        _provider: ProviderIndex,
        _output: crate::authorization::AuthorizationAllowOutput,
    ) -> Option<(
        Option<crate::authorization::protocol::ProviderCredentialSet>,
        Option<crate::authorization::protocol::ProviderBodyReplacement>,
    )> {
        None
    }

    fn bind_allow_output_for_test(
        &self,
        _provider: ProviderIndex,
        _credentials: Option<crate::authorization::protocol::ProviderCredentialSet>,
        _replacement: Option<crate::authorization::protocol::ProviderBodyReplacement>,
    ) -> crate::authorization::AuthorizationAllowOutput {
        panic!("the empty authorization snapshot cannot bind allow output")
    }

    fn dispatch<'a>(
        &'a self,
        _provider: ProviderIndex,
        _context: AuthorizationDispatchContext<'a>,
        _guard: &'a crate::safety::HttpWireBodyGuard,
        _request_deadline: tokio::time::Instant,
    ) -> BoxFuture<
        'a,
        Result<
            crate::authorization::AuthorizationDecision,
            crate::authorization::AuthorizationDispatchError,
        >,
    > {
        Box::pin(async { Err(crate::authorization::AuthorizationDispatchError::UnknownProvider) })
    }
}
impl CredentialResolver for EmptySnapshot {
    fn inject(
        &self,
        actions: &[crate::credentials::ResolvedCredentialAction],
        _headers: &mut http::HeaderMap,
    ) -> Result<(), crate::credentials::CredentialError> {
        assert!(actions.is_empty());
        Ok(())
    }

    fn extract_inbound(
        &self,
        _headers: &mut http::HeaderMap,
    ) -> Result<crate::credentials::InboundCredentials, crate::credentials::CredentialError> {
        panic!("empty test credentials cannot extract inbound values")
    }
}
impl ObservationSnapshot for EmptySnapshot {
    fn capture_epoch(&self) -> &Arc<crate::observation::CaptureEpoch> {
        static DISABLED: std::sync::LazyLock<Arc<crate::observation::CaptureEpoch>> =
            std::sync::LazyLock::new(|| Arc::new(crate::observation::CaptureEpoch::disabled()));
        &DISABLED
    }

    fn decision_level(
        &self,
        _disposition: http_access_types::DecisionDisposition,
    ) -> Option<crate::config::compiler::CompiledDecisionLogLevel> {
        None
    }
}
impl SafetySnapshot for EmptySnapshot {
    fn contains_loop_marker(&self, _headers: &http::HeaderMap) -> bool {
        false
    }

    fn inject_loop_marker(
        &self,
        _headers: &mut http::HeaderMap,
        _request_id: &str,
    ) -> Result<(), crate::safety::InvalidLoopMarker> {
        Ok(())
    }

    fn begin_http_body(
        &self,
        _plan: crate::policy::HttpWireBodyPlanIndex,
        quota_key: crate::safety::WireBodyQuotaKey,
    ) -> Result<crate::safety::HttpBodyAdmission, crate::safety::HttpBodyAdmissionError> {
        crate::safety::WireBodyPool::new(1, 1)
            .begin_admission_for_test(0, 0, quota_key)
            .map_err(crate::safety::HttpBodyAdmissionError::Resource)
    }

    fn begin_forward_response(
        &self,
        _quota_key: crate::safety::WireBodyQuotaKey,
    ) -> Result<crate::safety::ForwardResponseAdmission, crate::safety::ForwardResponseAdmissionError>
    {
        unreachable!("the empty runtime snapshot cannot forward a response")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerEvent {
    RetirementStarted(CleanupReason),
    Cleanup(CleanupReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShutdownEvent {
    StaticBegin,
    CandidateCleanup,
    GenerationRetirementStarted,
    GenerationCleanup,
    StaticFinish,
}

fn shutdown_event_index(events: &[ShutdownEvent], event: ShutdownEvent) -> usize {
    events
        .iter()
        .position(|candidate| *candidate == event)
        .unwrap_or_else(|| panic!("missing shutdown event: {event:?}"))
}

#[derive(Default)]
struct FakeOwner {
    commits: AtomicUsize,
    candidate_cleanups: AtomicUsize,
    retirements: AtomicUsize,
    shutdowns: AtomicUsize,
    reject_publication: AtomicBool,
    panic_cleanup: AtomicBool,
    panic_retirement_started: AtomicBool,
    block_commit: AtomicBool,
    commit_released: Mutex<bool>,
    commit_release: Condvar,
    commit_started: AtomicBool,
    commit_entered: Notify,
    cleanup_events: Option<Arc<Mutex<Vec<CleanupReason>>>>,
    shutdown_events: Option<Arc<Mutex<Vec<ShutdownEvent>>>>,
    events: Mutex<Vec<OwnerEvent>>,
}

struct FakePublicationGuard<'a> {
    owner: &'a FakeOwner,
    _not_send: PhantomData<Rc<()>>,
}

impl PublicationGuard for FakePublicationGuard<'_> {
    fn commit(&mut self) {
        if self.owner.block_commit.load(Ordering::Acquire) {
            self.owner.commit_started.store(true, Ordering::Release);
            self.owner.commit_entered.notify_waiters();
            let mut released = self.owner.commit_released.lock().unwrap();
            while !*released {
                released = self.owner.commit_release.wait(released).unwrap();
            }
        }
        self.owner.commits.fetch_add(1, Ordering::AcqRel);
    }
}

impl GenerationOwner for FakeOwner {
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
        if self.reject_publication.swap(false, Ordering::AcqRel) {
            return Err(RuntimeError::CandidateNotLive("fake owner exited".into()));
        }
        Ok(Box::new(FakePublicationGuard {
            owner: self,
            _not_send: PhantomData,
        }))
    }

    fn retirement_started(&self, reason: CleanupReason) {
        if reason == CleanupReason::Shutdown {
            if let Some(events) = &self.shutdown_events {
                events
                    .lock()
                    .unwrap()
                    .push(ShutdownEvent::GenerationRetirementStarted);
            }
        }
        if self.panic_retirement_started.swap(false, Ordering::AcqRel) {
            panic!("fake retirement-start panic");
        }
        self.events
            .lock()
            .unwrap()
            .push(OwnerEvent::RetirementStarted(reason));
    }

    fn cleanup(&self, reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.panic_cleanup.swap(false, Ordering::AcqRel) {
                panic!("fake cleanup panic");
            }
            if let Some(events) = &self.cleanup_events {
                events.lock().unwrap().push(reason);
            }
            if let Some(events) = &self.shutdown_events {
                let event = match reason {
                    CleanupReason::CandidateRejected => Some(ShutdownEvent::CandidateCleanup),
                    CleanupReason::Shutdown => Some(ShutdownEvent::GenerationCleanup),
                    CleanupReason::Retired => None,
                };
                if let Some(event) = event {
                    events.lock().unwrap().push(event);
                }
            }
            self.events
                .lock()
                .unwrap()
                .push(OwnerEvent::Cleanup(reason));
            match reason {
                CleanupReason::CandidateRejected => {
                    self.candidate_cleanups.fetch_add(1, Ordering::AcqRel);
                }
                CleanupReason::Retired => {
                    self.retirements.fetch_add(1, Ordering::AcqRel);
                }
                CleanupReason::Shutdown => {
                    self.shutdowns.fetch_add(1, Ordering::AcqRel);
                }
            }
        })
    }
}

impl FakeOwner {
    fn events(&self) -> Vec<OwnerEvent> {
        self.events.lock().unwrap().clone()
    }

    async fn wait_for_commit(&self) {
        loop {
            let entered = self.commit_entered.notified();
            if self.commit_started.load(Ordering::Acquire) {
                return;
            }
            entered.await;
        }
    }

    fn release_commit(&self) {
        *self.commit_released.lock().unwrap() = true;
        self.commit_release.notify_all();
    }
}

struct FakeStaticResources {
    readiness: Arc<ServiceReadiness>,
    brand: StaticResourceBrand,
    begin_shutdowns: AtomicUsize,
    shutdown_begun: AtomicBool,
    block_begin_return: AtomicBool,
    begin_return_entered: AtomicBool,
    begin_return_changed: Notify,
    begin_return_released: Mutex<bool>,
    begin_return_release: Condvar,
    shutdowns: AtomicUsize,
    shutdown_events: Arc<Mutex<Vec<ShutdownEvent>>>,
    shutdown_retentions: Mutex<Vec<GenerationRetention>>,
}

impl Default for FakeStaticResources {
    fn default() -> Self {
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ingress_started();
        Self {
            readiness,
            brand: StaticResourceBrand::new(),
            begin_shutdowns: AtomicUsize::new(0),
            shutdown_begun: AtomicBool::new(false),
            block_begin_return: AtomicBool::new(false),
            begin_return_entered: AtomicBool::new(false),
            begin_return_changed: Notify::new(),
            begin_return_released: Mutex::new(false),
            begin_return_release: Condvar::new(),
            shutdowns: AtomicUsize::new(0),
            shutdown_events: Arc::new(Mutex::new(Vec::new())),
            shutdown_retentions: Mutex::new(Vec::new()),
        }
    }
}

impl StaticResources for FakeStaticResources {
    fn brand(&self) -> &StaticResourceBrand {
        &self.brand
    }

    fn readiness(&self) -> &Arc<ServiceReadiness> {
        &self.readiness
    }

    fn begin_shutdown(&self) {
        if self.shutdown_begun.swap(true, Ordering::AcqRel) {
            return;
        }
        self.begin_shutdowns.fetch_add(1, Ordering::AcqRel);
        self.shutdown_events
            .lock()
            .unwrap()
            .push(ShutdownEvent::StaticBegin);
        if self.block_begin_return.load(Ordering::Acquire) {
            self.begin_return_entered.store(true, Ordering::Release);
            self.begin_return_changed.notify_waiters();
            let mut released = self.begin_return_released.lock().unwrap();
            while !*released {
                released = self.begin_return_release.wait(released).unwrap();
            }
        }
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.shutdowns.fetch_add(1, Ordering::AcqRel);
            self.shutdown_retentions.lock().unwrap().clear();
            self.shutdown_events
                .lock()
                .unwrap()
                .push(ShutdownEvent::StaticFinish);
        })
    }
}

impl FakeStaticResources {
    fn release_retention_during_shutdown(&self, retention: GenerationRetention) {
        self.shutdown_retentions.lock().unwrap().push(retention);
    }

    async fn wait_for_begin_return_block(&self) {
        loop {
            let changed = self.begin_return_changed.notified();
            if self.begin_return_entered.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    fn release_begin_return(&self) {
        *self.begin_return_released.lock().unwrap() = true;
        self.begin_return_release.notify_all();
    }
}

struct BlockingStaticResources {
    readiness: Arc<ServiceReadiness>,
    brand: StaticResourceBrand,
    begin_shutdowns: AtomicUsize,
    shutdown_begun: AtomicBool,
    shutdowns: AtomicUsize,
    completions: AtomicUsize,
    entered: Notify,
    completed: Notify,
    release: Semaphore,
}

impl Default for BlockingStaticResources {
    fn default() -> Self {
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ingress_started();
        Self {
            readiness,
            brand: StaticResourceBrand::new(),
            begin_shutdowns: AtomicUsize::new(0),
            shutdown_begun: AtomicBool::new(false),
            shutdowns: AtomicUsize::new(0),
            completions: AtomicUsize::new(0),
            entered: Notify::new(),
            completed: Notify::new(),
            release: Semaphore::new(0),
        }
    }
}

impl StaticResources for BlockingStaticResources {
    fn brand(&self) -> &StaticResourceBrand {
        &self.brand
    }

    fn readiness(&self) -> &Arc<ServiceReadiness> {
        &self.readiness
    }

    fn begin_shutdown(&self) {
        if !self.shutdown_begun.swap(true, Ordering::AcqRel) {
            self.begin_shutdowns.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.shutdowns.fetch_add(1, Ordering::AcqRel);
            self.entered.notify_waiters();
            let permit = self
                .release
                .acquire()
                .await
                .expect("semaphore remains open");
            permit.forget();
            self.completions.fetch_add(1, Ordering::AcqRel);
            self.completed.notify_waiters();
        })
    }
}

impl BlockingStaticResources {
    async fn wait_until_entered(&self) {
        loop {
            let entered = self.entered.notified();
            if self.shutdowns.load(Ordering::Acquire) != 0 {
                return;
            }
            entered.await;
        }
    }

    async fn wait_until_completed(&self) {
        loop {
            let completed = self.completed.notified();
            if self.completions.load(Ordering::Acquire) != 0 {
                return;
            }
            completed.await;
        }
    }
}

#[derive(Default)]
struct FakeSource {
    candidates: Mutex<VecDeque<FakeCandidate>>,
    calls: AtomicUsize,
}

enum FakeCandidate {
    Text(String),
    Compiled(Box<CompiledConfig>),
}

impl FakeSource {
    fn push(&self, config: String) {
        self.candidates
            .lock()
            .unwrap()
            .push_back(FakeCandidate::Text(config));
    }

    fn push_compiled(&self, compiled: CompiledConfig) {
        self.candidates
            .lock()
            .unwrap()
            .push_back(FakeCandidate::Compiled(Box::new(compiled)));
    }
}

impl CandidateSource for FakeSource {
    fn load_latest(
        &self,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<CompiledConfig, RuntimeError>> {
        Box::pin(async move {
            cancellation.check()?;
            self.calls.fetch_add(1, Ordering::AcqRel);
            let candidate = self
                .candidates
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| RuntimeError::CandidateSource("no fake config queued".into()))?;
            match candidate {
                FakeCandidate::Text(text) => compile(&text).map_err(RuntimeError::CandidateSource),
                FakeCandidate::Compiled(compiled) => Ok(*compiled),
            }
        })
    }
}

struct FakeActivator {
    static_fingerprint: crate::config::StaticFingerprint,
    static_resource_brand: StaticResourceBrand,
    calls: AtomicUsize,
    entered: AtomicUsize,
    entered_changed: Notify,
    release: Notify,
    block_next: AtomicBool,
    fail_next: AtomicBool,
    reject_publication_next: AtomicBool,
    panic_cleanup_next: AtomicBool,
    block_commit_next: AtomicBool,
    owners: Mutex<Vec<Arc<FakeOwner>>>,
    cleanup_events: Arc<Mutex<Vec<CleanupReason>>>,
    shutdown_events: Mutex<Option<Arc<Mutex<Vec<ShutdownEvent>>>>>,
}

impl FakeActivator {
    fn new(
        static_fingerprint: crate::config::StaticFingerprint,
        static_resource_brand: StaticResourceBrand,
    ) -> Self {
        Self {
            static_fingerprint,
            static_resource_brand,
            calls: AtomicUsize::new(0),
            entered: AtomicUsize::new(0),
            entered_changed: Notify::new(),
            release: Notify::new(),
            block_next: AtomicBool::new(false),
            fail_next: AtomicBool::new(false),
            reject_publication_next: AtomicBool::new(false),
            panic_cleanup_next: AtomicBool::new(false),
            block_commit_next: AtomicBool::new(false),
            owners: Mutex::new(Vec::new()),
            cleanup_events: Arc::new(Mutex::new(Vec::new())),
            shutdown_events: Mutex::new(None),
        }
    }

    async fn wait_until_entered(&self, expected: usize) {
        loop {
            let changed = self.entered_changed.notified();
            if self.entered.load(Ordering::Acquire) >= expected {
                return;
            }
            changed.await;
        }
    }

    fn owner(&self, index: usize) -> Arc<FakeOwner> {
        self.owners.lock().unwrap()[index].clone()
    }

    fn observe_static_shutdown(&self, events: Arc<Mutex<Vec<ShutdownEvent>>>) {
        *self.shutdown_events.lock().unwrap() = Some(events);
    }
}

impl CandidateActivator for FakeActivator {
    fn static_resource_brand(&self) -> &StaticResourceBrand {
        &self.static_resource_brand
    }

    fn static_fingerprint(&self) -> &crate::config::StaticFingerprint {
        &self.static_fingerprint
    }

    fn activate(
        &self,
        id: GenerationId,
        plan: crate::config::ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<ActivatedGeneration, RuntimeError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let owner = Arc::new(FakeOwner {
                cleanup_events: Some(self.cleanup_events.clone()),
                shutdown_events: self.shutdown_events.lock().unwrap().clone(),
                ..FakeOwner::default()
            });
            owner.reject_publication.store(
                self.reject_publication_next.swap(false, Ordering::AcqRel),
                Ordering::Release,
            );
            owner.panic_cleanup.store(
                self.panic_cleanup_next.swap(false, Ordering::AcqRel),
                Ordering::Release,
            );
            owner.block_commit.store(
                self.block_commit_next.swap(false, Ordering::AcqRel),
                Ordering::Release,
            );
            self.owners.lock().unwrap().push(owner.clone());
            let entered = self.entered.fetch_add(1, Ordering::AcqRel) + 1;
            self.entered_changed.notify_waiters();

            if self.block_next.swap(false, Ordering::AcqRel) {
                tokio::select! {
                    _ = self.release.notified() => {}
                    _ = cancellation.cancelled() => {
                        owner.cleanup(CleanupReason::CandidateRejected).await;
                        return Err(RuntimeError::ActivationCancelled);
                    }
                }
            }
            if let Err(error) = cancellation.check() {
                owner.cleanup(CleanupReason::CandidateRejected).await;
                return Err(error);
            }
            if self.fail_next.swap(false, Ordering::AcqRel) {
                owner.cleanup(CleanupReason::CandidateRejected).await;
                return Err(RuntimeError::CandidateActivation(format!(
                    "fake activation {entered} failed"
                )));
            }

            let standalone = crate::standalone::UnboundStandaloneGenerationPlan::compile(&plan, id)
                .map_err(|error| RuntimeError::CandidateActivation(error.to_string()))?
                .into_bound_for_runtime_test();
            let snapshot = Arc::new(EmptySnapshot);
            Ok(ActivatedGeneration {
                standalone,
                request_timeout: plan.request_timeout,
                max_content_decoding_expansion_ratio: plan.max_content_decoding_expansion_ratio,
                resource_plan: plan.resource_plan,
                egress: snapshot.clone(),
                authorization: snapshot.clone(),
                credentials: snapshot.clone(),
                observation: snapshot.clone(),
                safety: snapshot,
                owner,
            })
        })
    }
}

fn config(request_timeout: &str, bind: &str, max_retiring_generations: usize) -> String {
    format!(
        r#"
schema_version = 3

[service]
request_timeout = "{request_timeout}"
max_retiring_generations = {max_retiring_generations}

[listeners.explicit_http]
bind = "{bind}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#
    )
}

fn compile(text: &str) -> Result<CompiledConfig, String> {
    compile_config_text(ConfigTextInput {
        text,
        source_path: Path::new("/tmp/acl-proxy.toml"),
        config_root: Path::new("/tmp"),
    })
    .map_err(|error| error.to_string())
}

async fn runtime_fixture(
    initial: &str,
) -> (
    Arc<Runtime>,
    CompiledConfig,
    Arc<FakeSource>,
    Arc<FakeActivator>,
    Arc<FakeStaticResources>,
) {
    let compiled = compile(initial).expect("compile initial config");
    let source = Arc::new(FakeSource::default());
    let static_resources = Arc::new(FakeStaticResources::default());
    let activator = Arc::new(FakeActivator::new(
        compiled.static_fingerprint.clone(),
        static_resources.brand.clone(),
    ));
    activator.observe_static_shutdown(static_resources.shutdown_events.clone());
    let static_ownership = StaticOwnership::new(
        compiled.static_config.clone(),
        compiled.static_fingerprint.clone(),
        static_resources.clone(),
    );
    let runtime = Runtime::new(static_ownership, source.clone(), activator.clone())
        .await
        .expect("matching runtime construction");
    (runtime, compiled, source, activator, static_resources)
}

#[tokio::test]
async fn webhook_delivery_resources_end_before_callback_wait() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (body_sender, body_receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        let mut scratch = [0u8; 4096];
        let (head_end, content_length) = loop {
            let read = stream.read(&mut scratch).await.unwrap();
            assert_ne!(read, 0, "webhook request ended before its complete head");
            wire.extend_from_slice(&scratch[..read]);
            if let Some(head_end) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
                let head_end = head_end + 4;
                let head = std::str::from_utf8(&wire[..head_end]).unwrap();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length: ")
                            .map(|value| value.parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (head_end, content_length);
            }
        };
        while wire.len() - head_end < content_length {
            let read = stream.read(&mut scratch).await.unwrap();
            assert_ne!(read, 0, "webhook request body ended early");
            wire.extend_from_slice(&scratch[..read]);
        }
        body_sender
            .send(wire[head_end..head_end + content_length].to_vec())
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    let destination = DestinationGuard::with_sources(
        DestinationFacts::for_test([], None, None, 16).unwrap(),
        Arc::new(FixedDestinationResolver(endpoint)),
        Arc::new(EmptyLocalAddressSource),
    );
    let webhook_runtime = WebhookAuthorizationRuntime::for_test_with_destination(
        Some("http://control.test/_acl/external-auth/callback"),
        destination,
    );
    let authorization_plan = AuthorizationPlan {
        internal_context_headers: vec![],
        callback: Some(AuthorizationCallbackPlan {
            resume_token_ttl: Duration::from_secs(5),
            max_pending_operations: PendingOperationLimit::try_new(1).unwrap(),
        }),
        providers: std::collections::BTreeMap::from([(
            "webhook".to_string(),
            AuthorizationProviderPlan::Webhook(WebhookProviderPlan {
                url: format!("http://provider.test:{}/authorize", endpoint.port()),
                timeout: Duration::from_secs(5),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: vec![],
                max_request_bytes: 8192,
                max_response_bytes: 4096,
                outputs: std::collections::BTreeMap::new(),
                tls: None,
            }),
        )]),
    };
    let provider_registry = ProviderRegistry::from_names(["webhook".to_string()]);
    let provider = provider_registry.get("webhook").unwrap();
    let authorization = ProductAuthorizationSnapshot::activate(
        authorization_plan,
        provider_registry,
        webhook_runtime.clone(),
        ActivationCancellation::new_for_test(),
    )
    .await
    .unwrap();
    let (authorization, _, owners) = authorization.into_parts();
    assert!(owners.is_empty());

    let compiled = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    let standalone = crate::standalone::UnboundStandaloneGenerationPlan::compile(
        &compiled.reloadable_plan,
        GenerationId::new(1),
    )
    .unwrap()
    .into_bound_for_runtime_test();
    let empty = Arc::new(EmptySnapshot);
    let generation = Arc::new(Generation::from_activated(
        GenerationId::new(1),
        ActivatedGeneration {
            standalone,
            request_timeout: Duration::from_secs(30),
            max_content_decoding_expansion_ratio: 128,
            resource_plan: compiled.reloadable_plan.resource_plan.clone(),
            egress: empty.clone(),
            authorization: Arc::new(authorization),
            credentials: empty.clone(),
            observation: empty.clone(),
            safety: empty,
            owner: Arc::new(FakeOwner::default()),
        },
    ));
    assert_eq!(
        generation.standalone().snapshot_lease().generation().get(),
        1
    );
    assert!(generation
        .standalone()
        .snapshot_lease()
        .owns(generation.standalone().identity()));
    let lease = generation.try_lease().unwrap();
    let body_guard = WireBodyPool::new(2 * 1024 * 1024, 2 * 1024 * 1024).begin_for_test(
        512 * 1024,
        WireBodyQuotaKey::from_peer("192.0.2.10".parse().unwrap(), |_| false),
    );
    let request = ProviderRequest {
        request_id: "request-1",
        url: "https://example.test/resource",
        method: "GET",
        client_ip: "192.0.2.10",
        headers: None,
        body: None,
    };
    let dispatch = lease.dispatch_authorization(
        provider,
        "rule-1",
        request,
        &body_guard,
        tokio::time::Instant::now() + Duration::from_secs(5),
    );
    tokio::pin!(dispatch);
    let body = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut dispatch => panic!("dispatch completed before callback"),
            body = body_receiver => body.unwrap(),
        }
    })
    .await
    .expect("webhook request reaches provider");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("webhook provider closes after acknowledgement")
        .unwrap();

    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let encoded = value["resumeToken"].as_str().unwrap().as_bytes();
    let encoded: [u8; 43] = encoded.try_into().unwrap();
    let digest = ResumeTokenDigest::from_encoded(&encoded);
    let claim = match webhook_runtime.pending_store().try_claim(digest).unwrap() {
        CallbackClaimResult::Claimed(claim) => claim,
        CallbackClaimResult::Expired(_) => panic!("fresh callback token expired"),
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut dispatch => panic!("dispatch completed before claimed callback"),
            _ = claim.payload().wait_for_delivery_teardown() => {}
        }
    })
    .await
    .expect("delivery teardown precedes callback parsing");
    assert_eq!(webhook_runtime.transport_counts().live_deliveries, 0);
    let payload = claim.complete().unwrap();
    assert!(payload.complete(Ok(ProviderDecision::Deny)));

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), dispatch)
            .await
            .expect("callback completion releases dispatch")
            .unwrap(),
        crate::authorization::AuthorizationDecision::Deny
    ));
    assert_eq!(webhook_runtime.pending_store().counts().occupancy, 0);

    webhook_runtime.begin_shutdown(None);
    let rejected = lease
        .dispatch_authorization(
            provider,
            "rule-after-shutdown",
            ProviderRequest {
                request_id: "request-after-shutdown",
                url: "https://example.test/resource",
                method: "GET",
                client_ip: "192.0.2.10",
                headers: None,
                body: None,
            },
            &body_guard,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await;
    assert!(matches!(
        rejected,
        Err(crate::authorization::AuthorizationDispatchError::Webhook(
            crate::authorization::webhook::runtime::WebhookDispatchError::AdmissionClosed
        ))
    ));
    assert_eq!(webhook_runtime.pending_store().counts().occupancy, 0);
    webhook_runtime.wait_until_drained().await;
}

#[tokio::test]
async fn cross_wired_activator_is_rejected_at_runtime_construction() {
    let owned = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    let crossed = compile(&config("30s", "127.0.0.1:9999", 2)).unwrap();
    let static_resources = Arc::new(FakeStaticResources::default());
    let readiness = static_resources.readiness.clone();
    let static_ownership = StaticOwnership::new(
        owned.static_config,
        owned.static_fingerprint,
        static_resources.clone(),
    );
    let source = Arc::new(FakeSource::default());
    let activator: Arc<dyn CandidateActivator> = Arc::new(FakeActivator::new(
        crossed.static_fingerprint,
        static_resources.brand.clone(),
    ));

    let construction = Runtime::new(static_ownership, source.clone(), activator.clone());
    assert!(!readiness.is_ready());
    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    let result = construction.await;

    assert!(matches!(
        result,
        Err(RuntimeError::ActivatorStaticFingerprintMismatch)
    ));
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert!(!readiness.is_ready());
    assert_eq!(Arc::strong_count(&static_resources), 1);
    assert_eq!(Arc::strong_count(&source), 1);
    assert_eq!(Arc::strong_count(&activator), 1);
}

#[tokio::test]
async fn same_config_independent_static_resource_owner_is_rejected() {
    let owned = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    let static_resources = Arc::new(FakeStaticResources::default());
    let static_ownership = StaticOwnership::new(
        owned.static_config,
        owned.static_fingerprint.clone(),
        static_resources.clone(),
    );
    let source = Arc::new(FakeSource::default());
    let activator: Arc<dyn CandidateActivator> = Arc::new(FakeActivator::new(
        owned.static_fingerprint,
        StaticResourceBrand::new(),
    ));

    let result = Runtime::new(static_ownership, source, activator).await;

    assert!(matches!(
        result,
        Err(RuntimeError::ActivatorStaticResourceMismatch)
    ));
    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn claimed_static_fingerprint_mismatch_shuts_down_without_retention() {
    let owned = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    let crossed = compile(&config("30s", "127.0.0.1:9999", 2)).unwrap();
    let static_resources = Arc::new(FakeStaticResources::default());
    let activator: Arc<dyn CandidateActivator> = Arc::new(FakeActivator::new(
        owned.static_fingerprint.clone(),
        static_resources.brand.clone(),
    ));
    let static_ownership = StaticOwnership::new(
        owned.static_config,
        crossed.static_fingerprint,
        static_resources.clone(),
    );
    let source = Arc::new(FakeSource::default());

    let result = Runtime::new(static_ownership, source.clone(), activator.clone()).await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("false compiled fingerprint claim must be rejected"),
    };

    assert_eq!(error, RuntimeError::StaticOwnershipFingerprintMismatch);
    assert_eq!(
        error.to_string(),
        "claimed static configuration fingerprint does not match canonical configuration"
    );
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(Arc::strong_count(&static_resources), 1);
    assert_eq!(Arc::strong_count(&source), 1);
    assert_eq!(Arc::strong_count(&activator), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn non_utf8_static_path_derivation_failure_shuts_down_without_retention() {
    let mut owned = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    owned.static_config.config_root = OsString::from_vec(vec![b'/', 0xff]).into();
    let static_resources = Arc::new(FakeStaticResources::default());
    let activator: Arc<dyn CandidateActivator> = Arc::new(FakeActivator::new(
        owned.static_fingerprint.clone(),
        static_resources.brand.clone(),
    ));
    let static_ownership = StaticOwnership::new(
        owned.static_config,
        owned.static_fingerprint,
        static_resources.clone(),
    );
    let source = Arc::new(FakeSource::default());

    let result = Runtime::new(static_ownership, source.clone(), activator.clone()).await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("non-UTF-8 static path must reject construction"),
    };

    assert_eq!(error, RuntimeError::StaticFingerprintDerivationFailed);
    assert_eq!(
        error.to_string(),
        "static configuration fingerprint could not be derived"
    );
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(Arc::strong_count(&static_resources), 1);
    assert_eq!(Arc::strong_count(&source), 1);
    assert_eq!(Arc::strong_count(&activator), 1);
}

#[tokio::test]
async fn unpolled_cross_wired_construction_still_completes_static_shutdown() {
    let BlockedConstruction {
        construction,
        static_resources,
        readiness,
        source,
        activator,
    } = blocked_cross_wired_construction();

    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert!(!readiness.is_ready());
    static_resources.wait_until_entered().await;
    drop(construction);
    release_blocked_static_shutdown(&static_resources).await;

    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(static_resources.completions.load(Ordering::Acquire), 1);
    assert_eq!(Arc::strong_count(&static_resources), 1);
    assert_eq!(Arc::strong_count(&source), 1);
    assert_eq!(Arc::strong_count(&activator), 1);
}

#[tokio::test]
async fn abort_before_first_construction_poll_still_completes_static_shutdown() {
    let BlockedConstruction {
        construction,
        static_resources,
        readiness,
        source,
        activator,
    } = blocked_cross_wired_construction();
    let poll_gate = Arc::new(Notify::new());
    let construction_task = tokio::spawn({
        let poll_gate = poll_gate.clone();
        async move {
            poll_gate.notified().await;
            construction.await
        }
    });

    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert!(!readiness.is_ready());
    static_resources.wait_until_entered().await;
    construction_task.abort();
    match construction_task.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("construction task must be cancelled"),
    }
    release_blocked_static_shutdown(&static_resources).await;

    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(static_resources.completions.load(Ordering::Acquire), 1);
    assert_eq!(Arc::strong_count(&static_resources), 1);
    assert_eq!(Arc::strong_count(&source), 1);
    assert_eq!(Arc::strong_count(&activator), 1);
    assert_eq!(Arc::strong_count(&poll_gate), 1);
}

#[test]
fn rejected_construction_outside_tokio_cleans_inline_when_polled() {
    let owned = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    let crossed = compile(&config("30s", "127.0.0.1:9999", 2)).unwrap();
    let static_resources = Arc::new(FakeStaticResources::default());
    let readiness = static_resources.readiness.clone();
    let static_ownership = StaticOwnership::new(
        owned.static_config,
        owned.static_fingerprint,
        static_resources.clone(),
    );
    let source = Arc::new(FakeSource::default());
    let activator: Arc<dyn CandidateActivator> = Arc::new(FakeActivator::new(
        crossed.static_fingerprint,
        static_resources.brand.clone(),
    ));

    let construction = Runtime::new(static_ownership, source.clone(), activator.clone());
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 0);
    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert!(!readiness.is_ready());

    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = executor.block_on(construction);

    assert!(matches!(
        result,
        Err(RuntimeError::ActivatorStaticFingerprintMismatch)
    ));
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(Arc::strong_count(&static_resources), 1);
    assert_eq!(Arc::strong_count(&source), 1);
    assert_eq!(Arc::strong_count(&activator), 1);
}

struct BlockedConstruction {
    construction: BoxFuture<'static, Result<Arc<Runtime>, RuntimeError>>,
    static_resources: Arc<BlockingStaticResources>,
    readiness: Arc<ServiceReadiness>,
    source: Arc<FakeSource>,
    activator: Arc<dyn CandidateActivator>,
}

fn blocked_cross_wired_construction() -> BlockedConstruction {
    let owned = compile(&config("30s", "127.0.0.1:8881", 2)).unwrap();
    let crossed = compile(&config("30s", "127.0.0.1:9999", 2)).unwrap();
    let static_resources = Arc::new(BlockingStaticResources::default());
    let readiness = static_resources.readiness.clone();
    let static_ownership = StaticOwnership::new(
        owned.static_config,
        owned.static_fingerprint,
        static_resources.clone(),
    );
    let source = Arc::new(FakeSource::default());
    let activator: Arc<dyn CandidateActivator> = Arc::new(FakeActivator::new(
        crossed.static_fingerprint,
        static_resources.brand.clone(),
    ));
    let construction = Runtime::new(static_ownership, source.clone(), activator.clone());
    BlockedConstruction {
        construction,
        static_resources,
        readiness,
        source,
        activator,
    }
}

async fn release_blocked_static_shutdown(static_resources: &Arc<BlockingStaticResources>) {
    static_resources.release.add_permits(1);
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        static_resources.wait_until_completed(),
    )
    .await
    .expect("detached construction cleanup completes");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while Arc::strong_count(static_resources) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("construction cleanup releases static resources");
}

async fn wait_for_retiring(runtime: &Runtime, expected: usize) {
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if runtime.retiring_generations() == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await;
    if result.is_err() {
        panic!(
            "retiring generation count did not reach {expected}; current={}",
            runtime.retiring_generations()
        );
    }
}

#[tokio::test]
async fn initial_publish_installs_one_ready_generation() {
    let (runtime, initial, _source, activator, _static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;

    let id = runtime.start(initial).await.expect("initial publish");

    assert_eq!(id.get(), 1);
    assert_eq!(runtime.lifecycle(), LifecycleState::Running);
    assert!(runtime.is_ready());
    assert_eq!(runtime.active_generation_id(), Some(id));
    assert_eq!(activator.owner(0).commits.load(Ordering::Acquire), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_publication_does_not_mark_ready_before_commit() {
    let (runtime, initial, _source, activator, _static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    activator.block_commit_next.store(true, Ordering::Release);

    let start_runtime = runtime.clone();
    let start = tokio::spawn(async move { start_runtime.start(initial).await });
    activator.wait_until_entered(1).await;
    let owner = activator.owner(0);
    owner.wait_for_commit().await;

    assert_eq!(runtime.lifecycle(), LifecycleState::Publishing);
    assert!(!runtime.is_ready());

    owner.release_commit();
    start.await.unwrap().unwrap();
    assert!(runtime.is_ready());
}

#[tokio::test]
async fn initial_static_fingerprint_mismatch_rejects_before_activation() {
    let (runtime, _initial, _source, activator, _static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    let crossed = compile(&config("30s", "127.0.0.1:9999", 2)).unwrap();

    assert_eq!(
        runtime.start(crossed).await,
        Err(RuntimeError::StaticFingerprintChanged)
    );
    assert_eq!(activator.calls.load(Ordering::Acquire), 0);
    assert_eq!(runtime.lifecycle(), LifecycleState::Starting);
    assert_eq!(runtime.active_generation_id(), None);
}

#[tokio::test]
async fn forged_initial_fingerprint_cannot_hide_cross_wired_static_config() {
    let (runtime, mut initial, _source, activator, _static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    let crossed = compile(&config("30s", "127.0.0.1:9999", 2)).unwrap();
    initial.static_config = crossed.static_config;

    assert_eq!(
        runtime.start(initial).await,
        Err(RuntimeError::StaticFingerprintChanged)
    );
    assert_eq!(activator.calls.load(Ordering::Acquire), 0);
    assert_eq!(runtime.lifecycle(), LifecycleState::Starting);
    assert_eq!(runtime.active_generation_id(), None);
}

#[tokio::test]
async fn forged_reload_fingerprint_cannot_hide_cross_wired_static_config() {
    let initial_text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) =
        runtime_fixture(&initial_text).await;
    let claimed = initial.static_fingerprint.clone();
    let first = runtime.start(initial).await.unwrap();
    let mut crossed = compile(&config("31s", "127.0.0.1:9999", 2)).unwrap();
    crossed.static_fingerprint = claimed;
    source.push_compiled(crossed);

    assert_eq!(
        runtime.trigger_reload().await.unwrap_err(),
        RuntimeError::StaticFingerprintChanged
    );
    assert_eq!(runtime.active_generation_id(), Some(first));
    assert_eq!(activator.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn reload_is_atomic_and_static_fingerprint_rejection_preserves_active() {
    let initial_text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) =
        runtime_fixture(&initial_text).await;
    let first = runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();

    source.push(config("31s", "127.0.0.1:8881", 2));
    let ReloadTriggerResult::Completed {
        generation: second, ..
    } = runtime.trigger_reload().await.unwrap()
    else {
        panic!("reload unexpectedly coalesced");
    };
    assert_ne!(second, first);
    assert_eq!(old_lease.id(), first);
    assert_eq!(runtime.active_generation_id(), Some(second));

    source.push(config("32s", "127.0.0.1:9999", 2));
    assert_eq!(
        runtime.trigger_reload().await.unwrap_err(),
        RuntimeError::StaticFingerprintChanged
    );
    assert_eq!(runtime.active_generation_id(), Some(second));
    assert_eq!(activator.calls.load(Ordering::Acquire), 2);
    drop(old_lease);
}

#[tokio::test]
async fn failed_activation_preserves_the_published_generation() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    let first = runtime.start(initial).await.unwrap();
    activator.fail_next.store(true, Ordering::Release);
    source.push(config("31s", "127.0.0.1:8881", 2));

    assert!(matches!(
        runtime.trigger_reload().await,
        Err(RuntimeError::CandidateActivation(_))
    ));
    assert_eq!(runtime.active_generation_id(), Some(first));
    assert!(runtime.is_ready());
    assert_eq!(
        activator
            .owner(1)
            .candidate_cleanups
            .load(Ordering::Acquire),
        1
    );
}

#[tokio::test]
async fn concurrent_reload_triggers_coalesce_and_reread_latest() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 2));
    source.push(config("32s", "127.0.0.1:8881", 2));
    activator.block_next.store(true, Ordering::Release);

    let first_runtime = runtime.clone();
    let first = tokio::spawn(async move { first_runtime.trigger_reload().await });
    activator.wait_until_entered(2).await;
    assert_eq!(
        runtime.trigger_reload().await.unwrap(),
        ReloadTriggerResult::Coalesced
    );
    activator.release.notify_waiters();

    let ReloadTriggerResult::Completed {
        attempts,
        generation,
    } = first.await.unwrap().unwrap()
    else {
        panic!("reload owner unexpectedly coalesced");
    };
    assert_eq!(attempts, 2);
    assert_eq!(generation.get(), 3);
    assert_eq!(runtime.active_generation_id(), Some(generation));
    assert_eq!(source.calls.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn retiring_ceiling_rejects_before_loading_or_activating() {
    let text = config("30s", "127.0.0.1:8881", 1);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    let first_lease = runtime.lease().await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 1));
    source.push(config("32s", "127.0.0.1:8881", 1));
    runtime.trigger_reload().await.unwrap();
    wait_for_retiring(&runtime, 1).await;

    assert_eq!(
        runtime.trigger_reload().await.unwrap_err(),
        RuntimeError::RetiringGenerationLimit { limit: 1 }
    );
    assert_eq!(source.calls.load(Ordering::Acquire), 1);
    assert_eq!(activator.calls.load(Ordering::Acquire), 2);

    drop(first_lease);
    wait_for_retiring(&runtime, 0).await;
    runtime.trigger_reload().await.unwrap();
    assert_eq!(source.calls.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn old_lease_delays_retirement_cleanup_and_releases_it_once() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();
    let old_owner = activator.owner(0);
    source.push(config("31s", "127.0.0.1:8881", 2));

    runtime.trigger_reload().await.unwrap();
    wait_for_retiring(&runtime, 1).await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 0);
    assert_eq!(
        old_owner.events(),
        vec![OwnerEvent::RetirementStarted(CleanupReason::Retired)]
    );

    drop(old_lease);
    wait_for_retiring(&runtime, 0).await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
    assert_eq!(
        old_owner.events(),
        vec![
            OwnerEvent::RetirementStarted(CleanupReason::Retired),
            OwnerEvent::Cleanup(CleanupReason::Retired),
        ]
    );
    tokio::task::yield_now().await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
    assert_eq!(old_owner.events().len(), 2);
}

#[tokio::test]
async fn upgraded_stream_does_not_pin_retiring_generation() {
    let initial_text = config("30s", "127.0.0.1:8881", 1);
    let (runtime, initial, source, activator, _static_resources) =
        runtime_fixture(&initial_text).await;
    runtime.start(initial).await.unwrap();

    let old_lease = runtime.lease().await.unwrap();
    let old_owner = activator.owner(0);
    let upgrades =
        UpgradeRuntime::try_new(UpgradeRuntimeLimits::new(1, 8, 2, Duration::from_secs(60)))
            .unwrap();
    let (committed_tx, committed_rx) = oneshot::channel();
    upgrades
        .try_spawn_handshake(
            UpgradeAllocation::from_compiled_rule(0, Some(0)).unwrap(),
            move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(std::future::pending::<()>, |_| async {}),
                            |snapshot| async move {
                                assert!(snapshot.wire_redaction().is_none());
                                Ok(UpgradeRelayPair::new(
                                    std::future::pending::<UpgradeTerminalCause>(),
                                    std::future::pending::<UpgradeTerminalCause>(),
                                ))
                            },
                        ),
                    )
                    .unwrap();
                committed_tx.send(entry).unwrap();
            },
        )
        .unwrap();
    let entry = committed_rx.await.unwrap();
    drop(old_lease);

    for timeout in ["31s", "32s", "33s"] {
        source.push(config(timeout, "127.0.0.1:8881", 1));
        runtime.trigger_reload().await.unwrap();
        wait_for_retiring(&runtime, 0).await;
    }

    assert_eq!(runtime.active_generation_id().unwrap().get(), 4);
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
    assert_eq!(upgrades.counts().committed, 1);

    upgrades
        .shutdown_and_wait(Some(tokio::time::Instant::now()))
        .await;
    entry.wait_closed().await;
    assert_eq!(upgrades.counts().committed, 0);
}

#[tokio::test]
async fn operation_retention_derived_after_retirement_keeps_exact_generation_alive() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    let first = runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();
    let old_owner = activator.owner(0);
    source.push(config("31s", "127.0.0.1:8881", 2));

    runtime.trigger_reload().await.unwrap();
    wait_for_retiring(&runtime, 1).await;
    let retained = old_lease.retain_for_operation().unwrap();
    assert_eq!(retained.id(), first);
    drop(old_lease);
    tokio::task::yield_now().await;
    assert_eq!(runtime.retiring_generations(), 1);
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 0);

    drop(retained);
    wait_for_retiring(&runtime, 0).await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn pending_and_claimed_callback_retention_hold_the_exact_retiring_generation() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();
    let old_owner = activator.owner(0);
    let retention = old_lease.retain_for_operation().unwrap();
    let start = tokio::time::Instant::now();
    let deadline = PendingDeadline::earliest(
        start,
        start + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(20),
    );
    let store = PendingCapabilityStore::new();
    let admission = store
        .try_admit(
            PendingOperationLimit::try_new(1).unwrap(),
            deadline,
            retention,
        )
        .unwrap();
    let digest = admission.token().digest();
    let (_token, _handle) = admission.into_parts();

    source.push(config("31s", "127.0.0.1:8881", 2));
    runtime.trigger_reload().await.unwrap();
    wait_for_retiring(&runtime, 1).await;
    drop(old_lease);
    tokio::task::yield_now().await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 0);

    let CallbackClaimResult::Claimed(claim) = store
        .try_claim_at(digest, tokio::time::Instant::now())
        .unwrap()
    else {
        panic!("live callback retention unexpectedly expired");
    };
    tokio::task::yield_now().await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 0);

    drop(claim.complete_at(tokio::time::Instant::now()).unwrap());
    wait_for_retiring(&runtime, 0).await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
    assert_eq!(store.counts().occupancy, 0);
}

#[tokio::test]
async fn cleanup_panic_cannot_pin_retiring_count_or_shutdown() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, _source, activator, static_resources) = runtime_fixture(&text).await;
    activator.panic_cleanup_next.store(true, Ordering::Release);
    runtime.start(initial).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), runtime.shutdown())
        .await
        .expect("cleanup panic must not deadlock shutdown");

    assert_eq!(runtime.retiring_generations(), 0);
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn retirement_start_panic_cannot_interrupt_publication_or_shutdown() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, static_resources) = runtime_fixture(&text).await;
    let first = runtime.start(initial).await.unwrap();
    let old_owner = activator.owner(0);
    old_owner
        .panic_retirement_started
        .store(true, Ordering::Release);
    source.push(config("31s", "127.0.0.1:8881", 2));

    let ReloadTriggerResult::Completed {
        generation: second, ..
    } = runtime.trigger_reload().await.unwrap()
    else {
        panic!("reload unexpectedly coalesced");
    };
    assert_ne!(second, first);
    assert_eq!(runtime.lifecycle(), LifecycleState::Running);
    assert_eq!(runtime.active_generation_id(), Some(second));
    wait_for_retiring(&runtime, 0).await;
    assert_eq!(
        old_owner.events(),
        vec![OwnerEvent::Cleanup(CleanupReason::Retired)]
    );

    tokio::time::timeout(std::time::Duration::from_secs(1), runtime.shutdown())
        .await
        .expect("retirement-start panic must not deadlock later shutdown");
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn rejected_publication_cleans_candidate_and_preserves_active() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    let first = runtime.start(initial).await.unwrap();
    activator
        .reject_publication_next
        .store(true, Ordering::Release);
    source.push(config("31s", "127.0.0.1:8881", 2));

    assert_eq!(
        runtime.trigger_reload().await.unwrap_err(),
        RuntimeError::CandidateNotLive("fake owner exited".into())
    );
    assert_eq!(runtime.active_generation_id(), Some(first));
    assert_eq!(
        activator
            .owner(1)
            .candidate_cleanups
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(activator.owner(0).commits.load(Ordering::Acquire), 1);
    assert_eq!(
        activator.owner(1).events(),
        vec![OwnerEvent::Cleanup(CleanupReason::CandidateRejected)]
    );
}

#[tokio::test]
async fn completed_retirement_supervisors_are_reaped_incrementally() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();

    for second in 31..51 {
        source.push(config(&format!("{second}s"), "127.0.0.1:8881", 2));
        runtime.trigger_reload().await.unwrap();
        wait_for_retiring(&runtime, 0).await;
    }

    assert!(runtime.retirement_task_count().await <= 1);
}

#[tokio::test]
async fn reload_trigger_at_worker_exit_is_handed_off_without_loss() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 2));
    source.push(config("32s", "127.0.0.1:8881", 2));
    runtime.block_reload_worker_exit();

    let worker_runtime = runtime.clone();
    let worker = tokio::spawn(async move { worker_runtime.trigger_reload().await });
    runtime.wait_for_reload_worker_exit().await;
    assert_eq!(
        runtime.trigger_reload().await.unwrap(),
        ReloadTriggerResult::Coalesced
    );
    runtime.release_reload_worker_exit();

    let ReloadTriggerResult::Completed {
        attempts,
        generation,
    } = worker.await.unwrap().unwrap()
    else {
        panic!("reload worker unexpectedly coalesced");
    };
    assert_eq!(attempts, 2);
    assert_eq!(generation.get(), 3);
    assert_eq!(runtime.active_generation_id(), Some(generation));
    assert_eq!(source.calls.load(Ordering::Acquire), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_waits_until_swapped_generation_publication_commits() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 2));
    activator.block_commit_next.store(true, Ordering::Release);

    let reload_runtime = runtime.clone();
    let reload = tokio::spawn(async move { reload_runtime.trigger_reload().await });
    activator.wait_until_entered(2).await;
    let candidate_owner = activator.owner(1);
    candidate_owner.wait_for_commit().await;
    assert_eq!(runtime.lifecycle(), LifecycleState::Publishing);
    assert_eq!(
        runtime.active_generation_id().map(GenerationId::get),
        Some(2)
    );

    let lease_runtime = runtime.clone();
    let lease = tokio::spawn(async move {
        lease_runtime
            .lease()
            .await
            .map(|generation| generation.id())
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!lease.is_finished(), "lease escaped before commit");

    candidate_owner.release_commit();
    let ReloadTriggerResult::Completed { generation, .. } = reload.await.unwrap().unwrap() else {
        panic!("reload unexpectedly coalesced");
    };
    assert_eq!(lease.await.unwrap(), Some(generation));
    assert_eq!(candidate_owner.commits.load(Ordering::Acquire), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lease_loaded_before_publication_retries_the_committed_generation() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text).await;
    let first = runtime.start(initial).await.unwrap();
    runtime.block_lease_before_acquire();
    runtime.block_publication_exit();

    let lease_runtime = runtime.clone();
    let waiter = tokio::spawn(async move {
        lease_runtime
            .lease()
            .await
            .map(|generation| generation.id())
    });
    runtime.wait_for_lease_before_acquire().await;

    source.push(config("31s", "127.0.0.1:8881", 2));
    let reload_runtime = runtime.clone();
    let reload = tokio::spawn(async move { reload_runtime.trigger_reload().await });
    runtime.wait_for_publication_exit().await;
    let second = runtime.active_generation_id().unwrap();
    assert_ne!(second, first);
    assert_eq!(runtime.lifecycle(), LifecycleState::Running);
    assert_eq!(runtime.retiring_generations(), 1);
    assert!(
        !reload.is_finished(),
        "retirement scheduling must remain gated"
    );

    runtime.release_lease_before_acquire();
    assert_eq!(waiter.await.unwrap(), Some(second));

    runtime.release_publication_exit();
    let ReloadTriggerResult::Completed {
        generation: published,
        ..
    } = reload.await.unwrap().unwrap()
    else {
        panic!("reload unexpectedly coalesced");
    };
    assert_eq!(published, second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lease_acquired_before_validation_retries_the_committed_generation() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text).await;
    let first = runtime.start(initial).await.unwrap();
    runtime.block_lease_before_validation();

    let lease_runtime = runtime.clone();
    let waiter = tokio::spawn(async move {
        lease_runtime
            .lease()
            .await
            .map(|generation| generation.id())
    });
    runtime.wait_for_lease_before_validation().await;

    source.push(config("31s", "127.0.0.1:8881", 2));
    let ReloadTriggerResult::Completed {
        generation: second, ..
    } = runtime.trigger_reload().await.unwrap()
    else {
        panic!("reload unexpectedly coalesced");
    };
    assert_ne!(second, first);
    assert_eq!(runtime.lifecycle(), LifecycleState::Running);
    assert_eq!(runtime.active_generation_id(), Some(second));
    assert_eq!(runtime.retiring_generations(), 1);
    assert!(!waiter.is_finished(), "stale lease escaped validation");

    runtime.release_lease_before_validation();
    assert_eq!(waiter.await.unwrap(), Some(second));
    wait_for_retiring(&runtime, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lease_waiter_wakes_on_shutdown_before_drain_finishes() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, _source, activator, _static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();
    let owner = activator.owner(0);
    runtime.block_lease_before_acquire();

    let lease_runtime = runtime.clone();
    let waiter = tokio::spawn(async move {
        lease_runtime
            .lease()
            .await
            .map(|generation| generation.id())
    });
    runtime.wait_for_lease_before_acquire().await;

    let shutdown_runtime = runtime.clone();
    let shutdown = tokio::spawn(async move { shutdown_runtime.shutdown().await });
    wait_for_retiring(&runtime, 1).await;
    assert_eq!(runtime.lifecycle(), LifecycleState::ShuttingDown);
    assert!(
        !shutdown.is_finished(),
        "old lease must keep shutdown draining"
    );
    assert_eq!(
        owner.events(),
        vec![OwnerEvent::RetirementStarted(CleanupReason::Shutdown)]
    );

    runtime.release_lease_before_acquire();
    assert_eq!(waiter.await.unwrap(), None);
    assert!(
        !shutdown.is_finished(),
        "lease waiter must finish before drain"
    );

    drop(old_lease);
    shutdown.await.unwrap();
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert_eq!(
        owner.events(),
        vec![
            OwnerEvent::RetirementStarted(CleanupReason::Shutdown),
            OwnerEvent::Cleanup(CleanupReason::Shutdown),
        ]
    );
}

#[tokio::test]
async fn new_work_admission_closes_before_generation_drain_and_final_shutdown() {
    let (runtime, initial, _source, _activator, static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    runtime.start(initial).await.unwrap();

    runtime.shutdown().await;
    runtime.shutdown().await;

    let events = static_resources.shutdown_events.lock().unwrap().clone();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0], ShutdownEvent::StaticBegin);
    assert!(
        shutdown_event_index(&events, ShutdownEvent::GenerationRetirementStarted)
            < shutdown_event_index(&events, ShutdownEvent::GenerationCleanup)
    );
    assert!(events.contains(&ShutdownEvent::StaticFinish));
    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert!(!runtime.is_ready());
}

#[tokio::test]
async fn static_shutdown_releases_generation_retention_before_retirement_finishes() {
    let (runtime, initial, _source, _activator, static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    runtime.start(initial).await.unwrap();
    let lease = runtime.lease().await.unwrap();
    static_resources.release_retention_during_shutdown(lease.retain_for_operation().unwrap());
    drop(lease);

    tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
        .await
        .expect("static drain must run while generation retirement is waiting");

    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert_eq!(runtime.retiring_generations(), 0);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_shutdown_callers_close_new_work_admission_once() {
    let (runtime, initial, _source, _activator, static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    runtime.start(initial).await.unwrap();

    let first_runtime = runtime.clone();
    let second_runtime = runtime.clone();
    tokio::join!(first_runtime.shutdown(), second_runtime.shutdown());

    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert!(!runtime.is_ready());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_work_gate_and_publication_serialize_before_shutdown_transition() {
    let (runtime, initial, source, activator, static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2)).await;
    let initial_generation = runtime.start(initial).await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 2));
    static_resources
        .block_begin_return
        .store(true, Ordering::Release);

    let shutdown_runtime = runtime.clone();
    let shutdown = tokio::spawn(async move { shutdown_runtime.shutdown().await });
    static_resources.wait_for_begin_return_block().await;

    assert!(static_resources.shutdown_begun.load(Ordering::Acquire));
    assert_eq!(runtime.lifecycle(), LifecycleState::Running);
    assert_eq!(static_resources.begin_shutdowns.load(Ordering::Acquire), 1);
    assert!(!runtime.is_ready());

    let reload_runtime = runtime.clone();
    let reload = tokio::spawn(async move { reload_runtime.trigger_reload().await });
    activator.wait_until_entered(2).await;
    tokio::task::yield_now().await;
    assert_eq!(runtime.active_generation_id(), Some(initial_generation));
    assert_eq!(activator.owner(1).commits.load(Ordering::Acquire), 0);

    static_resources.release_begin_return();
    shutdown.await.unwrap();
    assert!(matches!(
        reload.await.unwrap(),
        Err(RuntimeError::ShuttingDown | RuntimeError::ActivationCancelled)
    ));
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_wins_blocked_reload_and_cleans_candidate_before_active() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 2));
    activator.block_next.store(true, Ordering::Release);

    let reload_runtime = runtime.clone();
    let reload = tokio::spawn(async move { reload_runtime.trigger_reload().await });
    activator.wait_until_entered(2).await;
    assert_eq!(
        runtime.trigger_reload().await.unwrap(),
        ReloadTriggerResult::Coalesced
    );
    assert!(runtime.has_pending_reload());

    runtime.shutdown().await;

    assert_eq!(
        reload.await.unwrap(),
        Err(RuntimeError::ActivationCancelled)
    );
    assert_eq!(
        *activator.cleanup_events.lock().unwrap(),
        vec![CleanupReason::CandidateRejected, CleanupReason::Shutdown]
    );
    assert!(!runtime.has_pending_reload());
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert!(!runtime.is_ready());
    assert_eq!(runtime.active_generation_id(), None);
    assert_eq!(activator.owner(1).commits.load(Ordering::Acquire), 0);
    let events = static_resources.shutdown_events.lock().unwrap().clone();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0], ShutdownEvent::StaticBegin);
    assert!(
        shutdown_event_index(&events, ShutdownEvent::CandidateCleanup)
            < shutdown_event_index(&events, ShutdownEvent::GenerationRetirementStarted)
    );
    assert!(
        shutdown_event_index(&events, ShutdownEvent::GenerationRetirementStarted)
            < shutdown_event_index(&events, ShutdownEvent::GenerationCleanup)
    );
    assert!(events.contains(&ShutdownEvent::StaticFinish));

    source.push(config("32s", "127.0.0.1:8881", 2));
    assert_eq!(
        runtime.trigger_reload().await,
        Err(RuntimeError::ShuttingDown)
    );
    assert!(!runtime.is_ready());
    assert_eq!(runtime.active_generation_id(), None);
}

#[tokio::test]
async fn shutdown_wins_during_initial_activation_and_prevents_publication() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, _source, activator, static_resources) = runtime_fixture(&text).await;
    activator.block_next.store(true, Ordering::Release);

    let start_runtime = runtime.clone();
    let start = tokio::spawn(async move { start_runtime.start(initial).await });
    activator.wait_until_entered(1).await;
    runtime.shutdown().await;

    assert_eq!(start.await.unwrap(), Err(RuntimeError::ActivationCancelled));
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
    assert!(!runtime.is_ready());
    assert_eq!(runtime.active_generation_id(), None);
    assert_eq!(
        activator
            .owner(0)
            .candidate_cleanups
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(
        *static_resources.shutdown_events.lock().unwrap(),
        vec![
            ShutdownEvent::StaticBegin,
            ShutdownEvent::CandidateCleanup,
            ShutdownEvent::StaticFinish,
        ]
    );
}

#[tokio::test]
async fn publication_winner_is_the_generation_shutdown_drains() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, static_resources) = runtime_fixture(&text).await;
    runtime.start(initial).await.unwrap();
    source.push(config("31s", "127.0.0.1:8881", 2));
    let ReloadTriggerResult::Completed { generation, .. } = runtime.trigger_reload().await.unwrap()
    else {
        panic!("reload unexpectedly coalesced");
    };
    assert_eq!(runtime.active_generation_id(), Some(generation));

    runtime.shutdown().await;

    assert_eq!(activator.owner(0).retirements.load(Ordering::Acquire), 1);
    assert_eq!(activator.owner(1).shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(static_resources.shutdowns.load(Ordering::Acquire), 1);
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
}
