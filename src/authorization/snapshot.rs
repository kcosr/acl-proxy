use std::sync::Arc;

use http::HeaderName;
use tokio::time::Instant;

use super::process::{
    ProcessActivationError, ProcessDecision, ProcessProvider, ProcessRequestError,
};
use super::protocol::ProviderRequest;
use crate::config::v3_compile::{
    AuthorizationPlan, AuthorizationProviderPlan, CompiledProviderFailureMode,
};
use crate::runtime::{
    ActivationCancellation, AuthorizationSnapshot, BoxFuture, CleanupReason, GenerationOwner,
    ProviderIndex, ProviderRegistry,
};
use crate::safety::HttpWireBodyGuard;

pub(crate) struct ProductAuthorizationSnapshot {
    internal_context_headers: Box<[HeaderName]>,
    providers: Box<[ActiveProvider]>,
}

enum ActiveProvider {
    Process(Arc<ProcessProvider>),
}

pub(crate) struct AuthorizationActivation {
    provider_registry: ProviderRegistry,
    snapshot: ProductAuthorizationSnapshot,
    owners: Box<[Arc<dyn GenerationOwner>]>,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorizationProviderMetadata<'snapshot> {
    pub(crate) include_headers: &'snapshot [HeaderName],
    pub(crate) failure_mode: CompiledProviderFailureMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationDecision {
    Allow,
    Deny,
    Pass,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AuthorizationDispatchError {
    #[error("authorization provider index is not active")]
    UnknownProvider,
    #[error("process authorization provider dispatch failed")]
    Process(#[source] ProcessRequestError),
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AuthorizationActivationError {
    #[error("authorization activation was cancelled")]
    Cancelled,
    #[error("authorization callbacks are not supported by this runtime")]
    UnsupportedCallback,
    #[error("authorization provider '{provider}' has a kind not supported by this runtime")]
    UnsupportedProviderKind { provider: String },
    #[error("process authorization provider '{provider}' requires unsupported capabilities")]
    UnsupportedProcessCapabilities { provider: String },
    #[error("process authorization provider '{provider}' could not be activated")]
    ProcessActivation { provider: String },
}

impl ProductAuthorizationSnapshot {
    pub(crate) async fn activate(
        plan: AuthorizationPlan,
        cancellation: ActivationCancellation,
    ) -> Result<AuthorizationActivation, AuthorizationActivationError> {
        if cancellation.is_cancelled() {
            return Err(AuthorizationActivationError::Cancelled);
        }
        if plan.callback.is_some() {
            return Err(AuthorizationActivationError::UnsupportedCallback);
        }
        if let Some((provider, _)) = plan
            .providers
            .iter()
            .find(|(_, plan)| matches!(plan, AuthorizationProviderPlan::Webhook(_)))
        {
            return Err(AuthorizationActivationError::UnsupportedProviderKind {
                provider: provider.clone(),
            });
        }

        let provider_registry = ProviderRegistry::from_names(plan.providers.keys().cloned());
        let mut providers = Vec::with_capacity(provider_registry.len());
        let mut rollback = ActivationRollback::new(provider_registry.len());

        for (name, provider) in plan.providers {
            debug_assert_eq!(
                provider_registry.get(&name).map(ProviderIndex::get),
                Some(providers.len())
            );
            let AuthorizationProviderPlan::Process(process_plan) = provider else {
                unreachable!("unsupported provider kinds were rejected before activation");
            };
            let process =
                match ProcessProvider::activate(process_plan, || cancellation.is_cancelled()).await
                {
                    Ok(process) => process,
                    Err(error) => {
                        let error = map_activation_error(error, &cancellation, &name);
                        rollback.rollback().await;
                        return Err(error);
                    }
                };
            rollback.push(process.clone());
            providers.push(ActiveProvider::Process(process));
        }

        if cancellation.is_cancelled() {
            rollback.rollback().await;
            return Err(AuthorizationActivationError::Cancelled);
        }

        Ok(AuthorizationActivation {
            provider_registry,
            snapshot: Self {
                internal_context_headers: plan.internal_context_headers.into_boxed_slice(),
                providers: providers.into_boxed_slice(),
            },
            owners: rollback.disarm(),
        })
    }

    pub(crate) fn internal_context_headers(&self) -> &[HeaderName] {
        &self.internal_context_headers
    }

    pub(crate) fn provider_metadata(
        &self,
        provider: ProviderIndex,
    ) -> Option<AuthorizationProviderMetadata<'_>> {
        match self.providers.get(provider.get())? {
            ActiveProvider::Process(process) => Some(AuthorizationProviderMetadata {
                include_headers: process.include_headers(),
                failure_mode: process.failure_mode(),
            }),
        }
    }
}

impl AuthorizationSnapshot for ProductAuthorizationSnapshot {
    fn dispatch<'a>(
        &'a self,
        provider: ProviderIndex,
        request: ProviderRequest<'a>,
        guard: HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, AuthorizationDispatchError>> {
        Box::pin(async move {
            let provider = self
                .providers
                .get(provider.get())
                .ok_or(AuthorizationDispatchError::UnknownProvider)?;
            match provider {
                ActiveProvider::Process(process) => process
                    .decide(request, guard, request_deadline)
                    .await
                    .map(AuthorizationDecision::from)
                    .map_err(AuthorizationDispatchError::Process),
            }
        })
    }
}

impl From<ProcessDecision> for AuthorizationDecision {
    fn from(decision: ProcessDecision) -> Self {
        match decision {
            ProcessDecision::Allow => Self::Allow,
            ProcessDecision::Deny => Self::Deny,
            ProcessDecision::Pass => Self::Pass,
        }
    }
}

impl AuthorizationActivation {
    pub(crate) fn provider_registry(&self) -> &ProviderRegistry {
        &self.provider_registry
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductAuthorizationSnapshot,
        ProviderRegistry,
        Box<[Arc<dyn GenerationOwner>]>,
    ) {
        (self.snapshot, self.provider_registry, self.owners)
    }
}

impl std::ops::Deref for AuthorizationActivation {
    type Target = ProductAuthorizationSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

fn map_activation_error(
    error: ProcessActivationError,
    cancellation: &ActivationCancellation,
    provider: &str,
) -> AuthorizationActivationError {
    if cancellation.is_cancelled() || error == ProcessActivationError::Cancelled {
        AuthorizationActivationError::Cancelled
    } else {
        match error {
            ProcessActivationError::UnsupportedCapabilities => {
                AuthorizationActivationError::UnsupportedProcessCapabilities {
                    provider: provider.to_owned(),
                }
            }
            ProcessActivationError::Spawn | ProcessActivationError::EnvironmentUnavailable => {
                AuthorizationActivationError::ProcessActivation {
                    provider: provider.to_owned(),
                }
            }
            ProcessActivationError::Cancelled => AuthorizationActivationError::Cancelled,
        }
    }
}

struct ActivationRollback {
    owners: Vec<Arc<dyn GenerationOwner>>,
}

impl ActivationRollback {
    fn new(capacity: usize) -> Self {
        Self {
            owners: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, owner: Arc<dyn GenerationOwner>) {
        self.owners.push(owner);
    }

    async fn rollback(&mut self) {
        if let Some(supervisor) = self.start_supervisor() {
            let _ = supervisor.await;
        }
    }

    fn disarm(mut self) -> Box<[Arc<dyn GenerationOwner>]> {
        std::mem::take(&mut self.owners).into_boxed_slice()
    }

    fn start_supervisor(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        let owners = std::mem::take(&mut self.owners);
        (!owners.is_empty()).then(|| {
            tokio::spawn(async move {
                let cleanups = owners
                    .into_iter()
                    .map(|owner| {
                        tokio::spawn(async move {
                            owner.cleanup(CleanupReason::CandidateRejected).await;
                        })
                    })
                    .collect::<Vec<_>>();
                for cleanup in cleanups {
                    let _ = cleanup.await;
                }
            })
        })
    }
}

impl Drop for ActivationRollback {
    fn drop(&mut self) {
        if let Some(supervisor) = self.start_supervisor() {
            drop(supervisor);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::config::v3_compile::{CompiledProviderFailureMode, ProcessProviderPlan};
    use crate::runtime::{PublicationGuard, RuntimeError};
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn write_python(directory: &TempDir, name: &str, source: &str) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, source).unwrap();
        path
    }

    fn process_plan(directory: &TempDir, script: &Path) -> ProcessProviderPlan {
        ProcessProviderPlan {
            command: PathBuf::from("/usr/bin/python3"),
            working_directory: directory.path().to_path_buf(),
            args: vec![script.to_string_lossy().into_owned()],
            timeout: Duration::from_secs(2),
            on_failure: CompiledProviderFailureMode::Deny,
            inherit_environment: false,
            pass_environment: vec![],
            environment: BTreeMap::new(),
            include_headers: vec![],
            include_request_body: false,
            allow_request_body_replacement: false,
            max_request_body_bytes: 1024,
            max_decoded_request_body_bytes: 1024,
            max_stdout_line_bytes: 4096,
            max_pending_requests: 8,
            restart_backoff: Duration::from_millis(25),
            retire_timeout: Duration::from_millis(100),
            outputs: BTreeMap::new(),
        }
    }

    fn authorization_plan(
        providers: BTreeMap<String, AuthorizationProviderPlan>,
    ) -> AuthorizationPlan {
        AuthorizationPlan {
            internal_context_headers: vec![],
            callback: None,
            providers,
        }
    }

    fn cancellation() -> ActivationCancellation {
        ActivationCancellation::new_for_test()
    }

    fn request(id: &str) -> ProviderRequest<'_> {
        ProviderRequest {
            request_id: id,
            url: "https://example.test/resource",
            method: "GET",
            client_ip: "192.0.2.10",
            headers: None,
            body: None,
        }
    }

    fn body_guard() -> HttpWireBodyGuard {
        WireBodyPool::new(8 * 1024 * 1024, 8 * 1024 * 1024).begin_for_test(
            2 * 1024 * 1024,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    async fn cleanup(owners: &[Arc<dyn GenerationOwner>]) {
        for owner in owners {
            owner.cleanup(CleanupReason::Shutdown).await;
        }
    }

    #[tokio::test]
    async fn provider_registry_and_dense_storage_share_sorted_name_indices() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "idle.py",
            "import sys\nfor _ in sys.stdin:\n    pass\n",
        );
        let mut alpha = process_plan(&directory, &script);
        alpha.include_headers = vec![HeaderName::from_static("x-alpha")];
        let mut zeta = process_plan(&directory, &script);
        zeta.include_headers = vec![HeaderName::from_static("x-zeta")];
        zeta.on_failure = CompiledProviderFailureMode::Error;
        let activation = ProductAuthorizationSnapshot::activate(
            authorization_plan(BTreeMap::from([
                ("zeta".to_string(), AuthorizationProviderPlan::Process(zeta)),
                (
                    "alpha".to_string(),
                    AuthorizationProviderPlan::Process(alpha),
                ),
            ])),
            cancellation(),
        )
        .await
        .unwrap();

        let alpha = activation.provider_registry().get("alpha").unwrap();
        let zeta = activation.provider_registry().get("zeta").unwrap();
        assert_eq!((alpha.get(), zeta.get()), (0, 1));
        assert_eq!(
            activation.provider_metadata(alpha).unwrap().include_headers[0],
            "x-alpha"
        );
        assert!(matches!(
            activation.provider_metadata(zeta).unwrap().failure_mode,
            CompiledProviderFailureMode::Error
        ));

        let (_, _, owners) = activation.into_parts();
        assert_eq!(owners.len(), 2);
        cleanup(&owners).await;
    }

    #[tokio::test]
    async fn object_safe_dispatch_routes_by_provider_index() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "allow.py",
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id":request["id"],"type":"response","decision":"allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let activation = ProductAuthorizationSnapshot::activate(
            authorization_plan(BTreeMap::from([(
                "decision".to_string(),
                AuthorizationProviderPlan::Process(process_plan(&directory, &script)),
            )])),
            cancellation(),
        )
        .await
        .unwrap();
        let provider = activation.provider_registry().get("decision").unwrap();
        let (snapshot, _, owners) = activation.into_parts();
        for owner in &owners {
            let mut guard = owner.publication_guard().unwrap();
            guard.commit();
        }

        let object: &dyn AuthorizationSnapshot = &snapshot;
        assert_eq!(
            object
                .dispatch(
                    provider,
                    request("request-1"),
                    body_guard(),
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .unwrap(),
            AuthorizationDecision::Allow
        );
        let foreign =
            ProviderRegistry::from_names(["unused-a".to_string(), "unused-z".to_string()])
                .get("unused-z")
                .unwrap();
        assert!(matches!(
            object
                .dispatch(
                    foreign,
                    request("request-2"),
                    body_guard(),
                    Instant::now() + Duration::from_secs(5),
                )
                .await,
            Err(AuthorizationDispatchError::UnknownProvider)
        ));
        cleanup(&owners).await;
    }

    #[tokio::test]
    async fn pre_cancelled_activation_starts_no_provider() {
        let cancellation = cancellation();
        cancellation.cancel_for_test();
        let result = ProductAuthorizationSnapshot::activate(
            authorization_plan(BTreeMap::new()),
            cancellation,
        )
        .await;
        assert!(matches!(
            result,
            Err(AuthorizationActivationError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn later_spawn_failure_cleans_an_already_started_provider_before_returning() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "idle-before-failure.py",
            "import sys\nfor _ in sys.stdin:\n    pass\n",
        );
        let first = process_plan(&directory, &script);
        let mut failing = process_plan(&directory, &script);
        failing.command = directory.path().join("missing-provider-command");

        let result = ProductAuthorizationSnapshot::activate(
            authorization_plan(BTreeMap::from([
                (
                    "alpha-starts".to_string(),
                    AuthorizationProviderPlan::Process(first),
                ),
                (
                    "zeta-fails".to_string(),
                    AuthorizationProviderPlan::Process(failing),
                ),
            ])),
            cancellation(),
        )
        .await;

        match result {
            Err(AuthorizationActivationError::ProcessActivation { provider }) => {
                assert_eq!(provider, "zeta-fails");
                assert!(!provider.contains("missing-provider-command"));
            }
            _ => panic!("expected a sanitized process activation failure"),
        }
    }

    #[tokio::test]
    async fn activation_error_names_provider_without_disclosing_missing_environment_input() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "unused.py", "raise SystemExit(0)\n");
        let missing = format!("ACL_PROXY_AGGREGATE_MISSING_{}", std::process::id());
        std::env::remove_var(&missing);
        let mut provider = process_plan(&directory, &script);
        provider.pass_environment = vec![missing.clone()];

        let result = ProductAuthorizationSnapshot::activate(
            authorization_plan(BTreeMap::from([(
                "safe-provider-name".to_string(),
                AuthorizationProviderPlan::Process(provider),
            )])),
            cancellation(),
        )
        .await;
        let error = match result {
            Err(error @ AuthorizationActivationError::ProcessActivation { .. }) => error,
            _ => panic!("expected environment activation failure"),
        };
        let rendered = format!("{error:?} {error}");
        assert!(rendered.contains("safe-provider-name"));
        assert!(!rendered.contains(&missing));
    }

    struct RecordingOwner {
        index: usize,
        cleaned: Arc<Mutex<Vec<usize>>>,
    }

    impl GenerationOwner for RecordingOwner {
        fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
            unreachable!("cleanup regression does not publish owners")
        }

        fn retirement_started(&self, _reason: CleanupReason) {}

        fn cleanup(&self, reason: CleanupReason) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                assert_eq!(reason, CleanupReason::CandidateRejected);
                self.cleaned.lock().unwrap().push(self.index);
            })
        }
    }

    #[tokio::test]
    async fn partial_activation_cleanup_joins_every_owner_from_dense_storage() {
        let cleaned = Arc::new(Mutex::new(Vec::new()));
        let owners = (0..3)
            .map(|index| {
                Arc::new(RecordingOwner {
                    index,
                    cleaned: cleaned.clone(),
                }) as Arc<dyn GenerationOwner>
            })
            .collect::<Vec<_>>();

        let mut rollback = ActivationRollback::new(owners.len());
        for owner in owners {
            rollback.push(owner);
        }
        rollback.rollback().await;
        let mut cleaned = cleaned.lock().unwrap().clone();
        cleaned.sort_unstable();
        assert_eq!(cleaned, [0, 1, 2]);
    }

    #[tokio::test]
    async fn dropping_rollback_waiter_still_reaps_every_started_process() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "ignore-term.py",
            r#"import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], "w") as marker:
    marker.write(str(os.getpid()))
while True:
    time.sleep(1)
"#,
        );
        let mut rollback = ActivationRollback::new(2);
        let mut pid_files = Vec::new();
        for index in 0..2 {
            let pid_file = directory.path().join(format!("provider-{index}.pid"));
            let mut plan = process_plan(&directory, &script);
            plan.args.push(pid_file.to_string_lossy().into_owned());
            let provider = ProcessProvider::activate(plan, || false).await.unwrap();
            rollback.push(provider);
            pid_files.push(pid_file);
        }
        let mut pids = Vec::new();
        for pid_file in &pid_files {
            for _ in 0..200 {
                if let Ok(contents) = fs::read_to_string(pid_file) {
                    pids.push(contents.parse::<libc::pid_t>().unwrap());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        assert_eq!(pids.len(), 2);

        let waiter = tokio::spawn(async move {
            rollback.rollback().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished());
        waiter.abort();
        let _ = waiter.await;

        for pid in pids {
            let mut reaped = false;
            for _ in 0..700 {
                // SAFETY: signal zero only checks whether the recorded child PID exists.
                if unsafe { libc::kill(pid, 0) } == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    reaped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(reaped, "rollback supervisor did not reap child {pid}");
        }
    }
}
