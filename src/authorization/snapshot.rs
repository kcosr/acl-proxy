use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use http::HeaderName;
#[cfg(test)]
use http_access_types::PolicyGeneration;
use tokio::time::Instant;

use super::process::{
    ProcessActivationError, ProcessDecision, ProcessProvider, ProcessRequestError,
};
#[cfg(test)]
use super::protocol::ProviderRequest;
use super::protocol::{
    ProviderBodyReplacement, ProviderCredentialSet, ProviderCredentialWireError,
    ProviderCredentialWireStore, ProviderDecision, ProviderOutputDefinition, ProviderOutputIndex,
    ProviderOutputRegistry,
};
use super::unix_socket::{UnixSocketActivationError, UnixSocketProvider, UnixSocketRequestError};
use super::webhook::provider::{WebhookActivationError, WebhookProvider};
use super::webhook::runtime::{WebhookAuthorizationRuntime, WebhookDispatchError};
use crate::candidate_tls::CandidateTlsResolver;
use crate::config::compiler::{
    AuthorizationCallbackPlan, AuthorizationPlan, AuthorizationProviderPlan,
    CompiledProviderFailureMode,
};
use crate::runtime::{
    ActivationCancellation, AuthorizationDispatchContext, AuthorizationSnapshot, BoxFuture,
    CleanupReason, GenerationOwner, ProviderIndex, ProviderRegistry,
};
use crate::safety::HttpWireBodyGuard;

pub(crate) struct ProductAuthorizationSnapshot {
    id: u64,
    internal_context_headers: Box<[HeaderName]>,
    legacy_execution_context_header: Option<HeaderName>,
    providers: Box<[ActiveProvider]>,
    callback: Option<AuthorizationCallbackPlan>,
    webhook_runtime: Arc<WebhookAuthorizationRuntime>,
}

enum ActiveProvider {
    Process(Arc<ProcessProvider>),
    UnixSocket(Arc<UnixSocketProvider>),
    Webhook(Arc<WebhookProvider>),
}

pub(crate) struct AuthorizationActivation {
    provider_registry: ProviderRegistry,
    snapshot: ProductAuthorizationSnapshot,
    owners: Box<[Arc<dyn GenerationOwner>]>,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorizationProviderMetadata<'snapshot> {
    pub(crate) include_headers: &'snapshot [HeaderName],
    pub(crate) include_identity: bool,
    pub(crate) include_request_body: bool,
    pub(crate) max_request_body_bytes: usize,
    pub(crate) max_decoded_request_body_bytes: usize,
    pub(crate) failure_mode: CompiledProviderFailureMode,
}

pub(crate) struct ActivatedProviderOutputBinding<'snapshot> {
    provider: ProviderIndex,
    output: ProviderOutputIndex,
    definition: &'snapshot ProviderOutputDefinition,
}

pub(crate) enum AuthorizationDecision {
    Allow(AuthorizationAllowOutput),
    Deny,
    Pass,
}

pub(crate) struct AuthorizationAllowOutput {
    snapshot_id: u64,
    provider: ProviderIndex,
    credentials: Option<ProviderCredentialSet>,
    replacement: Option<ProviderBodyReplacement>,
}

static NEXT_AUTHORIZATION_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(1);

fn next_authorization_snapshot_id() -> u64 {
    let id = NEXT_AUTHORIZATION_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
    assert!(id != 0, "authorization snapshot ID overflow");
    id
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthorizationDispatchError {
    #[error("authorization provider index is not active")]
    UnknownProvider,
    #[error("process authorization provider dispatch failed")]
    Process(#[source] ProcessRequestError),
    #[error("webhook authorization provider dispatch failed")]
    Webhook(#[source] WebhookDispatchError),
    #[error("Unix authorization provider dispatch failed")]
    UnixSocket(#[source] UnixSocketRequestError),
}

impl AuthorizationDispatchError {
    pub(crate) fn is_timeout(&self) -> bool {
        use crate::authorization::callback::PendingTerminalCause;

        match self {
            Self::Process(ProcessRequestError::Timeout) => true,
            Self::Webhook(WebhookDispatchError::Terminal(cause))
            | Self::Webhook(WebhookDispatchError::Callback(
                super::webhook::runtime::WebhookCompletionError::Terminal(cause),
            )) => matches!(
                cause,
                PendingTerminalCause::RequestDeadline
                    | PendingTerminalCause::ProviderDeadline
                    | PendingTerminalCause::ResumeTokenDeadline
            ),
            Self::UnixSocket(error) => error.is_timeout(),
            Self::UnknownProvider | Self::Process(_) | Self::Webhook(_) => false,
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        matches!(self, Self::UnixSocket(error) if error.is_cancelled())
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AuthorizationActivationError {
    #[error("authorization activation was cancelled")]
    Cancelled,
    #[error("authorization provider registry does not match the activation plan")]
    ProviderRegistryMismatch,
    #[error("webhook authorization callback configuration is inconsistent")]
    InvalidWebhookConfiguration,
    #[error("webhook authorization provider '{provider}' could not be activated: {reason}")]
    WebhookActivation {
        provider: String,
        #[source]
        reason: crate::tls::TlsActivationError,
    },
    #[error("process authorization provider '{provider}' could not be activated")]
    ProcessActivation { provider: String },
    #[error("Unix authorization provider '{provider}' could not be activated")]
    UnixSocketActivation {
        provider: String,
        #[source]
        reason: UnixSocketActivationError,
    },
}

impl ProductAuthorizationSnapshot {
    pub(crate) async fn activate(
        plan: AuthorizationPlan,
        provider_registry: ProviderRegistry,
        webhook_runtime: Arc<WebhookAuthorizationRuntime>,
        tls_resolver: &mut CandidateTlsResolver,
    ) -> Result<AuthorizationActivation, AuthorizationActivationError> {
        Self::activate_inner(
            plan,
            provider_registry,
            webhook_runtime,
            tls_resolver,
            |_| {},
        )
        .await
    }

    #[cfg(test)]
    async fn activate_with_hook(
        plan: AuthorizationPlan,
        provider_registry: ProviderRegistry,
        webhook_runtime: Arc<WebhookAuthorizationRuntime>,
        tls_io_runtime: Arc<crate::tls_io_runtime::TlsIoRuntime>,
        generation: PolicyGeneration,
        cancellation: ActivationCancellation,
        after_provider_activation: impl FnMut(&Arc<ProcessProvider>),
    ) -> Result<AuthorizationActivation, AuthorizationActivationError> {
        let mut tls_resolver =
            CandidateTlsResolver::activate(tls_io_runtime, cancellation, generation)
                .await
                .map_err(|error| AuthorizationActivationError::WebhookActivation {
                    provider: "system-roots".to_owned(),
                    reason: error,
                })?;
        Self::activate_inner(
            plan,
            provider_registry,
            webhook_runtime,
            &mut tls_resolver,
            after_provider_activation,
        )
        .await
    }

    async fn activate_inner(
        plan: AuthorizationPlan,
        provider_registry: ProviderRegistry,
        webhook_runtime: Arc<WebhookAuthorizationRuntime>,
        tls_resolver: &mut CandidateTlsResolver,
        mut after_provider_activation: impl FnMut(&Arc<ProcessProvider>),
    ) -> Result<AuthorizationActivation, AuthorizationActivationError> {
        if tls_resolver.cancellation().is_cancelled() {
            return Err(AuthorizationActivationError::Cancelled);
        }
        let has_webhook = plan
            .providers
            .values()
            .any(|provider| matches!(provider, AuthorizationProviderPlan::Webhook(_)));
        if has_webhook != plan.callback.is_some()
            || (has_webhook && webhook_runtime.callback_url().is_none())
        {
            return Err(AuthorizationActivationError::InvalidWebhookConfiguration);
        }

        let registry_matches = provider_registry.len() == plan.providers.len()
            && plan.providers.keys().enumerate().all(|(index, name)| {
                provider_registry.get(name).map(ProviderIndex::get) == Some(index)
            });
        if !registry_matches {
            return Err(AuthorizationActivationError::ProviderRegistryMismatch);
        }
        let mut providers = Vec::with_capacity(provider_registry.len());
        let mut rollback = ActivationRollback::new(provider_registry.len());

        for (name, provider) in plan.providers {
            debug_assert_eq!(
                provider_registry.get(&name).map(ProviderIndex::get),
                Some(providers.len())
            );
            match provider {
                AuthorizationProviderPlan::Process(process_plan) => {
                    let process = match ProcessProvider::activate(process_plan, || {
                        tls_resolver.cancellation().is_cancelled()
                    })
                    .await
                    {
                        Ok(process) => process,
                        Err(error) => {
                            let error =
                                map_activation_error(error, tls_resolver.cancellation(), &name);
                            rollback.rollback().await;
                            return Err(error);
                        }
                    };
                    rollback.push(process.clone());
                    after_provider_activation(&process);
                    providers.push(ActiveProvider::Process(process));
                }
                AuthorizationProviderPlan::UnixSocket(unix_plan) => {
                    let unix = match UnixSocketProvider::activate(unix_plan) {
                        Ok(unix) => unix,
                        Err(reason) => {
                            rollback.rollback().await;
                            return Err(AuthorizationActivationError::UnixSocketActivation {
                                provider: name,
                                reason,
                            });
                        }
                    };
                    providers.push(ActiveProvider::UnixSocket(unix));
                }
                AuthorizationProviderPlan::Webhook(webhook_plan) => {
                    let webhook = match WebhookProvider::activate(webhook_plan, tls_resolver).await
                    {
                        Ok(webhook) => webhook,
                        Err(error) => {
                            let error = map_webhook_activation_error(
                                error,
                                tls_resolver.cancellation(),
                                &name,
                            );
                            rollback.rollback().await;
                            return Err(error);
                        }
                    };
                    providers.push(ActiveProvider::Webhook(webhook));
                }
            }
        }

        if tls_resolver.cancellation().is_cancelled() {
            rollback.rollback().await;
            return Err(AuthorizationActivationError::Cancelled);
        }

        Ok(AuthorizationActivation {
            provider_registry,
            snapshot: Self {
                id: next_authorization_snapshot_id(),
                internal_context_headers: plan.internal_context_headers.into_boxed_slice(),
                legacy_execution_context_header: plan.legacy_execution_context_header,
                providers: providers.into_boxed_slice(),
                callback: plan.callback,
                webhook_runtime,
            },
            owners: rollback.disarm(),
        })
    }

    pub(crate) fn internal_context_headers(&self) -> &[HeaderName] {
        &self.internal_context_headers
    }

    pub(crate) fn legacy_execution_context_header(&self) -> Option<&HeaderName> {
        self.legacy_execution_context_header.as_ref()
    }

    fn bind_allow_output(
        &self,
        provider: ProviderIndex,
        credentials: Option<ProviderCredentialSet>,
        replacement: Option<ProviderBodyReplacement>,
    ) -> AuthorizationAllowOutput {
        AuthorizationAllowOutput {
            snapshot_id: self.id,
            provider,
            credentials,
            replacement,
        }
    }

    fn consume_allow_output(
        &self,
        provider: ProviderIndex,
        output: AuthorizationAllowOutput,
    ) -> Option<(
        Option<ProviderCredentialSet>,
        Option<ProviderBodyReplacement>,
    )> {
        (output.snapshot_id == self.id && output.provider == provider)
            .then_some((output.credentials, output.replacement))
    }

    fn outputs(&self, provider: ProviderIndex) -> Option<&ProviderOutputRegistry> {
        match self.providers.get(provider.get())? {
            ActiveProvider::Process(process) => process.outputs(),
            ActiveProvider::UnixSocket(unix) => Some(unix.outputs()),
            ActiveProvider::Webhook(webhook) => Some(webhook.outputs()),
        }
    }

    pub(crate) fn provider_metadata(
        &self,
        provider: ProviderIndex,
    ) -> Option<AuthorizationProviderMetadata<'_>> {
        match self.providers.get(provider.get())? {
            ActiveProvider::Process(process) => Some(AuthorizationProviderMetadata {
                include_headers: process.include_headers(),
                include_identity: process.include_identity(),
                include_request_body: process.include_request_body(),
                max_request_body_bytes: process.max_request_body_bytes(),
                max_decoded_request_body_bytes: process.max_decoded_request_body_bytes(),
                failure_mode: process.failure_mode(),
            }),
            ActiveProvider::Webhook(webhook) => Some(AuthorizationProviderMetadata {
                include_headers: webhook.include_headers(),
                include_identity: webhook.include_identity(),
                include_request_body: false,
                max_request_body_bytes: 0,
                max_decoded_request_body_bytes: 0,
                failure_mode: webhook.failure_mode(),
            }),
            ActiveProvider::UnixSocket(unix) => Some(AuthorizationProviderMetadata {
                include_headers: unix.include_headers(),
                include_identity: unix.include_identity(),
                include_request_body: false,
                max_request_body_bytes: 0,
                max_decoded_request_body_bytes: 0,
                failure_mode: unix.failure_mode(),
            }),
        }
    }

    pub(crate) fn compact_provider_credential_wire(
        &self,
        provider: ProviderIndex,
        credentials: &ProviderCredentialSet,
        guard: &HttpWireBodyGuard,
    ) -> Result<ProviderCredentialWireStore, ProviderCredentialWireError> {
        let outputs = match self
            .providers
            .get(provider.get())
            .ok_or(ProviderCredentialWireError::UnknownProvider)?
        {
            ActiveProvider::Process(process) => process
                .outputs()
                .ok_or(ProviderCredentialWireError::ForeignRegistry)?,
            ActiveProvider::Webhook(webhook) => webhook.outputs(),
            ActiveProvider::UnixSocket(unix) => unix.outputs(),
        };
        outputs.compact_provider_credential_wire(credentials, guard)
    }

    fn bind_process_decision(
        &self,
        provider: ProviderIndex,
        decision: ProcessDecision,
    ) -> AuthorizationDecision {
        match decision {
            ProcessDecision::Allow => {
                AuthorizationDecision::Allow(self.bind_allow_output(provider, None, None))
            }
            ProcessDecision::AllowWithOutputs {
                credentials,
                replacement,
            } => AuthorizationDecision::Allow(self.bind_allow_output(
                provider,
                credentials,
                replacement,
            )),
            ProcessDecision::Deny => AuthorizationDecision::Deny,
            ProcessDecision::Pass => AuthorizationDecision::Pass,
        }
    }

    fn bind_provider_decision(
        &self,
        provider: ProviderIndex,
        decision: ProviderDecision,
    ) -> AuthorizationDecision {
        match decision {
            ProviderDecision::Allow {
                credentials,
                replacement,
            } => AuthorizationDecision::Allow(self.bind_allow_output(
                provider,
                Some(credentials),
                replacement,
            )),
            ProviderDecision::AllowWithoutEffects => {
                AuthorizationDecision::Allow(self.bind_allow_output(provider, None, None))
            }
            ProviderDecision::Deny => AuthorizationDecision::Deny,
            ProviderDecision::Pass => AuthorizationDecision::Pass,
        }
    }

    #[cfg(test)]
    fn dispatch_process_for_test<'a>(
        &'a self,
        provider: ProviderIndex,
        request: ProviderRequest<'a>,
        guard: &'a HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, AuthorizationDispatchError>> {
        Box::pin(async move {
            let active = self
                .providers
                .get(provider.get())
                .ok_or(AuthorizationDispatchError::UnknownProvider)?;
            match active {
                ActiveProvider::Process(process) => process
                    .decide(
                        request,
                        crate::runtime::AuthorizationInvocationMode::EffectsAllowed,
                        guard,
                        request_deadline,
                    )
                    .await
                    .map(|decision| self.bind_process_decision(provider, decision))
                    .map_err(AuthorizationDispatchError::Process),
                ActiveProvider::Webhook(_) => {
                    unreachable!("process-only test dispatch selected a webhook provider")
                }
                ActiveProvider::UnixSocket(_) => {
                    unreachable!("process-only test dispatch selected a Unix provider")
                }
            }
        })
    }
}

impl ActivatedProviderOutputBinding<'_> {
    pub(crate) fn provider(&self) -> ProviderIndex {
        self.provider
    }

    pub(crate) fn output(&self) -> ProviderOutputIndex {
        self.output
    }

    pub(crate) fn definition(&self) -> &ProviderOutputDefinition {
        self.definition
    }
}

impl ProductAuthorizationSnapshot {
    pub(crate) fn provider_output_binding(
        &self,
        provider_registry: &ProviderRegistry,
        provider_name: &str,
        output_name: &str,
    ) -> Option<ActivatedProviderOutputBinding<'_>> {
        let provider = provider_registry.get(provider_name)?;
        let outputs = self.outputs(provider)?;
        let output = outputs.index(output_name)?;
        let definition = outputs.definitions().get(output.get())?;
        Some(ActivatedProviderOutputBinding {
            provider,
            output,
            definition,
        })
    }
}

impl AuthorizationSnapshot for ProductAuthorizationSnapshot {
    fn internal_context_headers(&self) -> &[HeaderName] {
        ProductAuthorizationSnapshot::internal_context_headers(self)
    }

    fn legacy_execution_context_header(&self) -> Option<&HeaderName> {
        ProductAuthorizationSnapshot::legacy_execution_context_header(self)
    }

    fn provider_metadata(
        &self,
        provider: ProviderIndex,
    ) -> Option<AuthorizationProviderMetadata<'_>> {
        ProductAuthorizationSnapshot::provider_metadata(self, provider)
    }

    fn compact_provider_credential_wire(
        &self,
        provider: ProviderIndex,
        credentials: &ProviderCredentialSet,
        guard: &HttpWireBodyGuard,
    ) -> Result<ProviderCredentialWireStore, ProviderCredentialWireError> {
        ProductAuthorizationSnapshot::compact_provider_credential_wire(
            self,
            provider,
            credentials,
            guard,
        )
    }

    fn consume_allow_output(
        &self,
        provider: ProviderIndex,
        output: AuthorizationAllowOutput,
    ) -> Option<(
        Option<ProviderCredentialSet>,
        Option<ProviderBodyReplacement>,
    )> {
        ProductAuthorizationSnapshot::consume_allow_output(self, provider, output)
    }

    #[cfg(test)]
    fn bind_allow_output_for_test(
        &self,
        provider: ProviderIndex,
        credentials: Option<ProviderCredentialSet>,
        replacement: Option<ProviderBodyReplacement>,
    ) -> AuthorizationAllowOutput {
        self.bind_allow_output(provider, credentials, replacement)
    }

    fn dispatch<'a>(
        &'a self,
        provider: ProviderIndex,
        context: AuthorizationDispatchContext<'a>,
        guard: &'a HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, AuthorizationDispatchError>> {
        Box::pin(async move {
            let active = self
                .providers
                .get(provider.get())
                .ok_or(AuthorizationDispatchError::UnknownProvider)?;
            match active {
                ActiveProvider::Process(process) => {
                    let (request, invocation_mode) = context.into_request_parts();
                    process
                        .decide(request, invocation_mode, guard, request_deadline)
                        .await
                        .map(|decision| self.bind_process_decision(provider, decision))
                        .map_err(AuthorizationDispatchError::Process)
                }
                ActiveProvider::Webhook(webhook) => self
                    .webhook_runtime
                    .dispatch(
                        webhook.clone(),
                        self.callback
                            .as_ref()
                            .expect("an activated webhook snapshot owns callback policy"),
                        context,
                        guard,
                        request_deadline,
                    )
                    .await
                    .map(|decision| self.bind_provider_decision(provider, decision))
                    .map_err(AuthorizationDispatchError::Webhook),
                ActiveProvider::UnixSocket(unix) => {
                    let (request, invocation_mode, cancellation) = context.into_unix_parts();
                    unix.decide(
                        request,
                        invocation_mode,
                        &cancellation,
                        guard,
                        request_deadline,
                    )
                    .await
                    .map(|decision| self.bind_provider_decision(provider, decision))
                    .map_err(AuthorizationDispatchError::UnixSocket)
                }
            }
        })
    }
}

impl AuthorizationActivation {
    #[cfg(test)]
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

    #[cfg(test)]
    pub(crate) fn process_provider_for_test(&self, index: usize) -> Option<Arc<ProcessProvider>> {
        match self.snapshot.providers.get(index)? {
            ActiveProvider::Process(provider) => Some(provider.clone()),
            ActiveProvider::UnixSocket(_) | ActiveProvider::Webhook(_) => None,
        }
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
            ProcessActivationError::Spawn | ProcessActivationError::EnvironmentUnavailable => {
                AuthorizationActivationError::ProcessActivation {
                    provider: provider.to_owned(),
                }
            }
            ProcessActivationError::Cancelled => AuthorizationActivationError::Cancelled,
        }
    }
}

fn map_webhook_activation_error(
    error: WebhookActivationError,
    cancellation: &ActivationCancellation,
    provider: &str,
) -> AuthorizationActivationError {
    if cancellation.is_cancelled() || matches!(&error, WebhookActivationError::Cancelled) {
        AuthorizationActivationError::Cancelled
    } else {
        match error {
            WebhookActivationError::Tls(reason) => {
                AuthorizationActivationError::WebhookActivation {
                    provider: provider.to_owned(),
                    reason,
                }
            }
            WebhookActivationError::Cancelled => AuthorizationActivationError::Cancelled,
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use http_access_url::canonicalize_http_url;
    use tempfile::TempDir;

    use super::*;
    use crate::config::compiler::{
        AuthorizationCallbackPlan, CompiledProviderFailureMode, PendingOperationLimit,
        ProcessProviderPlan, ProviderOutputPlan, WebhookProviderPlan,
    };
    use crate::runtime::{PublicationGuard, RuntimeError};
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn write_python(directory: &TempDir, name: &str, source: &str) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, source).unwrap();
        path
    }

    async fn wait_for_pid_file(path: &Path) -> libc::pid_t {
        const TIMEOUT: Duration = Duration::from_secs(5);
        const RETRY_DELAY: Duration = Duration::from_millis(5);

        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let last_observation = match fs::read_to_string(path) {
                Ok(contents) => match contents.trim().parse::<libc::pid_t>() {
                    Ok(pid) if pid > 0 => return pid,
                    Ok(pid) => format!("contents {contents:?} contained non-positive PID {pid}"),
                    Err(error) => {
                        format!("contents {contents:?} could not be parsed as a PID: {error}")
                    }
                },
                Err(error) => format!("read failed: {error}"),
            };
            let now = tokio::time::Instant::now();
            if now >= deadline {
                panic!(
                    "PID file {} was not ready within {TIMEOUT:?}; last observation: {last_observation}",
                    path.display()
                );
            }
            tokio::time::sleep_until((now + RETRY_DELAY).min(deadline)).await;
        }
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
            blocked_environment: vec![],
            include_headers: vec![],
            include_identity: false,
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
            legacy_execution_context_header: None,
            callback: None,
            providers,
        }
    }

    fn cancellation() -> ActivationCancellation {
        ActivationCancellation::new_for_test()
    }

    #[test]
    fn webhook_activation_error_preserves_sanitized_ca_classification() {
        let cancellation = cancellation();
        for (reason, expected) in [
            (
                crate::tls::TlsActivationError::InvalidMaterial,
                "TLS trust material",
            ),
            (
                crate::tls::TlsActivationError::ResourceLimit,
                "resource limit",
            ),
        ] {
            let error = map_webhook_activation_error(
                WebhookActivationError::Tls(reason),
                &cancellation,
                "safe-provider",
            );
            let rendered = error.to_string();
            assert!(rendered.contains("safe-provider"));
            assert!(rendered.contains(expected), "{rendered}");
            assert!(!rendered.contains('/') && !rendered.contains('\\'));
        }
    }

    #[tokio::test]
    async fn production_webhook_ca_errors_and_cancellation_map_at_the_snapshot_boundary() {
        fn plan(path: &str) -> AuthorizationPlan {
            AuthorizationPlan {
                internal_context_headers: vec![],
                legacy_execution_context_header: None,
                callback: Some(AuthorizationCallbackPlan {
                    resume_token_ttl: Duration::from_secs(5),
                    max_pending_operations: PendingOperationLimit::try_new(1).unwrap(),
                }),
                providers: BTreeMap::from([(
                    "safe-provider".to_owned(),
                    AuthorizationProviderPlan::Webhook(WebhookProviderPlan {
                        url: http_access_url::canonicalize_http_url(
                            "https://provider.test/authorize",
                        )
                        .unwrap(),
                        timeout: Duration::from_secs(1),
                        on_failure: CompiledProviderFailureMode::Deny,
                        include_headers: vec![],
                        include_identity: false,
                        max_request_bytes: 1024,
                        max_response_bytes: 1024,
                        outputs: BTreeMap::new(),
                        tls: Some(crate::config::compiler::WebhookTlsPlan {
                            trust: crate::config::compiler::TlsClientTrustMode::Custom,
                            ca_certificate: Some(path.into()),
                        }),
                    }),
                )]),
            }
        }

        let missing = plan("/sensitive/missing/provider-ca.pem");
        let tls_io = crate::tls_io_runtime::TlsIoRuntime::new().unwrap();
        let mut plans = crate::candidate_tls::CandidateTlsPlanSet::new();
        plans
            .register(
                crate::config::compiler::TlsClientTrustMode::Custom,
                Some(Path::new("/sensitive/missing/provider-ca.pem")),
            )
            .unwrap();
        let error = CandidateTlsResolver::activate_with_plans(
            Arc::clone(&tls_io),
            cancellation(),
            http_access_types::PolicyGeneration::new(7).unwrap(),
            plans,
        )
        .await
        .err()
        .expect("missing custom CA must reject the candidate");
        assert_eq!(error, crate::tls::TlsActivationError::UntrustedSource);
        assert!(!error.to_string().contains("/sensitive/"));
        drop(missing);
        tls_io.shutdown_and_wait(None).await;

        let cancellation = cancellation();
        let tls_io = crate::tls_io_runtime::TlsIoRuntime::new().unwrap();
        let mut plans = crate::candidate_tls::CandidateTlsPlanSet::new();
        plans
            .register(
                crate::config::compiler::TlsClientTrustMode::Custom,
                Some(Path::new("/sensitive/missing/provider-ca.pem")),
            )
            .unwrap();
        cancellation.cancel_for_test();
        let error = CandidateTlsResolver::activate_with_plans(
            Arc::clone(&tls_io),
            cancellation.clone(),
            http_access_types::PolicyGeneration::new(7).unwrap(),
            plans,
        )
        .await
        .err()
        .expect("cancelled candidate must not load custom CA material");
        assert_eq!(error, crate::tls::TlsActivationError::ActivationCancelled);
        tls_io.shutdown_and_wait(None).await;
    }

    async fn activate(
        plan: AuthorizationPlan,
        cancellation: ActivationCancellation,
    ) -> Result<AuthorizationActivation, AuthorizationActivationError> {
        let provider_registry = ProviderRegistry::from_names(plan.providers.keys().cloned());
        let mut tls_resolver = CandidateTlsResolver::activate(
            crate::tls_io_runtime::TlsIoRuntime::new().unwrap(),
            cancellation,
            http_access_types::PolicyGeneration::new(7).unwrap(),
        )
        .await
        .expect("test host system roots load");
        ProductAuthorizationSnapshot::activate(
            plan,
            provider_registry,
            WebhookAuthorizationRuntime::for_test(None),
            &mut tls_resolver,
        )
        .await
    }

    fn request(id: &str) -> ProviderRequest<'_> {
        ProviderRequest {
            request_id: id,
            rule_id: "rule-1",
            url: "https://example.test/resource",
            method: "GET",
            client_ip: "192.0.2.10",
            identity: None,
            headers: None,
            body: None,
        }
    }

    fn body_guard() -> HttpWireBodyGuard {
        body_guard_with_pool().2
    }

    fn body_guard_with_pool() -> (Arc<WireBodyPool>, WireBodyQuotaKey, HttpWireBodyGuard) {
        let pool = WireBodyPool::new(8 * 1024 * 1024, 8 * 1024 * 1024);
        let quota_key = WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false);
        let guard = pool.begin_for_test(2 * 1024 * 1024, quota_key.clone());
        (pool, quota_key, guard)
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
        alpha.max_request_body_bytes = 257;
        alpha.max_decoded_request_body_bytes = 511;
        let mut zeta = process_plan(&directory, &script);
        zeta.include_headers = vec![HeaderName::from_static("x-zeta")];
        zeta.on_failure = CompiledProviderFailureMode::Error;
        let activation = activate(
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
        let snapshot: &dyn AuthorizationSnapshot = &*activation;
        assert_eq!((alpha.get(), zeta.get()), (0, 1));
        assert_eq!(
            snapshot.provider_metadata(alpha).unwrap().include_headers[0],
            "x-alpha"
        );
        assert_eq!(
            snapshot
                .provider_metadata(alpha)
                .unwrap()
                .max_request_body_bytes,
            257
        );
        assert_eq!(
            snapshot
                .provider_metadata(alpha)
                .unwrap()
                .max_decoded_request_body_bytes,
            511
        );
        assert!(matches!(
            snapshot.provider_metadata(zeta).unwrap().failure_mode,
            CompiledProviderFailureMode::Error
        ));
        assert!(snapshot.internal_context_headers().is_empty());

        let (_, _, owners) = activation.into_parts();
        assert_eq!(owners.len(), 2);
        cleanup(&owners).await;
    }

    #[tokio::test]
    async fn webhook_provider_activates_with_generation_callback_policy() {
        let plan = AuthorizationPlan {
            internal_context_headers: vec![],
            legacy_execution_context_header: None,
            callback: Some(AuthorizationCallbackPlan {
                resume_token_ttl: Duration::from_secs(30),
                max_pending_operations: PendingOperationLimit::try_new(4).unwrap(),
            }),
            providers: BTreeMap::from([(
                "webhook".to_string(),
                AuthorizationProviderPlan::Webhook(WebhookProviderPlan {
                    url: canonicalize_http_url("http://127.0.0.1:9/authorize").unwrap(),
                    timeout: Duration::from_secs(2),
                    on_failure: CompiledProviderFailureMode::Deny,
                    include_headers: vec![HeaderName::from_static("x-context")],
                    include_identity: false,
                    max_request_bytes: 8192,
                    max_response_bytes: 4096,
                    outputs: BTreeMap::new(),
                    tls: None,
                }),
            )]),
        };
        let registry = ProviderRegistry::from_names(plan.providers.keys().cloned());
        let mut tls_resolver = CandidateTlsResolver::activate(
            crate::tls_io_runtime::TlsIoRuntime::new().unwrap(),
            cancellation(),
            http_access_types::PolicyGeneration::new(7).unwrap(),
        )
        .await
        .expect("test host system roots load");
        let activation = ProductAuthorizationSnapshot::activate(
            plan,
            registry,
            WebhookAuthorizationRuntime::for_test(Some(
                "http://127.0.0.1:8888/_acl/external-auth/callback",
            )),
            &mut tls_resolver,
        )
        .await
        .unwrap();
        let provider = activation.provider_registry().get("webhook").unwrap();

        assert_eq!(
            activation
                .provider_metadata(provider)
                .unwrap()
                .include_headers,
            ["x-context"]
        );
        let (_, _, owners) = activation.into_parts();
        assert!(owners.is_empty());
    }

    #[tokio::test]
    async fn object_safe_snapshot_stages_exact_raw_provider_material() {
        let plan = AuthorizationPlan {
            internal_context_headers: vec![],
            legacy_execution_context_header: None,
            callback: Some(AuthorizationCallbackPlan {
                resume_token_ttl: Duration::from_secs(30),
                max_pending_operations: PendingOperationLimit::try_new(4).unwrap(),
            }),
            providers: BTreeMap::from([(
                "webhook".to_string(),
                AuthorizationProviderPlan::Webhook(WebhookProviderPlan {
                    url: canonicalize_http_url("http://127.0.0.1:9/authorize").unwrap(),
                    timeout: Duration::from_secs(2),
                    on_failure: CompiledProviderFailureMode::Deny,
                    include_headers: vec![],
                    include_identity: false,
                    max_request_bytes: 8192,
                    max_response_bytes: 4096,
                    outputs: BTreeMap::from([(
                        "token".to_string(),
                        ProviderOutputPlan::Bearer {
                            required: true,
                            transport_security:
                                crate::config::compiler::CompiledTransportSecurity::TlsRequired,
                        },
                    )]),
                    tls: None,
                }),
            )]),
        };
        let registry = ProviderRegistry::from_names(plan.providers.keys().cloned());
        let mut tls_resolver = CandidateTlsResolver::activate(
            crate::tls_io_runtime::TlsIoRuntime::new().unwrap(),
            cancellation(),
            http_access_types::PolicyGeneration::new(7).unwrap(),
        )
        .await
        .expect("test host system roots load");
        let activation = ProductAuthorizationSnapshot::activate(
            plan,
            registry,
            WebhookAuthorizationRuntime::for_test(Some(
                "http://127.0.0.1:8888/_acl/external-auth/callback",
            )),
            &mut tls_resolver,
        )
        .await
        .unwrap();
        let provider = activation.provider_registry().get("webhook").unwrap();
        let binding = activation
            .provider_output_binding(activation.provider_registry(), "webhook", "token")
            .unwrap();
        let credentials = ProviderCredentialSet::single_value_for_test(
            binding.output(),
            1,
            b"raw-provider-secret",
        );
        let snapshot: &dyn AuthorizationSnapshot = &*activation;
        let material = snapshot
            .compact_provider_credential_wire(provider, &credentials, &body_guard())
            .unwrap();
        assert_eq!(material.output_len(binding.output()), Some(19));
        let mut destination = [0; 19];
        material
            .copy_output(binding.output(), &mut destination)
            .unwrap();
        assert_eq!(&destination, b"raw-provider-secret");

        let (_, _, owners) = activation.into_parts();
        assert!(owners.is_empty());
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
        let activation = activate(
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

        let _: &dyn AuthorizationSnapshot = &snapshot;
        let decision = snapshot
            .dispatch_process_for_test(
                provider,
                request("request-1"),
                &body_guard(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        let AuthorizationDecision::Allow(output) = decision else {
            panic!("expected the process provider to allow the request");
        };
        let (credentials, replacement) = snapshot
            .consume_allow_output(provider, output)
            .expect("the dispatch output is bound to its snapshot and provider");
        assert!(credentials.is_none());
        assert!(replacement.is_none());
        let foreign =
            ProviderRegistry::from_names(["unused-a".to_string(), "unused-z".to_string()])
                .get("unused-z")
                .unwrap();
        let foreign_provider_output = snapshot
            .dispatch_process_for_test(
                provider,
                request("request-provider-binding"),
                &body_guard(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        let AuthorizationDecision::Allow(foreign_provider_output) = foreign_provider_output else {
            panic!("expected the process provider to allow the request");
        };
        assert!(snapshot
            .consume_allow_output(foreign, foreign_provider_output)
            .is_none());
        assert!(matches!(
            snapshot
                .dispatch_process_for_test(
                    foreign,
                    request("request-2"),
                    &body_guard(),
                    Instant::now() + Duration::from_secs(5),
                )
                .await,
            Err(AuthorizationDispatchError::UnknownProvider)
        ));
        cleanup(&owners).await;
    }

    #[test]
    fn allow_output_transfers_and_releases_owned_replacement() {
        let (pool, quota_key, guard) = body_guard_with_pool();
        let mut body = guard.buffer();
        body.try_extend_from_slice(b"owned replacement").unwrap();
        let body = body.finish();
        let charge = body.charged_bytes();
        let provider = ProviderRegistry::from_names(["test".to_owned()])
            .get("test")
            .unwrap();
        let output = AuthorizationAllowOutput {
            snapshot_id: 1,
            provider,
            credentials: None,
            replacement: Some(ProviderBodyReplacement::from_decoded_for_test(body)),
        };

        assert_eq!(pool.global_charge(), charge);
        assert_eq!(pool.quota_charge(&quota_key), charge);

        let AuthorizationAllowOutput {
            credentials,
            replacement,
            ..
        } = output;
        assert!(credentials.is_none());
        assert_eq!(pool.global_charge(), charge);

        drop(replacement);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);
    }

    #[tokio::test]
    async fn http_wire_body_pool_is_global_and_pass_safe() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "pass.py",
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id":request["id"],"type":"response","decision":"pass"}, separators=(",", ":")), flush=True)
"#,
        );
        let activation = activate(
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
            let mut publication = owner.publication_guard().unwrap();
            publication.commit();
        }

        let (pool, quota_key, guard) = body_guard_with_pool();
        let mut body = guard.buffer();
        body.try_extend_from_slice(b"retained request body")
            .unwrap();
        let body = body.finish();
        let body_charge = body.charged_bytes();
        assert_eq!(guard.live_bytes(), body_charge);
        assert_eq!(pool.global_charge(), body_charge);
        assert_eq!(pool.quota_charge(&quota_key), body_charge);

        let _: &dyn AuthorizationSnapshot = &snapshot;
        assert!(matches!(
            snapshot
                .dispatch_process_for_test(
                    provider,
                    request("request-pass"),
                    &guard,
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .unwrap(),
            AuthorizationDecision::Pass
        ));
        assert_eq!(guard.live_bytes(), body_charge);
        assert_eq!(pool.global_charge(), body_charge);
        assert_eq!(pool.quota_charge(&quota_key), body_charge);

        let mut successor = guard.buffer();
        successor
            .try_extend_from_slice(b"pass-reachable successor work")
            .unwrap();
        let successor = successor.finish();
        let successor_charge = successor.charged_bytes();
        assert_eq!(guard.live_bytes(), body_charge + successor_charge);
        assert_eq!(pool.global_charge(), body_charge + successor_charge);
        assert_eq!(
            pool.quota_charge(&quota_key),
            body_charge + successor_charge
        );

        let peer_key =
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)), |_| false);
        let peer_guard = pool.begin_for_test(2 * 1024 * 1024, peer_key.clone());
        let mut concurrent = peer_guard.buffer();
        concurrent
            .try_extend_from_slice(b"concurrent request")
            .unwrap();
        let concurrent = concurrent.finish();
        let concurrent_charge = concurrent.charged_bytes();
        assert_eq!(peer_guard.live_bytes(), concurrent_charge);
        assert_eq!(pool.quota_charge(&peer_key), concurrent_charge);
        assert_eq!(
            pool.global_charge(),
            body_charge + successor_charge + concurrent_charge
        );

        let body = guard.transfer_body(body).unwrap();
        assert_eq!(body.len(), b"retained request body".len());
        drop(body);
        assert_eq!(guard.live_bytes(), successor_charge);
        assert_eq!(pool.global_charge(), successor_charge + concurrent_charge);
        drop(successor);
        drop(concurrent);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(peer_guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);
        assert_eq!(pool.quota_charge(&peer_key), 0);
        cleanup(&owners).await;
    }

    #[tokio::test]
    async fn pre_cancelled_activation_starts_no_provider() {
        let cancellation = cancellation();
        let tls_io = crate::tls_io_runtime::TlsIoRuntime::new().unwrap();
        let mut tls_resolver = CandidateTlsResolver::activate(
            Arc::clone(&tls_io),
            cancellation.clone(),
            PolicyGeneration::new(7).unwrap(),
        )
        .await
        .expect("test host system roots load");
        cancellation.cancel_for_test();
        let plan = authorization_plan(BTreeMap::new());
        let result = ProductAuthorizationSnapshot::activate(
            plan,
            ProviderRegistry::from_names(std::iter::empty()),
            WebhookAuthorizationRuntime::for_test(None),
            &mut tls_resolver,
        )
        .await;
        assert!(matches!(
            result,
            Err(AuthorizationActivationError::Cancelled)
        ));
        assert_eq!(tls_resolver.file_reads(), 0);
        tls_io.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    async fn mismatched_provider_registry_is_rejected_before_spawn() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "idle.py",
            "import time\nwhile True:\n    time.sleep(1)\n",
        );
        let plan = authorization_plan(BTreeMap::from([(
            "configured".to_string(),
            AuthorizationProviderPlan::Process(process_plan(&directory, &script)),
        )]));
        let activations = AtomicUsize::new(0);
        let result = ProductAuthorizationSnapshot::activate_with_hook(
            plan,
            ProviderRegistry::from_names(["different".to_string()]),
            WebhookAuthorizationRuntime::for_test(None),
            crate::tls_io_runtime::TlsIoRuntime::new().unwrap(),
            PolicyGeneration::new(7).unwrap(),
            cancellation(),
            |_| {
                activations.fetch_add(1, Ordering::AcqRel);
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(AuthorizationActivationError::ProviderRegistryMismatch)
        ));
        assert_eq!(activations.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn cancellation_after_process_activation_cleans_and_reaps_exactly_once() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            "idle-until-cancelled.py",
            "import time\nwhile True:\n    time.sleep(1)\n",
        );
        let plan = authorization_plan(BTreeMap::from([(
            "provider".to_string(),
            AuthorizationProviderPlan::Process(process_plan(&directory, &script)),
        )]));
        let provider_registry = ProviderRegistry::from_names(plan.providers.keys().cloned());
        let cancellation = cancellation();
        let observed = Arc::new(Mutex::new(None));
        let hook_observed = observed.clone();
        let hook_cancellation = cancellation.clone();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            ProductAuthorizationSnapshot::activate_with_hook(
                plan,
                provider_registry,
                WebhookAuthorizationRuntime::for_test(None),
                crate::tls_io_runtime::TlsIoRuntime::new().unwrap(),
                PolicyGeneration::new(7).unwrap(),
                cancellation,
                move |provider| {
                    let pid = provider.child_id().expect("activated provider has a child");
                    *hook_observed.lock().unwrap() = Some((provider.clone(), pid));
                    hook_cancellation.cancel_for_test();
                },
            ),
        )
        .await
        .expect("cancelled activation completes cleanup");

        assert!(matches!(
            result,
            Err(AuthorizationActivationError::Cancelled)
        ));
        let (provider, pid) = observed
            .lock()
            .unwrap()
            .take()
            .expect("hook observed the activated provider");
        assert_eq!(provider.cleanup_starts(), 1);
        // SAFETY: signal zero only checks whether the child PID still exists.
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
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

        let result = activate(
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

        let result = activate(
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
            pids.push(wait_for_pid_file(pid_file).await);
        }

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
