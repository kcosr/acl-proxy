use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use crate::config::{ReloadableProductPlan, RuntimeCandidate, StaticFingerprint};

use super::generation::{ActivatedGeneration, GenerationId};
use super::StaticResourceBrand;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub(crate) struct ActivationCancellation {
    inner: Arc<ActivationCancellationInner>,
}

struct ActivationCancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl ActivationCancellation {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ActivationCancellationInner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    pub(super) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn check(&self) -> Result<(), RuntimeError> {
        if self.is_cancelled() {
            Err(RuntimeError::ActivationCancelled)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self::new()
    }

    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.cancel();
    }
}

pub(crate) trait CandidateSource: Send + Sync {
    /// Reads and purely compiles the newest candidate. No side effects should
    /// occur here; activation owns material resolution and process startup.
    fn load_latest(
        &self,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<RuntimeCandidate, RuntimeError>>;
}

pub(crate) trait CandidateActivator: Send + Sync {
    /// Proves that activation uses the exact process-static resource owner
    /// supplied to the runtime, not merely an equivalent configuration.
    fn static_resource_brand(&self) -> &StaticResourceBrand;

    /// Identifies the process-lifetime configuration used to construct this
    /// activator and its static admission/runtime state.
    fn static_fingerprint(&self) -> &StaticFingerprint;

    /// Consumes the unresolved plan. The returned value must contain only
    /// resolved handles and adapter-local indices. Logical reference names and
    /// redaction environment locators may not survive this boundary; credential
    /// locators remain encapsulated only in the opaque late resolver. Before
    /// returning `Err`, implementations must synchronously terminate and join
    /// every resource created during the attempt. The core has no owner handle
    /// with which to clean a failed partial activation.
    fn activate(
        &self,
        id: GenerationId,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<ActivatedGeneration, RuntimeError>>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RuntimeError {
    #[error("candidate source failed: {0}")]
    CandidateSource(String),
    #[error("candidate activation failed: {0}")]
    CandidateActivation(String),
    #[error("candidate activation was cancelled")]
    ActivationCancelled,
    #[error("reload changes restart-required static configuration")]
    StaticFingerprintChanged,
    #[error("static configuration fingerprint could not be derived")]
    StaticFingerprintDerivationFailed,
    #[error("claimed static configuration fingerprint does not match canonical configuration")]
    StaticOwnershipFingerprintMismatch,
    #[error("candidate activator is bound to different static configuration")]
    ActivatorStaticFingerprintMismatch,
    #[error("candidate activator is bound to a different static resource owner")]
    ActivatorStaticResourceMismatch,
    #[error("publishing would exceed the retiring-generation ceiling ({limit})")]
    RetiringGenerationLimit { limit: usize },
    #[error("runtime is not accepting reloads")]
    NotRunning,
    #[error("runtime is shutting down")]
    ShuttingDown,
    #[error("initial generation has already been published")]
    AlreadyStarted,
    #[error("candidate failed its final pre-publication liveness check: {0}")]
    CandidateNotLive(String),
    #[error("activation coordinator task failed")]
    CoordinatorTask,
}
