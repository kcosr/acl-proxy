use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use access_tls_trust::{
    PreparedTlsClientTrust, PreparedTlsTrustCandidate, TlsClientTrustMode, TlsClientTrustPlan,
    TlsTrustFileSource, TlsTrustGeneration,
};
use http_access_types::PolicyGeneration;

use crate::runtime::ActivationCancellation;
use crate::tls::TlsActivationError;
use crate::tls_io_runtime::{TlsIoRuntime, TlsTrustRetentionLease};

const MAX_LOGICAL_TRUST_SCOPES: usize = 258;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct TrustScopeKey {
    mode: TlsClientTrustMode,
    custom_path: Option<PathBuf>,
}

struct TrustSource {
    source: TlsTrustFileSource,
}

/// Complete, pre-I/O set of client trust requirements for one candidate.
pub(crate) struct CandidateTlsPlanSet {
    plans: BTreeMap<TrustScopeKey, TlsClientTrustPlan>,
    sources: BTreeMap<PathBuf, TrustSource>,
}

impl CandidateTlsPlanSet {
    pub(crate) fn new() -> Self {
        Self {
            plans: BTreeMap::new(),
            sources: BTreeMap::new(),
        }
    }

    pub(crate) fn register(
        &mut self,
        mode: TlsClientTrustMode,
        custom_path: Option<&Path>,
    ) -> Result<(), TlsActivationError> {
        let custom_path = custom_path.map(Path::to_path_buf);
        let custom_source = match custom_path.as_ref() {
            Some(path) => {
                if !self.sources.contains_key(path) {
                    let source =
                        TlsTrustFileSource::new(path.clone()).map_err(TlsActivationError::from)?;
                    self.sources.insert(path.clone(), TrustSource { source });
                }
                Some(
                    self.sources
                        .get(path)
                        .expect("registered TLS trust source is present")
                        .source
                        .authored_source_id(),
                )
            }
            None => None,
        };
        let plan =
            TlsClientTrustPlan::new(mode, custom_source).map_err(TlsActivationError::from)?;
        self.plans.insert(TrustScopeKey { mode, custom_path }, plan);
        if self.plans.len() > MAX_LOGICAL_TRUST_SCOPES {
            return Err(TlsActivationError::ResourceLimit);
        }
        Ok(())
    }
}

/// Generation-bound prepared TLS trust shared by every candidate consumer.
pub(crate) struct CandidateTlsResolver {
    cancellation: ActivationCancellation,
    generation: PolicyGeneration,
    plans: BTreeMap<TrustScopeKey, TlsClientTrustPlan>,
    candidate: PreparedTlsTrustCandidate,
    retention: Option<TlsTrustRetentionLease>,
    #[cfg(test)]
    custom_acquisitions: usize,
}

impl CandidateTlsResolver {
    #[cfg(test)]
    pub(crate) async fn activate(
        tls_io_runtime: Arc<TlsIoRuntime>,
        cancellation: ActivationCancellation,
        generation: PolicyGeneration,
    ) -> Result<Self, TlsActivationError> {
        let mut plans = CandidateTlsPlanSet::new();
        plans.register(TlsClientTrustMode::System, None)?;
        Self::activate_with_plans(tls_io_runtime, cancellation, generation, plans).await
    }

    pub(crate) async fn activate_with_plans(
        tls_io_runtime: Arc<TlsIoRuntime>,
        cancellation: ActivationCancellation,
        generation: PolicyGeneration,
        plan_set: CandidateTlsPlanSet,
    ) -> Result<Self, TlsActivationError> {
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        let tls_generation =
            TlsTrustGeneration::new(generation.get()).map_err(TlsActivationError::from)?;
        let CandidateTlsPlanSet { plans, sources } = plan_set;
        #[cfg(test)]
        let acquisitions_before = tls_io_runtime.custom_acquisitions_for_test();
        let (candidate, retention) = tls_io_runtime
            .prepare_candidate(
                tls_generation,
                plans.values().copied().collect(),
                sources.into_values().map(|source| source.source).collect(),
                &cancellation,
            )
            .await?;
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        Ok(Self {
            cancellation,
            generation,
            plans,
            candidate,
            retention: Some(retention),
            #[cfg(test)]
            custom_acquisitions: tls_io_runtime
                .custom_acquisitions_for_test()
                .checked_sub(acquisitions_before)
                .expect("candidate custom-acquisition counter is monotonic"),
        })
    }

    pub(crate) fn generation(&self) -> PolicyGeneration {
        self.generation
    }

    pub(crate) fn cancellation(&self) -> &ActivationCancellation {
        &self.cancellation
    }

    pub(crate) fn prepared(
        &self,
        mode: TlsClientTrustMode,
        custom_path: Option<&Path>,
    ) -> Result<Arc<PreparedTlsClientTrust>, TlsActivationError> {
        self.check_cancellation()?;
        let key = TrustScopeKey {
            mode,
            custom_path: custom_path.map(Path::to_path_buf),
        };
        let plan = self
            .plans
            .get(&key)
            .ok_or(TlsActivationError::InvalidPlan)?;
        self.candidate
            .prepared(plan)
            .ok_or(TlsActivationError::InvalidPlan)
    }

    pub(crate) fn into_generation_owner(mut self) -> TlsTrustGenerationOwner {
        TlsTrustGenerationOwner {
            retention: std::sync::Mutex::new(self.retention.take()),
        }
    }

    fn check_cancellation(&self) -> Result<(), TlsActivationError> {
        if self.cancellation.is_cancelled() {
            Err(TlsActivationError::ActivationCancelled)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn file_reads(&self) -> usize {
        self.custom_acquisitions
    }
}

pub(crate) struct TlsTrustGenerationOwner {
    retention: std::sync::Mutex<Option<TlsTrustRetentionLease>>,
}

struct TlsTrustPublicationGuard;

impl crate::runtime::PublicationGuard for TlsTrustPublicationGuard {
    fn commit(&mut self) {}
}

impl crate::runtime::GenerationOwner for TlsTrustGenerationOwner {
    fn publication_guard(
        &self,
    ) -> Result<Box<dyn crate::runtime::PublicationGuard + '_>, crate::runtime::RuntimeError> {
        if self
            .retention
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none()
        {
            return Err(crate::runtime::RuntimeError::CandidateNotLive(
                "TLS trust generation is no longer retained".to_owned(),
            ));
        }
        Ok(Box::new(TlsTrustPublicationGuard))
    }

    fn retirement_started(&self, _reason: crate::runtime::CleanupReason) {}

    fn cleanup(&self, _reason: crate::runtime::CleanupReason) -> crate::runtime::BoxFuture<'_, ()> {
        Box::pin(async move {
            self.retention
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        })
    }
}
