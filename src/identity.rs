use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use access_async_contracts::{AccessCancellation, BoxAccessFuture};
use access_flow::{AccessFlowAdmission, AccessFlowAdmissionInput};
use access_identity::{
    AdmittedIdentity, IdentityFingerprintKey, IdentityPresentation, IdentityResolver,
    SensitiveBearer, StaticGroup, StaticPrincipal, StaticResolver, StaticResolverBuilder,
    StaticToken, MAX_BEARER_LEN,
};
use http_access_runtime::{
    BoxFuture, ForwardingCancellation, HttpBearerAdmission, HttpBearerAdmissionError,
    HttpBearerAdmissionInput, HttpConnectionAuthenticationCapacity,
};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};

use crate::config::compiler::{IdentityPlan, IdentitySourcePlan};
use crate::credentials::{read_environment_credential, CredentialError};
use crate::identity_file::read_trusted_identity_file;
use crate::runtime::PublicationGuard;

#[derive(Debug, thiserror::Error)]
pub(crate) enum IdentityActivationError {
    #[error("identity process hardening failed")]
    ProcessHardening,
    #[error("identity source is unavailable")]
    SourceUnavailable,
    #[error("identity material is invalid")]
    InvalidMaterial,
    #[error("identity resolver activation failed")]
    Resolver,
    #[error("identity resolver configuration change requires a process restart")]
    RestartRequired,
}

pub(crate) struct IdentitySourceRegistry {
    initial_resolver_environment: Mutex<BTreeMap<IdentitySourcePlan, Zeroizing<Vec<u8>>>>,
    parent_environment: Mutex<BTreeMap<IdentitySourcePlan, SensitiveBearer>>,
    environment_sealed: AtomicBool,
}

pub(crate) struct ActivatedIdentitySources {
    material: BTreeMap<IdentitySourcePlan, Zeroizing<Vec<u8>>>,
}

impl ActivatedIdentitySources {
    pub(crate) fn bearer(
        &self,
        source: &IdentitySourcePlan,
    ) -> Result<SensitiveBearer, IdentityActivationError> {
        SensitiveBearer::new(
            self.material
                .get(source)
                .ok_or(IdentityActivationError::SourceUnavailable)?,
        )
        .map_err(|_| IdentityActivationError::InvalidMaterial)
    }
}

impl Drop for ActivatedIdentitySources {
    fn drop(&mut self) {
        for value in self.material.values_mut() {
            value.zeroize();
        }
    }
}

impl IdentitySourceRegistry {
    pub(crate) fn activate() -> Result<Arc<Self>, IdentityActivationError> {
        suppress_process_dumps()?;
        Ok(Arc::new(Self {
            initial_resolver_environment: Mutex::new(BTreeMap::new()),
            parent_environment: Mutex::new(BTreeMap::new()),
            environment_sealed: AtomicBool::new(false),
        }))
    }

    pub(crate) fn preload(
        &self,
        plan: &crate::config::compiler::ReloadableProductPlan,
    ) -> Result<(), IdentityActivationError> {
        let resolver_sources = plan
            .identity
            .iter()
            .flat_map(|identity| identity.tokens.iter())
            .filter_map(|token| match &token.source {
                source @ IdentitySourcePlan::Environment { .. } => Some(source.clone()),
                IdentitySourcePlan::File { .. } => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        let parent_source = plan
            .egress
            .parent_proxy
            .iter()
            .filter_map(|parent| parent.presentation.as_ref())
            .find_map(|source| match source {
                source @ IdentitySourcePlan::Environment { .. } => Some(source.clone()),
                IdentitySourcePlan::File { .. } => None,
            });
        self.preload_selected_environment_sources(resolver_sources, parent_source)
    }

    fn preload_selected_environment_sources(
        &self,
        resolver_sources: std::collections::BTreeSet<IdentitySourcePlan>,
        parent_source: Option<IdentitySourcePlan>,
    ) -> Result<(), IdentityActivationError> {
        if self.environment_sealed.swap(true, Ordering::AcqRel) {
            return Err(IdentityActivationError::SourceUnavailable);
        }
        let mut all_sources = resolver_sources.clone();
        all_sources.extend(parent_source.iter().cloned());

        let mut first_error = None;
        for source in all_sources {
            let IdentitySourcePlan::Environment { variable } = &source else {
                unreachable!("preload union contains only environment locators");
            };
            match read_and_remove_environment(variable) {
                Ok(material) => {
                    if resolver_sources.contains(&source) {
                        lock(&self.initial_resolver_environment)
                            .insert(source.clone(), Zeroizing::new(material.to_vec()));
                    }
                    if parent_source.as_ref() == Some(&source) {
                        match SensitiveBearer::new(&material) {
                            Ok(bearer) => {
                                lock(&self.parent_environment).insert(source, bearer);
                            }
                            Err(_) if first_error.is_none() => {
                                first_error = Some(IdentityActivationError::InvalidMaterial);
                            }
                            Err(_) => {}
                        }
                    }
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn activate_candidate(
        &self,
        resolver: Option<&IdentityPlan>,
        parent: Option<&IdentitySourcePlan>,
    ) -> Result<ActivatedIdentitySources, IdentityActivationError> {
        let resolver_sources = resolver
            .into_iter()
            .flat_map(|plan| plan.tokens.iter().map(|token| &token.source))
            .collect::<std::collections::BTreeSet<_>>();
        let mut all_sources = resolver_sources.clone();
        all_sources.extend(parent);
        let mut material = BTreeMap::new();
        for source in all_sources {
            let activated = match source {
                IdentitySourcePlan::Environment { .. } if resolver_sources.contains(source) => {
                    lock(&self.initial_resolver_environment)
                        .remove(source)
                        .ok_or(IdentityActivationError::RestartRequired)?
                }
                IdentitySourcePlan::Environment { .. } => {
                    let parent = lock(&self.parent_environment);
                    let bearer = parent
                        .get(source)
                        .ok_or(IdentityActivationError::RestartRequired)?;
                    Zeroizing::new(bearer.expose(|value| value.to_vec()))
                }
                IdentitySourcePlan::File { path } => read_trusted_identity_file(path)
                    .map_err(|_| IdentityActivationError::SourceUnavailable)?,
            };
            SensitiveBearer::new(&activated)
                .map_err(|_| IdentityActivationError::InvalidMaterial)?;
            material.insert(source.clone(), activated);
        }
        Ok(ActivatedIdentitySources { material })
    }

    #[cfg(test)]
    fn resolver_environment_entries_for_test(&self) -> usize {
        lock(&self.initial_resolver_environment).len()
    }
}

impl Drop for IdentitySourceRegistry {
    fn drop(&mut self) {
        let material = self
            .initial_resolver_environment
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for value in material.values_mut() {
            value.zeroize();
        }
    }
}

pub(crate) struct IdentityPublisher {
    fingerprint_key: IdentityFingerprintKey,
    state: Mutex<IdentityPublisherState>,
    accepting: AtomicBool,
    #[cfg(test)]
    admission_gate: Mutex<Option<Arc<IdentityAdmissionGate>>>,
}

#[cfg(test)]
pub(crate) struct IdentityAdmissionGate {
    entered: AtomicUsize,
    entered_changed: Notify,
    releases: Semaphore,
}

#[cfg(test)]
impl IdentityAdmissionGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicUsize::new(0),
            entered_changed: Notify::new(),
            releases: Semaphore::new(0),
        })
    }

    async fn hold(&self) {
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.entered_changed.notify_waiters();
        self.releases
            .acquire()
            .await
            .expect("test admission gate remains open")
            .forget();
    }

    pub(crate) async fn wait_for_entries(&self, expected: usize) {
        loop {
            let changed = self.entered_changed.notified();
            if self.entered.load(Ordering::Acquire) >= expected {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn release(&self, count: usize) {
        self.releases.add_permits(count);
    }
}

struct IdentityPublisherState {
    generation: Option<Arc<IdentityGeneration>>,
    plan_key: Option<IdentityPlanKey>,
    connection_capacity: HttpConnectionAuthenticationCapacity,
    published: bool,
}

impl Default for IdentityPublisherState {
    fn default() -> Self {
        Self {
            generation: None,
            plan_key: None,
            connection_capacity: HttpConnectionAuthenticationCapacity::new(1)
                .expect("one is a valid connection authentication capacity"),
            published: false,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct IdentityPlanKey(IdentityPlan);

impl IdentityPlanKey {
    fn contains_environment(&self) -> bool {
        self.0
            .tokens
            .iter()
            .any(|token| matches!(token.source, IdentitySourcePlan::Environment { .. }))
    }
}

struct IdentityGeneration {
    resolver: Arc<StaticResolver>,
    cancellation: Arc<ForwardingCancellation>,
    capacity: Arc<Semaphore>,
    max_pending_authentications: usize,
}

impl IdentityPublisher {
    pub(crate) fn activate() -> Result<Arc<Self>, IdentityActivationError> {
        let fingerprint_key =
            IdentityFingerprintKey::generate().map_err(|_| IdentityActivationError::Resolver)?;
        Ok(Arc::new(Self {
            fingerprint_key,
            state: Mutex::new(IdentityPublisherState::default()),
            accepting: AtomicBool::new(true),
            #[cfg(test)]
            admission_gate: Mutex::new(None),
        }))
    }

    pub(crate) fn stage(
        self: &Arc<Self>,
        plan: Option<IdentityPlan>,
        connection_capacity: HttpConnectionAuthenticationCapacity,
        parent_source: Option<&IdentitySourcePlan>,
        sources: &IdentitySourceRegistry,
    ) -> Result<(Arc<IdentityCandidateLease>, Option<SensitiveBearer>), IdentityActivationError>
    {
        let plan_key = plan.as_ref().cloned().map(IdentityPlanKey);
        let (candidate, build_resolver) = {
            let state = lock(&self.state);
            let active_has_environment = state
                .plan_key
                .as_ref()
                .is_some_and(IdentityPlanKey::contains_environment);
            let candidate_has_environment = plan_key
                .as_ref()
                .is_some_and(IdentityPlanKey::contains_environment);
            if state.published && (active_has_environment || candidate_has_environment) {
                if state.plan_key != plan_key {
                    return Err(IdentityActivationError::RestartRequired);
                }
                (state.generation.clone(), false)
            } else {
                (None, plan.is_some())
            }
        };
        let resolver_plan = if build_resolver { plan.as_ref() } else { None };
        let activated = sources.activate_candidate(resolver_plan, parent_source)?;
        let candidate = if build_resolver {
            plan.map(|plan| self.activate_generation(plan, &activated))
                .transpose()?
        } else {
            candidate
        };
        let parent = parent_source
            .map(|source| activated.bearer(source))
            .transpose()?;
        let candidate_is_fresh = build_resolver && candidate.is_some();
        Ok((
            Arc::new(IdentityCandidateLease {
                publisher: Arc::clone(self),
                candidate: Mutex::new(candidate),
                candidate_is_fresh,
                plan_key: Mutex::new(plan_key),
                connection_capacity,
                selected: Mutex::new(None),
            }),
            parent,
        ))
    }

    fn activate_generation(
        &self,
        plan: IdentityPlan,
        sources: &ActivatedIdentitySources,
    ) -> Result<Arc<IdentityGeneration>, IdentityActivationError> {
        let expected_resources = plan.resources;
        let principals = plan
            .principals
            .into_iter()
            .map(|principal| StaticPrincipal {
                id: principal.id,
                kind: principal.kind,
            })
            .collect();
        let groups = plan
            .groups
            .into_iter()
            .map(|group| StaticGroup {
                id: group.id,
                members: group.members.into_boxed_slice(),
            })
            .collect();
        let tokens = plan
            .tokens
            .into_iter()
            .map(|token| {
                Ok(StaticToken {
                    id: token.id,
                    principal: token.principal,
                    bearer: sources.bearer(&token.source)?,
                })
            })
            .collect::<Result<Vec<_>, IdentityActivationError>>()?;
        let resolver =
            StaticResolverBuilder::new(plan.authority, plan.audience, &self.fingerprint_key)
                .principals(principals)
                .groups(groups)
                .tokens(tokens)
                .build()
                .map_err(|_| IdentityActivationError::Resolver)?;
        if resolver.resource_projection() != expected_resources {
            return Err(IdentityActivationError::Resolver);
        }
        Ok(Arc::new(IdentityGeneration {
            resolver: Arc::new(resolver),
            cancellation: Arc::new(ForwardingCancellation::new()),
            capacity: Arc::new(Semaphore::new(plan.max_pending_authentications)),
            max_pending_authentications: plan.max_pending_authentications,
        }))
    }

    pub(crate) fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        if let Some(generation) = lock(&self.state).generation.as_ref() {
            generation.cancellation.cancel();
            generation.capacity.close();
        }
    }

    fn current(&self) -> Result<Arc<IdentityGeneration>, HttpBearerAdmissionError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(HttpBearerAdmissionError::Unavailable);
        }
        lock(&self.state)
            .generation
            .clone()
            .ok_or(HttpBearerAdmissionError::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn generation_marker_for_test(&self) -> Option<usize> {
        lock(&self.state)
            .generation
            .as_ref()
            .map(|generation| Arc::as_ptr(generation) as usize)
    }

    #[cfg(test)]
    pub(crate) fn connection_capacity_for_test(&self) -> usize {
        lock(&self.state).connection_capacity.get()
    }

    #[cfg(test)]
    pub(crate) fn set_admission_gate_for_test(&self, gate: Arc<IdentityAdmissionGate>) {
        *lock(&self.admission_gate) = Some(gate);
    }

    async fn resolve(
        &self,
        bearer: SensitiveBearer,
        deadline: std::time::Instant,
        cancellation: &dyn AccessCancellation,
    ) -> Result<AdmittedIdentity, HttpBearerAdmissionError> {
        let generation = self.current()?;
        let _permit = Arc::clone(&generation.capacity)
            .try_acquire_owned()
            .map_err(|_| HttpBearerAdmissionError::Unavailable)?;
        #[cfg(test)]
        let admission_gate = { lock(&self.admission_gate).clone() };
        #[cfg(test)]
        if let Some(gate) = admission_gate {
            gate.hold().await;
        }
        let audience = access_identity::IdentityAudience::new("acl-proxy.identity")
            .map_err(|_| HttpBearerAdmissionError::Unavailable)?;
        let identity = generation
            .resolver
            .resolve(bearer, &audience, deadline, cancellation)
            .await
            .map_err(|error| match error {
                access_identity::ResolveError::InvalidAudience
                | access_identity::ResolveError::InvalidPresentation
                | access_identity::ResolveError::Expired => HttpBearerAdmissionError::Invalid,
                access_identity::ResolveError::Cancelled
                | access_identity::ResolveError::DeadlineExceeded
                | access_identity::ResolveError::Unavailable => {
                    HttpBearerAdmissionError::Unavailable
                }
                _ => HttpBearerAdmissionError::Unavailable,
            })?;
        let retirement: Arc<dyn AccessCancellation> = generation.cancellation.clone();
        Ok(AdmittedIdentity::authenticated(identity, retirement))
    }
}

impl HttpBearerAdmission for IdentityPublisher {
    fn connection_authentication_capacity(&self) -> HttpConnectionAuthenticationCapacity {
        lock(&self.state).connection_capacity
    }

    fn admit<'a>(
        &'a self,
        input: HttpBearerAdmissionInput<'a>,
    ) -> BoxFuture<'a, Result<AdmittedIdentity, HttpBearerAdmissionError>> {
        let (bearer, deadline, cancellation) = input.into_parts();
        Box::pin(self.resolve(bearer, deadline, cancellation))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessFlowIdentityAdmissionError {
    Invalid,
    Unavailable,
}

impl std::fmt::Display for AccessFlowIdentityAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "identity invalid",
            Self::Unavailable => "identity service unavailable",
        })
    }
}

impl std::error::Error for AccessFlowIdentityAdmissionError {}

impl<C: Send + Sync> AccessFlowAdmission<C> for IdentityPublisher {
    type Facts = AdmittedIdentity;
    type Error = AccessFlowIdentityAdmissionError;

    fn admit<'a>(
        &'a self,
        input: AccessFlowAdmissionInput<'a, C>,
    ) -> BoxAccessFuture<'a, Result<Self::Facts, Self::Error>> {
        Box::pin(async move {
            match input.presentation {
                IdentityPresentation::Disabled => Ok(AdmittedIdentity::disabled()),
                IdentityPresentation::Anonymous => Ok(AdmittedIdentity::anonymous()),
                IdentityPresentation::Bearer(bearer) => {
                    let bearer = bearer
                        .expose(SensitiveBearer::new)
                        .map_err(|_| AccessFlowIdentityAdmissionError::Invalid)?;
                    self.resolve(bearer, input.deadline, input.cancellation)
                        .await
                        .map_err(|error| match error {
                            HttpBearerAdmissionError::Invalid => {
                                AccessFlowIdentityAdmissionError::Invalid
                            }
                            HttpBearerAdmissionError::Unavailable => {
                                AccessFlowIdentityAdmissionError::Unavailable
                            }
                        })
                }
            }
        })
    }
}

pub(crate) struct IdentityCandidateLease {
    publisher: Arc<IdentityPublisher>,
    candidate: Mutex<Option<Arc<IdentityGeneration>>>,
    candidate_is_fresh: bool,
    plan_key: Mutex<Option<IdentityPlanKey>>,
    connection_capacity: HttpConnectionAuthenticationCapacity,
    selected: Mutex<Option<Arc<IdentityGeneration>>>,
}

struct IdentityPublicationGuard<'a> {
    owner: &'a IdentityCandidateLease,
    state: MutexGuard<'a, IdentityPublisherState>,
    committed: bool,
}

impl PublicationGuard for IdentityPublicationGuard<'_> {
    fn commit(&mut self) {
        let candidate = lock(&self.owner.candidate).take();
        let selected = match (self.state.generation.as_ref(), candidate) {
            (Some(active), Some(candidate))
                if active
                    .resolver
                    .generation()
                    .same_generation(candidate.resolver.generation())
                    && active.max_pending_authentications
                        == candidate.max_pending_authentications =>
            {
                Some(Arc::clone(active))
            }
            (_, candidate) => candidate,
        };
        let replaced = std::mem::replace(&mut self.state.generation, selected);
        if let Some(replaced) = replaced {
            let retained = self
                .state
                .generation
                .as_ref()
                .is_some_and(|selected| Arc::ptr_eq(selected, &replaced));
            if !retained {
                replaced.cancellation.cancel();
                replaced.capacity.close();
            }
        }
        self.state.plan_key = lock(&self.owner.plan_key).take();
        self.state.connection_capacity = self.owner.connection_capacity;
        self.state.published = true;
        *lock(&self.owner.selected) = self.state.generation.clone();
        self.committed = true;
    }
}

impl Drop for IdentityPublicationGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // The active publisher state was never modified.
        }
    }
}

impl IdentityCandidateLease {
    pub(crate) fn publication_guard(&self) -> Box<dyn PublicationGuard + '_> {
        Box::new(IdentityPublicationGuard {
            owner: self,
            state: lock(&self.publisher.state),
            committed: false,
        })
    }

    pub(crate) fn reject(&self) {
        if let Some(candidate) = lock(&self.candidate).take() {
            if self.candidate_is_fresh {
                candidate.cancellation.cancel();
                candidate.capacity.close();
            }
        }
    }

    pub(crate) fn release(&self) {
        lock(&self.selected).take();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_and_remove_environment(
    variable: &str,
) -> Result<Zeroizing<Vec<u8>>, IdentityActivationError> {
    let mut staging = Zeroizing::new(vec![0_u8; MAX_BEARER_LEN]);
    let read = read_environment_credential(variable, &mut staging);
    let removed = unset_environment(variable);
    let initialized = match read {
        Ok(initialized) => initialized,
        Err(CredentialError::SourceUnavailable) => {
            removed?;
            return Err(IdentityActivationError::SourceUnavailable);
        }
        Err(_) => {
            removed?;
            return Err(IdentityActivationError::InvalidMaterial);
        }
    };
    removed?;
    SensitiveBearer::new(&staging[..initialized])
        .map_err(|_| IdentityActivationError::InvalidMaterial)?;
    Ok(Zeroizing::new(staging[..initialized].to_vec()))
}

fn unset_environment(variable: &str) -> Result<(), IdentityActivationError> {
    let variable =
        std::ffi::CString::new(variable).map_err(|_| IdentityActivationError::SourceUnavailable)?;
    // SAFETY: the name is NUL-terminated and contains no interior NUL.
    if unsafe { libc::unsetenv(variable.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(IdentityActivationError::SourceUnavailable)
    }
}

fn suppress_process_dumps() -> Result<(), IdentityActivationError> {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the initialized limit for this process.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(IdentityActivationError::ProcessHardening);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE with scalar zero has no pointer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(IdentityActivationError::ProcessHardening);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use access_identity::{AuthorityId, IdentityAudience, PrincipalId, PrincipalKind, TokenId};

    use super::*;
    use crate::config::compiler::{IdentityPlan, IdentityPrincipalPlan, IdentityTokenPlan};
    use crate::runtime::{
        BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError,
    };

    const BEARER_A: &str = "identity-test-bearer-a-0000000000000000";
    const BEARER_B: &str = "identity-test-bearer-b-0000000000000000";
    const BEARER_C: &str = "identity-test-bearer-c-0000000000000000";

    #[cfg(unix)]
    fn trusted_tempdir(prefix: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(std::env::var_os("HOME").unwrap())
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn environment_source(variable: &str) -> IdentitySourcePlan {
        IdentitySourcePlan::Environment {
            variable: variable.to_owned(),
        }
    }

    fn plan(source: IdentitySourcePlan) -> IdentityPlan {
        plan_with_sources(vec![source])
    }

    fn connection_capacity(value: usize) -> HttpConnectionAuthenticationCapacity {
        HttpConnectionAuthenticationCapacity::new(value).unwrap()
    }

    fn plan_with_sources(sources: Vec<IdentitySourcePlan>) -> IdentityPlan {
        let authority = AuthorityId::new("test-authority").unwrap();
        let principals = vec![IdentityPrincipalPlan {
            id: PrincipalId::new("test-service").unwrap(),
            kind: PrincipalKind::ServiceAccount,
        }];
        let groups = vec![];
        let tokens = sources
            .into_iter()
            .enumerate()
            .map(|(index, source)| IdentityTokenPlan {
                id: TokenId::new(format!("test-token-{index}")).unwrap(),
                principal: PrincipalId::new("test-service").unwrap(),
                source,
            })
            .collect::<Vec<_>>();
        IdentityPlan {
            max_pending_authentications: 2,
            resources: crate::config::compiler::project_identity_resources_for_test(
                &authority,
                &principals,
                &groups,
                &tokens,
            ),
            authority,
            audience: IdentityAudience::new("acl-proxy.identity").unwrap(),
            principals,
            groups,
            tokens,
        }
    }

    #[test]
    fn preloaded_environment_is_removed_temporary_and_sealed() {
        const INITIAL: &str = "AW_PRELOAD_IDENTITY_TOKEN";
        const LATE: &str = "AW_LATE_IDENTITY_TOKEN";
        unsafe {
            std::env::set_var(INITIAL, BEARER_A);
            std::env::set_var(LATE, BEARER_B);
        }
        let registry = IdentitySourceRegistry::activate().unwrap();
        let initial = environment_source(INITIAL);
        registry
            .preload_selected_environment_sources(
                std::collections::BTreeSet::from([initial.clone()]),
                None,
            )
            .unwrap();
        assert!(std::env::var_os(INITIAL).is_none());
        assert_eq!(registry.resolver_environment_entries_for_test(), 1);

        let publisher = IdentityPublisher::activate().unwrap();
        let (candidate, parent) = publisher
            .stage(Some(plan(initial)), connection_capacity(2), None, &registry)
            .unwrap();
        assert!(parent.is_none());
        candidate.publication_guard().commit();
        assert_eq!(registry.resolver_environment_entries_for_test(), 0);

        let late = environment_source(LATE);
        let result = publisher.stage(Some(plan(late)), connection_capacity(2), None, &registry);
        assert!(matches!(
            result,
            Err(IdentityActivationError::RestartRequired)
        ));
        assert_eq!(std::env::var(LATE).unwrap(), BEARER_B);
        unsafe {
            std::env::remove_var(LATE);
        }
    }

    #[test]
    fn shared_environment_is_read_once_for_resolver_and_typed_parent() {
        const SHARED: &str = "AW_SHARED_TEST_IDENTITY_TOKEN";
        unsafe {
            std::env::set_var(SHARED, BEARER_A);
        }
        let source = environment_source(SHARED);
        let registry = IdentitySourceRegistry::activate().unwrap();
        registry
            .preload_selected_environment_sources(
                std::collections::BTreeSet::from([source.clone()]),
                Some(source.clone()),
            )
            .unwrap();
        assert!(std::env::var_os(SHARED).is_none());
        assert_eq!(registry.resolver_environment_entries_for_test(), 1);

        let publisher = IdentityPublisher::activate().unwrap();
        let (candidate, parent) = publisher
            .stage(
                Some(plan(source.clone())),
                connection_capacity(2),
                Some(&source),
                &registry,
            )
            .unwrap();
        assert_eq!(registry.resolver_environment_entries_for_test(), 0);
        assert!(parent.unwrap().expose(|value| value == BEARER_A.as_bytes()));
        candidate.publication_guard().commit();

        let (reload, parent) = publisher
            .stage(
                Some(plan(source.clone())),
                connection_capacity(2),
                Some(&source),
                &registry,
            )
            .unwrap();
        assert!(parent.unwrap().expose(|value| value == BEARER_A.as_bytes()));
        reload.publication_guard().commit();
    }

    #[test]
    fn environment_activation_rejects_overflow_and_line_endings_without_trimming() {
        for (variable, value) in [
            (
                "AW_OVERFLOW_TEST_IDENTITY_TOKEN",
                "a".repeat(MAX_BEARER_LEN + 1),
            ),
            ("AW_LF_TEST_IDENTITY_TOKEN", format!("{BEARER_A}\n")),
            ("AW_CRLF_TEST_IDENTITY_TOKEN", format!("{BEARER_A}\r\n")),
        ] {
            unsafe {
                std::env::set_var(variable, value);
            }
            let registry = IdentitySourceRegistry::activate().unwrap();
            let error = registry
                .preload_selected_environment_sources(
                    std::collections::BTreeSet::from([environment_source(variable)]),
                    None,
                )
                .expect_err("invalid exact environment bytes must fail");
            assert!(matches!(error, IdentityActivationError::InvalidMaterial));
            assert!(std::env::var_os(variable).is_none());
            assert_eq!(registry.resolver_environment_entries_for_test(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn process_hardening_precedes_identity_source_reads_in_an_isolated_process() {
        const CHILD: &str = "ACL_PROXY_IDENTITY_HARDENING_CHILD";
        const TOKEN: &str = "AW_IDENTITY_HARDENING_ORDER_TOKEN";
        if std::env::var_os(CHILD).is_some() {
            unsafe {
                std::env::set_var(TOKEN, BEARER_A);
            }
            #[cfg(target_os = "linux")]
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);

            let registry = IdentitySourceRegistry::activate().unwrap();
            let mut core = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_CORE, core.as_mut_ptr()) },
                0
            );
            let core = unsafe { core.assume_init() };
            assert_eq!((core.rlim_cur, core.rlim_max), (0, 0));
            #[cfg(target_os = "linux")]
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
            assert_eq!(std::env::var(TOKEN).unwrap(), BEARER_A);

            registry
                .preload_selected_environment_sources(
                    std::collections::BTreeSet::from([environment_source(TOKEN)]),
                    None,
                )
                .unwrap();
            assert!(std::env::var_os(TOKEN).is_none());
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "identity::tests::process_hardening_precedes_identity_source_reads_in_an_isolated_process",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated hardening proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn candidate_reads_shared_file_locator_once_for_independent_consumers() {
        use std::os::unix::fs::PermissionsExt;

        let directory = trusted_tempdir(".identity-shared-file-");
        let path = directory.path().join("identity-token");
        std::fs::write(&path, BEARER_A).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let source = IdentitySourcePlan::File { path: path.clone() };
        let registry = IdentitySourceRegistry::activate().unwrap();
        let publisher = IdentityPublisher::activate().unwrap();

        let (candidate, parent) = publisher
            .stage(
                Some(plan(source.clone())),
                connection_capacity(2),
                Some(&source),
                &registry,
            )
            .expect("candidate source activation");
        std::fs::remove_file(path).unwrap();

        assert!(parent.unwrap().expose(|bytes| bytes == BEARER_A.as_bytes()));
        candidate.publication_guard().commit();
    }

    #[test]
    fn environment_plan_reuses_exact_generation_and_rejects_every_change() {
        const FIRST: &str = "AW_FIRST_IDENTITY_TOKEN";
        const SECOND: &str = "AW_SECOND_IDENTITY_TOKEN";
        unsafe {
            std::env::set_var(FIRST, BEARER_A);
            std::env::set_var(SECOND, BEARER_B);
        }
        let sources = IdentitySourceRegistry::activate().unwrap();
        let publisher = IdentityPublisher::activate().unwrap();

        let first_source = environment_source(FIRST);
        sources
            .preload_selected_environment_sources(
                std::collections::BTreeSet::from([first_source.clone()]),
                None,
            )
            .unwrap();
        let first_plan = plan(first_source);
        let (first, _) = publisher
            .stage(
                Some(first_plan.clone()),
                connection_capacity(2),
                None,
                &sources,
            )
            .unwrap();
        first.publication_guard().commit();
        let first_generation = lock(&publisher.state).generation.clone().unwrap();

        let (equivalent, _) = publisher
            .stage(
                Some(first_plan.clone()),
                connection_capacity(2),
                None,
                &sources,
            )
            .unwrap();
        equivalent.publication_guard().commit();
        let reused_generation = lock(&publisher.state).generation.clone().unwrap();
        assert!(Arc::ptr_eq(&first_generation, &reused_generation));
        assert!(!first_generation.cancellation.is_cancelled());
        assert_eq!(publisher.connection_authentication_capacity().get(), 2);

        let (capacity_only, _) = publisher
            .stage(
                Some(first_plan.clone()),
                connection_capacity(7),
                None,
                &sources,
            )
            .unwrap();
        capacity_only.publication_guard().commit();
        assert_eq!(publisher.connection_authentication_capacity().get(), 7);
        assert!(Arc::ptr_eq(
            &first_generation,
            lock(&publisher.state).generation.as_ref().unwrap()
        ));
        assert!(!first_generation.cancellation.is_cancelled());

        let (rejected, _) = publisher
            .stage(
                Some(first_plan.clone()),
                connection_capacity(9),
                None,
                &sources,
            )
            .unwrap();
        rejected.reject();
        assert_eq!(publisher.connection_authentication_capacity().get(), 7);
        assert!(Arc::ptr_eq(
            &first_generation,
            lock(&publisher.state).generation.as_ref().unwrap()
        ));
        assert!(!first_generation.cancellation.is_cancelled());

        for changed in [
            None,
            Some(plan(environment_source(SECOND))),
            Some({
                let mut changed = first_plan.clone();
                changed.max_pending_authentications += 1;
                changed
            }),
        ] {
            assert!(matches!(
                publisher.stage(changed, connection_capacity(2), None, &sources),
                Err(IdentityActivationError::RestartRequired)
            ));
        }
        assert!(Arc::ptr_eq(
            &first_generation,
            lock(&publisher.state).generation.as_ref().unwrap()
        ));
        assert!(!first_generation.cancellation.is_cancelled());
        assert_eq!(std::env::var(SECOND).unwrap(), BEARER_B);
        unsafe {
            std::env::remove_var(SECOND);
        }
    }

    #[cfg(unix)]
    #[test]
    fn mixed_environment_file_plan_is_process_static_but_file_only_rotates() {
        use std::os::unix::fs::PermissionsExt;

        const ENVIRONMENT: &str = "AW_MIXED_IDENTITY_TOKEN";
        unsafe {
            std::env::set_var(ENVIRONMENT, BEARER_A);
        }
        let directory = trusted_tempdir(".identity-rotation-");
        let mixed_path = directory.path().join("mixed");
        std::fs::write(&mixed_path, BEARER_B).unwrap();
        std::fs::set_permissions(&mixed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mixed_plan = plan_with_sources(vec![
            environment_source(ENVIRONMENT),
            IdentitySourcePlan::File {
                path: mixed_path.clone(),
            },
        ]);
        let mixed_sources = IdentitySourceRegistry::activate().unwrap();
        mixed_sources
            .preload_selected_environment_sources(
                std::collections::BTreeSet::from([environment_source(ENVIRONMENT)]),
                None,
            )
            .unwrap();
        let mixed_publisher = IdentityPublisher::activate().unwrap();
        let (first, _) = mixed_publisher
            .stage(
                Some(mixed_plan.clone()),
                connection_capacity(2),
                None,
                &mixed_sources,
            )
            .unwrap();
        first.publication_guard().commit();
        let mixed_generation = lock(&mixed_publisher.state).generation.clone().unwrap();
        std::fs::remove_file(&mixed_path).unwrap();
        let (equivalent, _) = mixed_publisher
            .stage(
                Some(mixed_plan),
                connection_capacity(2),
                None,
                &mixed_sources,
            )
            .unwrap();
        equivalent.publication_guard().commit();
        assert!(Arc::ptr_eq(
            &mixed_generation,
            lock(&mixed_publisher.state).generation.as_ref().unwrap()
        ));

        let file_path = directory.path().join("file-only");
        std::fs::write(&file_path, BEARER_A).unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file_plan = plan(IdentitySourcePlan::File {
            path: file_path.clone(),
        });
        let file_sources = IdentitySourceRegistry::activate().unwrap();
        file_sources
            .preload_selected_environment_sources(Default::default(), None)
            .unwrap();
        let file_publisher = IdentityPublisher::activate().unwrap();
        let (first, _) = file_publisher
            .stage(
                Some(file_plan.clone()),
                connection_capacity(2),
                None,
                &file_sources,
            )
            .unwrap();
        first.publication_guard().commit();
        let first_generation = lock(&file_publisher.state).generation.clone().unwrap();

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            file_publisher.stage(
                Some(file_plan.clone()),
                connection_capacity(2),
                None,
                &file_sources
            ),
            Err(IdentityActivationError::SourceUnavailable)
        ));
        assert!(Arc::ptr_eq(
            &first_generation,
            lock(&file_publisher.state).generation.as_ref().unwrap()
        ));
        assert!(!first_generation.cancellation.is_cancelled());

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file_path, BEARER_C).unwrap();
        let (rotated, _) = file_publisher
            .stage(
                Some(file_plan.clone()),
                connection_capacity(2),
                None,
                &file_sources,
            )
            .unwrap();
        rotated.publication_guard().commit();
        let rotated_generation = lock(&file_publisher.state).generation.clone().unwrap();
        assert!(!Arc::ptr_eq(&first_generation, &rotated_generation));
        assert!(first_generation.cancellation.is_cancelled());

        let (equivalent, _) = file_publisher
            .stage(Some(file_plan), connection_capacity(2), None, &file_sources)
            .unwrap();
        equivalent.publication_guard().commit();
        assert!(Arc::ptr_eq(
            &rotated_generation,
            lock(&file_publisher.state).generation.as_ref().unwrap()
        ));
        assert!(!rotated_generation.cancellation.is_cancelled());
    }

    struct NoopGuard;

    impl PublicationGuard for NoopGuard {
        fn commit(&mut self) {}
    }

    struct RecordingProductOwner {
        retirements: AtomicUsize,
    }

    impl GenerationOwner for RecordingProductOwner {
        fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
            Ok(Box::new(NoopGuard))
        }

        fn retirement_started(&self, _reason: CleanupReason) {
            self.retirements.fetch_add(1, Ordering::AcqRel);
        }

        fn cleanup(&self, _reason: CleanupReason) -> BoxFuture<'_, ()> {
            Box::pin(std::future::ready(()))
        }
    }

    #[test]
    fn ordinary_product_retirement_releases_but_never_cancels_reused_identity() {
        const VARIABLE: &str = "AW_RETIREMENT_IDENTITY_TOKEN";
        unsafe {
            std::env::set_var(VARIABLE, BEARER_A);
        }
        let sources = IdentitySourceRegistry::activate().unwrap();
        let publisher = IdentityPublisher::activate().unwrap();
        let source = environment_source(VARIABLE);
        sources
            .preload_selected_environment_sources(
                std::collections::BTreeSet::from([source.clone()]),
                None,
            )
            .unwrap();
        let (lease, _) = publisher
            .stage(Some(plan(source)), connection_capacity(2), None, &sources)
            .unwrap();
        lease.publication_guard().commit();
        let active = lock(&publisher.state).generation.clone().unwrap();
        let product = Arc::new(RecordingProductOwner {
            retirements: AtomicUsize::new(0),
        });
        let owner =
            crate::activation::owner::IdentityBoundGenerationOwner::new(product.clone(), lease);

        owner.retirement_started(CleanupReason::Retired);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(owner.cleanup(CleanupReason::Retired));

        assert_eq!(product.retirements.load(Ordering::Acquire), 1);
        assert!(!active.cancellation.is_cancelled());
        assert!(Arc::ptr_eq(
            &active,
            lock(&publisher.state).generation.as_ref().unwrap()
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_cancels_the_active_generation_and_closes_admission() {
        use std::os::unix::fs::PermissionsExt;

        let directory = trusted_tempdir(".identity-shutdown-");
        let path = directory.path().join("token");
        std::fs::write(&path, BEARER_A).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let source = IdentitySourcePlan::File { path };
        let sources = IdentitySourceRegistry::activate().unwrap();
        sources
            .preload_selected_environment_sources(Default::default(), None)
            .unwrap();
        let publisher = IdentityPublisher::activate().unwrap();
        let (lease, _) = publisher
            .stage(Some(plan(source)), connection_capacity(2), None, &sources)
            .unwrap();
        lease.publication_guard().commit();
        let generation = lock(&publisher.state).generation.clone().unwrap();

        publisher.begin_shutdown();
        publisher.begin_shutdown();

        assert!(!publisher.accepting.load(Ordering::Acquire));
        assert!(generation.cancellation.is_cancelled());
        assert!(generation.capacity.is_closed());
        let cancellation = ForwardingCancellation::new();
        assert_eq!(
            publisher
                .resolve(
                    SensitiveBearer::new(BEARER_A.as_bytes()).unwrap(),
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                    &cancellation,
                )
                .await
                .err(),
            Some(HttpBearerAdmissionError::Unavailable)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn disabled_and_anonymous_access_flows_do_not_consume_authentication_capacity() {
        use access_flow::AccessFlowDestination;
        use std::os::unix::fs::PermissionsExt;

        let directory = trusted_tempdir(".identity-pool-");
        let path = directory.path().join("token");
        std::fs::write(&path, BEARER_A).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sources = IdentitySourceRegistry::activate().unwrap();
        sources
            .preload_selected_environment_sources(Default::default(), None)
            .unwrap();
        let publisher = IdentityPublisher::activate().unwrap();
        let mut identity_plan = plan(IdentitySourcePlan::File { path });
        identity_plan.max_pending_authentications = 1;
        let (lease, _) = publisher
            .stage(Some(identity_plan), connection_capacity(2), None, &sources)
            .unwrap();
        lease.publication_guard().commit();
        let gate = IdentityAdmissionGate::new();
        publisher.set_admission_gate_for_test(Arc::clone(&gate));
        let resolving = {
            let publisher = Arc::clone(&publisher);
            tokio::spawn(async move {
                let cancellation = ForwardingCancellation::new();
                publisher
                    .resolve(
                        SensitiveBearer::new(BEARER_A.as_bytes()).unwrap(),
                        std::time::Instant::now() + std::time::Duration::from_secs(2),
                        &cancellation,
                    )
                    .await
            })
        };
        gate.wait_for_entries(1).await;
        assert_eq!(
            lock(&publisher.state)
                .generation
                .as_ref()
                .unwrap()
                .capacity
                .available_permits(),
            0
        );

        let destination = AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap();
        let cancellation = ForwardingCancellation::new();
        for presentation in [
            IdentityPresentation::Disabled,
            IdentityPresentation::Anonymous,
        ] {
            let admitted = <IdentityPublisher as AccessFlowAdmission<()>>::admit(
                publisher.as_ref(),
                AccessFlowAdmissionInput {
                    destination,
                    presentation: &presentation,
                    channel_facts: &(),
                    deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                    cancellation: &cancellation,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                admitted.context(),
                access_identity::IdentityContext::Disabled
                    | access_identity::IdentityContext::Anonymous
            ));
        }
        assert_eq!(gate.entered.load(Ordering::Acquire), 1);

        gate.release(1);
        assert!(resolving.await.unwrap().is_ok());
    }
}
