use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use tokio::sync::Notify;

use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput};

use super::*;

struct EmptySnapshot;

impl PolicySnapshot for EmptySnapshot {}
impl EgressSnapshot for EmptySnapshot {}
impl AuthorizationSnapshot for EmptySnapshot {}
impl CredentialResolver for EmptySnapshot {}
impl RedactionSnapshot for EmptySnapshot {}
impl ObservationSnapshot for EmptySnapshot {}
impl SafetySnapshot for EmptySnapshot {}

#[derive(Default)]
struct FakeOwner {
    commits: AtomicUsize,
    candidate_cleanups: AtomicUsize,
    retirements: AtomicUsize,
    shutdowns: AtomicUsize,
    reject_publication: AtomicBool,
    panic_cleanup: AtomicBool,
    block_commit: AtomicBool,
    commit_released: Mutex<bool>,
    commit_release: Condvar,
    commit_started: AtomicBool,
    commit_entered: Notify,
    cleanup_events: Option<Arc<Mutex<Vec<CleanupReason>>>>,
}

struct FakePublicationGuard<'a> {
    owner: &'a FakeOwner,
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
        Ok(Box::new(FakePublicationGuard { owner: self }))
    }

    fn cleanup(&self, reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.panic_cleanup.swap(false, Ordering::AcqRel) {
                panic!("fake cleanup panic");
            }
            if let Some(events) = &self.cleanup_events {
                events.lock().unwrap().push(reason);
            }
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

#[derive(Default)]
struct FakeStaticResources {
    shutdowns: AtomicUsize,
}

impl StaticResources for FakeStaticResources {
    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.shutdowns.fetch_add(1, Ordering::AcqRel);
        })
    }
}

#[derive(Default)]
struct FakeSource {
    configs: Mutex<VecDeque<String>>,
    calls: AtomicUsize,
}

impl FakeSource {
    fn push(&self, config: String) {
        self.configs.lock().unwrap().push_back(config);
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
            let text = self
                .configs
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| RuntimeError::CandidateSource("no fake config queued".into()))?;
            compile(&text).map_err(RuntimeError::CandidateSource)
        })
    }
}

#[derive(Default)]
struct FakeActivator {
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
}

impl FakeActivator {
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
}

impl CandidateActivator for FakeActivator {
    fn activate(
        &self,
        _id: GenerationId,
        plan: crate::config::ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<ActivatedGeneration, RuntimeError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let owner = Arc::new(FakeOwner {
                cleanup_events: Some(self.cleanup_events.clone()),
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

            let snapshot = Arc::new(EmptySnapshot);
            Ok(ActivatedGeneration {
                request_timeout: plan.request_timeout,
                max_content_decoding_expansion_ratio: plan.max_content_decoding_expansion_ratio,
                resource_plan: plan.resource_plan,
                bindings: ResolvedBindings::default(),
                policy: snapshot.clone(),
                egress: snapshot.clone(),
                authorization: snapshot.clone(),
                credentials: snapshot.clone(),
                redaction: snapshot.clone(),
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

fn runtime_fixture(
    initial: &str,
) -> (
    Arc<Runtime>,
    crate::config::ReloadableProductPlan,
    Arc<FakeSource>,
    Arc<FakeActivator>,
    Arc<FakeStaticResources>,
) {
    let compiled = compile(initial).expect("compile initial config");
    let source = Arc::new(FakeSource::default());
    let activator = Arc::new(FakeActivator::default());
    let static_resources = Arc::new(FakeStaticResources::default());
    let static_ownership = StaticOwnership::new(
        compiled.static_config,
        compiled.static_fingerprint,
        static_resources.clone(),
    );
    let runtime = Runtime::new(static_ownership, source.clone(), activator.clone());
    (
        runtime,
        compiled.reloadable_plan,
        source,
        activator,
        static_resources,
    )
}

async fn wait_for_retiring(runtime: &Runtime, expected: usize) {
    for _ in 0..1000 {
        if runtime.retiring_generations() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "retiring generation count did not reach {expected}; current={}",
        runtime.retiring_generations()
    );
}

#[tokio::test]
async fn initial_publish_installs_one_ready_generation() {
    let (runtime, initial, _source, activator, _static_resources) =
        runtime_fixture(&config("30s", "127.0.0.1:8881", 2));

    let id = runtime.start(initial).await.expect("initial publish");

    assert_eq!(id.get(), 1);
    assert_eq!(runtime.lifecycle(), LifecycleState::Running);
    assert!(runtime.is_ready());
    assert_eq!(runtime.active_generation_id(), Some(id));
    assert_eq!(activator.owner(0).commits.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn reload_is_atomic_and_static_fingerprint_rejection_preserves_active() {
    let initial_text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&initial_text);
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
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
    runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();
    let old_owner = activator.owner(0);
    source.push(config("31s", "127.0.0.1:8881", 2));

    runtime.trigger_reload().await.unwrap();
    wait_for_retiring(&runtime, 1).await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 0);

    drop(old_lease);
    wait_for_retiring(&runtime, 0).await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
    tokio::task::yield_now().await;
    assert_eq!(old_owner.retirements.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn cleanup_panic_cannot_pin_retiring_count_or_shutdown() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, _source, activator, static_resources) = runtime_fixture(&text);
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
async fn rejected_publication_cleans_candidate_and_preserves_active() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
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
}

#[tokio::test]
async fn completed_retirement_supervisors_are_reaped_incrementally() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, source, _activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, _source, _activator, _static_resources) = runtime_fixture(&text);
    runtime.start(initial).await.unwrap();
    let old_lease = runtime.lease().await.unwrap();
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

    runtime.release_lease_before_acquire();
    assert_eq!(waiter.await.unwrap(), None);
    assert!(
        !shutdown.is_finished(),
        "lease waiter must finish before drain"
    );

    drop(old_lease);
    shutdown.await.unwrap();
    assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_wins_blocked_reload_and_cleans_candidate_before_active() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, _static_resources) = runtime_fixture(&text);
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
    let (runtime, initial, _source, activator, static_resources) = runtime_fixture(&text);
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
}

#[tokio::test]
async fn publication_winner_is_the_generation_shutdown_drains() {
    let text = config("30s", "127.0.0.1:8881", 2);
    let (runtime, initial, source, activator, static_resources) = runtime_fixture(&text);
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
