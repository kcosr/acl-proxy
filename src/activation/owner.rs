use std::fmt;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use crate::runtime::{BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError};

pub(crate) struct ProductGenerationOwner {
    owners: Box<[Arc<dyn GenerationOwner>]>,
    cleanup: Arc<CleanupState>,
}

struct CleanupState {
    started: AtomicBool,
    complete: AtomicBool,
    changed: Notify,
}

struct ProductPublicationGuard<'owner> {
    guards: Box<[Box<dyn PublicationGuard + 'owner>]>,
    _not_send: PhantomData<Rc<()>>,
}

impl ProductGenerationOwner {
    pub(crate) fn new(owners: impl IntoIterator<Item = Arc<dyn GenerationOwner>>) -> Self {
        Self {
            owners: owners.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            cleanup: Arc::new(CleanupState {
                started: AtomicBool::new(false),
                complete: AtomicBool::new(false),
                changed: Notify::new(),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self::new([])
    }
}

impl fmt::Debug for ProductGenerationOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductGenerationOwner")
            .field("owner_count", &self.owners.len())
            .finish()
    }
}

impl PublicationGuard for ProductPublicationGuard<'_> {
    fn commit(&mut self) {
        for (owner_index, guard) in self.guards.iter_mut().enumerate() {
            if catch_unwind(AssertUnwindSafe(|| guard.commit())).is_err() {
                tracing::error!(
                    owner_index,
                    "generation sub-owner panicked while committing publication"
                );
            }
        }
    }
}

impl GenerationOwner for ProductGenerationOwner {
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
        let mut guards = Vec::with_capacity(self.owners.len());
        for (owner_index, owner) in self.owners.iter().enumerate() {
            match catch_unwind(AssertUnwindSafe(|| owner.publication_guard())) {
                Ok(Ok(guard)) => guards.push(guard),
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    tracing::error!(
                        owner_index,
                        "generation sub-owner panicked during publication liveness check"
                    );
                    return Err(RuntimeError::CandidateNotLive(
                        "generation resource failed its publication liveness check".to_string(),
                    ));
                }
            }
        }
        Ok(Box::new(ProductPublicationGuard {
            guards: guards.into_boxed_slice(),
            _not_send: PhantomData,
        }))
    }

    fn retirement_started(&self, reason: CleanupReason) {
        for (owner_index, owner) in self.owners.iter().enumerate() {
            if catch_unwind(AssertUnwindSafe(|| owner.retirement_started(reason))).is_err() {
                tracing::error!(
                    owner_index,
                    ?reason,
                    "generation sub-owner panicked while starting retirement"
                );
            }
        }
    }

    fn cleanup(&self, reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self
                .cleanup
                .started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let owners = self.owners.to_vec();
                let state = self.cleanup.clone();
                // The supervisor owns cleanup to completion even if this caller is cancelled.
                std::mem::drop(tokio::spawn(async move {
                    let tasks = owners
                        .into_iter()
                        .map(|owner| {
                            tokio::spawn(async move {
                                owner.cleanup(reason).await;
                            })
                        })
                        .collect::<Vec<_>>();

                    for task in tasks {
                        let _ = task.await;
                    }
                    state.complete.store(true, Ordering::Release);
                    state.changed.notify_waiters();
                }));
            }

            loop {
                let changed = self.cleanup.changed.notified();
                if self.cleanup.complete.load(Ordering::Acquire) {
                    return;
                }
                changed.await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Acquire(usize),
        GuardDrop(usize),
        Commit(usize),
        Retirement(usize),
        Cleanup(usize),
    }

    struct FakeOwner {
        index: usize,
        events: Arc<Mutex<Vec<Event>>>,
        guard_error: bool,
        guard_panic: bool,
        commit_panic: bool,
        retirement_panic: bool,
        cleanup_panic: bool,
        cleanup_calls: AtomicUsize,
        cleanup_started: Option<Arc<Notify>>,
        cleanup_release: Option<Arc<Notify>>,
    }

    struct FakeGuard {
        index: usize,
        events: Arc<Mutex<Vec<Event>>>,
        commit_panic: bool,
        _not_send: Rc<()>,
    }

    impl Drop for FakeGuard {
        fn drop(&mut self) {
            self.events
                .lock()
                .unwrap()
                .push(Event::GuardDrop(self.index));
        }
    }

    impl PublicationGuard for FakeGuard {
        fn commit(&mut self) {
            self.events.lock().unwrap().push(Event::Commit(self.index));
            assert!(!self.commit_panic, "test commit panic");
        }
    }

    impl GenerationOwner for FakeOwner {
        fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
            self.events.lock().unwrap().push(Event::Acquire(self.index));
            assert!(!self.guard_panic, "test acquisition panic");
            if self.guard_error {
                return Err(RuntimeError::CandidateNotLive(
                    "test sub-owner is unavailable".to_string(),
                ));
            }
            Ok(Box::new(FakeGuard {
                index: self.index,
                events: self.events.clone(),
                commit_panic: self.commit_panic,
                _not_send: Rc::new(()),
            }))
        }

        fn retirement_started(&self, _reason: CleanupReason) {
            self.events
                .lock()
                .unwrap()
                .push(Event::Retirement(self.index));
            assert!(!self.retirement_panic, "test retirement panic");
        }

        fn cleanup(&self, _reason: CleanupReason) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
                self.events.lock().unwrap().push(Event::Cleanup(self.index));
                if let Some(started) = &self.cleanup_started {
                    started.notify_one();
                }
                if let Some(release) = &self.cleanup_release {
                    release.notified().await;
                }
                assert!(!self.cleanup_panic, "test cleanup panic");
            })
        }
    }

    fn fake_owner(
        index: usize,
        events: &Arc<Mutex<Vec<Event>>>,
        guard_error: bool,
        retirement_panic: bool,
        cleanup_panic: bool,
    ) -> Arc<FakeOwner> {
        Arc::new(FakeOwner {
            index,
            events: events.clone(),
            guard_error,
            guard_panic: false,
            commit_panic: false,
            retirement_panic,
            cleanup_panic,
            cleanup_calls: AtomicUsize::new(0),
            cleanup_started: None,
            cleanup_release: None,
        })
    }

    fn aggregate(owners: &[Arc<FakeOwner>]) -> ProductGenerationOwner {
        ProductGenerationOwner::new(
            owners
                .iter()
                .cloned()
                .map(|owner| owner as Arc<dyn GenerationOwner>),
        )
    }

    #[test]
    fn publication_guards_are_acquired_committed_and_dropped_in_stable_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owners = [
            fake_owner(0, &events, false, false, false),
            fake_owner(1, &events, false, false, false),
        ];
        let aggregate = aggregate(&owners);

        let mut guard = aggregate.publication_guard().unwrap();
        guard.commit();
        drop(guard);

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                Event::Acquire(0),
                Event::Acquire(1),
                Event::Commit(0),
                Event::Commit(1),
                Event::GuardDrop(0),
                Event::GuardDrop(1),
            ]
        );
    }

    #[test]
    fn later_publication_failure_drops_every_earlier_guard() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owners = [
            fake_owner(0, &events, false, false, false),
            fake_owner(1, &events, true, false, false),
            fake_owner(2, &events, false, false, false),
        ];
        let aggregate = aggregate(&owners);

        let error = match aggregate.publication_guard() {
            Ok(_) => panic!("publication unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            RuntimeError::CandidateNotLive("test sub-owner is unavailable".to_string())
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec![Event::Acquire(0), Event::Acquire(1), Event::GuardDrop(0),]
        );
    }

    #[test]
    fn commit_panic_is_contained_and_later_guards_still_commit() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first = fake_owner(0, &events, false, false, false);
        let panicking = Arc::new(FakeOwner {
            index: 1,
            events: events.clone(),
            guard_error: false,
            guard_panic: false,
            commit_panic: true,
            retirement_panic: false,
            cleanup_panic: false,
            cleanup_calls: AtomicUsize::new(0),
            cleanup_started: None,
            cleanup_release: None,
        });
        let last = fake_owner(2, &events, false, false, false);
        let aggregate = aggregate(&[first, panicking, last]);

        let mut guard = aggregate.publication_guard().unwrap();
        guard.commit();
        drop(guard);

        let events = events.lock().unwrap();
        assert!(events.contains(&Event::Commit(0)));
        assert!(events.contains(&Event::Commit(1)));
        assert!(events.contains(&Event::Commit(2)));
    }

    #[tokio::test]
    async fn acquisition_panic_drops_earlier_guards_and_candidate_cleanup_can_run() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first = fake_owner(0, &events, false, false, false);
        let panicking = Arc::new(FakeOwner {
            index: 1,
            events: events.clone(),
            guard_error: false,
            guard_panic: true,
            commit_panic: false,
            retirement_panic: false,
            cleanup_panic: false,
            cleanup_calls: AtomicUsize::new(0),
            cleanup_started: None,
            cleanup_release: None,
        });
        let last = fake_owner(2, &events, false, false, false);
        let owners = [first, panicking, last];
        let aggregate = aggregate(&owners);

        let error = match aggregate.publication_guard() {
            Ok(_) => panic!("publication unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            RuntimeError::CandidateNotLive(
                "generation resource failed its publication liveness check".to_string()
            )
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec![Event::Acquire(0), Event::Acquire(1), Event::GuardDrop(0)]
        );

        aggregate.cleanup(CleanupReason::CandidateRejected).await;
        assert!(owners
            .iter()
            .all(|owner| owner.cleanup_calls.load(Ordering::Acquire) == 1));
    }

    #[test]
    fn thread_affine_sub_guard_is_supported_and_aggregate_guard_is_thread_affine() {
        trait AmbiguousIfSend<Marker> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        struct Invalid;
        impl<T: ?Sized + Send> AmbiguousIfSend<Invalid> for T {}

        let _ = <ProductPublicationGuard<'static> as AmbiguousIfSend<_>>::check;

        let events = Arc::new(Mutex::new(Vec::new()));
        let owners = [fake_owner(0, &events, false, false, false)];
        let aggregate = aggregate(&owners);
        let guard = aggregate.publication_guard().unwrap();
        drop(guard);
    }

    #[test]
    fn retirement_panic_is_contained_per_owner() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owners = [
            fake_owner(0, &events, false, true, false),
            fake_owner(1, &events, false, false, false),
        ];
        let aggregate = aggregate(&owners);

        aggregate.retirement_started(CleanupReason::Retired);

        assert_eq!(
            *events.lock().unwrap(),
            vec![Event::Retirement(0), Event::Retirement(1)]
        );
    }

    #[tokio::test]
    async fn cleanup_is_idempotent_and_one_panicking_owner_does_not_suppress_others() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owners = [
            fake_owner(0, &events, false, false, true),
            fake_owner(1, &events, false, false, false),
        ];
        let aggregate = aggregate(&owners);

        aggregate.cleanup(CleanupReason::Shutdown).await;
        aggregate.cleanup(CleanupReason::Shutdown).await;

        assert_eq!(owners[0].cleanup_calls.load(Ordering::Acquire), 1);
        assert_eq!(owners[1].cleanup_calls.load(Ordering::Acquire), 1);
        let events = events.lock().unwrap();
        assert!(events.contains(&Event::Cleanup(0)));
        assert!(events.contains(&Event::Cleanup(1)));
    }

    #[tokio::test]
    async fn cleanup_supervisor_survives_caller_cancellation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let owner = Arc::new(FakeOwner {
            index: 0,
            events,
            guard_error: false,
            guard_panic: false,
            commit_panic: false,
            retirement_panic: false,
            cleanup_panic: false,
            cleanup_calls: AtomicUsize::new(0),
            cleanup_started: Some(started.clone()),
            cleanup_release: Some(release.clone()),
        });
        let aggregate = Arc::new(aggregate(std::slice::from_ref(&owner)));

        let cleanup_owner = aggregate.clone();
        let first = tokio::spawn(async move {
            cleanup_owner
                .cleanup(CleanupReason::CandidateRejected)
                .await;
        });
        started.notified().await;
        first.abort();
        let _ = first.await;
        release.notify_one();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            aggregate.cleanup(CleanupReason::CandidateRejected),
        )
        .await
        .expect("independent cleanup supervisor did not complete");
        assert_eq!(owner.cleanup_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn empty_owner_has_a_trivial_guard_and_cleanup() {
        let owner = ProductGenerationOwner::empty();
        let mut guard = owner.publication_guard().unwrap();
        guard.commit();
        drop(guard);
        owner.cleanup(CleanupReason::CandidateRejected).await;
        owner.retirement_started(CleanupReason::Retired);
    }
}
