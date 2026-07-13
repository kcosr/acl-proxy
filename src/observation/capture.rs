use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, TryLockError};

use crate::runtime::{BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError};

/// One process-wide capture byte pool shared by every active and retiring
/// observation epoch. Admission uses atomic accounting and never waits or delays
/// the wire path.
pub(crate) struct CapturePool {
    publication_gate: RwLock<()>,
    committed_limit: AtomicUsize,
    used: AtomicUsize,
}

impl fmt::Debug for CapturePool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturePool")
            .field("committed_limit", &self.committed_limit())
            .field("used", &self.used())
            .finish()
    }
}

impl CapturePool {
    /// Creates the pool owned once by `ProductActivator` and shared with every
    /// observation generation it activates.
    pub(crate) fn new(initial_limit: usize) -> Arc<Self> {
        Arc::new(Self {
            publication_gate: RwLock::new(()),
            committed_limit: AtomicUsize::new(initial_limit),
            used: AtomicUsize::new(0),
        })
    }

    /// Attempts an exact capture-owned byte reservation. Failure is immediate
    /// and observation-only; callers omit the payload rather than wait.
    pub(crate) fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<CapturePermit> {
        self.try_acquire_with_hook(bytes, || {})
    }

    fn try_acquire_with_hook(
        self: &Arc<Self>,
        bytes: usize,
        hook: impl FnOnce(),
    ) -> Option<CapturePermit> {
        let _publication = match self.publication_gate.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        hook();
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(bytes)?;
            if next > self.committed_limit.load(Ordering::Acquire) {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Some(CapturePermit {
            pool: self.clone(),
            bytes,
        })
    }

    pub(crate) fn committed_limit(&self) -> usize {
        self.committed_limit.load(Ordering::Acquire)
    }

    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    fn commit_limit(&self, limit: usize) {
        let _publication = self
            .publication_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.committed_limit.store(limit, Ordering::Release);
    }

    #[cfg(test)]
    fn commit_limit_with_hook(&self, limit: usize, hook: impl FnOnce()) {
        let _publication = self
            .publication_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hook();
        self.committed_limit.store(limit, Ordering::Release);
    }

    fn release(&self, bytes: usize) {
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        assert!(previous >= bytes, "capture permit accounting underflow");
    }
}

pub(crate) struct CapturePermit {
    pool: Arc<CapturePool>,
    bytes: usize,
}

impl CapturePermit {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl fmt::Debug for CapturePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturePermit")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for CapturePermit {
    fn drop(&mut self) {
        self.pool.release(self.bytes);
    }
}

/// Candidate-owned publication effect. Constructing or dropping an update has
/// no effect on the active capture ceiling; only publication commit changes it.
pub(crate) struct CaptureLimitUpdate {
    pool: Arc<CapturePool>,
    proposed_limit: usize,
}

impl fmt::Debug for CaptureLimitUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureLimitUpdate")
            .field("proposed_limit", &self.proposed_limit)
            .finish()
    }
}

impl CaptureLimitUpdate {
    pub(crate) fn new(pool: Arc<CapturePool>, proposed_limit: usize) -> Self {
        Self {
            pool,
            proposed_limit,
        }
    }

    pub(crate) fn publication_guard(&self) -> CaptureLimitPublicationGuard<'_> {
        CaptureLimitPublicationGuard {
            update: self,
            committed: false,
        }
    }

    pub(crate) fn proposed_limit(&self) -> usize {
        self.proposed_limit
    }
}

impl GenerationOwner for CaptureLimitUpdate {
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
        Ok(Box::new(CaptureLimitUpdate::publication_guard(self)))
    }

    fn retirement_started(&self, _reason: CleanupReason) {}

    fn cleanup(&self, _reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

pub(crate) struct CaptureLimitPublicationGuard<'update> {
    update: &'update CaptureLimitUpdate,
    committed: bool,
}

impl PublicationGuard for CaptureLimitPublicationGuard<'_> {
    fn commit(&mut self) {
        if !self.committed {
            self.update.pool.commit_limit(self.update.proposed_limit);
            self.committed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use super::*;

    #[test]
    fn rejected_update_does_not_change_the_committed_limit() {
        let pool = CapturePool::new(16);
        let update = CaptureLimitUpdate::new(pool.clone(), 32);
        {
            let _rejected_guard = update.publication_guard();
        }
        assert_eq!(pool.committed_limit(), 16);
    }

    #[test]
    fn publication_commit_changes_the_limit_once() {
        let pool = CapturePool::new(16);
        let update = CaptureLimitUpdate::new(pool.clone(), 32);
        let mut guard = update.publication_guard();
        guard.commit();
        guard.commit();
        assert_eq!(pool.committed_limit(), 32);
    }

    #[test]
    fn old_permits_survive_a_lower_limit_and_new_admission_uses_it() {
        let pool = CapturePool::new(16);
        let old = pool.try_acquire(12).expect("old permit");
        let update = CaptureLimitUpdate::new(pool.clone(), 4);
        update.publication_guard().commit();

        assert_eq!(pool.used(), 12);
        assert!(pool.try_acquire(1).is_none());
        drop(old);
        assert_eq!(pool.used(), 0);
        assert_eq!(pool.try_acquire(4).expect("new limit").bytes(), 4);
    }

    #[test]
    fn exact_permits_saturate_without_waiting() {
        let pool = CapturePool::new(10);
        let first = pool.try_acquire(6).expect("first");
        let second = pool.try_acquire(4).expect("second");
        assert!(pool.try_acquire(1).is_none());
        assert_eq!(pool.used(), 10);
        drop((first, second));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn arithmetic_overflow_is_an_observation_only_omission() {
        let pool = CapturePool::new(usize::MAX);
        let permit = pool.try_acquire(usize::MAX).expect("maximum permit");
        assert!(pool.try_acquire(1).is_none());
        drop(permit);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn concurrent_admissions_share_the_limit_gate() {
        let pool = CapturePool::new(16);
        let first_entered = Arc::new(Barrier::new(2));
        let finish_first = Arc::new(Barrier::new(2));
        let first_pool = pool.clone();
        let first = thread::spawn({
            let first_entered = first_entered.clone();
            let finish_first = finish_first.clone();
            move || {
                first_pool.try_acquire_with_hook(4, || {
                    first_entered.wait();
                    finish_first.wait();
                })
            }
        });

        first_entered.wait();
        let second = pool
            .try_acquire(4)
            .expect("another admission may enter while the first holds a read gate");
        finish_first.wait();
        let first = first.join().expect("first admission thread").unwrap();

        assert_eq!(pool.used(), 8);
        drop((first, second));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn lower_limit_publication_excludes_stale_limit_admission() {
        let pool = CapturePool::new(16);
        let existing = pool.try_acquire(8).expect("existing permit");
        let publication_entered = Arc::new(Barrier::new(2));
        let finish_publication = Arc::new(Barrier::new(2));
        let publication_pool = pool.clone();
        let publisher = thread::spawn({
            let publication_entered = publication_entered.clone();
            let finish_publication = finish_publication.clone();
            move || {
                publication_pool.commit_limit_with_hook(8, || {
                    publication_entered.wait();
                    finish_publication.wait();
                });
            }
        });

        publication_entered.wait();
        assert!(pool.try_acquire(1).is_none());
        finish_publication.wait();
        publisher.join().expect("publisher");

        assert_eq!(pool.committed_limit(), 8);
        assert!(pool.try_acquire(1).is_none());
        drop(existing);
    }
}
