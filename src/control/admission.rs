use std::fmt;
use std::sync::{Arc, Mutex, TryLockError};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::http1::store::{ParserStore, PARSER_STORE_BYTES};

#[derive(Clone)]
pub(crate) struct ControlParserArena {
    inner: Arc<ArenaInner>,
}

struct ArenaInner {
    maximum: usize,
    state: Mutex<ArenaState>,
    #[cfg(test)]
    admission_contentions: AtomicUsize,
}

struct ArenaState {
    available: Vec<ParserStore>,
    live: usize,
}

impl ControlParserArena {
    pub(crate) fn try_new(max_connections: usize) -> Result<Self, ControlArenaError> {
        Self::try_new_with(max_connections, || {
            ParserStore::try_new().map_err(|_| ControlArenaError::Allocation)
        })
    }

    fn try_new_with(
        max_connections: usize,
        mut allocate: impl FnMut() -> Result<ParserStore, ControlArenaError>,
    ) -> Result<Self, ControlArenaError> {
        if max_connections == 0 {
            return Err(ControlArenaError::ZeroConnections);
        }
        max_connections
            .checked_mul(PARSER_STORE_BYTES)
            .ok_or(ControlArenaError::CapacityOverflow)?;

        let mut available = Vec::new();
        available
            .try_reserve_exact(max_connections)
            .map_err(|_| ControlArenaError::Allocation)?;
        for _ in 0..max_connections {
            available.push(allocate()?);
        }
        Ok(Self {
            inner: Arc::new(ArenaInner {
                maximum: max_connections,
                state: Mutex::new(ArenaState { available, live: 0 }),
                #[cfg(test)]
                admission_contentions: AtomicUsize::new(0),
            }),
        })
    }

    pub(crate) fn try_acquire(&self) -> Result<ControlConnectionLease, ControlAdmissionError> {
        let mut state = match self.inner.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                #[cfg(test)]
                self.inner
                    .admission_contentions
                    .fetch_add(1, Ordering::SeqCst);
                self.inner
                    .state
                    .lock()
                    .map_err(|_| ControlAdmissionError::Poisoned)?
            }
            Err(TryLockError::Poisoned(_)) => return Err(ControlAdmissionError::Poisoned),
        };
        let store = state
            .available
            .pop()
            .ok_or(ControlAdmissionError::AtCapacity)?;
        state.live = state
            .live
            .checked_add(1)
            .ok_or(ControlAdmissionError::Poisoned)?;
        Ok(ControlConnectionLease {
            arena: Arc::clone(&self.inner),
            store: Some(store),
        })
    }

    pub(crate) fn counts(&self) -> ControlArenaCounts {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ControlArenaCounts {
            maximum: self.inner.maximum,
            live: state.live,
            available: state.available.len(),
        }
    }
}

pub(crate) struct ControlConnectionLease {
    arena: Arc<ArenaInner>,
    store: Option<ParserStore>,
}

impl ControlConnectionLease {
    pub(crate) fn parser_store(&self) -> &ParserStore {
        self.store
            .as_ref()
            .expect("control connection lease always owns its parser store")
    }

    pub(crate) fn parser_store_mut(&mut self) -> &mut ParserStore {
        self.store
            .as_mut()
            .expect("control connection lease always owns its parser store")
    }

    pub(crate) fn prepare_for_next_request(&mut self) -> Result<(), ControlReuseError> {
        if self.parser_store().initialized_len() != 0 {
            return Err(ControlReuseError::PipelinedBytesRemain);
        }
        self.parser_store_mut().wipe();
        Ok(())
    }
}

impl Drop for ControlConnectionLease {
    fn drop(&mut self) {
        let mut store = self
            .store
            .take()
            .expect("control connection lease always owns its parser store");
        store.wipe();
        let mut state = self
            .arena
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.available.push(store);
        state.live = state
            .live
            .checked_sub(1)
            .expect("live control lease count cannot underflow");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlArenaCounts {
    pub(crate) maximum: usize,
    pub(crate) live: usize,
    pub(crate) available: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlArenaError {
    Allocation,
    CapacityOverflow,
    ZeroConnections,
}

impl fmt::Display for ControlArenaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("could not allocate the control parser arena"),
            Self::CapacityOverflow => {
                formatter.write_str("control parser arena capacity multiplication overflowed")
            }
            Self::ZeroConnections => {
                formatter.write_str("control parser arena requires a positive connection count")
            }
        }
    }
}

impl std::error::Error for ControlArenaError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlAdmissionError {
    AtCapacity,
    Poisoned,
}

impl fmt::Display for ControlAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtCapacity => formatter.write_str("control connection capacity exhausted"),
            Self::Poisoned => formatter.write_str("control connection admission gate failed"),
        }
    }
}

impl std::error::Error for ControlAdmissionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlReuseError {
    PipelinedBytesRemain,
}

impl fmt::Display for ControlReuseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PipelinedBytesRemain => {
                formatter.write_str("control connection has unread pipelined bytes")
            }
        }
    }
}

impl std::error::Error for ControlReuseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn control_connection_slot_and_parser_buffer_release_atomically() {
        let arena = ControlParserArena::try_new(1).unwrap();
        let mut lease = arena.try_acquire().unwrap();
        lease
            .parser_store_mut()
            .append(b"sensitive callback")
            .unwrap();
        assert_eq!(
            arena.counts(),
            ControlArenaCounts {
                maximum: 1,
                live: 1,
                available: 0,
            }
        );
        assert!(matches!(
            arena.try_acquire(),
            Err(ControlAdmissionError::AtCapacity)
        ));

        drop(lease);

        assert_eq!(
            arena.counts(),
            ControlArenaCounts {
                maximum: 1,
                live: 0,
                available: 1,
            }
        );
        let lease = arena.try_acquire().unwrap();
        assert_eq!(lease.parser_store().initialized_len(), 0);
        assert!(lease
            .parser_store()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn allocation_failure_never_admits_a_connection_slot() {
        let result = ControlParserArena::try_new_with(2, || Err(ControlArenaError::Allocation));
        assert!(matches!(result, Err(ControlArenaError::Allocation)));
    }

    #[test]
    fn arena_rejects_zero_and_checked_capacity_overflow() {
        assert!(matches!(
            ControlParserArena::try_new(0),
            Err(ControlArenaError::ZeroConnections)
        ));
        assert!(matches!(
            ControlParserArena::try_new(usize::MAX),
            Err(ControlArenaError::CapacityOverflow)
        ));
    }

    #[test]
    fn subcapacity_concurrent_admission_never_fails_on_mutex_contention() {
        const THREADS: usize = 8;
        const ITERATIONS: usize = 1_000;
        let arena = ControlParserArena::try_new(THREADS).unwrap();
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut workers = Vec::new();
        for _ in 0..THREADS {
            let arena = arena.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..ITERATIONS {
                    let lease = arena
                        .try_acquire()
                        .expect("subcapacity acquisition must survive mutex contention");
                    thread::yield_now();
                    drop(lease);
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(arena.counts().live, 0);
        assert_eq!(arena.counts().available, THREADS);
    }

    #[test]
    fn admission_waits_for_ordinary_mutex_contention_then_succeeds() {
        let arena = ControlParserArena::try_new(1).unwrap();
        let held_state = arena.inner.state.lock().unwrap();
        let worker_arena = arena.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = worker_arena.try_acquire().map(drop);
            result_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while arena.inner.admission_contentions.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "worker did not observe held admission mutex"
            );
            thread::yield_now();
        }
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        drop(held_state);

        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(())
        );
        worker.join().unwrap();
    }

    #[test]
    fn control_keep_alive_reuse_requires_an_empty_store_and_full_wipe() {
        let arena = ControlParserArena::try_new(1).unwrap();
        let mut lease = arena.try_acquire().unwrap();
        lease.parser_store_mut().append(b"handled request").unwrap();
        let handled = lease.parser_store().initialized_len();
        lease.parser_store_mut().consume_prefix(handled).unwrap();
        let before = lease.parser_store().zeroized_bytes_for_test();

        lease.prepare_for_next_request().unwrap();

        assert_eq!(
            lease.parser_store().zeroized_bytes_for_test() - before,
            PARSER_STORE_BYTES
        );
        assert!(lease
            .parser_store()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn control_keep_alive_reuse_rejects_pipelined_bytes_before_drop_wipes() {
        let arena = ControlParserArena::try_new(1).unwrap();
        let mut lease = arena.try_acquire().unwrap();
        lease
            .parser_store_mut()
            .append(b"GET /next HTTP/1.1\r\n\r\n")
            .unwrap();

        assert_eq!(
            lease.prepare_for_next_request(),
            Err(ControlReuseError::PipelinedBytesRemain)
        );
        assert_eq!(
            lease.parser_store().initialized(),
            b"GET /next HTTP/1.1\r\n\r\n"
        );
        drop(lease);

        let lease = arena.try_acquire().unwrap();
        assert_eq!(lease.parser_store().initialized_len(), 0);
        assert!(lease
            .parser_store()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));
    }
}
