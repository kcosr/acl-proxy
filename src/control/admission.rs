use std::fmt;
use std::sync::{Arc, Mutex, TryLockError};

use crate::http1::store::{ParserStore, PARSER_STORE_BYTES};

#[derive(Clone)]
pub(crate) struct ControlParserArena {
    inner: Arc<ArenaInner>,
}

struct ArenaInner {
    maximum: usize,
    state: Mutex<ArenaState>,
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
            }),
        })
    }

    pub(crate) fn try_acquire(&self) -> Result<ControlConnectionLease, ControlAdmissionError> {
        let mut state = match self.inner.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(ControlAdmissionError::Busy),
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

    pub(crate) fn wipe_for_next_request(&mut self) {
        self.parser_store_mut().wipe();
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
    Busy,
    Poisoned,
}

impl fmt::Display for ControlAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtCapacity => formatter.write_str("control connection capacity exhausted"),
            Self::Busy => formatter.write_str("control connection admission gate is busy"),
            Self::Poisoned => formatter.write_str("control connection admission gate failed"),
        }
    }
}

impl std::error::Error for ControlAdmissionError {}

#[cfg(test)]
mod tests {
    use super::*;

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
}
