use std::sync::atomic::{AtomicU8, Ordering};

const STARTING: u8 = 0;
const READY: u8 = 1;
const CLOSED: u8 = 2;

/// Process-lifetime readiness shared by the runtime and static resources.
/// Once shutdown closes the gate, no later publication can make it ready.
pub(crate) struct ServiceReadiness {
    state: AtomicU8,
}

impl ServiceReadiness {
    pub(crate) fn new() -> Self {
        Self {
            state: AtomicU8::new(STARTING),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }

    pub(super) fn mark_ready(&self) {
        let _ = self
            .state
            .compare_exchange(STARTING, READY, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn begin_shutdown(&self) {
        self.state.store(CLOSED, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceReadiness;

    #[test]
    fn shutdown_gate_is_terminal_and_idempotent() {
        let readiness = ServiceReadiness::new();

        readiness.begin_shutdown();
        readiness.begin_shutdown();
        readiness.mark_ready();

        assert!(!readiness.is_ready());
    }
}
