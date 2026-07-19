use std::sync::atomic::{AtomicU8, Ordering};

const RUNTIME_PUBLISHED: u8 = 1 << 0;
const INGRESS_STARTED: u8 = 1 << 1;
const CLOSED: u8 = 1 << 2;
const READY: u8 = RUNTIME_PUBLISHED | INGRESS_STARTED;

/// Process-lifetime readiness shared by the runtime and static resources.
/// Once shutdown closes the gate, no later publication can make it ready.
pub(crate) struct ServiceReadiness {
    state: AtomicU8,
}

impl ServiceReadiness {
    pub(crate) fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }

    pub(super) fn mark_runtime_published(&self) {
        self.mark(RUNTIME_PUBLISHED);
    }

    pub(crate) fn mark_ingress_started(&self) {
        self.mark(INGRESS_STARTED);
    }

    fn mark(&self, bit: u8) {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & CLOSED != 0 || state & bit != 0 {
                return;
            }
            match self.state.compare_exchange_weak(
                state,
                state | bit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(current) => state = current,
            }
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.state.store(CLOSED, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn mark_ready_for_test(&self) {
        self.mark_runtime_published();
        self.mark_ingress_started();
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
        readiness.mark_ingress_started();
        readiness.mark_runtime_published();

        assert!(!readiness.is_ready());
    }

    #[test]
    fn readiness_requires_runtime_publication_and_started_ingress_in_either_order() {
        let publication_first = ServiceReadiness::new();
        publication_first.mark_runtime_published();
        assert!(!publication_first.is_ready());
        publication_first.mark_ingress_started();
        assert!(publication_first.is_ready());

        let ingress_first = ServiceReadiness::new();
        ingress_first.mark_ingress_started();
        assert!(!ingress_first.is_ready());
        ingress_first.mark_runtime_published();
        assert!(ingress_first.is_ready());
    }
}
