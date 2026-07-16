use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hyper::rt::Executor;
use tokio::sync::Notify;

tokio::task_local! {
    static CURRENT_H2_STREAM: H2StreamCancellation;
}

struct H2StreamCancellationState {
    cancelled: AtomicBool,
    changed: Notify,
}

#[derive(Clone)]
pub(crate) struct H2StreamCancellation(Arc<H2StreamCancellationState>);

impl H2StreamCancellation {
    pub(crate) fn current() -> Option<Self> {
        CURRENT_H2_STREAM.try_with(Clone::clone).ok()
    }

    pub(crate) fn cancel(&self) {
        if !self.0.cancelled.swap(true, Ordering::AcqRel) {
            self.0.changed.notify_one();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.0.cancelled.load(Ordering::Acquire) {
            return;
        }
        self.0.changed.notified().await;
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct H2StreamExecutor;

impl<F> Executor<F> for H2StreamExecutor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        let cancellation = H2StreamCancellation(Arc::new(H2StreamCancellationState {
            cancelled: AtomicBool::new(false),
            changed: Notify::new(),
        }));
        let scoped_cancellation = cancellation.clone();
        drop(tokio::spawn(CURRENT_H2_STREAM.scope(
            scoped_cancellation,
            async move {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {}
                    _ = future => {}
                }
            },
        )));
    }
}
