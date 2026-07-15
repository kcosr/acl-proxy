use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_access_runtime::{
    BodyBudget, BodyChunkCopy, BodySource, BodySourceEvent, BodyTrailerCopy, RuntimeError,
    RuntimeTrailers,
};
use hyper::body::HttpBody;
use hyper::Body;

use crate::safety::wire_body::{RequestStagingBodyBuilder, WireBodyBufferError};
use crate::safety::{GuardedBody, HttpWireBodyGuard, RequestStagingAuthority};

const MAX_SOURCE_FRAMES: usize = 65_536;
const MAX_BODY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_INTERNAL_EVENTS_PER_POLL: usize = 64;
const COPY_BLOCK_BYTES: usize = 64 * 1024;

enum ActivationState {
    Unarmed,
    Armed(RequestStagingAuthority),
    Claimed,
    Terminal,
}

struct ActivationSlot {
    state: ActivationState,
}

/// A single-use capability that arms its paired [`ProductBodySource`].
pub(crate) struct ProductBodySourceActivation {
    slot: Weak<Mutex<ActivationSlot>>,
}

impl ProductBodySourceActivation {
    /// Installs staging authority branded by the selected request guard.
    pub(crate) fn activate(
        self,
        guard: &HttpWireBodyGuard,
        staging: RequestStagingAuthority,
    ) -> Result<(), RuntimeError> {
        staging
            .validate_guard(guard)
            .map_err(|_| RuntimeError::BindingMismatch)?;
        let slot = self.slot.upgrade().ok_or(RuntimeError::InvalidInput)?;
        let mut slot = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(slot.state, ActivationState::Unarmed) {
            return Err(RuntimeError::InvalidInput);
        }
        slot.state = ActivationState::Armed(staging);
        Ok(())
    }
}

/// The product Hyper-to-runtime request-body adapter.
pub(crate) struct ProductBodySource {
    body: Body,
    activation: Arc<Mutex<ActivationSlot>>,
    staging: Option<RequestStagingAuthority>,
    chunk_bytes: usize,
    trailer_count: usize,
    trailer_bytes: usize,
    presented_frames: usize,
    transport_frame: Option<Bytes>,
    transport_offset: usize,
    pending_progress: bool,
    staging_builder: Option<RequestStagingBodyBuilder>,
    staged_body: Option<GuardedBody>,
    staged_head_offset: usize,
    runtime_copy: Option<BodyChunkCopy>,
    data_ended: bool,
    end_emitted: bool,
    pending_trailers: Option<http::header::IntoIter<http::HeaderValue>>,
    last_trailer_name: Option<http::HeaderName>,
    pending_trailer_value: Option<http::HeaderValue>,
    pending_trailer_value_offset: usize,
    runtime_trailer_copy: Option<BodyTrailerCopy>,
    trailer_input_complete: bool,
    trailers_complete: bool,
    terminal_error: Option<RuntimeError>,
}

impl ProductBodySource {
    /// Creates an unarmed source and its unique activation capability.
    pub(crate) fn unarmed(
        body: Body,
        chunk_bytes: u64,
        trailer_count: u64,
        trailer_bytes: u64,
    ) -> Result<(Self, ProductBodySourceActivation), RuntimeError> {
        if chunk_bytes == 0
            || chunk_bytes > MAX_BODY_BYTES
            || trailer_count > MAX_SOURCE_FRAMES as u64
            || trailer_bytes > MAX_BODY_BYTES
            || (trailer_count == 0) != (trailer_bytes == 0)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let chunk_bytes = usize::try_from(chunk_bytes).map_err(|_| RuntimeError::InvalidInput)?;
        let trailer_count =
            usize::try_from(trailer_count).map_err(|_| RuntimeError::InvalidInput)?;
        let trailer_bytes =
            usize::try_from(trailer_bytes).map_err(|_| RuntimeError::InvalidInput)?;
        let activation = Arc::new(Mutex::new(ActivationSlot {
            state: ActivationState::Unarmed,
        }));
        let capability = ProductBodySourceActivation {
            slot: Arc::downgrade(&activation),
        };
        Ok((
            Self {
                body,
                activation,
                staging: None,
                chunk_bytes,
                trailer_count,
                trailer_bytes,
                presented_frames: 0,
                transport_frame: None,
                transport_offset: 0,
                pending_progress: false,
                staging_builder: None,
                staged_body: None,
                staged_head_offset: 0,
                runtime_copy: None,
                data_ended: false,
                end_emitted: false,
                pending_trailers: None,
                last_trailer_name: None,
                pending_trailer_value: None,
                pending_trailer_value_offset: 0,
                runtime_trailer_copy: None,
                trailer_input_complete: false,
                trailers_complete: false,
                terminal_error: None,
            },
            capability,
        ))
    }

    fn claim_staging(&mut self) -> Result<(), RuntimeError> {
        if self.staging.is_some() {
            return Ok(());
        }
        let mut slot = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = std::mem::replace(&mut slot.state, ActivationState::Terminal);
        match state {
            ActivationState::Armed(staging) => {
                slot.state = ActivationState::Claimed;
                self.staging = Some(staging);
                Ok(())
            }
            ActivationState::Unarmed => Err(RuntimeError::InvalidInput),
            ActivationState::Claimed | ActivationState::Terminal => Err(RuntimeError::InvalidInput),
        }
    }

    fn fail<T>(&mut self, error: RuntimeError) -> Poll<Result<T, RuntimeError>> {
        self.terminal_error = Some(error);
        self.transport_frame = None;
        self.pending_progress = false;
        self.staging_builder = None;
        self.staged_body = None;
        self.runtime_copy = None;
        self.pending_trailers = None;
        self.last_trailer_name = None;
        self.pending_trailer_value = None;
        self.runtime_trailer_copy = None;
        self.trailer_input_complete = false;
        Poll::Ready(Err(error))
    }

    fn map_staging_error(error: WireBodyBufferError) -> RuntimeError {
        match error {
            WireBodyBufferError::ForeignGuard => RuntimeError::BindingMismatch,
            WireBodyBufferError::CursorPeakExceeded
            | WireBodyBufferError::QuotaExhausted
            | WireBodyBufferError::GlobalExhausted
            | WireBodyBufferError::AllocationFailed
            | WireBodyBufferError::ReservedLengthMismatch => RuntimeError::LimitExceeded,
        }
    }

    fn finish_staging(&mut self) {
        let builder = self
            .staging_builder
            .take()
            .expect("nonempty staging builder exists");
        debug_assert!(builder.len() > 0);
        self.staged_body = Some(builder.finish());
        self.staged_head_offset = 0;
    }

    fn copy_staged_fragment(
        &mut self,
        budget: &BodyBudget,
    ) -> Result<Option<BodySourceEvent>, RuntimeError> {
        if self.runtime_copy.is_none() {
            let staged_len = self.staged_body.as_ref().expect("staged body exists").len();
            self.runtime_copy = Some(budget.begin_chunk_copy(
                u64::try_from(staged_len).map_err(|_| RuntimeError::LimitExceeded)?,
            )?);
        }

        let staged = self.staged_body.as_mut().expect("staged body exists");
        let available = staged.current_chunk(self.staged_head_offset);
        let copied = available.len().min(COPY_BLOCK_BYTES);
        debug_assert!(copied > 0);
        self.runtime_copy
            .as_mut()
            .expect("runtime copy exists")
            .push_fragment(&available[..copied])?;
        staged.consume(copied, &mut self.staged_head_offset);
        if !staged.is_empty() {
            return Ok(None);
        }

        self.staged_body = None;
        self.staged_head_offset = 0;
        let copy = self.runtime_copy.take().expect("runtime copy exists");
        Ok(Some(BodySourceEvent::Chunk(copy.finish()?)))
    }

    fn poll_checked_trailers(
        &mut self,
        context: &mut Context<'_>,
        budget: &BodyBudget,
    ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
        if self.pending_trailers.is_none() && self.runtime_trailer_copy.is_none() {
            match Pin::new(&mut self.body).poll_trailers(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return self.fail(RuntimeError::ServiceFailure),
                Poll::Ready(Ok(None)) => {
                    self.trailers_complete = true;
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Ok(Some(trailers))) if trailers.is_empty() => {
                    self.trailers_complete = true;
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Ok(Some(trailers))) => {
                    let field_count = trailers.len();
                    if field_count > self.trailer_count {
                        return self.fail(RuntimeError::LimitExceeded);
                    }
                    self.runtime_trailer_copy = match budget.begin_trailer_copy(
                        u64::try_from(field_count).unwrap_or(u64::MAX),
                        u64::try_from(self.trailer_bytes).unwrap_or(u64::MAX),
                    ) {
                        Ok(copy) => Some(copy),
                        Err(error) => return self.fail(error),
                    };
                    self.pending_trailers = Some(trailers.into_iter());
                }
            }
        }

        if self.trailer_input_complete {
            let poll = self
                .runtime_trailer_copy
                .as_mut()
                .expect("complete trailer input has a copy")
                .poll_finish(context);
            return match poll {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(trailers)) => {
                    self.runtime_trailer_copy = None;
                    self.trailer_input_complete = false;
                    self.trailers_complete = true;
                    Poll::Ready(Ok(Some(trailers)))
                }
                Poll::Ready(Err(error)) => self.fail(error),
            };
        }

        for _ in 0..MAX_INTERNAL_EVENTS_PER_POLL {
            if let Some(value) = self.pending_trailer_value.as_ref() {
                let end = self
                    .pending_trailer_value_offset
                    .saturating_add(COPY_BLOCK_BYTES)
                    .min(value.as_bytes().len());
                let fragment = &value.as_bytes()[self.pending_trailer_value_offset..end];
                if let Err(error) = self
                    .runtime_trailer_copy
                    .as_mut()
                    .expect("pending trailer value has a copy")
                    .push_value_fragment(fragment)
                {
                    return self.fail(error);
                }
                self.pending_trailer_value_offset = end;
                if end == value.as_bytes().len() {
                    if let Err(error) = self
                        .runtime_trailer_copy
                        .as_mut()
                        .expect("completed trailer value has a copy")
                        .finish_field()
                    {
                        return self.fail(error);
                    }
                    self.pending_trailer_value = None;
                    self.pending_trailer_value_offset = 0;
                }
                continue;
            }

            let next = self.pending_trailers.as_mut().and_then(Iterator::next);
            match next {
                Some((name, value)) => {
                    if let Some(name) = name {
                        self.last_trailer_name = Some(name);
                    }
                    let Some(name) = self.last_trailer_name.as_ref() else {
                        return self.fail(RuntimeError::InvalidInput);
                    };
                    if let Err(error) = self
                        .runtime_trailer_copy
                        .as_mut()
                        .expect("pending trailer iterator has a copy")
                        .start_field(
                            name.as_str(),
                            u64::try_from(value.as_bytes().len()).unwrap_or(u64::MAX),
                        )
                    {
                        return self.fail(error);
                    }
                    if value.as_bytes().is_empty() {
                        if let Err(error) = self
                            .runtime_trailer_copy
                            .as_mut()
                            .expect("empty trailer value has a copy")
                            .finish_field()
                        {
                            return self.fail(error);
                        }
                    } else {
                        self.pending_trailer_value = Some(value);
                    }
                }
                None => {
                    self.pending_trailers = None;
                    self.last_trailer_name = None;
                    self.trailer_input_complete = true;
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }

        context.waker().wake_by_ref();
        Poll::Pending
    }
}

impl BodySource for ProductBodySource {
    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        budget: &BodyBudget,
    ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
        if let Some(error) = self.terminal_error {
            return Poll::Ready(Err(error));
        }
        if let Err(error) = self.claim_staging() {
            let mut slot = self
                .activation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.state = ActivationState::Terminal;
            drop(slot);
            return self.fail(error);
        }
        if self.end_emitted {
            return self.fail(RuntimeError::InvalidInput);
        }

        for _ in 0..MAX_INTERNAL_EVENTS_PER_POLL {
            if self.staged_body.is_some() {
                match self.copy_staged_fragment(budget) {
                    Ok(Some(event)) => return Poll::Ready(Ok(event)),
                    Ok(None) => continue,
                    Err(error) => return self.fail(error),
                }
            }

            if self.transport_frame.is_some() {
                if self.staging_builder.is_none() {
                    self.staging_builder = Some(
                        self.staging
                            .as_ref()
                            .expect("armed source has staging authority")
                            .buffer(),
                    );
                }
                let this = self.as_mut().get_mut();
                let frame = this
                    .transport_frame
                    .as_ref()
                    .expect("transport frame exists");
                let builder = this
                    .staging_builder
                    .as_mut()
                    .expect("staging builder exists");
                let chunk_remaining = this.chunk_bytes - builder.len();
                let frame_remaining = frame.len() - this.transport_offset;
                let copied = chunk_remaining.min(frame_remaining).min(COPY_BLOCK_BYTES);
                let end = this.transport_offset + copied;
                let fragment = &frame[this.transport_offset..end];
                if let Err(error) = builder.try_extend_from_slice(fragment) {
                    return self.fail(Self::map_staging_error(error));
                }
                this.transport_offset = end;
                if end == frame.len() {
                    this.transport_frame = None;
                    this.transport_offset = 0;
                }
                if this
                    .staging_builder
                    .as_ref()
                    .is_some_and(|builder| builder.len() == this.chunk_bytes)
                {
                    this.finish_staging();
                }
                if std::mem::take(&mut this.pending_progress) {
                    return Poll::Ready(Ok(BodySourceEvent::Progress));
                }
                continue;
            }

            if self.data_ended {
                if self
                    .staging_builder
                    .as_ref()
                    .is_some_and(|builder| builder.len() > 0)
                {
                    self.finish_staging();
                    continue;
                }
                self.end_emitted = true;
                return Poll::Ready(Ok(BodySourceEvent::End));
            }

            match Pin::new(&mut self.body).poll_data(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(_))) => return self.fail(RuntimeError::ServiceFailure),
                Poll::Ready(Some(Ok(frame))) => {
                    self.presented_frames = match self.presented_frames.checked_add(1) {
                        Some(count) if count <= MAX_SOURCE_FRAMES => count,
                        _ => return self.fail(RuntimeError::LimitExceeded),
                    };
                    if frame.is_empty() {
                        continue;
                    }
                    self.transport_frame = Some(frame);
                    self.transport_offset = 0;
                    self.pending_progress = true;
                    continue;
                }
                Poll::Ready(None) => {
                    self.data_ended = true;
                    continue;
                }
            }
        }

        context.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        budget: &BodyBudget,
    ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
        if let Some(error) = self.terminal_error {
            return Poll::Ready(Err(error));
        }
        if let Err(error) = self.claim_staging() {
            return self.fail(error);
        }
        if !self.end_emitted || self.trailers_complete {
            return self.fail(RuntimeError::InvalidInput);
        }
        self.poll_checked_trailers(context, budget)
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    use http::HeaderMap;
    use tokio_stream::Stream;

    use super::*;
    use crate::safety::wire_body::guarded_body_allocation_bytes;
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct CountingPendingStream {
        polls: Arc<AtomicUsize>,
    }

    impl Stream for CountingPendingStream {
        type Item = Result<Bytes, io::Error>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
        }
    }

    fn quota_key() -> WireBodyQuotaKey {
        WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| true)
    }

    fn guard_for(max_staging_bytes: usize) -> (Arc<WireBodyPool>, HttpWireBodyGuard) {
        let peak = guarded_body_allocation_bytes(max_staging_bytes)
            .expect("test staging peak is representable")
            .max(1);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, quota_key());
        (pool, guard)
    }

    fn body_from_frames(frames: impl IntoIterator<Item = Bytes>) -> Body {
        let frames = frames.into_iter().collect::<Vec<_>>();
        Body::wrap_stream(tokio_stream::iter(
            frames.into_iter().map(Ok::<_, io::Error>),
        ))
    }

    fn activate_source(
        body: Body,
        chunk_bytes: usize,
    ) -> (ProductBodySource, HttpWireBodyGuard, Arc<WireBodyPool>) {
        let (source, activation) =
            ProductBodySource::unarmed(body, chunk_bytes as u64, 0, 0).unwrap();
        let (pool, guard) = guard_for(chunk_bytes.max(1));
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        (source, guard, pool)
    }

    fn budget(capacity: u64) -> BodyBudget {
        BodyBudget::new(capacity).unwrap()
    }

    fn poll_data_once(
        source: &mut ProductBodySource,
        budget: &BodyBudget,
        wake_counter: &Arc<WakeCounter>,
    ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
        let waker = Waker::from(Arc::clone(wake_counter));
        let mut context = Context::from_waker(&waker);
        Pin::new(source).poll_next(&mut context, budget)
    }

    fn collect_data(
        source: &mut ProductBodySource,
        budget: &BodyBudget,
    ) -> Result<(usize, Vec<Vec<u8>>), RuntimeError> {
        let wake_counter = Arc::new(WakeCounter::default());
        let mut progress = 0;
        let mut chunks = Vec::new();
        for _ in 0..200_000 {
            match poll_data_once(source, budget, &wake_counter) {
                Poll::Pending => continue,
                Poll::Ready(Ok(BodySourceEvent::Progress)) => progress += 1,
                Poll::Ready(Ok(BodySourceEvent::Chunk(chunk))) => {
                    chunks.push(chunk.as_bytes().to_vec());
                }
                Poll::Ready(Ok(BodySourceEvent::End)) => return Ok((progress, chunks)),
                Poll::Ready(Err(error)) => return Err(error),
            }
        }
        panic!("body source did not terminate within the test work bound");
    }

    #[test]
    fn tiny_frames_coalesce_to_authored_chunks() {
        let body = body_from_frames([
            Bytes::from_static(b"a"),
            Bytes::from_static(b"bc"),
            Bytes::from_static(b"defg"),
        ]);
        let (mut source, _guard, _pool) = activate_source(body, 3);
        let (progress, chunks) = collect_data(&mut source, &budget(4096)).unwrap();
        assert_eq!(progress, 3);
        assert_eq!(
            chunks,
            [b"abc".as_slice(), b"def".as_slice(), b"g".as_slice()]
        );
    }

    #[test]
    fn empty_frames_consume_frame_work_without_progress_or_chunks() {
        let body = body_from_frames([Bytes::new(), Bytes::from_static(b"x"), Bytes::new()]);
        let (mut source, _guard, _pool) = activate_source(body, 8);
        let (progress, chunks) = collect_data(&mut source, &budget(4096)).unwrap();
        assert_eq!(progress, 1);
        assert_eq!(chunks, [b"x".as_slice()]);
        assert_eq!(source.presented_frames, 3);
    }

    #[test]
    fn one_large_frame_has_one_progress_event_and_multiple_chunks() {
        let body = body_from_frames([Bytes::from_static(b"abcdefghij")]);
        let (mut source, _guard, _pool) = activate_source(body, 4);
        let (progress, chunks) = collect_data(&mut source, &budget(4096)).unwrap();
        assert_eq!(progress, 1);
        assert_eq!(
            chunks,
            [b"abcd".as_slice(), b"efgh".as_slice(), b"ij".as_slice()]
        );
    }

    #[test]
    fn bounded_copy_stops_at_work_cap_and_self_wakes() {
        let len = COPY_BLOCK_BYTES * (MAX_INTERNAL_EVENTS_PER_POLL + 1);
        let body = body_from_frames([Bytes::from(vec![0xa5; len])]);
        let (mut source, _guard, _pool) = activate_source(body, len);
        let budget = budget((len as u64) * 2);
        let wakes = Arc::new(WakeCounter::default());

        assert_eq!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Ready(Ok(BodySourceEvent::Progress))
        );
        assert!(matches!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Pending
        ));
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        let (progress, chunks) = collect_data(&mut source, &budget).unwrap();
        assert_eq!(progress, 0);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), len);
    }

    #[test]
    fn source_frame_cap_counts_empty_frames() {
        let frames = std::iter::repeat_with(Bytes::new).take(MAX_SOURCE_FRAMES + 1);
        let body = body_from_frames(frames);
        let (mut source, _guard, _pool) = activate_source(body, 1);
        assert_eq!(
            collect_data(&mut source, &budget(4096)),
            Err(RuntimeError::LimitExceeded)
        );
        assert_eq!(source.presented_frames, MAX_SOURCE_FRAMES);
    }

    #[test]
    fn prearm_poll_is_terminal_and_never_polls_hyper() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = Body::wrap_stream(CountingPendingStream {
            polls: Arc::clone(&polls),
        });
        let (mut source, activation) = ProductBodySource::unarmed(body, 8, 0, 0).unwrap();
        let budget = budget(4096);
        let wakes = Arc::new(WakeCounter::default());
        assert_eq!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Ready(Err(RuntimeError::InvalidInput))
        );
        assert_eq!(polls.load(Ordering::Relaxed), 0);

        let (_pool, guard) = guard_for(8);
        assert_eq!(
            activation.activate(&guard, RequestStagingAuthority::for_test(&guard)),
            Err(RuntimeError::InvalidInput)
        );
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prearm_trailer_poll_terminalizes_activation() {
        let (mut source, activation) = ProductBodySource::unarmed(Body::empty(), 8, 1, 8).unwrap();
        let budget = budget(4096);
        assert!(matches!(
            Pin::new(&mut source)
                .poll_trailers(&mut Context::from_waker(std::task::Waker::noop()), &budget,),
            Poll::Ready(Err(RuntimeError::InvalidInput))
        ));
        let (_pool, guard) = guard_for(8);
        assert_eq!(
            activation.activate(&guard, RequestStagingAuthority::for_test(&guard)),
            Err(RuntimeError::InvalidInput)
        );
    }

    #[test]
    fn duplicate_activation_capability_is_rejected() {
        let (source, activation) = ProductBodySource::unarmed(Body::empty(), 8, 0, 0).unwrap();
        let duplicate = ProductBodySourceActivation {
            slot: Weak::clone(&activation.slot),
        };
        let (_pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        assert_eq!(
            duplicate.activate(&guard, RequestStagingAuthority::for_test(&guard)),
            Err(RuntimeError::InvalidInput)
        );
        drop(source);
    }

    #[test]
    fn foreign_staging_authority_is_rejected() {
        let (_source, activation) = ProductBodySource::unarmed(Body::empty(), 8, 0, 0).unwrap();
        let (_first_pool, first_guard) = guard_for(8);
        let (_second_pool, second_guard) = guard_for(8);
        assert_eq!(
            activation.activate(
                &second_guard,
                RequestStagingAuthority::for_test(&first_guard),
            ),
            Err(RuntimeError::BindingMismatch)
        );
    }

    #[test]
    fn dropped_source_invalidates_activation_and_drops_staging_charge() {
        let (source, activation) = ProductBodySource::unarmed(Body::empty(), 8, 0, 0).unwrap();
        drop(source);
        let (_pool, guard) = guard_for(8);
        assert_eq!(
            activation.activate(&guard, RequestStagingAuthority::for_test(&guard)),
            Err(RuntimeError::InvalidInput)
        );

        let len = COPY_BLOCK_BYTES * (MAX_INTERNAL_EVENTS_PER_POLL + 1);
        let body = body_from_frames([Bytes::from(vec![0x5a; len])]);
        let (mut source, guard, pool) = activate_source(body, len);
        let budget = budget((len as u64) * 2);
        let wakes = Arc::new(WakeCounter::default());
        assert!(matches!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Ready(Ok(BodySourceEvent::Progress))
        ));
        assert!(matches!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Pending
        ));
        assert!(guard.live_bytes() > 0);
        drop(source);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn dropping_inflight_runtime_chunk_copy_releases_all_accounting() {
        let len = COPY_BLOCK_BYTES * (MAX_INTERNAL_EVENTS_PER_POLL + 1);
        let body = body_from_frames([Bytes::from(vec![0x5a; len])]);
        let (mut source, guard, pool) = activate_source(body, len);
        let capacity = BodyBudget::required_storage_bytes(len as u64, 1).unwrap();
        let budget = budget(capacity);
        let wakes = Arc::new(WakeCounter::default());
        assert!(matches!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Ready(Ok(BodySourceEvent::Progress))
        ));
        assert!(matches!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Pending
        ));
        assert!(matches!(
            poll_data_once(&mut source, &budget, &wakes),
            Poll::Pending
        ));
        assert!(source.runtime_copy.is_some());
        assert!(guard.live_bytes() > 0);
        drop(source);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        drop(budget.begin_chunk_copy(len as u64).unwrap());
    }

    #[tokio::test]
    async fn trailers_are_checked_and_copied_into_runtime_budget() {
        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            sender.send_data(Bytes::from_static(b"body")).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-checksum", http::HeaderValue::from_static("ok"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let (mut source, activation) = ProductBodySource::unarmed(body, 8, 1, 32).unwrap();
        let (_pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        let budget = budget(4096);

        loop {
            let event = poll_fn(|context| Pin::new(&mut source).poll_next(context, &budget))
                .await
                .unwrap();
            if event == BodySourceEvent::End {
                break;
            }
        }
        let trailers = poll_fn(|context| Pin::new(&mut source).poll_trailers(context, &budget))
            .await
            .unwrap()
            .unwrap();
        producer.await.unwrap();
        assert_eq!(trailers.len(), 1);
        let field = trailers.iter().next().unwrap();
        assert_eq!(field.name(), "x-checksum");
        assert_eq!(field.value(), b"ok");
    }

    #[tokio::test]
    async fn empty_and_forbidden_trailer_values_follow_runtime_contract() {
        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-empty", http::HeaderValue::from_static(""));
            sender.send_trailers(trailers).await.unwrap();
        });
        let (mut source, activation) = ProductBodySource::unarmed(body, 8, 1, 7).unwrap();
        let (_pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        let runtime_budget = budget(4096);
        assert_eq!(
            poll_fn(|context| Pin::new(&mut source).poll_next(context, &runtime_budget))
                .await
                .unwrap(),
            BodySourceEvent::End
        );
        let trailers =
            poll_fn(|context| Pin::new(&mut source).poll_trailers(context, &runtime_budget))
                .await
                .unwrap()
                .unwrap();
        producer.await.unwrap();
        assert_eq!(trailers.iter().next().unwrap().value(), b"");

        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            let mut trailers = HeaderMap::new();
            trailers.insert("authorization", http::HeaderValue::from_static("secret"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let (mut source, activation) = ProductBodySource::unarmed(body, 8, 1, 32).unwrap();
        let (_pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        let runtime_budget = budget(4096);
        assert_eq!(
            poll_fn(|context| Pin::new(&mut source).poll_next(context, &runtime_budget))
                .await
                .unwrap(),
            BodySourceEvent::End
        );
        assert!(matches!(
            poll_fn(|context| Pin::new(&mut source).poll_trailers(context, &runtime_budget)).await,
            Err(RuntimeError::InvalidInput)
        ));
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn trailer_count_limit_and_inflight_cancellation_are_bounded() {
        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-one", http::HeaderValue::from_static("1"));
            trailers.insert("x-two", http::HeaderValue::from_static("2"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let (mut source, activation) = ProductBodySource::unarmed(body, 8, 1, 32).unwrap();
        let (_pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        let runtime_budget = budget(4096);
        assert_eq!(
            poll_fn(|context| Pin::new(&mut source).poll_next(context, &runtime_budget))
                .await
                .unwrap(),
            BodySourceEvent::End
        );
        assert!(matches!(
            poll_fn(|context| Pin::new(&mut source).poll_trailers(context, &runtime_budget)).await,
            Err(RuntimeError::LimitExceeded)
        ));
        producer.await.unwrap();

        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-over", http::HeaderValue::from_static("12"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let (mut source, activation) = ProductBodySource::unarmed(body, 8, 1, 7).unwrap();
        let (_pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        let runtime_budget = budget(4096);
        assert_eq!(
            poll_fn(|context| Pin::new(&mut source).poll_next(context, &runtime_budget))
                .await
                .unwrap(),
            BodySourceEvent::End
        );
        assert!(matches!(
            poll_fn(|context| Pin::new(&mut source).poll_trailers(context, &runtime_budget)).await,
            Err(RuntimeError::LimitExceeded)
        ));
        producer.await.unwrap();

        let value_length = COPY_BLOCK_BYTES * (MAX_INTERNAL_EVENTS_PER_POLL + 1);
        let trailer_name = "x-large";
        let payload = trailer_name.len() + value_length;
        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            let mut trailers = HeaderMap::new();
            trailers.insert(
                "x-large",
                http::HeaderValue::from_bytes(&vec![b'a'; value_length]).unwrap(),
            );
            sender.send_trailers(trailers).await.unwrap();
        });
        let (mut source, activation) =
            ProductBodySource::unarmed(body, 8, 1, payload as u64).unwrap();
        let (pool, guard) = guard_for(8);
        activation
            .activate(&guard, RequestStagingAuthority::for_test(&guard))
            .unwrap();
        let capacity =
            BodyBudget::required_replay_storage_bytes(0, 8, 1, payload as u64, None).unwrap();
        let runtime_budget = budget(capacity);
        assert_eq!(
            poll_fn(|context| Pin::new(&mut source).poll_next(context, &runtime_budget))
                .await
                .unwrap(),
            BodySourceEvent::End
        );
        let wakes = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wakes));
        assert!(matches!(
            Pin::new(&mut source).poll_trailers(&mut Context::from_waker(&waker), &runtime_budget),
            Poll::Pending
        ));
        assert!(source.runtime_trailer_copy.is_some());
        drop(source);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        let mut retry = runtime_budget
            .begin_trailer_copy(1, payload as u64)
            .unwrap();
        retry
            .start_field(trailer_name, value_length as u64)
            .unwrap();
        drop(retry);
        producer.await.unwrap();
    }
}
