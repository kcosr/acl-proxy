use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use allocator_api2::boxed::Box as FallibleBox;
use tokio::sync::Notify;
use zeroize::Zeroize;

use crate::http1::store::{ParserStore, ParserStoreAllocationError, PARSER_STORE_BYTES};

#[derive(Clone)]
pub(crate) struct WebhookTransportArena {
    inner: Arc<ArenaInner>,
}

struct ArenaInner {
    maximum_deliveries: usize,
    buffer_bytes: usize,
    bytes_per_delivery: usize,
    maximum_transport_bytes: usize,
    state: Mutex<ArenaState>,
    changed: Notify,
}

struct ArenaState {
    accepting: bool,
    live_deliveries: usize,
    reserved_transport_bytes: usize,
}

impl WebhookTransportArena {
    pub(crate) fn try_new(
        maximum_deliveries: usize,
        buffer_bytes: usize,
        maximum_transport_bytes: usize,
    ) -> Result<Self, WebhookTransportArenaError> {
        if maximum_deliveries == 0 {
            return Err(WebhookTransportArenaError::ZeroDeliveries);
        }
        if buffer_bytes < PARSER_STORE_BYTES {
            return Err(WebhookTransportArenaError::BufferTooSmall {
                minimum: PARSER_STORE_BYTES,
                actual: buffer_bytes,
            });
        }
        if maximum_transport_bytes == 0 {
            return Err(WebhookTransportArenaError::ZeroTransportBytes);
        }
        let bytes_per_delivery = buffer_bytes
            .checked_mul(2)
            .ok_or(WebhookTransportArenaError::CapacityOverflow)?;
        let required_transport_bytes = maximum_deliveries
            .checked_mul(bytes_per_delivery)
            .ok_or(WebhookTransportArenaError::CapacityOverflow)?;
        if required_transport_bytes > maximum_transport_bytes {
            return Err(WebhookTransportArenaError::InsufficientTransportBytes {
                required: required_transport_bytes,
                available: maximum_transport_bytes,
            });
        }

        Ok(Self {
            inner: Arc::new(ArenaInner {
                maximum_deliveries,
                buffer_bytes,
                bytes_per_delivery,
                maximum_transport_bytes,
                state: Mutex::new(ArenaState {
                    accepting: true,
                    live_deliveries: 0,
                    reserved_transport_bytes: 0,
                }),
                changed: Notify::new(),
            }),
        })
    }

    pub(crate) fn try_acquire(
        &self,
    ) -> Result<WebhookTransportLease, WebhookTransportAdmissionError> {
        self.try_acquire_with(TransportBuffers::try_new)
    }

    fn try_acquire_with(
        &self,
        allocate: impl FnOnce(usize) -> Result<TransportBuffers, WebhookTransportAdmissionError>,
    ) -> Result<WebhookTransportLease, WebhookTransportAdmissionError> {
        {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| WebhookTransportAdmissionError::Poisoned)?;
            if !state.accepting {
                return Err(WebhookTransportAdmissionError::Closed);
            }
            if state.live_deliveries >= self.inner.maximum_deliveries {
                return Err(WebhookTransportAdmissionError::AtCapacity);
            }
            let reserved_transport_bytes = state
                .reserved_transport_bytes
                .checked_add(self.inner.bytes_per_delivery)
                .ok_or(WebhookTransportAdmissionError::Poisoned)?;
            if reserved_transport_bytes > self.inner.maximum_transport_bytes {
                return Err(WebhookTransportAdmissionError::AtCapacity);
            }
            state.live_deliveries = state
                .live_deliveries
                .checked_add(1)
                .ok_or(WebhookTransportAdmissionError::Poisoned)?;
            state.reserved_transport_bytes = reserved_transport_bytes;
        }

        match allocate(self.inner.buffer_bytes) {
            Ok(buffers) => Ok(WebhookTransportLease {
                arena: Arc::clone(&self.inner),
                buffers: Some(buffers),
            }),
            Err(error) => {
                release_reservation(&self.inner);
                Err(error)
            }
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.accepting = false;
        drop(state);
        self.inner.changed.notify_waiters();
    }

    pub(crate) async fn wait_until_empty(&self) {
        loop {
            let changed = self.inner.changed.notified();
            if self.counts().live_deliveries == 0 {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn counts(&self) -> WebhookTransportArenaCounts {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        WebhookTransportArenaCounts {
            accepting: state.accepting,
            maximum_deliveries: self.inner.maximum_deliveries,
            live_deliveries: state.live_deliveries,
            buffer_bytes: self.inner.buffer_bytes,
            reserved_transport_bytes: state.reserved_transport_bytes,
            maximum_transport_bytes: self.inner.maximum_transport_bytes,
        }
    }
}

pub(crate) struct WebhookTransportLease {
    arena: Arc<ArenaInner>,
    buffers: Option<TransportBuffers>,
}

impl WebhookTransportLease {
    #[cfg(test)]
    pub(crate) fn outbound(&self) -> &[u8] {
        self.buffers().outbound.as_ref()
    }

    pub(crate) fn outbound_mut(&mut self) -> &mut [u8] {
        self.buffers_mut().outbound.as_mut()
    }

    #[cfg(test)]
    pub(crate) fn inbound(&self) -> &ParserStore {
        &self.buffers().inbound
    }

    #[cfg(test)]
    pub(crate) fn inbound_mut(&mut self) -> &mut ParserStore {
        &mut self.buffers_mut().inbound
    }

    pub(crate) fn split(mut self) -> (WebhookOutboundBuffer, WebhookInboundBuffer) {
        let buffers = self
            .buffers
            .take()
            .expect("webhook transport lease always owns both buffers");
        let reservation = Arc::new(SplitReservation {
            arena: Arc::clone(&self.arena),
            remaining_buffers: AtomicU8::new(2),
        });
        (
            WebhookOutboundBuffer {
                buffer: Some(buffers.outbound),
                reservation: Arc::clone(&reservation),
            },
            WebhookInboundBuffer {
                parser_store: Some(buffers.inbound),
                reservation,
            },
        )
    }

    #[cfg(test)]
    fn buffers(&self) -> &TransportBuffers {
        self.buffers
            .as_ref()
            .expect("webhook transport lease always owns both buffers")
    }

    fn buffers_mut(&mut self) -> &mut TransportBuffers {
        self.buffers
            .as_mut()
            .expect("webhook transport lease always owns both buffers")
    }
}

impl Drop for WebhookTransportLease {
    fn drop(&mut self) {
        let Some(buffers) = self.buffers.take() else {
            return;
        };
        drop(buffers);
        release_reservation(&self.arena);
    }
}

pub(crate) struct WebhookOutboundBuffer {
    buffer: Option<OutboundBuffer>,
    reservation: Arc<SplitReservation>,
}

impl WebhookOutboundBuffer {
    fn buffer(&self) -> &OutboundBuffer {
        self.buffer
            .as_ref()
            .expect("webhook outbound wrapper always owns its buffer")
    }

    fn buffer_mut(&mut self) -> &mut OutboundBuffer {
        self.buffer
            .as_mut()
            .expect("webhook outbound wrapper always owns its buffer")
    }
}

impl AsRef<[u8]> for WebhookOutboundBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buffer().as_ref()
    }
}

impl AsMut<[u8]> for WebhookOutboundBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer_mut().as_mut()
    }
}

impl Drop for WebhookOutboundBuffer {
    fn drop(&mut self) {
        let buffer = self
            .buffer
            .take()
            .expect("webhook outbound wrapper always owns its buffer");
        drop(buffer);
        self.reservation.release_buffer();
    }
}

pub(crate) struct WebhookInboundBuffer {
    parser_store: Option<ParserStore>,
    reservation: Arc<SplitReservation>,
}

impl WebhookInboundBuffer {
    #[cfg(test)]
    pub(crate) fn parser_store(&self) -> &ParserStore {
        self.parser_store
            .as_ref()
            .expect("webhook inbound wrapper always owns its parser store")
    }

    pub(crate) fn parser_store_mut(&mut self) -> &mut ParserStore {
        self.parser_store
            .as_mut()
            .expect("webhook inbound wrapper always owns its parser store")
    }
}

impl Drop for WebhookInboundBuffer {
    fn drop(&mut self) {
        let parser_store = self
            .parser_store
            .take()
            .expect("webhook inbound wrapper always owns its parser store");
        drop(parser_store);
        self.reservation.release_buffer();
    }
}

struct SplitReservation {
    arena: Arc<ArenaInner>,
    remaining_buffers: AtomicU8,
}

impl SplitReservation {
    fn release_buffer(&self) {
        let previous = self.remaining_buffers.fetch_sub(1, Ordering::AcqRel);
        assert!(
            (1..=2).contains(&previous),
            "webhook split reservation cannot release a buffer twice"
        );
        if previous == 1 {
            release_reservation(&self.arena);
        }
    }
}

fn release_reservation(arena: &ArenaInner) {
    let mut state = arena
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.live_deliveries = state
        .live_deliveries
        .checked_sub(1)
        .expect("live webhook delivery count cannot underflow");
    state.reserved_transport_bytes = state
        .reserved_transport_bytes
        .checked_sub(arena.bytes_per_delivery)
        .expect("reserved webhook transport bytes cannot underflow");
    let empty = state.live_deliveries == 0;
    drop(state);
    if empty {
        arena.changed.notify_waiters();
    }
}

struct TransportBuffers {
    outbound: OutboundBuffer,
    inbound: ParserStore,
}

impl TransportBuffers {
    fn try_new(buffer_bytes: usize) -> Result<Self, WebhookTransportAdmissionError> {
        Self::try_new_with(
            buffer_bytes,
            OutboundBuffer::try_new,
            ParserStore::try_with_capacity,
        )
    }

    fn try_new_with(
        buffer_bytes: usize,
        allocate_outbound: impl FnOnce(usize) -> Result<OutboundBuffer, OutboundAllocationError>,
        allocate_inbound: impl FnOnce(usize) -> Result<ParserStore, ParserStoreAllocationError>,
    ) -> Result<Self, WebhookTransportAdmissionError> {
        let outbound = allocate_outbound(buffer_bytes)
            .map_err(|_| WebhookTransportAdmissionError::Allocation)?;
        let inbound = allocate_inbound(buffer_bytes)
            .map_err(|_| WebhookTransportAdmissionError::Allocation)?;
        Ok(Self { outbound, inbound })
    }
}

struct OutboundBuffer {
    bytes: FallibleBox<[u8]>,
    #[cfg(test)]
    drop_counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl OutboundBuffer {
    fn try_new(buffer_bytes: usize) -> Result<Self, OutboundAllocationError> {
        let mut bytes = FallibleBox::<[u8]>::try_new_uninit_slice(buffer_bytes)
            .map_err(|_| OutboundAllocationError)?;
        for byte in bytes.iter_mut() {
            byte.write(0);
        }
        // Every element was initialized to zero above.
        let bytes = unsafe { bytes.assume_init() };
        Ok(Self {
            bytes,
            #[cfg(test)]
            drop_counter: None,
        })
    }

    fn wipe(&mut self) {
        self.bytes.zeroize();
    }
}

impl AsRef<[u8]> for OutboundBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for OutboundBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Drop for OutboundBuffer {
    fn drop(&mut self) {
        self.wipe();
        #[cfg(test)]
        if let Some(counter) = &self.drop_counter {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutboundAllocationError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookTransportArenaError {
    ZeroDeliveries,
    BufferTooSmall { minimum: usize, actual: usize },
    ZeroTransportBytes,
    CapacityOverflow,
    InsufficientTransportBytes { required: usize, available: usize },
}

impl fmt::Display for WebhookTransportArenaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDeliveries => {
                formatter.write_str("webhook transport arena requires a positive delivery limit")
            }
            Self::BufferTooSmall { minimum, actual } => write!(
                formatter,
                "webhook transport buffers require at least {minimum} bytes but received {actual}"
            ),
            Self::ZeroTransportBytes => {
                formatter.write_str("webhook transport arena requires a positive byte limit")
            }
            Self::CapacityOverflow => {
                formatter.write_str("webhook transport capacity arithmetic overflowed")
            }
            Self::InsufficientTransportBytes {
                required,
                available,
            } => write!(
                formatter,
                "webhook transport arena requires {required} bytes but only {available} are available"
            ),
        }
    }
}

impl std::error::Error for WebhookTransportArenaError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookTransportAdmissionError {
    Allocation,
    AtCapacity,
    Closed,
    Poisoned,
}

impl fmt::Display for WebhookTransportAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("could not allocate webhook transport buffers"),
            Self::AtCapacity => formatter.write_str("webhook delivery capacity exhausted"),
            Self::Closed => formatter.write_str("webhook delivery admission is closed"),
            Self::Poisoned => formatter.write_str("webhook delivery admission gate failed"),
        }
    }
}

impl std::error::Error for WebhookTransportAdmissionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WebhookTransportArenaCounts {
    pub(crate) accepting: bool,
    pub(crate) maximum_deliveries: usize,
    pub(crate) live_deliveries: usize,
    pub(crate) buffer_bytes: usize,
    pub(crate) reserved_transport_bytes: usize,
    pub(crate) maximum_transport_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BUFFER_BYTES: usize = 64 * 1024;

    #[test]
    fn webhook_delivery_admission_and_transport_pool_are_bounded() {
        let arena = WebhookTransportArena::try_new(2, BUFFER_BYTES, 4 * BUFFER_BYTES).unwrap();
        let first = arena.try_acquire().unwrap();
        let second = arena.try_acquire().unwrap();

        assert_eq!(
            arena.counts(),
            WebhookTransportArenaCounts {
                accepting: true,
                maximum_deliveries: 2,
                live_deliveries: 2,
                buffer_bytes: BUFFER_BYTES,
                reserved_transport_bytes: 4 * BUFFER_BYTES,
                maximum_transport_bytes: 4 * BUFFER_BYTES,
            }
        );
        assert!(matches!(
            arena.try_acquire(),
            Err(WebhookTransportAdmissionError::AtCapacity)
        ));

        drop(first);
        let replacement = arena.try_acquire().unwrap();
        assert_eq!(replacement.outbound().len(), BUFFER_BYTES);
        assert_eq!(replacement.inbound().capacity(), BUFFER_BYTES);
        assert!(replacement.outbound().iter().all(|byte| *byte == 0));
        assert!(replacement
            .inbound()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));

        drop(second);
        drop(replacement);
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(arena.counts().reserved_transport_bytes, 0);
    }

    #[tokio::test]
    async fn shutdown_closes_admission_and_drains_complete_split_reservations() {
        let arena = WebhookTransportArena::try_new(1, BUFFER_BYTES, 2 * BUFFER_BYTES).unwrap();
        let (outbound, inbound) = arena.try_acquire().unwrap().split();

        arena.begin_shutdown();
        arena.begin_shutdown();
        assert!(!arena.counts().accepting);
        assert!(matches!(
            arena.try_acquire(),
            Err(WebhookTransportAdmissionError::Closed)
        ));

        drop(outbound);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            arena.wait_until_empty()
        )
        .await
        .is_err());

        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(1), arena.wait_until_empty())
            .await
            .expect("arena drains after both split buffers return");
        assert_eq!(arena.counts().live_deliveries, 0);
    }

    #[test]
    fn arena_dimension_boundaries_use_checked_exact_arithmetic() {
        assert_eq!(
            WebhookTransportArena::try_new(0, BUFFER_BYTES, 2 * BUFFER_BYTES)
                .err()
                .unwrap(),
            WebhookTransportArenaError::ZeroDeliveries
        );
        assert_eq!(
            WebhookTransportArena::try_new(1, 0, 1).err().unwrap(),
            WebhookTransportArenaError::BufferTooSmall {
                minimum: PARSER_STORE_BYTES,
                actual: 0,
            }
        );
        assert_eq!(
            WebhookTransportArena::try_new(1, PARSER_STORE_BYTES - 1, 2 * PARSER_STORE_BYTES,)
                .err()
                .unwrap(),
            WebhookTransportArenaError::BufferTooSmall {
                minimum: PARSER_STORE_BYTES,
                actual: PARSER_STORE_BYTES - 1,
            }
        );
        assert_eq!(
            WebhookTransportArena::try_new(1, PARSER_STORE_BYTES, 0)
                .err()
                .unwrap(),
            WebhookTransportArenaError::ZeroTransportBytes
        );
        assert_eq!(
            WebhookTransportArena::try_new(usize::MAX, PARSER_STORE_BYTES, usize::MAX)
                .err()
                .unwrap(),
            WebhookTransportArenaError::CapacityOverflow
        );
        assert_eq!(
            WebhookTransportArena::try_new(2, BUFFER_BYTES, 4 * BUFFER_BYTES - 1)
                .err()
                .unwrap(),
            WebhookTransportArenaError::InsufficientTransportBytes {
                required: 4 * BUFFER_BYTES,
                available: 4 * BUFFER_BYTES - 1,
            }
        );

        let exact = WebhookTransportArena::try_new(2, BUFFER_BYTES, 4 * BUFFER_BYTES).unwrap();
        assert_eq!(exact.counts().maximum_transport_bytes, 4 * BUFFER_BYTES);
    }

    #[test]
    fn outbound_allocation_failure_rolls_back_slot_and_byte_reservation() {
        let arena = WebhookTransportArena::try_new(1, BUFFER_BYTES, 2 * BUFFER_BYTES).unwrap();
        let result = arena.try_acquire_with(|_| Err(WebhookTransportAdmissionError::Allocation));

        assert!(matches!(
            result,
            Err(WebhookTransportAdmissionError::Allocation)
        ));
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(arena.counts().reserved_transport_bytes, 0);
        drop(arena.try_acquire().unwrap());
    }

    #[test]
    fn inbound_allocation_failure_drops_and_wipes_partial_outbound_buffer() {
        let drops = Arc::new(AtomicUsize::new(0));
        let allocation_drops = Arc::clone(&drops);
        let result = TransportBuffers::try_new_with(
            BUFFER_BYTES,
            move |bytes| {
                let mut outbound = OutboundBuffer::try_new(bytes)?;
                outbound.as_mut().fill(0xa5);
                outbound.drop_counter = Some(allocation_drops);
                Ok(outbound)
            },
            |_| Err(ParserStoreAllocationError),
        );

        assert!(matches!(
            result,
            Err(WebhookTransportAdmissionError::Allocation)
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn webhook_application_protocol_buffers_zeroize_on_every_exit() {
        let arena = WebhookTransportArena::try_new(1, BUFFER_BYTES, 2 * BUFFER_BYTES).unwrap();
        let mut lease = arena.try_acquire().unwrap();
        lease.outbound_mut().fill(0xa5);
        lease
            .inbound_mut()
            .append(b"sensitive acknowledgement")
            .unwrap();

        drop(lease);

        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(arena.counts().reserved_transport_bytes, 0);
        let replacement = arena.try_acquire().unwrap();
        assert!(replacement.outbound().iter().all(|byte| *byte == 0));
        assert_eq!(replacement.inbound().initialized_len(), 0);
        assert!(replacement
            .inbound()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn split_lease_remains_charged_until_both_task_buffers_are_dropped() {
        let arena = WebhookTransportArena::try_new(1, BUFFER_BYTES, 2 * BUFFER_BYTES).unwrap();
        let mut lease = arena.try_acquire().unwrap();
        lease.outbound_mut().fill(0xa5);
        lease.inbound_mut().append(b"sensitive response").unwrap();

        let (mut outbound, mut inbound) = lease.split();
        assert_eq!(outbound.as_ref().len(), BUFFER_BYTES);
        assert_eq!(inbound.parser_store().capacity(), BUFFER_BYTES);
        outbound.as_mut()[0] = 0x5a;
        inbound
            .parser_store_mut()
            .append(b" more sensitive bytes")
            .unwrap();

        drop(outbound);
        assert_eq!(arena.counts().live_deliveries, 1);
        assert_eq!(arena.counts().reserved_transport_bytes, 2 * BUFFER_BYTES);
        assert!(matches!(
            arena.try_acquire(),
            Err(WebhookTransportAdmissionError::AtCapacity)
        ));

        drop(inbound);
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(arena.counts().reserved_transport_bytes, 0);
        drop(arena.try_acquire().unwrap());
    }

    #[test]
    fn split_task_buffers_are_send_and_static() {
        fn assert_send_static<T: Send + 'static>() {}

        assert_send_static::<WebhookOutboundBuffer>();
        assert_send_static::<WebhookInboundBuffer>();
    }
}
