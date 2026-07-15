use bytes::Buf;
use hyper::body::{HttpBody, SizeHint};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::network::canonical_ip;
use crate::safety::allocation::{
    self, AllocationAuthority, ExactAllocationLease, ReservedStableBodyBuilder, StableBody,
    StableBodyBuilder, StableBodySegments, StableScratch, StableWorkspaceAllocation,
};

const QUOTA_SHARD_COUNT: usize = 16;
pub(crate) use crate::safety::allocation::MAX_BUFFER_GROWTH_BYTES;

pub(crate) fn guarded_body_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    allocation::body_allocation_bytes(payload_bytes)
}

pub(crate) fn guarded_workspace_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    allocation::workspace_allocation_bytes(payload_bytes)
}

type QuotaShard = Mutex<HashMap<WireBodyQuotaKey, Arc<QuotaEntry>>>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum WireBodyQuotaKey {
    LocalHost,
    Peer(IpAddr),
}

impl WireBodyQuotaKey {
    pub(crate) fn from_peer(peer: IpAddr, is_process_local: impl FnOnce(IpAddr) -> bool) -> Self {
        let peer = canonical_ip(peer);
        if peer.is_loopback() || is_process_local(peer) {
            Self::LocalHost
        } else {
            Self::Peer(peer)
        }
    }
}

impl fmt::Debug for WireBodyQuotaKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalHost => formatter.write_str("WireBodyQuotaKey::LocalHost"),
            Self::Peer(_) => formatter.write_str("WireBodyQuotaKey::Peer"),
        }
    }
}

pub(crate) struct WireBodyPool {
    global_limit: usize,
    quota_limit: usize,
    global_charge: AtomicUsize,
    #[cfg(test)]
    peak_global_charge: AtomicUsize,
    quota_shards: Box<[QuotaShard]>,
    #[cfg(test)]
    fail_next_allocation: AtomicBool,
}

impl fmt::Debug for WireBodyPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireBodyPool")
            .field("global_limit", &self.global_limit)
            .field("quota_limit", &self.quota_limit)
            .field("global_charge", &self.global_charge.load(Ordering::Acquire))
            .field("quota_entry_count", &self.quota_entry_count())
            .finish()
    }
}

impl WireBodyPool {
    pub(crate) fn new(global_limit: usize, quota_limit: usize) -> Arc<Self> {
        assert!(global_limit > 0, "wire-body global limit must be positive");
        assert!(quota_limit > 0, "wire-body quota limit must be positive");
        assert!(
            quota_limit <= global_limit,
            "wire-body quota limit must not exceed the global limit"
        );
        Arc::new(Self {
            global_limit,
            quota_limit,
            global_charge: AtomicUsize::new(0),
            #[cfg(test)]
            peak_global_charge: AtomicUsize::new(0),
            quota_shards: (0..QUOTA_SHARD_COUNT)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            #[cfg(test)]
            fail_next_allocation: AtomicBool::new(false),
        })
    }

    pub(super) fn begin(
        self: &Arc<Self>,
        cursor_peak_bytes: usize,
        quota_key: WireBodyQuotaKey,
    ) -> HttpWireBodyGuard {
        HttpWireBodyGuard {
            inner: Arc::new(GuardInner {
                pool: self.clone(),
                quota_key,
                quota_lease: OnceLock::new(),
                cursor_peak_bytes,
                live_bytes: AtomicUsize::new(0),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn begin_for_test(
        self: &Arc<Self>,
        cursor_peak_bytes: usize,
        quota_key: WireBodyQuotaKey,
    ) -> HttpWireBodyGuard {
        self.begin(cursor_peak_bytes, quota_key)
    }

    #[cfg(test)]
    pub(crate) fn global_charge(&self) -> usize {
        self.global_charge.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn peak_global_charge(&self) -> usize {
        self.peak_global_charge.load(Ordering::Acquire)
    }

    fn quota_entry_count(&self) -> usize {
        self.quota_shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
            })
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn quota_charge(&self, key: &WireBodyQuotaKey) -> usize {
        let shard = self.shard(key);
        let entries = self.quota_shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries
            .get(key)
            .map(|entry| entry.charge.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn lease_quota(self: &Arc<Self>, key: &WireBodyQuotaKey) -> QuotaLease {
        let shard_index = self.shard(key);
        let mut shard = self.quota_shards[shard_index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = shard
            .entry(key.clone())
            .or_insert_with(|| Arc::new(QuotaEntry::default()))
            .clone();
        entry.active_leases.fetch_add(1, Ordering::Relaxed);
        QuotaLease {
            pool: self.clone(),
            key: key.clone(),
            shard_index,
            entry,
        }
    }

    fn try_charge(&self, lease: &QuotaLease, bytes: usize) -> Result<(), WireBodyBufferError> {
        if bytes == 0 {
            return Ok(());
        }
        try_atomic_add(&lease.entry.charge, bytes, self.quota_limit)
            .map_err(|_| WireBodyBufferError::QuotaExhausted)?;
        if try_atomic_add(&self.global_charge, bytes, self.global_limit).is_err() {
            lease.entry.charge.fetch_sub(bytes, Ordering::AcqRel);
            return Err(WireBodyBufferError::GlobalExhausted);
        }
        #[cfg(test)]
        self.peak_global_charge
            .fetch_max(self.global_charge.load(Ordering::Acquire), Ordering::AcqRel);
        Ok(())
    }

    fn release(&self, lease: &QuotaLease, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let global_before = self.global_charge.fetch_sub(bytes, Ordering::AcqRel);
        let quota_before = lease.entry.charge.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(global_before >= bytes, "wire-body global charge underflow");
        debug_assert!(quota_before >= bytes, "wire-body quota charge underflow");
    }

    fn shard(&self, key: &WireBodyQuotaKey) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize % self.quota_shards.len()
    }

    #[cfg(test)]
    fn fail_next_allocation(&self) {
        self.fail_next_allocation.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn take_allocation_failure(&self) -> bool {
        self.fail_next_allocation.swap(false, Ordering::AcqRel)
    }
}

fn try_atomic_add(counter: &AtomicUsize, bytes: usize, limit: usize) -> Result<(), ()> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(bytes).ok_or(())?;
        if next > limit {
            return Err(());
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

#[derive(Default)]
struct QuotaEntry {
    active_leases: AtomicUsize,
    charge: AtomicUsize,
}

struct QuotaLease {
    pool: Arc<WireBodyPool>,
    key: WireBodyQuotaKey,
    shard_index: usize,
    entry: Arc<QuotaEntry>,
}

impl Drop for QuotaLease {
    fn drop(&mut self) {
        let mut shard = self.pool.quota_shards[self.shard_index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let leases_before = self.entry.active_leases.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(leases_before > 0, "wire-body quota lease underflow");
        if leases_before == 1
            && self.entry.charge.load(Ordering::Acquire) == 0
            && shard
                .get(&self.key)
                .is_some_and(|mapped| Arc::ptr_eq(mapped, &self.entry))
        {
            shard.remove(&self.key);
        }
    }
}

pub(crate) struct HttpWireBodyGuard {
    inner: Arc<GuardInner>,
}

/// Cloneable allocation authority for a provider response. It deliberately
/// cannot transfer request bodies or allocate request-stream scratch.
#[derive(Clone)]
pub(crate) struct ProviderResponseCharge {
    inner: Arc<GuardInner>,
}

impl fmt::Debug for HttpWireBodyGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpWireBodyGuard")
            .field("cursor_peak_bytes", &self.inner.cursor_peak_bytes)
            .field("live_bytes", &self.live_bytes())
            .finish()
    }
}

impl HttpWireBodyGuard {
    pub(crate) fn buffer(&self) -> GuardedBodyBuilder {
        GuardedBodyBuilder::new(self.authority())
    }

    pub(crate) fn reserve_exact_buffer(
        &self,
        exact_len: usize,
    ) -> Result<ReservedGuardedBodyBuilder, WireBodyBufferError> {
        GuardedBodyBuilder::reserve_exact(self.authority(), exact_len)
    }

    pub(crate) fn stream_scratch(&self) -> Result<GuardedScratch, WireBodyBufferError> {
        GuardedScratch::try_new(self.authority())
    }

    pub(crate) fn codec_workspace_allocation(
        &self,
        bytes: usize,
    ) -> Result<GuardedWorkspaceAllocation, WireBodyBufferError> {
        GuardedWorkspaceAllocation::try_new(self.authority(), bytes)
    }

    pub(crate) fn charge_exact_allocation(
        &self,
        bytes: usize,
    ) -> Result<GuardedAllocationCharge, WireBodyBufferError> {
        GuardedAllocationCharge::try_new(self.authority(), bytes)
    }

    pub(crate) fn provider_response_charge(&self) -> ProviderResponseCharge {
        ProviderResponseCharge {
            inner: self.inner.clone(),
        }
    }

    pub(crate) fn live_bytes(&self) -> usize {
        self.inner.live_bytes.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn cursor_peak_bytes(&self) -> usize {
        self.inner.cursor_peak_bytes
    }

    pub(crate) fn transfer_body(
        &self,
        body: GuardedBody,
    ) -> Result<GuardedBody, WireBodyBufferError> {
        self.validate_body(&body)?;
        Ok(body)
    }

    pub(crate) fn validate_body(&self, body: &GuardedBody) -> Result<(), WireBodyBufferError> {
        if body.belongs_to(&self.authority()) {
            Ok(())
        } else {
            Err(WireBodyBufferError::ForeignGuard)
        }
    }

    fn authority(&self) -> WireAllocationAuthority {
        WireAllocationAuthority(self.inner.clone())
    }
}

impl ProviderResponseCharge {
    pub(crate) fn buffer(&self) -> GuardedBodyBuilder {
        GuardedBodyBuilder::new(WireAllocationAuthority(self.inner.clone()))
    }
}

#[derive(Clone)]
pub(crate) struct WireAllocationAuthority(Arc<GuardInner>);

pub(crate) type GuardedAllocationCharge = ExactAllocationLease<WireAllocationAuthority>;
pub(crate) type GuardedBodyBuilder = StableBodyBuilder<WireAllocationAuthority>;
pub(crate) type ReservedGuardedBodyBuilder = ReservedStableBodyBuilder<WireAllocationAuthority>;
pub(crate) type GuardedBody = StableBody<WireAllocationAuthority>;
pub(crate) type GuardedBodySegments<'a> = StableBodySegments<'a>;
pub(crate) type GuardedScratch = StableScratch<WireAllocationAuthority>;
pub(crate) type GuardedWorkspaceAllocation = StableWorkspaceAllocation<WireAllocationAuthority>;

struct GuardInner {
    pool: Arc<WireBodyPool>,
    quota_key: WireBodyQuotaKey,
    quota_lease: OnceLock<QuotaLease>,
    cursor_peak_bytes: usize,
    live_bytes: AtomicUsize,
}

impl GuardInner {
    fn try_charge(self: &Arc<Self>, bytes: usize) -> Result<(), WireBodyBufferError> {
        if bytes == 0 {
            return Ok(());
        }
        try_atomic_add(&self.live_bytes, bytes, self.cursor_peak_bytes)
            .map_err(|_| WireBodyBufferError::CursorPeakExceeded)?;
        let lease = self
            .quota_lease
            .get_or_init(|| self.pool.lease_quota(&self.quota_key));
        if let Err(error) = self.pool.try_charge(lease, bytes) {
            self.live_bytes.fetch_sub(bytes, Ordering::AcqRel);
            return Err(error);
        }
        Ok(())
    }

    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let lease = self
            .quota_lease
            .get()
            .expect("a charged guard has a quota lease");
        self.pool.release(lease, bytes);
        let live_before = self.live_bytes.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(live_before >= bytes, "wire-body guard charge underflow");
    }
}

impl AllocationAuthority for WireAllocationAuthority {
    type Error = WireBodyBufferError;

    fn try_charge(&self, bytes: usize) -> Result<(), Self::Error> {
        self.0.try_charge(bytes)
    }

    fn release(&self, bytes: usize) {
        self.0.release(bytes);
    }

    fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn limit_error() -> Self::Error {
        WireBodyBufferError::CursorPeakExceeded
    }

    fn allocation_error() -> Self::Error {
        WireBodyBufferError::AllocationFailed
    }

    fn reservation_error() -> Self::Error {
        WireBodyBufferError::ReservedLengthMismatch
    }

    #[cfg(test)]
    fn take_allocation_failure(&self) -> bool {
        self.0.pool.take_allocation_failure()
    }
}

/// One-shot Hyper body that keeps decoded bytes in their request guard until
/// the transport consumes them.
pub(crate) struct GuardedHttpBody {
    data: Option<GuardedBodyData>,
}

pub(crate) struct GuardedBodyData {
    body: GuardedBody,
    head_offset: usize,
}

impl GuardedBodyData {
    pub(crate) fn capture_segments(&self) -> GuardedBodySegments<'_> {
        debug_assert_eq!(self.head_offset, 0);
        self.body.segments()
    }
}

impl GuardedHttpBody {
    pub(crate) fn new(body: GuardedBody) -> Self {
        Self {
            data: Some(GuardedBodyData {
                body,
                head_offset: 0,
            }),
        }
    }
}

impl fmt::Debug for GuardedHttpBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedHttpBody")
            .field(
                "remaining",
                &self.data.as_ref().map(Buf::remaining).unwrap_or(0),
            )
            .finish()
    }
}

impl fmt::Debug for GuardedBodyData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedBodyData")
            .field("remaining", &self.remaining())
            .field("charged_bytes", &self.body.charged_bytes())
            .finish()
    }
}

impl Buf for GuardedBodyData {
    fn remaining(&self) -> usize {
        self.body.len()
    }

    fn chunk(&self) -> &[u8] {
        self.body.current_chunk(self.head_offset)
    }

    fn advance(&mut self, count: usize) {
        self.body.consume(count, &mut self.head_offset);
    }
}

impl HttpBody for GuardedHttpBody {
    type Data = GuardedBodyData;
    type Error = Infallible;

    fn poll_data(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Data, Self::Error>>> {
        match self.data.take() {
            Some(data) if data.has_remaining() => std::task::Poll::Ready(Some(Ok(data))),
            Some(_) | None => std::task::Poll::Ready(None),
        }
    }

    fn poll_trailers(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        std::task::Poll::Ready(Ok(None))
    }

    fn is_end_stream(&self) -> bool {
        self.data.as_ref().is_none_or(|data| !data.has_remaining())
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map(Buf::remaining).unwrap_or(0) as u64)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WireBodyBufferError {
    #[error("wire-body cursor peak exceeded")]
    CursorPeakExceeded,
    #[error("wire-body quota-key capacity exhausted")]
    QuotaExhausted,
    #[error("wire-body process capacity exhausted")]
    GlobalExhausted,
    #[error("wire-body allocation failed")]
    AllocationFailed,
    #[error("wire-body buffer belongs to another request guard")]
    ForeignGuard,
    #[error("wire-body exact reservation length was not satisfied")]
    ReservedLengthMismatch,
}

#[cfg(test)]
mod linked_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn key() -> WireBodyQuotaKey {
        WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), |_| false)
    }

    fn allocation(chunks: usize) -> usize {
        guarded_body_allocation_bytes(chunks * MAX_BUFFER_GROWTH_BYTES).unwrap()
    }

    fn body_bytes(body: &GuardedBody) -> Vec<u8> {
        body.segments().flatten().copied().collect()
    }

    #[test]
    fn stream_scratch_has_one_exact_reusable_charge() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, key());
        let mut scratch = guard.stream_scratch().unwrap();

        assert_eq!(scratch.capacity(), MAX_BUFFER_GROWTH_BYTES);
        assert_eq!(guard.live_bytes(), one);
        assert_eq!(pool.global_charge(), one);
        assert_eq!(
            scratch.extend_from_slice(&vec![0xa5; MAX_BUFFER_GROWTH_BYTES]),
            MAX_BUFFER_GROWTH_BYTES
        );
        assert_eq!(scratch.remaining(), 0);
        scratch.reset();
        assert!(scratch.is_empty());
        assert!(scratch.is_zeroed_for_test());
        assert_eq!(guard.live_bytes(), one);

        assert_eq!(scratch.extend_from_slice(b"reused"), 6);
        drop(scratch);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn stream_scratch_allocation_failure_restores_every_charge() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, key());
        pool.fail_next_allocation();

        assert!(matches!(
            guard.stream_scratch(),
            Err(WireBodyBufferError::AllocationFailed)
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn codec_workspace_is_precharged_aligned_and_zeroized() {
        let requested = MAX_BUFFER_GROWTH_BYTES + 1;
        let charged = guarded_workspace_allocation_bytes(requested).unwrap();
        let pool = WireBodyPool::new(charged, charged);
        let guard = pool.begin(charged, key());
        let mut allocation = guard.codec_workspace_allocation(requested).unwrap();
        while !allocation.is_initialized() {
            allocation.initialize_next(MAX_BUFFER_GROWTH_BYTES);
        }
        let mut workspace = allocation.finish();

        assert_eq!(workspace.len(), charged);
        assert_eq!(
            workspace.as_mut_ptr() as usize % std::mem::align_of::<u128>(),
            0
        );
        assert_eq!(guard.live_bytes(), charged);
        workspace.as_mut_bytes().fill(0xa5);
        workspace.reset();
        assert!(workspace.is_zeroed_for_test());

        drop(workspace);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn codec_workspace_allocation_failure_restores_every_charge() {
        let charged = guarded_workspace_allocation_bytes(1).unwrap();
        let pool = WireBodyPool::new(charged, charged);
        let guard = pool.begin(charged, key());
        pool.fail_next_allocation();

        assert!(matches!(
            guard.codec_workspace_allocation(1),
            Err(WireBodyBufferError::AllocationFailed)
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn provider_response_handles_cannot_release_request_owned_body_charge() {
        let one = allocation(1);
        let pool = WireBodyPool::new(2 * one, 2 * one);
        let guard = pool.begin(2 * one, key());
        let mut original = guard.buffer();
        original.try_extend_from_slice(b"request body").unwrap();
        let original = original.finish();
        assert_eq!(guard.live_bytes(), one);

        let response_charge = guard.provider_response_charge();
        let response_charge_clone = response_charge.clone();
        let mut response = response_charge.buffer();
        response.try_extend_from_slice(b"response suffix").unwrap();
        let response = response.finish();
        assert_eq!(guard.live_bytes(), 2 * one);

        drop(response);
        drop(response_charge);
        drop(response_charge_clone);
        assert_eq!(guard.live_bytes(), one);
        assert_eq!(pool.global_charge(), one);

        let original = guard.transfer_body(original).unwrap();
        assert_eq!(original.len(), b"request body".len());
        drop(original);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn linked_chunks_preserve_order_without_moving_initialized_storage() {
        let peak = allocation(2);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin(peak, key());
        let mut builder = guard.buffer();
        builder
            .try_extend_from_slice(&vec![1; MAX_BUFFER_GROWTH_BYTES])
            .unwrap();
        let first_pointer = builder.newest_storage_ptr_for_test().unwrap();
        builder.try_extend_from_slice(b"tail").unwrap();
        let older_pointer = builder.next_storage_ptr_for_test().unwrap();
        assert_eq!(older_pointer, first_pointer);

        let body = builder.finish();
        let bytes = body_bytes(&body);
        assert_eq!(
            &bytes[..MAX_BUFFER_GROWTH_BYTES],
            vec![1; MAX_BUFFER_GROWTH_BYTES]
        );
        assert_eq!(&bytes[MAX_BUFFER_GROWTH_BYTES..], b"tail");
        assert_eq!(body.charged_bytes(), peak);
        assert_eq!(guard.live_bytes(), peak);
        drop(body);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn allocation_failure_releases_pending_payload_and_node_charge() {
        let peak = allocation(1);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin(peak, key());
        pool.fail_next_allocation();
        let mut builder = guard.buffer();
        assert_eq!(
            builder.try_extend_from_slice(b"secret"),
            Err(WireBodyBufferError::AllocationFailed)
        );
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn second_chunk_failure_wipes_and_releases_the_entire_builder() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, key());
        let mut builder = guard.buffer();
        assert_eq!(
            builder.try_extend_from_slice(&vec![7; MAX_BUFFER_GROWTH_BYTES + 1]),
            Err(WireBodyBufferError::CursorPeakExceeded)
        );
        assert_eq!(builder.len(), 0);
        assert!(
            !builder.has_allocated_segments_for_test(),
            "no initialized segments remain"
        );
        assert_eq!(builder.charged_bytes(), 0);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn exact_layout_projection_matches_live_charge_at_boundaries() {
        let one = allocation(1);
        let two = allocation(2);
        assert_eq!(guarded_body_allocation_bytes(1), Some(one));
        assert_eq!(
            guarded_body_allocation_bytes(MAX_BUFFER_GROWTH_BYTES),
            Some(one)
        );
        assert_eq!(
            guarded_body_allocation_bytes(MAX_BUFFER_GROWTH_BYTES + 1),
            Some(two)
        );

        let pool = WireBodyPool::new(two, two);
        let guard = pool.begin(two, key());
        let mut builder = guard.buffer();
        builder
            .try_extend_from_slice(&vec![9; MAX_BUFFER_GROWTH_BYTES + 1])
            .unwrap();
        assert_eq!(builder.charged_bytes(), two);
        drop(builder);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn exact_reservation_preallocates_and_preserves_multi_chunk_order() {
        let two = allocation(2);
        let exact_len = MAX_BUFFER_GROWTH_BYTES + 7;
        let pool = WireBodyPool::new(two, two);
        let guard = pool.begin(two, key());
        let mut reserved = guard.reserve_exact_buffer(exact_len).unwrap();
        assert_eq!(reserved.charged_bytes(), two);
        assert_eq!(guard.live_bytes(), two);

        pool.fail_next_allocation();
        reserved
            .try_extend_from_slice(&vec![0xa5; MAX_BUFFER_GROWTH_BYTES])
            .unwrap();
        reserved.try_extend_from_slice(b"ordered").unwrap();
        let body = reserved.finish().unwrap();
        assert_eq!(body.len(), exact_len);
        assert_eq!(body_bytes(&body)[MAX_BUFFER_GROWTH_BYTES..], *b"ordered");

        drop(body);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert!(matches!(
            guard.stream_scratch(),
            Err(WireBodyBufferError::AllocationFailed)
        ));
    }

    #[test]
    fn exact_reservation_preserves_order_across_many_preallocated_chunks() {
        const CHUNKS: usize = 96;
        let charged = allocation(CHUNKS);
        let exact_len = CHUNKS * MAX_BUFFER_GROWTH_BYTES;
        let pool = WireBodyPool::new(charged, charged);
        let guard = pool.begin(charged, key());
        let mut reserved = guard.reserve_exact_buffer(exact_len).unwrap();

        for index in 0..CHUNKS {
            let marker = (index as u8).wrapping_mul(37);
            reserved
                .try_extend_from_slice(&vec![marker; MAX_BUFFER_GROWTH_BYTES])
                .unwrap();
        }

        let body = reserved.finish().unwrap();
        assert_eq!(body.segments().count(), CHUNKS);
        for (index, segment) in body.segments().enumerate() {
            let marker = (index as u8).wrapping_mul(37);
            assert_eq!(segment.len(), MAX_BUFFER_GROWTH_BYTES);
            assert!(segment.iter().all(|byte| *byte == marker));
        }
        drop(body);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn dropping_partial_many_chunk_reservation_releases_every_charge() {
        const CHUNKS: usize = 32;
        let charged = allocation(CHUNKS);
        let pool = WireBodyPool::new(charged, charged);
        let quota_key = key();
        let guard = pool.begin(charged, quota_key.clone());
        let mut reserved = guard
            .reserve_exact_buffer(CHUNKS * MAX_BUFFER_GROWTH_BYTES)
            .unwrap();
        reserved
            .try_extend_from_slice(&vec![0xa5; MAX_BUFFER_GROWTH_BYTES + 17])
            .unwrap();
        assert_eq!(guard.live_bytes(), charged);

        drop(reserved);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);
    }

    #[test]
    fn exact_reservation_failure_is_atomic_after_partial_allocation() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, key());

        assert!(matches!(
            guard.reserve_exact_buffer(MAX_BUFFER_GROWTH_BYTES + 1),
            Err(WireBodyBufferError::CursorPeakExceeded)
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&key()), 0);
    }

    #[test]
    fn exact_reservation_overfill_is_terminal_and_releases_charge() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, key());
        let mut reserved = guard.reserve_exact_buffer(6).unwrap();
        reserved.try_extend_from_slice(b"secret").unwrap();

        assert_eq!(
            reserved.try_extend_from_slice(b"x"),
            Err(WireBodyBufferError::ReservedLengthMismatch)
        );
        assert_eq!(reserved.len(), 0);
        assert_eq!(reserved.charged_bytes(), 0);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert!(matches!(
            reserved.finish(),
            Err(WireBodyBufferError::ReservedLengthMismatch)
        ));
    }

    #[test]
    fn exact_reservation_underfill_releases_charge() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, key());
        let mut reserved = guard.reserve_exact_buffer(7).unwrap();
        reserved.try_extend_from_slice(b"six123").unwrap();
        assert_eq!(guard.live_bytes(), one);

        assert!(matches!(
            reserved.finish(),
            Err(WireBodyBufferError::ReservedLengthMismatch)
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn foreign_guard_rejects_finished_body_and_releases_it() {
        let peak = allocation(1);
        let pool = WireBodyPool::new(peak * 2, peak);
        let first = pool.begin(peak, key());
        let second = pool.begin(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), |_| false),
        );
        let mut builder = first.buffer();
        builder.try_extend_from_slice(b"secret").unwrap();
        assert!(matches!(
            second.transfer_body(builder.finish()),
            Err(WireBodyBufferError::ForeignGuard)
        ));
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn cursor_peak_rejects_before_charging_shared_pools() {
        let one = allocation(1);
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one - 1, key());
        let mut builder = guard.buffer();
        assert_eq!(
            builder.try_extend_from_slice(b"x"),
            Err(WireBodyBufferError::CursorPeakExceeded)
        );
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_entry_count(), 0);
    }

    #[test]
    fn quota_failure_isolated_by_key_and_global_failure_rolls_back_quota() {
        let one = allocation(1);
        let first_key = key();
        let second_key =
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), |_| false);

        let quota_pool = WireBodyPool::new(one * 2, one);
        let first = quota_pool.begin(one, first_key.clone());
        let same_quota = quota_pool.begin(one, first_key.clone());
        let mut first_body = first.buffer();
        first_body.try_extend_from_slice(b"first").unwrap();
        assert_eq!(
            same_quota.buffer().try_extend_from_slice(b"second"),
            Err(WireBodyBufferError::QuotaExhausted)
        );
        assert_eq!(quota_pool.quota_charge(&first_key), one);

        let global_pool = WireBodyPool::new(one, one);
        let global_first = global_pool.begin(one, first_key);
        let global_second = global_pool.begin(one, second_key.clone());
        let mut global_first_body = global_first.buffer();
        global_first_body.try_extend_from_slice(b"first").unwrap();
        assert_eq!(
            global_second.buffer().try_extend_from_slice(b"second"),
            Err(WireBodyBufferError::GlobalExhausted)
        );
        assert_eq!(global_pool.quota_charge(&second_key), 0);
        assert_eq!(global_second.live_bytes(), 0);
    }

    #[test]
    fn dropping_builder_and_finished_body_release_exact_charges() {
        let two = allocation(2);
        let pool = WireBodyPool::new(two, two);
        let quota_key = key();
        let guard = pool.begin(two, quota_key.clone());

        let mut builder = guard.buffer();
        builder
            .try_extend_from_slice(&vec![3; MAX_BUFFER_GROWTH_BYTES + 1])
            .unwrap();
        assert_eq!(guard.live_bytes(), two);
        assert_eq!(pool.quota_charge(&quota_key), two);
        drop(builder);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);

        let mut builder = guard.buffer();
        builder.try_extend_from_slice(b"secret").unwrap();
        let body = builder.finish();
        assert_eq!(guard.live_bytes(), allocation(1));
        drop(body);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);
    }

    #[test]
    fn stable_body_truncation_wipes_tail_and_releases_exact_chunks() {
        let three = allocation(3);
        let two = allocation(2);
        let pool = WireBodyPool::new(three, three);
        let guard = pool.begin(three, key());
        let mut builder = guard.buffer();
        builder
            .try_extend_from_slice(&vec![0xa5; 2 * MAX_BUFFER_GROWTH_BYTES + 17])
            .unwrap();
        let mut body = builder.finish();
        assert_eq!(guard.live_bytes(), three);

        body.truncate(MAX_BUFFER_GROWTH_BYTES + 9);
        assert_eq!(body.len(), MAX_BUFFER_GROWTH_BYTES + 9);
        assert_eq!(body.charged_bytes(), two);
        assert_eq!(guard.live_bytes(), two);
        assert_eq!(
            body.segments().map(<[u8]>::len).collect::<Vec<_>>(),
            [MAX_BUFFER_GROWTH_BYTES, 9]
        );

        body.truncate(0);
        assert_eq!(body.len(), 0);
        assert_eq!(body.charged_bytes(), 0);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn guarded_http_body_releases_consumed_chunks_without_copying() {
        let two = allocation(2);
        let quota_key = key();
        let pool = WireBodyPool::new(two, two);
        let guard = pool.begin(two, quota_key.clone());
        let mut builder = guard.buffer();
        builder
            .try_extend_from_slice(&vec![0xa5; MAX_BUFFER_GROWTH_BYTES])
            .unwrap();
        builder.try_extend_from_slice(b"tail").unwrap();

        let mut body = GuardedHttpBody::new(builder.finish());
        assert_eq!(
            body.size_hint().exact(),
            Some((MAX_BUFFER_GROWTH_BYTES + 4) as u64)
        );
        assert_eq!(guard.live_bytes(), two);
        assert_eq!(pool.quota_charge(&quota_key), two);

        let mut data = body.data().await.unwrap().unwrap();
        assert!(body.is_end_stream());
        assert_eq!(data.chunk(), vec![0xa5; MAX_BUFFER_GROWTH_BYTES]);

        data.advance(17);
        assert_eq!(data.remaining(), MAX_BUFFER_GROWTH_BYTES + 4 - 17);
        assert!(data.body.current_chunk_prefix_is_zeroed_for_test(17));
        assert_eq!(guard.live_bytes(), two);

        data.advance(MAX_BUFFER_GROWTH_BYTES - 17);
        assert_eq!(data.chunk(), b"tail");
        assert_eq!(guard.live_bytes(), allocation(1));
        assert_eq!(pool.global_charge(), allocation(1));
        assert_eq!(pool.quota_charge(&quota_key), allocation(1));

        data.advance(4);
        assert!(!data.has_remaining());
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn guarded_http_body_cancellation_releases_all_charges() {
        let one = allocation(1);
        let quota_key = key();
        let pool = WireBodyPool::new(one, one);
        let guard = pool.begin(one, quota_key.clone());
        let mut builder = guard.buffer();
        builder.try_extend_from_slice(b"never forwarded").unwrap();

        let body = GuardedHttpBody::new(builder.finish());
        assert_eq!(guard.live_bytes(), one);
        assert!(!format!("{body:?}").contains("never forwarded"));
        drop(body);

        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);

        let mut empty = GuardedHttpBody::new(guard.buffer().finish());
        assert!(empty.is_end_stream());
        assert!(empty.data().await.is_none());
        assert_eq!(empty.size_hint().exact(), Some(0));
    }
}
