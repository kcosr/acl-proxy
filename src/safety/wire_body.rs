use allocator_api2::boxed::Box as FallibleBox;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroize;

const QUOTA_SHARD_COUNT: usize = 16;
pub(crate) const MAX_BUFFER_GROWTH_BYTES: usize = 64 * 1024;

pub(crate) fn guarded_body_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    if payload_bytes == 0 {
        return Some(0);
    }
    let chunks = payload_bytes.checked_add(MAX_BUFFER_GROWTH_BYTES - 1)? / MAX_BUFFER_GROWTH_BYTES;
    chunks.checked_mul(MAX_BUFFER_GROWTH_BYTES.checked_add(std::mem::size_of::<SecretChunk>())?)
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

fn canonical_ip(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(peer) => peer
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(peer)),
        peer => peer,
    }
}

pub(crate) struct WireBodyPool {
    global_limit: usize,
    quota_limit: usize,
    global_charge: AtomicUsize,
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

    pub(crate) fn global_charge(&self) -> usize {
        self.global_charge.load(Ordering::Acquire)
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

    fn quota_charge(&self, key: &WireBodyQuotaKey) -> usize {
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
        GuardedBodyBuilder {
            guard: self.inner.clone(),
            reverse: None,
            len: 0,
            charged_bytes: 0,
        }
    }

    pub(crate) fn stream_scratch(&self) -> Result<GuardedScratch, WireBodyBufferError> {
        let (chunk, charged_bytes) = allocate_secret_chunk(&self.inner)?;
        Ok(GuardedScratch {
            guard: self.inner.clone(),
            chunk,
            charged_bytes,
        })
    }

    pub(crate) fn live_bytes(&self) -> usize {
        self.inner.live_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn cursor_peak_bytes(&self) -> usize {
        self.inner.cursor_peak_bytes
    }

    pub(crate) fn transfer_body(
        &self,
        body: GuardedBody,
    ) -> Result<GuardedBody, WireBodyBufferError> {
        if Arc::ptr_eq(&self.inner, &body.guard) {
            Ok(body)
        } else {
            Err(WireBodyBufferError::ForeignGuard)
        }
    }
}

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

pub(crate) struct GuardedBodyBuilder {
    guard: Arc<GuardInner>,
    reverse: Option<FallibleBox<SecretChunk>>,
    len: usize,
    charged_bytes: usize,
}

impl fmt::Debug for GuardedBodyBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedBodyBuilder")
            .field("len", &self.len)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl GuardedBodyBuilder {
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }

    pub(crate) fn try_extend_from_slice(
        &mut self,
        mut input: &[u8],
    ) -> Result<(), WireBodyBufferError> {
        let result = (|| {
            let final_len = self
                .len
                .checked_add(input.len())
                .ok_or(WireBodyBufferError::CursorPeakExceeded)?;
            while !input.is_empty() {
                if self
                    .reverse
                    .as_ref()
                    .is_none_or(|chunk| chunk.initialized == chunk.bytes.len())
                {
                    self.try_allocate_chunk()?;
                }
                let chunk = self.reverse.as_mut().expect("chunk was allocated");
                let copied = chunk.extend_from_slice(input);
                input = &input[copied..];
            }
            self.len = final_len;
            Ok(())
        })();
        if result.is_err() {
            // An append can initialize a chunk before a later allocation fails.
            // Make failure terminal for the accumulated body rather than expose
            // bytes that are inconsistent with `len`.
            self.clear_and_release();
        }
        result
    }

    fn clear_and_release(&mut self) {
        drop_secret_chain(self.reverse.take());
        self.len = 0;
        let released = std::mem::take(&mut self.charged_bytes);
        self.guard.release(released);
    }

    fn try_allocate_chunk(&mut self) -> Result<(), WireBodyBufferError> {
        let (mut chunk, charged_bytes) = allocate_secret_chunk(&self.guard)?;
        chunk.next = self.reverse.take();
        self.reverse = Some(chunk);
        self.charged_bytes += charged_bytes;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> GuardedBody {
        let mut reverse = self.reverse.take();
        let mut forward = None;
        while let Some(mut chunk) = reverse {
            let next = chunk.next.take();
            chunk.next = forward;
            forward = Some(chunk);
            reverse = next;
        }
        GuardedBody {
            guard: self.guard.clone(),
            head: forward,
            len: self.len,
            charged_bytes: std::mem::take(&mut self.charged_bytes),
        }
    }
}

pub(crate) struct GuardedScratch {
    guard: Arc<GuardInner>,
    chunk: FallibleBox<SecretChunk>,
    charged_bytes: usize,
}

impl GuardedScratch {
    pub(crate) fn capacity(&self) -> usize {
        self.chunk.bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunk.initialized == 0
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity() - self.chunk.initialized
    }

    pub(crate) fn extend_from_slice(&mut self, input: &[u8]) -> usize {
        self.chunk.extend_from_slice(input)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.chunk.initialized()
    }

    pub(crate) fn reset(&mut self) {
        let initialized = self.chunk.initialized;
        self.chunk.bytes[..initialized].zeroize();
        self.chunk.initialized = 0;
    }

    #[cfg(test)]
    pub(crate) fn is_zeroed_for_test(&self) -> bool {
        self.chunk.bytes.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Debug for GuardedScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedScratch")
            .field("capacity", &self.capacity())
            .field("initialized", &self.chunk.initialized)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl Drop for GuardedScratch {
    fn drop(&mut self) {
        self.reset();
        self.guard.release(std::mem::take(&mut self.charged_bytes));
    }
}

impl Drop for GuardedBodyBuilder {
    fn drop(&mut self) {
        drop_secret_chain(self.reverse.take());
        let released = std::mem::take(&mut self.charged_bytes);
        self.guard.release(released);
    }
}

pub(crate) struct GuardedBody {
    guard: Arc<GuardInner>,
    head: Option<FallibleBox<SecretChunk>>,
    len: usize,
    charged_bytes: usize,
}

impl GuardedBody {
    pub(crate) fn segments(&self) -> GuardedBodySegments<'_> {
        GuardedBodySegments {
            next: self.head.as_deref(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}

impl fmt::Debug for GuardedBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedBody")
            .field("len", &self.len)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl Drop for GuardedBody {
    fn drop(&mut self) {
        drop_secret_chain(self.head.take());
        let released = std::mem::take(&mut self.charged_bytes);
        self.guard.release(released);
    }
}

pub(crate) struct GuardedBodySegments<'a> {
    next: Option<&'a SecretChunk>,
}

impl<'a> Iterator for GuardedBodySegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = self.next?;
        self.next = chunk.next.as_deref();
        Some(chunk.initialized())
    }
}

struct PendingCharge {
    guard: Arc<GuardInner>,
    bytes: usize,
}

fn allocate_secret_chunk(
    guard: &Arc<GuardInner>,
) -> Result<(FallibleBox<SecretChunk>, usize), WireBodyBufferError> {
    let allocation_bytes = MAX_BUFFER_GROWTH_BYTES
        .checked_add(std::mem::size_of::<SecretChunk>())
        .ok_or(WireBodyBufferError::CursorPeakExceeded)?;
    guard.try_charge(allocation_bytes)?;
    let mut charge = PendingCharge {
        guard: guard.clone(),
        bytes: allocation_bytes,
    };
    #[cfg(test)]
    if guard.pool.take_allocation_failure() {
        return Err(WireBodyBufferError::AllocationFailed);
    }
    let mut bytes = FallibleBox::<[u8]>::try_new_uninit_slice(MAX_BUFFER_GROWTH_BYTES)
        .map_err(|_| WireBodyBufferError::AllocationFailed)?;
    for byte in bytes.iter_mut() {
        byte.write(0);
    }
    // Every element was initialized to zero above.
    let bytes = unsafe { bytes.assume_init() };
    let chunk = FallibleBox::try_new(SecretChunk {
        bytes,
        initialized: 0,
        next: None,
    })
    .map_err(|_| WireBodyBufferError::AllocationFailed)?;
    Ok((chunk, charge.commit()))
}

impl PendingCharge {
    fn commit(&mut self) -> usize {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for PendingCharge {
    fn drop(&mut self) {
        self.guard.release(self.bytes);
    }
}

struct SecretChunk {
    bytes: FallibleBox<[u8]>,
    initialized: usize,
    next: Option<FallibleBox<SecretChunk>>,
}

impl SecretChunk {
    fn initialized(&self) -> &[u8] {
        &self.bytes[..self.initialized]
    }

    fn extend_from_slice(&mut self, input: &[u8]) -> usize {
        let copied = input.len().min(self.bytes.len() - self.initialized);
        self.bytes[self.initialized..self.initialized + copied].copy_from_slice(&input[..copied]);
        self.initialized += copied;
        copied
    }
}

impl Drop for SecretChunk {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn drop_secret_chain(mut chain: Option<FallibleBox<SecretChunk>>) {
    while let Some(mut chunk) = chain {
        chain = chunk.next.take();
        drop(chunk);
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
}

#[cfg(test)]
mod linked_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn key() -> WireBodyQuotaKey {
        WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), |_| false)
    }

    fn allocation(chunks: usize) -> usize {
        chunks * (MAX_BUFFER_GROWTH_BYTES + std::mem::size_of::<SecretChunk>())
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
        assert!(scratch.chunk.bytes.iter().all(|byte| *byte == 0));
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
    fn linked_chunks_preserve_order_without_moving_initialized_storage() {
        let peak = allocation(2);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin(peak, key());
        let mut builder = guard.buffer();
        builder
            .try_extend_from_slice(&vec![1; MAX_BUFFER_GROWTH_BYTES])
            .unwrap();
        let first_pointer = builder.reverse.as_ref().unwrap().bytes.as_ptr();
        builder.try_extend_from_slice(b"tail").unwrap();
        let older_pointer = builder
            .reverse
            .as_ref()
            .unwrap()
            .next
            .as_ref()
            .unwrap()
            .bytes
            .as_ptr();
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
        assert!(builder.reverse.is_none(), "no initialized segments remain");
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
}
