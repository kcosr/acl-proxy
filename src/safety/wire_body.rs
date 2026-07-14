use allocator_api2::boxed::Box as FallibleBox;
use bytes::Buf;
use hyper::body::{HttpBody, SizeHint};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::MaybeUninit;
use std::net::IpAddr;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroize;

use crate::network::canonical_ip;

const QUOTA_SHARD_COUNT: usize = 16;
pub(crate) const MAX_BUFFER_GROWTH_BYTES: usize = 64 * 1024;
const WORKSPACE_ALIGNMENT: usize = std::mem::align_of::<u128>();

pub(crate) fn guarded_body_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    if payload_bytes == 0 {
        return Some(0);
    }
    let chunks = payload_bytes.checked_add(MAX_BUFFER_GROWTH_BYTES - 1)? / MAX_BUFFER_GROWTH_BYTES;
    chunks.checked_mul(MAX_BUFFER_GROWTH_BYTES.checked_add(std::mem::size_of::<SecretChunk>())?)
}

pub(crate) fn guarded_workspace_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    if payload_bytes == 0 {
        return Some(0);
    }
    payload_bytes
        .checked_add(WORKSPACE_ALIGNMENT - 1)
        .map(|bytes| bytes / WORKSPACE_ALIGNMENT * WORKSPACE_ALIGNMENT)
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
        GuardedBodyBuilder {
            guard: self.inner.clone(),
            reverse: None,
            len: 0,
            charged_bytes: 0,
        }
    }

    pub(crate) fn reserve_exact_buffer(
        &self,
        exact_len: usize,
    ) -> Result<ReservedGuardedBodyBuilder, WireBodyBufferError> {
        let chunk_count = if exact_len == 0 {
            0
        } else {
            exact_len
                .checked_add(MAX_BUFFER_GROWTH_BYTES - 1)
                .ok_or(WireBodyBufferError::CursorPeakExceeded)?
                / MAX_BUFFER_GROWTH_BYTES
        };
        let mut inner = self.buffer();
        for _ in 0..chunk_count {
            if let Err(error) = inner.try_allocate_chunk() {
                inner.clear_and_release();
                return Err(error);
            }
        }
        Ok(ReservedGuardedBodyBuilder {
            inner,
            exact_len,
            valid: true,
        })
    }

    pub(crate) fn stream_scratch(&self) -> Result<GuardedScratch, WireBodyBufferError> {
        let (chunk, charged_bytes) = allocate_secret_chunk(&self.inner)?;
        Ok(GuardedScratch {
            guard: self.inner.clone(),
            chunk,
            charged_bytes,
        })
    }

    pub(crate) fn codec_workspace_allocation(
        &self,
        bytes: usize,
    ) -> Result<GuardedWorkspaceAllocation, WireBodyBufferError> {
        let charged_bytes = guarded_workspace_allocation_bytes(bytes)
            .ok_or(WireBodyBufferError::CursorPeakExceeded)?;
        self.inner.try_charge(charged_bytes)?;
        let mut charge = PendingCharge {
            guard: self.inner.clone(),
            bytes: charged_bytes,
        };
        #[cfg(test)]
        if self.inner.pool.take_allocation_failure() {
            return Err(WireBodyBufferError::AllocationFailed);
        }
        let words = charged_bytes / WORKSPACE_ALIGNMENT;
        let storage = FallibleBox::<[u128]>::try_new_uninit_slice(words)
            .map_err(|_| WireBodyBufferError::AllocationFailed)?;
        Ok(GuardedWorkspaceAllocation {
            guard: self.inner.clone(),
            storage: Some(storage),
            charged_bytes: charge.commit(),
            initialized_words: 0,
        })
    }

    pub(crate) fn charge_exact_allocation(
        &self,
        bytes: usize,
    ) -> Result<GuardedAllocationCharge, WireBodyBufferError> {
        self.inner.try_charge(bytes)?;
        Ok(GuardedAllocationCharge {
            guard: self.inner.clone(),
            bytes,
        })
    }

    pub(crate) fn provider_response_charge(&self) -> ProviderResponseCharge {
        ProviderResponseCharge {
            inner: self.inner.clone(),
        }
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
        self.validate_body(&body)?;
        Ok(body)
    }

    pub(crate) fn validate_body(&self, body: &GuardedBody) -> Result<(), WireBodyBufferError> {
        if Arc::ptr_eq(&self.inner, &body.guard) {
            Ok(())
        } else {
            Err(WireBodyBufferError::ForeignGuard)
        }
    }
}

pub(crate) struct GuardedAllocationCharge {
    guard: Arc<GuardInner>,
    bytes: usize,
}

impl GuardedAllocationCharge {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for GuardedAllocationCharge {
    fn drop(&mut self) {
        self.guard.release(std::mem::take(&mut self.bytes));
    }
}

impl ProviderResponseCharge {
    pub(crate) fn buffer(&self) -> GuardedBodyBuilder {
        GuardedBodyBuilder {
            guard: self.inner.clone(),
            reverse: None,
            len: 0,
            charged_bytes: 0,
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

pub(crate) struct ReservedGuardedBodyBuilder {
    inner: GuardedBodyBuilder,
    exact_len: usize,
    valid: bool,
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

impl ReservedGuardedBodyBuilder {
    pub(crate) fn len(&self) -> usize {
        self.inner.len
    }

    pub(crate) fn charged_bytes(&self) -> usize {
        self.inner.charged_bytes
    }

    pub(crate) fn try_extend_from_slice(
        &mut self,
        mut input: &[u8],
    ) -> Result<(), WireBodyBufferError> {
        let Some(final_len) = self.inner.len.checked_add(input.len()) else {
            self.invalidate();
            return Err(WireBodyBufferError::ReservedLengthMismatch);
        };
        if !self.valid || final_len > self.exact_len {
            self.invalidate();
            return Err(WireBodyBufferError::ReservedLengthMismatch);
        }

        while !input.is_empty() {
            let chunk = self
                .inner
                .reverse
                .as_deref_mut()
                .and_then(SecretChunk::oldest_with_capacity)
                .expect("an exact reservation has enough initialized storage");
            let copied = chunk.extend_from_slice(input);
            input = &input[copied..];
        }
        self.inner.len = final_len;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<GuardedBody, WireBodyBufferError> {
        if !self.valid || self.inner.len != self.exact_len {
            self.invalidate();
            return Err(WireBodyBufferError::ReservedLengthMismatch);
        }
        Ok(self.inner.finish())
    }

    fn invalidate(&mut self) {
        if self.valid {
            self.inner.clear_and_release();
            self.valid = false;
        }
    }
}

pub(crate) struct GuardedScratch {
    guard: Arc<GuardInner>,
    chunk: FallibleBox<SecretChunk>,
    charged_bytes: usize,
}

pub(crate) struct GuardedWorkspace {
    guard: Arc<GuardInner>,
    storage: FallibleBox<[u128]>,
    charged_bytes: usize,
}

pub(crate) struct GuardedWorkspaceAllocation {
    guard: Arc<GuardInner>,
    storage: Option<FallibleBox<[MaybeUninit<u128>]>>,
    charged_bytes: usize,
    initialized_words: usize,
}

impl GuardedWorkspaceAllocation {
    pub(crate) fn len(&self) -> usize {
        self.charged_bytes
    }

    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized_words
            == self
                .storage
                .as_deref()
                .map(<[MaybeUninit<u128>]>::len)
                .unwrap_or(0)
    }

    pub(crate) fn initialize_next(&mut self, max_bytes: usize) {
        let storage = self
            .storage
            .as_deref_mut()
            .expect("pending workspace storage exists until finish");
        let max_words = max_bytes.div_ceil(WORKSPACE_ALIGNMENT).max(1);
        let end = self
            .initialized_words
            .saturating_add(max_words)
            .min(storage.len());
        for word in &mut storage[self.initialized_words..end] {
            word.write(0);
        }
        self.initialized_words = end;
    }

    pub(crate) fn finish(mut self) -> GuardedWorkspace {
        assert!(
            self.is_initialized(),
            "workspace must be initialized before use"
        );
        let storage = self
            .storage
            .take()
            .expect("pending workspace storage exists until finish");
        // Every word was initialized before ownership is converted.
        let storage = unsafe { storage.assume_init() };
        GuardedWorkspace {
            guard: self.guard.clone(),
            storage,
            charged_bytes: std::mem::take(&mut self.charged_bytes),
        }
    }
}

impl fmt::Debug for GuardedWorkspaceAllocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedWorkspaceAllocation")
            .field("charged_bytes", &self.charged_bytes)
            .field("initialized_words", &self.initialized_words)
            .finish()
    }
}

impl Drop for GuardedWorkspaceAllocation {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.as_deref_mut() {
            for word in &mut storage[..self.initialized_words] {
                // Initialized words may already contain sensitive codec state.
                unsafe { word.assume_init_mut() }.zeroize();
            }
        }
        self.guard.release(std::mem::take(&mut self.charged_bytes));
    }
}

impl GuardedWorkspace {
    pub(crate) fn len(&self) -> usize {
        self.charged_bytes
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        // The allocation is u128-aligned and covers exactly `charged_bytes` bytes.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.storage.as_mut_ptr().cast::<u8>(),
                self.charged_bytes,
            )
        }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_ptr().cast::<u8>()
    }

    pub(crate) fn reset(&mut self) {
        self.storage.zeroize();
    }

    #[cfg(test)]
    pub(crate) fn is_zeroed_for_test(&self) -> bool {
        self.storage.iter().all(|word| *word == 0)
    }
}

impl fmt::Debug for GuardedWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedWorkspace")
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl Drop for GuardedWorkspace {
    fn drop(&mut self) {
        self.reset();
        self.guard.release(std::mem::take(&mut self.charged_bytes));
    }
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

    pub(crate) fn writable(&mut self) -> &mut [u8] {
        self.reset();
        &mut self.chunk.bytes
    }

    pub(crate) fn set_initialized(&mut self, initialized: usize) {
        assert!(initialized <= self.chunk.bytes.len());
        self.chunk.initialized = initialized;
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

/// One-shot Hyper body that keeps decoded bytes in their request guard until
/// the transport consumes them.
pub(crate) struct GuardedHttpBody {
    data: Option<GuardedBodyData>,
}

pub(crate) struct GuardedBodyData {
    body: GuardedBody,
    head_offset: usize,
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
            .field("charged_bytes", &self.body.charged_bytes)
            .finish()
    }
}

impl Buf for GuardedBodyData {
    fn remaining(&self) -> usize {
        self.body.len
    }

    fn chunk(&self) -> &[u8] {
        self.body
            .head
            .as_deref()
            .map(|head| &head.initialized()[self.head_offset..])
            .unwrap_or_default()
    }

    fn advance(&mut self, mut count: usize) {
        assert!(count <= self.remaining(), "guarded body advance overflow");
        while count != 0 {
            let available = self
                .body
                .head
                .as_deref()
                .map(|head| head.initialized - self.head_offset)
                .expect("a nonempty guarded body has a head chunk");
            if count < available {
                let head = self.body.head.as_deref_mut().expect("head exists");
                head.bytes[self.head_offset..self.head_offset + count].zeroize();
                self.head_offset += count;
                self.body.len -= count;
                return;
            }

            count -= available;
            self.head_offset = 0;
            let mut consumed = self.body.head.take().expect("head exists");
            self.body.head = consumed.next.take();
            self.body.len -= available;
            let allocation = secret_chunk_allocation_bytes();
            self.body.charged_bytes -= allocation;
            self.body.guard.release(allocation);
            drop(consumed);
        }
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

#[derive(Clone)]
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
    let allocation_bytes = secret_chunk_allocation_bytes();
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

fn secret_chunk_allocation_bytes() -> usize {
    MAX_BUFFER_GROWTH_BYTES + std::mem::size_of::<SecretChunk>()
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

    fn oldest_with_capacity(&mut self) -> Option<&mut Self> {
        let next_has_capacity = self
            .next
            .as_deref()
            .is_some_and(SecretChunk::chain_has_capacity);
        if next_has_capacity {
            return self
                .next
                .as_deref_mut()
                .and_then(SecretChunk::oldest_with_capacity);
        }
        (self.initialized < self.bytes.len()).then_some(self)
    }

    fn chain_has_capacity(&self) -> bool {
        self.initialized < self.bytes.len()
            || self
                .next
                .as_deref()
                .is_some_and(SecretChunk::chain_has_capacity)
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
        assert_eq!(workspace.as_mut_ptr() as usize % WORKSPACE_ALIGNMENT, 0);
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
        let head = data.body.head.as_deref().unwrap();
        assert!(head.bytes[..17].iter().all(|byte| *byte == 0));
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
