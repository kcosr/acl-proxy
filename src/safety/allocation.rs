use allocator_api2::boxed::Box as FallibleBox;
use std::fmt;
use std::mem::MaybeUninit;
use zeroize::Zeroize;

pub(crate) const MAX_BUFFER_GROWTH_BYTES: usize = 64 * 1024;
const WORKSPACE_ALIGNMENT: usize = std::mem::align_of::<u128>();

pub(crate) fn body_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    if payload_bytes == 0 {
        return Some(0);
    }
    let chunks = payload_bytes.checked_add(MAX_BUFFER_GROWTH_BYTES - 1)? / MAX_BUFFER_GROWTH_BYTES;
    chunks.checked_mul(secret_chunk_allocation_bytes())
}

pub(crate) fn workspace_allocation_bytes(payload_bytes: usize) -> Option<usize> {
    if payload_bytes == 0 {
        return Some(0);
    }
    payload_bytes
        .checked_add(WORKSPACE_ALIGNMENT - 1)
        .map(|bytes| bytes / WORKSPACE_ALIGNMENT * WORKSPACE_ALIGNMENT)
}

/// Branded accounting used by stable secret-memory allocations. Implementors
/// decide which pool is charged; storage can only be transferred between
/// values carrying the same authority instance.
pub(crate) trait AllocationAuthority: Clone {
    type Error;

    fn try_charge(&self, bytes: usize) -> Result<(), Self::Error>;
    fn release(&self, bytes: usize);
    fn is_same(&self, other: &Self) -> bool;
    fn limit_error() -> Self::Error;
    fn allocation_error() -> Self::Error;
    fn reservation_error() -> Self::Error;

    #[cfg(test)]
    fn take_allocation_failure(&self) -> bool {
        false
    }
}

pub(crate) struct ExactAllocationLease<A: AllocationAuthority> {
    authority: A,
    bytes: usize,
}

pub(crate) struct StableExactBytes<A: AllocationAuthority> {
    authority: A,
    storage: Option<FallibleBox<[u8]>>,
    charged_bytes: usize,
}

impl<A: AllocationAuthority> StableExactBytes<A> {
    pub(crate) fn try_zeroed(authority: A, len: usize) -> Result<Self, A::Error> {
        let mut charge = ExactAllocationLease::try_new(authority.clone(), len)?;
        #[cfg(test)]
        if authority.take_allocation_failure() {
            return Err(A::allocation_error());
        }
        let mut storage =
            FallibleBox::<[u8]>::try_new_uninit_slice(len).map_err(|_| A::allocation_error())?;
        for byte in storage.iter_mut() {
            byte.write(0);
        }
        let storage = unsafe { storage.assume_init() };
        Ok(Self {
            authority,
            storage: Some(storage),
            charged_bytes: charge.commit(),
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.charged_bytes
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.charged_bytes == 0
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.storage.as_deref().expect("exact byte storage exists")
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.storage
            .as_deref_mut()
            .expect("exact byte storage exists")
    }

    #[cfg(test)]
    pub(crate) fn belongs_to(&self, authority: &A) -> bool {
        self.authority.is_same(authority)
    }
}

impl<A: AllocationAuthority> fmt::Debug for StableExactBytes<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableExactBytes")
            .field("len", &self.charged_bytes)
            .finish()
    }
}

impl<A: AllocationAuthority> Drop for StableExactBytes<A> {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.as_deref_mut() {
            storage.zeroize();
        }
        drop(self.storage.take());
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

impl<A: AllocationAuthority> ExactAllocationLease<A> {
    pub(crate) fn try_new(authority: A, bytes: usize) -> Result<Self, A::Error> {
        authority.try_charge(bytes)?;
        Ok(Self { authority, bytes })
    }

    fn commit(&mut self) -> usize {
        std::mem::take(&mut self.bytes)
    }
}

impl<A: AllocationAuthority> Drop for ExactAllocationLease<A> {
    fn drop(&mut self) {
        self.authority.release(std::mem::take(&mut self.bytes));
    }
}

pub(crate) struct StableBodyBuilder<A: AllocationAuthority> {
    authority: A,
    reverse: Option<FallibleBox<SecretChunk>>,
    len: usize,
    charged_bytes: usize,
}

pub(crate) struct ReservedStableBodyBuilder<A: AllocationAuthority> {
    inner: StableBodyBuilder<A>,
    remaining: Option<FallibleBox<SecretChunk>>,
    current: Option<FallibleBox<SecretChunk>>,
    exact_len: usize,
    valid: bool,
}

impl<A: AllocationAuthority> StableBodyBuilder<A> {
    pub(crate) fn new(authority: A) -> Self {
        Self {
            authority,
            reverse: None,
            len: 0,
            charged_bytes: 0,
        }
    }

    pub(crate) fn reserve_exact(
        authority: A,
        exact_len: usize,
    ) -> Result<ReservedStableBodyBuilder<A>, A::Error> {
        let chunk_count = if exact_len == 0 {
            0
        } else {
            exact_len
                .checked_add(MAX_BUFFER_GROWTH_BYTES - 1)
                .ok_or_else(A::limit_error)?
                / MAX_BUFFER_GROWTH_BYTES
        };
        let mut inner = Self::new(authority);
        for _ in 0..chunk_count {
            if let Err(error) = inner.try_allocate_chunk() {
                inner.clear_and_release();
                return Err(error);
            }
        }
        let remaining = inner.reverse.take();
        Ok(ReservedStableBodyBuilder {
            inner,
            remaining,
            current: None,
            exact_len,
            valid: true,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(crate) fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }

    #[cfg(test)]
    pub(crate) fn newest_storage_ptr_for_test(&self) -> Option<*const u8> {
        self.reverse.as_ref().map(|chunk| chunk.bytes.as_ptr())
    }

    #[cfg(test)]
    pub(crate) fn next_storage_ptr_for_test(&self) -> Option<*const u8> {
        self.reverse
            .as_ref()
            .and_then(|chunk| chunk.next.as_ref())
            .map(|chunk| chunk.bytes.as_ptr())
    }

    #[cfg(test)]
    pub(crate) fn has_allocated_segments_for_test(&self) -> bool {
        self.reverse.is_some()
    }

    pub(crate) fn try_extend_from_slice(&mut self, mut input: &[u8]) -> Result<(), A::Error> {
        let result = (|| {
            let final_len = self
                .len
                .checked_add(input.len())
                .ok_or_else(A::limit_error)?;
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
            self.clear_and_release();
        }
        result
    }

    pub(crate) fn finish(mut self) -> StableBody<A> {
        let mut reverse = self.reverse.take();
        let mut forward = None;
        while let Some(mut chunk) = reverse {
            let next = chunk.next.take();
            chunk.next = forward;
            forward = Some(chunk);
            reverse = next;
        }
        StableBody {
            authority: self.authority.clone(),
            head: forward,
            len: self.len,
            charged_bytes: std::mem::take(&mut self.charged_bytes),
        }
    }

    fn try_allocate_chunk(&mut self) -> Result<(), A::Error> {
        let (mut chunk, charged_bytes) = allocate_secret_chunk(self.authority.clone())?;
        chunk.next = self.reverse.take();
        self.reverse = Some(chunk);
        self.charged_bytes += charged_bytes;
        Ok(())
    }

    fn clear_and_release(&mut self) {
        drop_secret_chain(self.reverse.take());
        self.len = 0;
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

impl<A: AllocationAuthority> fmt::Debug for StableBodyBuilder<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableBodyBuilder")
            .field("len", &self.len)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl<A: AllocationAuthority> Drop for StableBodyBuilder<A> {
    fn drop(&mut self) {
        drop_secret_chain(self.reverse.take());
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

impl<A: AllocationAuthority> ReservedStableBodyBuilder<A> {
    pub(crate) fn len(&self) -> usize {
        self.inner.len
    }

    #[cfg(test)]
    pub(crate) fn charged_bytes(&self) -> usize {
        self.inner.charged_bytes
    }

    pub(crate) fn try_extend_from_slice(&mut self, mut input: &[u8]) -> Result<(), A::Error> {
        let Some(final_len) = self.inner.len.checked_add(input.len()) else {
            self.invalidate();
            return Err(A::reservation_error());
        };
        if !self.valid || final_len > self.exact_len {
            self.invalidate();
            return Err(A::reservation_error());
        }
        while !input.is_empty() {
            if self.current.is_none() {
                let mut next = self
                    .remaining
                    .take()
                    .expect("an exact reservation has enough uninitialized storage");
                self.remaining = next.next.take();
                self.current = Some(next);
            }
            let chunk = self.current.as_deref_mut().expect("current chunk exists");
            let copied = chunk.extend_from_slice(input);
            input = &input[copied..];
            if chunk.initialized == chunk.bytes.len() {
                self.finish_current_chunk();
            }
        }
        self.inner.len = final_len;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<StableBody<A>, A::Error> {
        if !self.valid || self.inner.len != self.exact_len {
            self.invalidate();
            return Err(A::reservation_error());
        }
        self.finish_current_chunk();
        debug_assert!(
            self.remaining.is_none(),
            "an exact reservation fills every chunk"
        );
        let replacement = StableBodyBuilder::new(self.inner.authority.clone());
        Ok(std::mem::replace(&mut self.inner, replacement).finish())
    }

    fn finish_current_chunk(&mut self) {
        if let Some(mut chunk) = self.current.take() {
            chunk.next = self.inner.reverse.take();
            self.inner.reverse = Some(chunk);
        }
    }

    fn invalidate(&mut self) {
        if self.valid {
            drop_secret_chain(self.current.take());
            drop_secret_chain(self.remaining.take());
            self.inner.clear_and_release();
            self.valid = false;
        }
    }
}

impl<A: AllocationAuthority> Drop for ReservedStableBodyBuilder<A> {
    fn drop(&mut self) {
        self.invalidate();
    }
}

pub(crate) struct StableBody<A: AllocationAuthority> {
    authority: A,
    head: Option<FallibleBox<SecretChunk>>,
    len: usize,
    charged_bytes: usize,
}

impl<A: AllocationAuthority> StableBody<A> {
    pub(crate) fn segments(&self) -> StableBodySegments<'_> {
        StableBodySegments {
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

    pub(crate) fn belongs_to(&self, authority: &A) -> bool {
        self.authority.is_same(authority)
    }

    pub(crate) fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        let retained_charge = body_allocation_bytes(new_len)
            .expect("a smaller stable body has a representable allocation layout");
        let released_charge = self
            .charged_bytes
            .checked_sub(retained_charge)
            .expect("stable body charge covers its retained layout");

        if new_len == 0 {
            drop_secret_chain(self.head.take());
        } else {
            let mut remaining = new_len;
            let mut current = self
                .head
                .as_deref_mut()
                .expect("a nonempty stable body has a head chunk");
            loop {
                if remaining < current.initialized {
                    current.bytes[remaining..current.initialized].zeroize();
                    current.initialized = remaining;
                    drop_secret_chain(current.next.take());
                    break;
                }
                remaining -= current.initialized;
                if remaining == 0 {
                    drop_secret_chain(current.next.take());
                    break;
                }
                current = current
                    .next
                    .as_deref_mut()
                    .expect("retained length is covered by stable body chunks");
            }
        }
        self.len = new_len;
        self.charged_bytes = retained_charge;
        self.authority.release(released_charge);
    }

    #[cfg(test)]
    pub(crate) fn current_chunk(&self, offset: usize) -> &[u8] {
        self.head
            .as_deref()
            .map(|head| &head.initialized()[offset..])
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn current_chunk_prefix_is_zeroed_for_test(&self, bytes: usize) -> bool {
        self.head
            .as_deref()
            .is_some_and(|head| head.bytes[..bytes].iter().all(|byte| *byte == 0))
    }

    #[cfg(test)]
    pub(crate) fn consume(&mut self, mut count: usize, head_offset: &mut usize) {
        assert!(count <= self.len, "stable body advance overflow");
        while count != 0 {
            let available = self
                .head
                .as_deref()
                .map(|head| head.initialized - *head_offset)
                .expect("a nonempty stable body has a head chunk");
            if count < available {
                let head = self.head.as_deref_mut().expect("head exists");
                head.bytes[*head_offset..*head_offset + count].zeroize();
                *head_offset += count;
                self.len -= count;
                return;
            }
            count -= available;
            *head_offset = 0;
            let mut consumed = self.head.take().expect("head exists");
            self.head = consumed.next.take();
            self.len -= available;
            let allocation = secret_chunk_allocation_bytes();
            self.charged_bytes -= allocation;
            drop(consumed);
            self.authority.release(allocation);
        }
    }
}

impl<A: AllocationAuthority> fmt::Debug for StableBody<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableBody")
            .field("len", &self.len)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl<A: AllocationAuthority> Drop for StableBody<A> {
    fn drop(&mut self) {
        drop_secret_chain(self.head.take());
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

#[derive(Clone)]
pub(crate) struct StableBodySegments<'a> {
    next: Option<&'a SecretChunk>,
}

impl<'a> Iterator for StableBodySegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = self.next?;
        self.next = chunk.next.as_deref();
        Some(chunk.initialized())
    }
}

pub(crate) struct StableScratch<A: AllocationAuthority> {
    authority: A,
    chunk: Option<FallibleBox<SecretChunk>>,
    charged_bytes: usize,
}

impl<A: AllocationAuthority> StableScratch<A> {
    pub(crate) fn try_new(authority: A) -> Result<Self, A::Error> {
        let (chunk, charged_bytes) = allocate_secret_chunk(authority.clone())?;
        Ok(Self {
            authority,
            chunk: Some(chunk),
            charged_bytes,
        })
    }

    pub(crate) fn capacity(&self) -> usize {
        self.chunk().bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunk().initialized == 0
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity() - self.chunk().initialized
    }

    pub(crate) fn extend_from_slice(&mut self, input: &[u8]) -> usize {
        self.chunk_mut().extend_from_slice(input)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.chunk().initialized()
    }

    pub(crate) fn writable(&mut self) -> &mut [u8] {
        self.reset();
        &mut self.chunk_mut().bytes
    }

    pub(crate) fn set_initialized(&mut self, initialized: usize) {
        assert!(initialized <= self.chunk().bytes.len());
        self.chunk_mut().initialized = initialized;
    }

    pub(crate) fn reset(&mut self) {
        let initialized = self.chunk().initialized;
        self.chunk_mut().bytes[..initialized].zeroize();
        self.chunk_mut().initialized = 0;
    }

    #[cfg(test)]
    pub(crate) fn is_zeroed_for_test(&self) -> bool {
        self.chunk().bytes.iter().all(|byte| *byte == 0)
    }

    fn chunk(&self) -> &SecretChunk {
        self.chunk.as_deref().expect("scratch storage exists")
    }

    fn chunk_mut(&mut self) -> &mut SecretChunk {
        self.chunk.as_deref_mut().expect("scratch storage exists")
    }
}

impl<A: AllocationAuthority> fmt::Debug for StableScratch<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableScratch")
            .field("capacity", &self.capacity())
            .field("initialized", &self.chunk().initialized)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl<A: AllocationAuthority> Drop for StableScratch<A> {
    fn drop(&mut self) {
        self.reset();
        drop(self.chunk.take());
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

pub(crate) struct StableWorkspaceAllocation<A: AllocationAuthority> {
    authority: A,
    storage: Option<FallibleBox<[MaybeUninit<u128>]>>,
    charged_bytes: usize,
    initialized_words: usize,
}

pub(crate) struct StableWorkspace<A: AllocationAuthority> {
    authority: A,
    storage: Option<FallibleBox<[u128]>>,
    charged_bytes: usize,
}

impl<A: AllocationAuthority> StableWorkspaceAllocation<A> {
    pub(crate) fn try_new(authority: A, bytes: usize) -> Result<Self, A::Error> {
        let charged_bytes = workspace_allocation_bytes(bytes).ok_or_else(A::limit_error)?;
        let mut charge = ExactAllocationLease::try_new(authority.clone(), charged_bytes)?;
        #[cfg(test)]
        if authority.take_allocation_failure() {
            return Err(A::allocation_error());
        }
        let words = charged_bytes / WORKSPACE_ALIGNMENT;
        let storage = FallibleBox::<[u128]>::try_new_uninit_slice(words)
            .map_err(|_| A::allocation_error())?;
        Ok(Self {
            authority,
            storage: Some(storage),
            charged_bytes: charge.commit(),
            initialized_words: 0,
        })
    }

    #[cfg(test)]
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

    pub(crate) fn finish(mut self) -> StableWorkspace<A> {
        assert!(
            self.is_initialized(),
            "workspace must be initialized before use"
        );
        let storage = self
            .storage
            .take()
            .expect("pending workspace storage exists");
        // Every word was initialized before ownership is converted.
        let storage = unsafe { storage.assume_init() };
        StableWorkspace {
            authority: self.authority.clone(),
            storage: Some(storage),
            charged_bytes: std::mem::take(&mut self.charged_bytes),
        }
    }
}

impl<A: AllocationAuthority> Drop for StableWorkspaceAllocation<A> {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.as_deref_mut() {
            for word in &mut storage[..self.initialized_words] {
                // Initialized words may already contain sensitive codec state.
                unsafe { word.assume_init_mut() }.zeroize();
            }
        }
        drop(self.storage.take());
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

impl<A: AllocationAuthority> fmt::Debug for StableWorkspaceAllocation<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableWorkspaceAllocation")
            .field("charged_bytes", &self.charged_bytes)
            .field("initialized_words", &self.initialized_words)
            .finish()
    }
}

impl<A: AllocationAuthority> StableWorkspace<A> {
    pub(crate) fn len(&self) -> usize {
        self.charged_bytes
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        let storage = self
            .storage
            .as_deref_mut()
            .expect("workspace storage exists");
        unsafe {
            std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), self.charged_bytes)
        }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage
            .as_deref_mut()
            .expect("workspace storage exists")
            .as_mut_ptr()
            .cast::<u8>()
    }

    pub(crate) fn reset(&mut self) {
        self.storage
            .as_deref_mut()
            .expect("workspace storage exists")
            .zeroize();
    }

    #[cfg(test)]
    pub(crate) fn is_zeroed_for_test(&self) -> bool {
        self.storage
            .as_deref()
            .expect("workspace storage exists")
            .iter()
            .all(|word| *word == 0)
    }
}

impl<A: AllocationAuthority> fmt::Debug for StableWorkspace<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableWorkspace")
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl<A: AllocationAuthority> Drop for StableWorkspace<A> {
    fn drop(&mut self) {
        self.reset();
        drop(self.storage.take());
        self.authority
            .release(std::mem::take(&mut self.charged_bytes));
    }
}

fn allocate_secret_chunk<A: AllocationAuthority>(
    authority: A,
) -> Result<(FallibleBox<SecretChunk>, usize), A::Error> {
    let allocation_bytes = secret_chunk_allocation_bytes();
    let mut charge = ExactAllocationLease::try_new(authority.clone(), allocation_bytes)?;
    #[cfg(test)]
    if authority.take_allocation_failure() {
        return Err(A::allocation_error());
    }
    let mut bytes = FallibleBox::<[u8]>::try_new_uninit_slice(MAX_BUFFER_GROWTH_BYTES)
        .map_err(|_| A::allocation_error())?;
    for byte in bytes.iter_mut() {
        byte.write(0);
    }
    let bytes = unsafe { bytes.assume_init() };
    let chunk = FallibleBox::try_new(SecretChunk {
        bytes,
        initialized: 0,
        next: None,
    })
    .map_err(|_| A::allocation_error())?;
    Ok((chunk, charge.commit()))
}

fn secret_chunk_allocation_bytes() -> usize {
    MAX_BUFFER_GROWTH_BYTES + std::mem::size_of::<SecretChunk>()
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
