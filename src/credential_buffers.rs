use std::alloc::{alloc, Layout};
use std::mem::{align_of, size_of};
use std::ptr::NonNull;
use std::sync::Arc;

use allocator_api2::boxed::Box as FallibleBox;
use credential_core::{
    CredentialAllocationClass, CredentialBatchReservation, CredentialBufferContext,
    CredentialBufferError, CredentialExactBuffer, CredentialResourceProjection,
};
use zeroize::Zeroize;

use crate::safety::wire_body::GuardedAllocationCharge;
use crate::safety::HttpWireBodyGuard;

/// Credential-core allocation authority projected onto one request wire guard.
pub(crate) struct ProductCredentialBufferContext {
    guard: HttpWireBodyGuard,
}

pub(crate) struct ProductCredentialProjectionContext;

struct ProductCredentialReservation {
    _charge: GuardedAllocationCharge,
}

struct ProductCredentialExactBuffer {
    storage: FallibleBox<[u8]>,
}

impl ProductCredentialBufferContext {
    pub(crate) fn new(guard: HttpWireBodyGuard) -> Arc<Self> {
        Arc::new(Self { guard })
    }

    pub(crate) fn composed_process_peak_bytes(
        &self,
        projection: CredentialResourceProjection,
        product_owned_bytes: u64,
    ) -> Result<u64, CredentialBufferError> {
        u64::try_from(self.guard.live_bytes())
            .map_err(|_| CredentialBufferError::CapacityExhausted)?
            .checked_add(projection.simultaneous_peak_bytes())
            .and_then(|peak| peak.checked_add(product_owned_bytes))
            .ok_or(CredentialBufferError::CapacityExhausted)
    }
}

impl CredentialBufferContext for ProductCredentialBufferContext {
    fn projected_maximum_allocation_bytes(
        &self,
        _class: CredentialAllocationClass,
        maximum_payload_bytes: usize,
    ) -> Result<u64, CredentialBufferError> {
        projected_allocation_bytes(maximum_payload_bytes)
    }

    fn projected_maximum_conversion_bytes(
        &self,
        maximum_rendered_values: usize,
        _maximum_rendered_payload_bytes: usize,
    ) -> Result<u64, CredentialBufferError> {
        projected_conversion_bytes(maximum_rendered_values)
    }

    fn projected_reservation_bytes(&self) -> Result<u64, CredentialBufferError> {
        projected_reservation_bytes()
    }

    fn reserve_batch(
        &self,
        projection: CredentialResourceProjection,
        composed_process_peak_bytes: u64,
    ) -> Result<Arc<dyn CredentialBatchReservation>, CredentialBufferError> {
        if composed_process_peak_bytes < projection.simultaneous_peak_bytes() {
            return Err(CredentialBufferError::ReservationMismatch);
        }
        let live = u64::try_from(self.guard.live_bytes())
            .map_err(|_| CredentialBufferError::CapacityExhausted)?;
        let incremental = composed_process_peak_bytes.saturating_sub(live);
        let incremental =
            usize::try_from(incremental).map_err(|_| CredentialBufferError::CapacityExhausted)?;
        let charge = self
            .guard
            .charge_exact_allocation(incremental)
            .map_err(|_| CredentialBufferError::CapacityExhausted)?;
        Ok(Arc::new(ProductCredentialReservation { _charge: charge }))
    }
}

impl CredentialBufferContext for ProductCredentialProjectionContext {
    fn projected_maximum_allocation_bytes(
        &self,
        _class: CredentialAllocationClass,
        maximum_payload_bytes: usize,
    ) -> Result<u64, CredentialBufferError> {
        projected_allocation_bytes(maximum_payload_bytes)
    }

    fn projected_maximum_conversion_bytes(
        &self,
        maximum_rendered_values: usize,
        _maximum_rendered_payload_bytes: usize,
    ) -> Result<u64, CredentialBufferError> {
        projected_conversion_bytes(maximum_rendered_values)
    }

    fn projected_reservation_bytes(&self) -> Result<u64, CredentialBufferError> {
        projected_reservation_bytes()
    }

    fn reserve_batch(
        &self,
        _projection: CredentialResourceProjection,
        _composed_process_peak_bytes: u64,
    ) -> Result<Arc<dyn CredentialBatchReservation>, CredentialBufferError> {
        Err(CredentialBufferError::ReservationMismatch)
    }
}

fn projected_allocation_bytes(maximum_payload_bytes: usize) -> Result<u64, CredentialBufferError> {
    let bytes = maximum_payload_bytes
        .checked_add(size_of::<ProductCredentialExactBuffer>())
        .ok_or(CredentialBufferError::CapacityExhausted)?;
    u64::try_from(bytes).map_err(|_| CredentialBufferError::CapacityExhausted)
}

fn projected_conversion_bytes(
    maximum_rendered_values: usize,
) -> Result<u64, CredentialBufferError> {
    let bytes = maximum_rendered_values
        .checked_mul(size_of::<Option<(http::HeaderName, http::HeaderValue)>>())
        .ok_or(CredentialBufferError::CapacityExhausted)?;
    u64::try_from(bytes).map_err(|_| CredentialBufferError::CapacityExhausted)
}

fn projected_reservation_bytes() -> Result<u64, CredentialBufferError> {
    projected_arc_allocation_bytes::<ProductCredentialReservation>()
}

pub(crate) fn projected_arc_allocation_bytes<T>() -> Result<u64, CredentialBufferError> {
    let bytes = size_of::<T>()
        .checked_add(2 * size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(align_of::<T>().saturating_sub(1)))
        .ok_or(CredentialBufferError::CapacityExhausted)?;
    u64::try_from(bytes).map_err(|_| CredentialBufferError::CapacityExhausted)
}

impl CredentialBatchReservation for ProductCredentialReservation {
    fn allocate_exact(
        &self,
        _class: CredentialAllocationClass,
        len: usize,
    ) -> Result<Box<dyn CredentialExactBuffer>, CredentialBufferError> {
        let mut storage = FallibleBox::<[u8]>::try_new_uninit_slice(len)
            .map_err(|_| CredentialBufferError::AllocationFailed)?;
        for byte in storage.iter_mut() {
            byte.write(0);
        }
        // SAFETY: every element was initialized immediately above.
        let storage = unsafe { storage.assume_init() };
        try_box_exact_buffer(ProductCredentialExactBuffer { storage })
    }
}

impl CredentialExactBuffer for ProductCredentialExactBuffer {
    fn as_bytes(&self) -> &[u8] {
        &self.storage
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.storage
    }
}

impl Drop for ProductCredentialExactBuffer {
    fn drop(&mut self) {
        self.storage.zeroize();
    }
}

fn try_box_exact_buffer(
    value: ProductCredentialExactBuffer,
) -> Result<Box<dyn CredentialExactBuffer>, CredentialBufferError> {
    let layout = Layout::new::<ProductCredentialExactBuffer>();
    // SAFETY: `layout` is valid for ProductCredentialExactBuffer.
    let allocation = unsafe { alloc(layout) };
    let allocation = NonNull::new(allocation)
        .ok_or(CredentialBufferError::AllocationFailed)?
        .cast::<ProductCredentialExactBuffer>();
    // SAFETY: the allocation is properly aligned and large enough for `value`.
    unsafe { allocation.as_ptr().write(value) };
    // SAFETY: the pointer came from the global allocator with Box-compatible layout.
    let boxed = unsafe { Box::from_raw(allocation.as_ptr()) };
    Ok(boxed)
}
