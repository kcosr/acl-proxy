use std::mem::size_of;
use std::sync::Arc;

use allocator_api2::boxed::Box as FallibleBox;
use credential_core::{
    BoxCredentialFuture, CredentialBufferContext, CredentialCancellation, CredentialDescriptor,
    CredentialDestination, CredentialError, CredentialProfile, CredentialProgram,
    CredentialProgramPreparation, CredentialRequestSession, CredentialResolutionRequest,
    CredentialResolver, ResolvedCredential,
};
use http_access_types::{CredentialMutationKind, CredentialRef, ForwardingPlan};

use crate::authorization::protocol::{ProviderCredentialWireStore, ProviderOutputIndex};
use crate::credential_buffers::{projected_arc_allocation_bytes, ProductCredentialBufferContext};
use crate::credential_io_runtime::{
    projected_credential_io_operation_control_bytes, CredentialIoRuntime,
};
use crate::credentials::{
    open_credential_file, read_environment_credential, read_into_fixed_buffer,
    terminal_line_ending_len, OutboundCredentialLocator, OutboundCredentialSource,
};
#[cfg(test)]
use crate::safety::HttpWireBodyGuard;
#[cfg(test)]
use credential_core::CredentialPurpose;

type ConvertedCredential = Option<(http::HeaderName, http::HeaderValue)>;
type ConvertedCredentialSlots = FallibleBox<[ConvertedCredential]>;
const PROJECTED_CREDENTIAL_CANCELLATION_BYTES: u64 = 256;

pub(crate) struct ProductCredentialResolver {
    io: Arc<CredentialIoRuntime>,
    bindings: Box<[ProductCredentialBinding]>,
    reference_literal_bytes: usize,
    maximum_environment_staging_bytes: usize,
    has_external_source: bool,
    has_provider_wire: bool,
}

pub(crate) struct ProductCredentialPreparation {
    plan: Arc<ForwardingPlan>,
    program: CredentialProgramPreparation,
    resolver: ProductCredentialResolver,
    buffers: Arc<ProductCredentialBufferContext>,
    destinations: Box<[http::HeaderName]>,
    projected_product_bytes: u64,
}

pub(crate) struct ProductCredentialExecution {
    plan: Arc<ForwardingPlan>,
    program: CredentialProgram,
    resolver: ProductCredentialResolver,
    destinations: Box<[http::HeaderName]>,
    converted: ConvertedCredentialSlots,
    transport_reserved: bool,
    cancellation: Arc<dyn CredentialCancellation>,
}

pub(crate) enum ProductCredentialBinding {
    Source {
        reference: CredentialRef,
        source: OutboundCredentialSource,
    },
    Provider {
        reference: CredentialRef,
        output: ProviderOutputIndex,
        wire: Arc<ProviderCredentialWireStore>,
    },
}

impl ProductCredentialBinding {
    pub(crate) fn source(reference: CredentialRef, source: OutboundCredentialSource) -> Self {
        Self::Source { reference, source }
    }

    pub(crate) fn provider(
        reference: CredentialRef,
        output: ProviderOutputIndex,
        wire: Arc<ProviderCredentialWireStore>,
    ) -> Self {
        Self::Provider {
            reference,
            output,
            wire,
        }
    }

    fn reference(&self) -> &CredentialRef {
        match self {
            Self::Source { reference, .. } | Self::Provider { reference, .. } => reference,
        }
    }
}

impl ProductCredentialResolver {
    pub(crate) fn new(
        io: Arc<CredentialIoRuntime>,
        bindings: Vec<ProductCredentialBinding>,
    ) -> Result<Self, CredentialError> {
        let reference_literal_bytes = bindings.iter().try_fold(0usize, |total, binding| {
            total
                .checked_add(binding.reference().id().as_str().len())
                .ok_or(CredentialError::ResourceLimit)
        })?;
        let maximum_environment_staging_bytes = bindings
            .iter()
            .filter_map(|binding| match binding {
                ProductCredentialBinding::Source { source, .. }
                    if matches!(
                        source.locator(),
                        OutboundCredentialLocator::Environment { .. }
                    ) =>
                {
                    Some(source.maximum_staging_bytes())
                }
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let has_provider_wire = bindings
            .iter()
            .any(|binding| matches!(binding, ProductCredentialBinding::Provider { .. }));
        let has_external_source = bindings
            .iter()
            .any(|binding| matches!(binding, ProductCredentialBinding::Source { .. }));
        Ok(Self {
            io,
            bindings: bindings.into_boxed_slice(),
            reference_literal_bytes,
            maximum_environment_staging_bytes,
            has_external_source,
            has_provider_wire,
        })
    }

    fn binding(&self, reference: &CredentialRef) -> Option<&ProductCredentialBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.reference() == reference)
    }
}

impl ProductCredentialPreparation {
    pub(crate) fn prepare(
        plan: Arc<ForwardingPlan>,
        descriptors: Vec<CredentialDescriptor>,
        bindings: Vec<ProductCredentialBinding>,
        buffers: Arc<ProductCredentialBufferContext>,
        io: Arc<CredentialIoRuntime>,
    ) -> Result<Self, CredentialError> {
        let descriptors = descriptors.into_boxed_slice().into_vec();
        if descriptors.len() != bindings.len()
            || descriptors
                .iter()
                .zip(&bindings)
                .any(|(descriptor, binding)| descriptor.reference() != binding.reference())
        {
            return Err(CredentialError::BindingMismatch);
        }
        let mut destinations = Vec::new();
        destinations
            .try_reserve_exact(plan.credential_mutations().len())
            .map_err(|_| CredentialError::ResourceLimit)?;
        for mutation in plan.credential_mutations() {
            let destination = match mutation.kind() {
                CredentialMutationKind::Bearer(_) | CredentialMutationKind::Basic { .. } => {
                    http::header::AUTHORIZATION
                }
                CredentialMutationKind::CustomHeader { name, .. } => {
                    http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .map_err(|_| CredentialError::InvalidContract)?
                }
            };
            destinations.push(destination);
        }
        let destination_literal_bytes = plan.credential_mutations().iter().try_fold(
            0usize,
            |total, mutation| match mutation.kind() {
                CredentialMutationKind::CustomHeader { name, .. } => total
                    .checked_add(name.as_str().len())
                    .ok_or(CredentialError::ResourceLimit),
                CredentialMutationKind::Bearer(_) | CredentialMutationKind::Basic { .. } => {
                    Ok(total)
                }
            },
        )?;
        let destinations = destinations.into_boxed_slice();
        let resolver = ProductCredentialResolver::new(io, bindings)?;
        let projected_product_bytes = projected_product_adapter_bytes(
            resolver.bindings.len(),
            resolver.reference_literal_bytes,
            resolver.maximum_environment_staging_bytes,
            destinations.len(),
            destination_literal_bytes,
            resolver.has_external_source,
            resolver.has_provider_wire,
        )?;
        let authority: Arc<dyn CredentialBufferContext> = buffers.clone();
        let program = CredentialProgram::prepare(
            CredentialRequestSession::new(Arc::clone(&plan), CredentialProfile::StandaloneTrusted),
            descriptors,
            authority,
        )?;
        Ok(Self {
            plan,
            program,
            resolver,
            buffers,
            destinations,
            projected_product_bytes,
        })
    }

    pub(crate) fn admit_for_plan(
        self,
        plan: &Arc<ForwardingPlan>,
        cancellation: Arc<dyn CredentialCancellation>,
    ) -> Result<ProductCredentialExecution, CredentialError> {
        if !Arc::ptr_eq(plan, &self.plan) {
            return Err(CredentialError::BindingMismatch);
        }
        let composed = self
            .buffers
            .composed_process_peak_bytes(self.program.projection(), self.projected_product_bytes)?;
        let program = self.program.admit(composed)?;
        let converted = empty_conversion_slots(self.destinations.len())?;
        Ok(ProductCredentialExecution {
            plan: self.plan,
            program,
            resolver: self.resolver,
            destinations: self.destinations,
            converted,
            transport_reserved: false,
            cancellation,
        })
    }
}

pub(crate) fn projected_product_adapter_bytes(
    binding_count: usize,
    reference_literal_bytes: usize,
    maximum_environment_staging_bytes: usize,
    destination_count: usize,
    destination_literal_bytes: usize,
    has_external_source: bool,
    has_provider_wire: bool,
) -> Result<u64, CredentialError> {
    let binding_bytes = binding_count
        .checked_mul(size_of::<ProductCredentialBinding>())
        .ok_or(CredentialError::ResourceLimit)?;
    let destination_bytes = destination_count
        .checked_mul(size_of::<http::HeaderName>())
        .ok_or(CredentialError::ResourceLimit)?;
    let buffer_context_arc = projected_arc_allocation_bytes::<ProductCredentialBufferContext>()
        .map_err(CredentialError::from)?;
    let provider_wire_arc = if has_provider_wire {
        projected_arc_allocation_bytes::<ProviderCredentialWireStore>()
            .map_err(CredentialError::from)?
    } else {
        0
    };
    let header_map_bytes = projected_credential_header_map_bytes()?;
    let operation_control_bytes = if has_external_source {
        projected_credential_io_operation_control_bytes()
    } else {
        0
    };
    let owned = binding_bytes
        .checked_add(reference_literal_bytes)
        .and_then(|bytes| bytes.checked_add(destination_bytes))
        .and_then(|bytes| bytes.checked_add(destination_literal_bytes))
        .and_then(|bytes| bytes.checked_add(maximum_environment_staging_bytes))
        .ok_or(CredentialError::ResourceLimit)?;
    u64::try_from(owned)
        .map_err(|_| CredentialError::ResourceLimit)?
        .checked_add(buffer_context_arc)
        .and_then(|bytes| bytes.checked_add(provider_wire_arc))
        .and_then(|bytes| bytes.checked_add(PROJECTED_CREDENTIAL_CANCELLATION_BYTES))
        .and_then(|bytes| bytes.checked_add(operation_control_bytes))
        .and_then(|bytes| bytes.checked_add(header_map_bytes))
        .ok_or(CredentialError::ResourceLimit)
}

fn projected_credential_header_map_bytes() -> Result<u64, CredentialError> {
    const MAX_RAW_CAPACITY: usize = 1 << 15;
    let maximum_entries = MAX_RAW_CAPACITY - MAX_RAW_CAPACITY / 4;
    let index_slot = 2 * size_of::<u16>();
    let entry_slot = size_of::<http::HeaderName>()
        .checked_add(size_of::<http::HeaderValue>())
        .and_then(|bytes| bytes.checked_add(4 * size_of::<usize>()))
        .ok_or(CredentialError::ResourceLimit)?;
    let resident = MAX_RAW_CAPACITY
        .checked_mul(index_slot)
        .and_then(|bytes| {
            maximum_entries
                .checked_mul(entry_slot)
                .and_then(|entries| bytes.checked_add(entries))
        })
        .ok_or(CredentialError::ResourceLimit)?;
    let growth_peak = resident
        .checked_mul(2)
        .ok_or(CredentialError::ResourceLimit)?;
    u64::try_from(growth_peak).map_err(|_| CredentialError::ResourceLimit)
}

fn empty_conversion_slots(len: usize) -> Result<ConvertedCredentialSlots, CredentialError> {
    let mut slots =
        FallibleBox::try_new_uninit_slice(len).map_err(|_| CredentialError::ResourceLimit)?;
    for slot in slots.iter_mut() {
        slot.write(None);
    }
    // SAFETY: every slot was initialized to None immediately above.
    Ok(unsafe { slots.assume_init() })
}

impl ProductCredentialExecution {
    pub(crate) fn reserve_transport(
        &mut self,
        headers: &mut http::HeaderMap,
    ) -> Result<(), CredentialError> {
        if self.transport_reserved {
            return Err(CredentialError::InvalidContract);
        }
        let additional = self
            .destinations
            .iter()
            .filter(|name| !headers.contains_key(*name))
            .count();
        headers
            .try_reserve(additional)
            .map_err(|_| CredentialError::ResourceLimit)?;
        self.transport_reserved = true;
        Ok(())
    }

    pub(crate) async fn finalize<B>(
        mut self,
        request: &mut http::Request<B>,
    ) -> Result<(), CredentialError> {
        if !self.transport_reserved {
            return Err(CredentialError::InvalidContract);
        }
        let rendered = self
            .program
            .execute(&self.resolver, self.cancellation.as_ref())
            .await?;
        let mut transport = rendered
            .into_transport_for(self.plan.as_ref(), CredentialProfile::StandaloneTrusted)?;
        if transport.len() != self.destinations.len() {
            return Err(CredentialError::BindingMismatch);
        }
        for (index, expected) in self.destinations.iter().cloned().enumerate() {
            let credential = transport.next().ok_or(CredentialError::BindingMismatch)?;
            let (destination, bytes) = credential.into_parts();
            if !destination_matches(&destination, &expected) {
                return Err(CredentialError::BindingMismatch);
            }
            let value = sensitive_header_value(bytes)?;
            let slot = self
                .converted
                .get_mut(index)
                .ok_or(CredentialError::BindingMismatch)?;
            if slot.replace((expected, value)).is_some() {
                return Err(CredentialError::InvalidContract);
            }
        }
        if transport.next().is_some() {
            return Err(CredentialError::BindingMismatch);
        }
        publish_converted_credentials(
            self.cancellation.as_ref(),
            &mut self.converted,
            request.headers_mut(),
        )
    }
}

fn publish_converted_credentials(
    cancellation: &dyn CredentialCancellation,
    converted: &mut [Option<(http::HeaderName, http::HeaderValue)>],
    headers: &mut http::HeaderMap,
) -> Result<(), CredentialError> {
    if cancellation.is_cancelled() {
        return Err(CredentialError::Cancelled);
    }
    for slot in converted {
        let (destination, value) = slot.take().ok_or(CredentialError::InvalidContract)?;
        headers.insert(destination, value);
    }
    Ok(())
}

fn sensitive_header_value(bytes: bytes::Bytes) -> Result<http::HeaderValue, CredentialError> {
    let mut value = http::HeaderValue::from_maybe_shared(bytes)
        .map_err(|_| CredentialError::InvalidMaterial)?;
    value.set_sensitive(true);
    Ok(value)
}

fn destination_matches(destination: &CredentialDestination, expected: &http::HeaderName) -> bool {
    match destination {
        CredentialDestination::Authorization => expected == http::header::AUTHORIZATION,
        CredentialDestination::CustomHeader(name) => name.as_str() == expected.as_str(),
    }
}

impl CredentialResolver for ProductCredentialResolver {
    fn resolve<'a>(
        &'a self,
        request: CredentialResolutionRequest<'a>,
        cancellation: &'a dyn CredentialCancellation,
    ) -> BoxCredentialFuture<'a, Result<ResolvedCredential, CredentialError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(CredentialError::Cancelled);
            }
            match self
                .binding(request.descriptor().reference())
                .ok_or(CredentialError::UnknownReference)?
            {
                ProductCredentialBinding::Source { source, .. } => {
                    resolve_source(Arc::clone(&self.io), source.clone(), request, cancellation)
                        .await
                }
                ProductCredentialBinding::Provider { output, wire, .. } => {
                    let len = wire
                        .output_len(*output)
                        .ok_or(CredentialError::UnknownReference)?;
                    let mut writer = request.material_writer(len)?;
                    wire.copy_output(*output, writer.as_mut_bytes())
                        .map_err(|_| CredentialError::InvalidMaterial)?;
                    if cancellation.is_cancelled() {
                        return Err(CredentialError::Cancelled);
                    }
                    writer.finish()
                }
            }
        })
    }
}

async fn resolve_source(
    io: Arc<CredentialIoRuntime>,
    source: OutboundCredentialSource,
    request: CredentialResolutionRequest<'_>,
    cancellation: &dyn CredentialCancellation,
) -> Result<ResolvedCredential, CredentialError> {
    let staging_len = source.maximum_staging_bytes();
    let mut staging = request.staging_buffer(staging_len)?;
    let job =
        Box::new(
            move |cancelled: Arc<std::sync::atomic::AtomicBool>| match source.locator() {
                OutboundCredentialLocator::Environment { variable } => {
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(CredentialError::Cancelled);
                    }
                    let initialized = read_environment_credential(variable, staging.as_mut_bytes())
                        .map_err(|error| match error {
                            crate::credentials::CredentialError::SourceUnavailable => {
                                CredentialError::ServiceUnavailable
                            }
                            _ => CredentialError::InvalidMaterial,
                        })?;
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(CredentialError::Cancelled);
                    }
                    staging.rehome(0..initialized)
                }
                OutboundCredentialLocator::File { path } => {
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(CredentialError::Cancelled);
                    }
                    let mut file = open_credential_file(path)
                        .map_err(|_| CredentialError::ServiceUnavailable)?;
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(CredentialError::Cancelled);
                    }
                    let initialized = read_into_fixed_buffer(&mut file, staging.as_mut_bytes())
                        .map_err(|_| CredentialError::ServiceUnavailable)?;
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(CredentialError::Cancelled);
                    }
                    let ending = terminal_line_ending_len(&staging.as_mut_bytes()[..initialized]);
                    staging.rehome(0..initialized.saturating_sub(ending))
                }
            },
        ) as Box<_>;
    let operation = io
        .submit(job)
        .map_err(|_| CredentialError::ServiceUnavailable)?;
    let resolved = operation.await?;
    if cancellation.is_cancelled() {
        return Err(CredentialError::Cancelled);
    }
    Ok(resolved)
}

#[cfg(test)]
pub(crate) fn environment_execution_for_test(
    guard: &HttpWireBodyGuard,
    variable: &str,
    destination: &str,
) -> (ProductCredentialExecution, Arc<CredentialIoRuntime>) {
    execution_for_test(
        guard,
        OutboundCredentialSource::environment_for_test(variable),
        destination,
    )
}

#[cfg(test)]
pub(crate) fn file_execution_for_test(
    guard: &HttpWireBodyGuard,
    path: impl Into<std::path::PathBuf>,
    destination: &str,
) -> (ProductCredentialExecution, Arc<CredentialIoRuntime>) {
    execution_for_test(
        guard,
        OutboundCredentialSource::file_for_test(path),
        destination,
    )
}

#[cfg(test)]
fn execution_for_test(
    guard: &HttpWireBodyGuard,
    source: OutboundCredentialSource,
    destination: &str,
) -> (ProductCredentialExecution, Arc<CredentialIoRuntime>) {
    struct NeverCancelled;

    impl CredentialCancellation for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    let identity = http_access_types::SnapshotIdentity::new();
    let reference = CredentialRef::new(
        identity.clone(),
        http_access_types::StableId::new("transport-test-credential").unwrap(),
        1,
    )
    .unwrap();
    let destination = http_access_types::HeaderName::new(destination.to_owned()).unwrap();
    let mutation = http_access_types::CredentialMutation::custom_header(
        destination.clone(),
        reference.clone(),
    )
    .unwrap();
    let scheme = http_access_types::HttpScheme::Https;
    let origin = http_access_types::CanonicalUrl::new(
        scheme,
        http_access_types::CanonicalAuthority::new(
            scheme,
            http_access_types::CanonicalHost::new("origin.example").unwrap(),
            443,
        )
        .unwrap(),
        "/",
        None,
    )
    .unwrap();
    let body_limits = http_access_types::BodyLimits::new(1024, 1024, 1, 1, 1024, 0, 0).unwrap();
    let plan = Arc::new(
        ForwardingPlan::new(http_access_types::ForwardingPlanInput {
            snapshot_identity: identity,
            request_binding: http_access_types::RequestBinding::from_bytes([7; 32]),
            origin,
            route: http_access_types::Route::Direct,
            origin_tls: http_access_types::TlsIntent::SystemRoots,
            timeouts: http_access_types::StageTimeouts::new(1000, 1000, 1000, 1000).unwrap(),
            request_body: http_access_types::RequestBodyPolicy::new(
                http_access_types::BodyRepresentation::PreservedContentCoded,
                body_limits,
                http_access_types::TrailerPolicy::Deny,
            )
            .unwrap(),
            response: http_access_types::ResponsePolicy::new(
                body_limits,
                1000,
                http_access_types::RedirectPolicy::ReturnToCaller,
            )
            .unwrap(),
            request_mutation_batches: Vec::new(),
            response_mutation_batches: Vec::new(),
            redaction: None,
            capture: None,
            upgrade: http_access_types::UpgradePolicy::Deny,
            provenance: http_access_types::DecisionProvenance::new(
                http_access_types::PolicyGeneration::new(1).unwrap(),
                http_access_types::EffectivePolicy::Default,
                http_access_types::DecisionReason::new(
                    http_access_types::DecisionReasonCategory::Policy,
                    0,
                ),
                None,
            ),
            credential_mutations: vec![mutation],
        })
        .unwrap(),
    );
    let descriptor = CredentialDescriptor::new(
        reference.clone(),
        CredentialPurpose::CustomHeader(destination),
        CredentialProfile::StandaloneTrusted,
        credential_core::CredentialLimits::new(
            source.maximum_material_bytes(),
            source.maximum_staging_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    let io = CredentialIoRuntime::new().unwrap();
    let preparation = ProductCredentialPreparation::prepare(
        Arc::clone(&plan),
        vec![descriptor],
        vec![ProductCredentialBinding::source(reference, source)],
        ProductCredentialBufferContext::new(guard.clone()),
        Arc::clone(&io),
    )
    .unwrap();
    let execution = preparation
        .admit_for_plan(&plan, Arc::new(NeverCancelled))
        .unwrap();
    (execution, io)
}

#[cfg(test)]
mod tests {
    use super::{
        projected_product_adapter_bytes, publish_converted_credentials, sensitive_header_value,
        CredentialCancellation, CredentialError,
    };
    use crate::credential_io_runtime::projected_credential_io_operation_control_bytes;

    struct Cancelled;

    impl CredentialCancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn header_value_conversion_preserves_the_zeroizing_owner_allocation() {
        let bytes = bytes::Bytes::from(Vec::from(&b"owned-secret"[..]));
        let pointer = bytes.as_ptr();
        let value = sensitive_header_value(bytes).unwrap();

        assert_eq!(value.as_bytes().as_ptr(), pointer);
        assert!(value.is_sensitive());
    }

    #[test]
    fn cancellation_before_atomic_publication_leaves_headers_unchanged() {
        let destination = http::HeaderName::from_static("x-late-token");
        let value = sensitive_header_value(bytes::Bytes::from_static(b"owned-secret")).unwrap();
        let mut converted = vec![Some((destination.clone(), value))];
        let mut headers = http::HeaderMap::new();

        assert_eq!(
            publish_converted_credentials(&Cancelled, &mut converted, &mut headers),
            Err(CredentialError::Cancelled)
        );
        assert!(!headers.contains_key(destination));
        assert_eq!(converted.len(), 1);
    }

    #[test]
    fn external_source_projection_reserves_one_bounded_io_operation() {
        let without_source = projected_product_adapter_bytes(1, 0, 0, 1, 0, false, false).unwrap();
        let with_source = projected_product_adapter_bytes(1, 0, 0, 1, 0, true, false).unwrap();

        assert_eq!(
            with_source - without_source,
            projected_credential_io_operation_control_bytes()
        );
    }
}
