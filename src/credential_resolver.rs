use std::mem::size_of;
use std::sync::Arc;

use credential_core::{
    BoxCredentialFuture, CredentialBufferContext, CredentialCancellation, CredentialDescriptor,
    CredentialDestination, CredentialError, CredentialProfile, CredentialProgram,
    CredentialProgramPreparation, CredentialRequestSession, CredentialResolutionRequest,
    CredentialResolver, ResolvedCredential,
};
use http_access_types::{CredentialMutationKind, CredentialRef, ForwardingPlan};

use crate::authorization::protocol::{ProviderCredentialWireStore, ProviderOutputIndex};
use crate::credential_buffers::{projected_arc_allocation_bytes, ProductCredentialBufferContext};
use crate::credential_io_runtime::{projected_credential_io_operation_bytes, CredentialIoRuntime};
use crate::credentials::{
    open_credential_file, read_environment_credential, read_into_fixed_buffer,
    terminal_line_ending_len, OutboundCredentialLocator, OutboundCredentialSource,
};
#[cfg(test)]
use crate::safety::HttpWireBodyGuard;
#[cfg(test)]
use credential_core::CredentialPurpose;

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
        Ok(ProductCredentialExecution {
            plan: self.plan,
            program,
            resolver: self.resolver,
            destinations: self.destinations,
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
    let operation_bytes = if has_external_source {
        projected_credential_io_operation_bytes()
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
        .and_then(|bytes| bytes.checked_add(operation_bytes))
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

impl ProductCredentialExecution {
    pub(crate) async fn finalize<B>(
        self,
        request: &mut http::Request<B>,
    ) -> Result<(), CredentialError> {
        let rendered = self
            .program
            .execute(&self.resolver, self.cancellation.as_ref())
            .await?;
        let mut transport = rendered
            .into_transport_for(self.plan.as_ref(), CredentialProfile::StandaloneTrusted)?;
        if transport.len() != self.destinations.len() {
            return Err(CredentialError::BindingMismatch);
        }
        validate_active_final_header_projection(
            self.cancellation.as_ref(),
            request.headers(),
            &self.destinations,
            transport.metadata(),
        )?;
        let mut final_headers =
            stage_final_publication_headers(request.headers(), self.destinations.as_ref())?;
        for expected in self.destinations.iter().cloned() {
            let credential = transport.next().ok_or(CredentialError::BindingMismatch)?;
            let (destination, bytes) = credential.into_parts();
            if !destination_matches(&destination, &expected) {
                return Err(CredentialError::BindingMismatch);
            }
            let value = sensitive_header_value(bytes)?;
            if final_headers
                .try_insert(expected, value)
                .map_err(|_| CredentialError::ResourceLimit)?
                .is_some()
            {
                return Err(CredentialError::InvalidContract);
            }
        }
        if transport.next().is_some() {
            return Err(CredentialError::BindingMismatch);
        }
        publish_staged_headers(
            self.cancellation.as_ref(),
            request.headers_mut(),
            final_headers,
        )
    }
}

fn stage_final_publication_headers(
    headers: &http::HeaderMap,
    destinations: &[http::HeaderName],
) -> Result<http::HeaderMap, CredentialError> {
    let retained_field_count = headers
        .iter()
        .filter(|(name, _)| !destinations.contains(name))
        .count();
    let final_field_count = retained_field_count
        .checked_add(destinations.len())
        .ok_or(CredentialError::ResourceLimit)?;
    let mut staged = http::HeaderMap::new();
    staged
        .try_reserve(final_field_count)
        .map_err(|_| CredentialError::ResourceLimit)?;
    for (name, value) in headers {
        if destinations.contains(name) {
            continue;
        }
        staged
            .try_append(name.clone(), value.clone())
            .map_err(|_| CredentialError::ResourceLimit)?;
    }
    Ok(staged)
}

fn publish_staged_headers(
    cancellation: &dyn CredentialCancellation,
    headers: &mut http::HeaderMap,
    mut staged: http::HeaderMap,
) -> Result<(), CredentialError> {
    if cancellation.is_cancelled() {
        return Err(CredentialError::Cancelled);
    }
    std::mem::swap(headers, &mut staged);
    Ok(())
}

fn validate_active_final_header_projection<'a>(
    cancellation: &dyn CredentialCancellation,
    headers: &http::HeaderMap,
    destinations: &[http::HeaderName],
    metadata: impl ExactSizeIterator<Item = (&'a CredentialDestination, usize)>,
) -> Result<(), CredentialError> {
    if cancellation.is_cancelled() {
        return Err(CredentialError::Cancelled);
    }
    validate_final_header_projection(headers, destinations, metadata)
}

fn validate_final_header_projection<'a>(
    headers: &http::HeaderMap,
    destinations: &[http::HeaderName],
    metadata: impl ExactSizeIterator<Item = (&'a CredentialDestination, usize)>,
) -> Result<(), CredentialError> {
    if metadata.len() != destinations.len() {
        return Err(CredentialError::BindingMismatch);
    }
    let mut field_count = headers.len();
    let mut name_value_bytes = headers
        .iter()
        .try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
        })
        .ok_or(CredentialError::ResourceLimit)?;

    for (index, ((rendered_destination, value_len), destination)) in
        metadata.zip(destinations).enumerate()
    {
        if !destination_matches(rendered_destination, destination) {
            return Err(CredentialError::BindingMismatch);
        }
        if destinations[..index].contains(destination) {
            return Err(CredentialError::InvalidContract);
        }
        let existing = headers.get_all(destination);
        let existing_count = existing.iter().count();
        let existing_bytes = existing
            .iter()
            .try_fold(0usize, |total, existing| {
                total
                    .checked_add(destination.as_str().len())?
                    .checked_add(existing.as_bytes().len())
            })
            .ok_or(CredentialError::ResourceLimit)?;
        field_count = field_count
            .checked_sub(existing_count)
            .and_then(|count| count.checked_add(1))
            .ok_or(CredentialError::ResourceLimit)?;
        name_value_bytes = name_value_bytes
            .checked_sub(existing_bytes)
            .and_then(|bytes| bytes.checked_add(destination.as_str().len()))
            .and_then(|bytes| bytes.checked_add(value_len))
            .ok_or(CredentialError::ResourceLimit)?;
    }

    http_access_runtime::validate_header_projection(field_count, name_value_bytes)
        .map_err(|_| CredentialError::ResourceLimit)
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
            origin_protocol: http_access_types::HttpProtocol::Http1,
            route: http_access_types::Route::Direct,
            origin_security: http_access_types::TransportSecurity::Tls(
                http_access_types::ClientTlsIntent::new(
                    http_access_types::CanonicalHost::new("origin.example").unwrap(),
                    http_access_types::TlsTrust::SystemRoots,
                ),
            ),
            managed_network_policy: None,
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
        environment_execution_for_test, projected_product_adapter_bytes, publish_staged_headers,
        sensitive_header_value, stage_final_publication_headers,
        validate_active_final_header_projection, validate_final_header_projection,
        CredentialCancellation, CredentialError,
    };
    use crate::credential_io_runtime::projected_credential_io_operation_bytes;
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};
    use std::net::{IpAddr, Ipv4Addr};

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
        let mut headers = http::HeaderMap::new();
        headers.insert("x-visible", http::HeaderValue::from_static("original"));
        let mut staged = http::HeaderMap::new();
        staged.insert(destination.clone(), value);

        assert_eq!(
            publish_staged_headers(&Cancelled, &mut headers, staged),
            Err(CredentialError::Cancelled)
        );
        assert!(!headers.contains_key(destination));
        assert_eq!(headers["x-visible"], "original");
    }

    #[test]
    fn cancellation_precedes_final_projection_validation() {
        let destination = http::HeaderName::from_static("x-late-token");
        let empty = std::iter::empty::<(&credential_core::CredentialDestination, usize)>();

        assert_eq!(
            validate_active_final_header_projection(
                &Cancelled,
                &http::HeaderMap::new(),
                std::slice::from_ref(&destination),
                empty,
            ),
            Err(CredentialError::Cancelled)
        );
    }

    #[test]
    fn staged_publication_preserves_duplicate_order_and_sensitive_bits() {
        let destination = http::HeaderName::from_static("x-late-token");
        let mut headers = http::HeaderMap::new();
        let mut sensitive = http::HeaderValue::from_static("first");
        sensitive.set_sensitive(true);
        headers.append("x-visible", sensitive);
        headers.append("x-visible", http::HeaderValue::from_static("second"));
        headers.append(
            destination.clone(),
            http::HeaderValue::from_static("old-one"),
        );
        headers.append(
            destination.clone(),
            http::HeaderValue::from_static("old-two"),
        );

        let staged =
            stage_final_publication_headers(&headers, std::slice::from_ref(&destination)).unwrap();
        let visible = staged.get_all("x-visible").iter().collect::<Vec<_>>();
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0], "first");
        assert_eq!(visible[1], "second");
        assert!(visible[0].is_sensitive());
        assert!(!visible[1].is_sensitive());
        assert!(!staged.contains_key(destination));
    }

    #[tokio::test]
    async fn exact_capacity_projection_failure_leaves_request_headers_unchanged() {
        const VARIABLE: &str = "ACL_PROXY_ATOMIC_PUBLICATION_LIMIT_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var(VARIABLE, "secret");
        let peak = 8 * 1024 * 1024;
        let guard = WireBodyPool::new(peak, peak).begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let (execution, io) = environment_execution_for_test(&guard, VARIABLE, "x-late-token");
        let mut request = http::Request::new(());
        for _ in 0..http_access_runtime::MAX_HEADER_HYGIENE_FIELDS {
            request
                .headers_mut()
                .append("x-visible", http::HeaderValue::from_static("original"));
        }

        assert_eq!(
            execution.finalize(&mut request).await,
            Err(CredentialError::ResourceLimit)
        );
        assert_eq!(
            request.headers().get_all("x-visible").iter().count(),
            http_access_runtime::MAX_HEADER_HYGIENE_FIELDS
        );
        assert!(request
            .headers()
            .get_all("x-visible")
            .iter()
            .all(|value| value == "original"));
        assert!(!request.headers().contains_key("x-late-token"));

        io.shutdown_and_wait(None).await;
        std::env::remove_var(VARIABLE);
    }

    #[test]
    fn final_projection_replaces_all_existing_values_before_adding_one_secret() {
        let destination = http::HeaderName::from_static("x-late-token");
        let neutral_destination = http_access_types::HeaderName::new(destination.as_str()).unwrap();
        let rendered = [credential_core::CredentialDestination::CustomHeader(
            neutral_destination,
        )];
        let mut headers = http::HeaderMap::new();
        headers.append(
            destination.clone(),
            http::HeaderValue::from_static("old-one"),
        );
        headers.append(
            destination.clone(),
            http::HeaderValue::from_static("old-two"),
        );

        assert_eq!(
            validate_final_header_projection(
                &headers,
                std::slice::from_ref(&destination),
                rendered.iter().map(|destination| (destination, 1)),
            ),
            Ok(())
        );
    }

    fn repeated_empty_headers(name: &'static str, count: usize) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for _ in 0..count {
            headers.append(name, http::HeaderValue::from_static(""));
        }
        headers
    }

    fn custom_destination(
        destination: &http::HeaderName,
    ) -> credential_core::CredentialDestination {
        credential_core::CredentialDestination::CustomHeader(
            http_access_types::HeaderName::new(destination.as_str()).unwrap(),
        )
    }

    #[test]
    fn replacement_projection_accepts_exact_shared_limits_and_rejects_one_more_byte() {
        let destination = http::HeaderName::from_static("x-late-token");
        let mut headers =
            repeated_empty_headers("x-fill", http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1);
        headers.append(destination.clone(), http::HeaderValue::from_static("old"));
        let retained_bytes = (http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1)
            .checked_mul("x-fill".len())
            .unwrap();
        let exact_value_len = http_access_runtime::MAX_HEADER_HYGIENE_BYTES
            - retained_bytes
            - destination.as_str().len();
        let rendered = [custom_destination(&destination)];

        assert_eq!(
            validate_final_header_projection(
                &headers,
                std::slice::from_ref(&destination),
                rendered
                    .iter()
                    .map(|destination| (destination, exact_value_len)),
            ),
            Ok(())
        );
        assert_eq!(
            validate_final_header_projection(
                &headers,
                std::slice::from_ref(&destination),
                rendered
                    .iter()
                    .map(|destination| (destination, exact_value_len + 1)),
            ),
            Err(CredentialError::ResourceLimit)
        );
    }

    #[test]
    fn absent_destination_projection_accepts_exact_shared_limits_and_rejects_plus_one() {
        let destination = http::HeaderName::from_static("x-late-token");
        let headers =
            repeated_empty_headers("x-fill", http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1);
        let retained_bytes = (http_access_runtime::MAX_HEADER_HYGIENE_FIELDS - 1)
            .checked_mul("x-fill".len())
            .unwrap();
        let exact_value_len = http_access_runtime::MAX_HEADER_HYGIENE_BYTES
            - retained_bytes
            - destination.as_str().len();
        let rendered = [custom_destination(&destination)];

        assert_eq!(
            validate_final_header_projection(
                &headers,
                std::slice::from_ref(&destination),
                rendered
                    .iter()
                    .map(|destination| (destination, exact_value_len)),
            ),
            Ok(())
        );
        assert_eq!(
            validate_final_header_projection(
                &headers,
                std::slice::from_ref(&destination),
                rendered
                    .iter()
                    .map(|destination| (destination, exact_value_len + 1)),
            ),
            Err(CredentialError::ResourceLimit)
        );

        let field_overflow =
            repeated_empty_headers("x-fill", http_access_runtime::MAX_HEADER_HYGIENE_FIELDS);
        assert_eq!(
            validate_final_header_projection(
                &field_overflow,
                std::slice::from_ref(&destination),
                rendered.iter().map(|destination| (destination, 0)),
            ),
            Err(CredentialError::ResourceLimit)
        );
    }

    #[test]
    fn duplicate_credential_destinations_are_rejected_before_projection() {
        let destination = http::HeaderName::from_static("x-late-token");
        let rendered = [
            custom_destination(&destination),
            custom_destination(&destination),
        ];

        assert_eq!(
            validate_final_header_projection(
                &http::HeaderMap::new(),
                &[destination.clone(), destination],
                rendered.iter().map(|destination| (destination, 1)),
            ),
            Err(CredentialError::InvalidContract)
        );
    }

    #[test]
    fn external_source_projection_reserves_one_bounded_io_operation() {
        let without_source = projected_product_adapter_bytes(1, 0, 0, 1, 0, false, false).unwrap();
        let with_source = projected_product_adapter_bytes(1, 0, 0, 1, 0, true, false).unwrap();

        assert_eq!(
            with_source - without_source,
            projected_credential_io_operation_bytes()
        );
    }
}
