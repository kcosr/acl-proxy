use std::mem::size_of;
use std::sync::Arc;

use credential_core::{
    BoxCredentialFuture, CredentialBufferContext, CredentialCancellation, CredentialDescriptor,
    CredentialError, CredentialProfile, CredentialProgram, CredentialProgramPreparation,
    CredentialRequestSession, CredentialResolutionRequest, CredentialResolver, ResolvedCredential,
};
use http_access_runtime::ForwardingCredentials;
use http_access_types::{CredentialRef, ForwardingPlan};

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
    projected_product_bytes: u64,
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
        let resolver = ProductCredentialResolver::new(io, bindings)?;
        let projected_product_bytes = projected_product_adapter_bytes(
            resolver.bindings.len(),
            resolver.reference_literal_bytes,
            resolver.maximum_environment_staging_bytes,
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
            projected_product_bytes,
        })
    }

    pub(crate) fn admit_for_plan(
        self,
        plan: &Arc<ForwardingPlan>,
    ) -> Result<ForwardingCredentials, CredentialError> {
        if !Arc::ptr_eq(plan, &self.plan) {
            return Err(CredentialError::BindingMismatch);
        }
        let composed = self
            .buffers
            .composed_process_peak_bytes(self.program.projection(), self.projected_product_bytes)?;
        let program = self.program.admit(composed)?;
        ForwardingCredentials::new(self.plan, program, self.resolver)
    }
}

pub(crate) fn projected_product_adapter_bytes(
    binding_count: usize,
    reference_literal_bytes: usize,
    maximum_environment_staging_bytes: usize,
    has_external_source: bool,
    has_provider_wire: bool,
) -> Result<u64, CredentialError> {
    let binding_bytes = binding_count
        .checked_mul(size_of::<ProductCredentialBinding>())
        .ok_or(CredentialError::ResourceLimit)?;
    let buffer_context_arc = projected_arc_allocation_bytes::<ProductCredentialBufferContext>()
        .map_err(CredentialError::from)?;
    let provider_wire_arc = if has_provider_wire {
        projected_arc_allocation_bytes::<ProviderCredentialWireStore>()
            .map_err(CredentialError::from)?
    } else {
        0
    };
    let operation_bytes = if has_external_source {
        projected_credential_io_operation_bytes()
    } else {
        0
    };
    let owned = binding_bytes
        .checked_add(reference_literal_bytes)
        .and_then(|bytes| bytes.checked_add(maximum_environment_staging_bytes))
        .ok_or(CredentialError::ResourceLimit)?;
    u64::try_from(owned)
        .map_err(|_| CredentialError::ResourceLimit)?
        .checked_add(buffer_context_arc)
        .and_then(|bytes| bytes.checked_add(provider_wire_arc))
        .and_then(|bytes| bytes.checked_add(operation_bytes))
        .ok_or(CredentialError::ResourceLimit)
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
pub(crate) fn environment_credentials_for_test(
    guard: &HttpWireBodyGuard,
    variable: &str,
    destination: &str,
) -> (ForwardingCredentials, Arc<CredentialIoRuntime>) {
    credentials_for_test(
        guard,
        OutboundCredentialSource::environment_for_test(variable),
        destination,
    )
}

#[cfg(test)]
pub(crate) fn file_credentials_for_test(
    guard: &HttpWireBodyGuard,
    path: impl Into<std::path::PathBuf>,
    destination: &str,
) -> (ForwardingCredentials, Arc<CredentialIoRuntime>) {
    credentials_for_test(
        guard,
        OutboundCredentialSource::file_for_test(path),
        destination,
    )
}

#[cfg(test)]
fn credentials_for_test(
    guard: &HttpWireBodyGuard,
    source: OutboundCredentialSource,
    destination: &str,
) -> (ForwardingCredentials, Arc<CredentialIoRuntime>) {
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
    let credentials = preparation.admit_for_plan(&plan).unwrap();
    (credentials, io)
}

#[cfg(test)]
mod tests {
    use super::projected_product_adapter_bytes;
    use crate::credential_io_runtime::projected_credential_io_operation_bytes;

    #[test]
    fn external_source_projection_reserves_one_bounded_io_operation() {
        let without_source = projected_product_adapter_bytes(1, 0, 0, false, false).unwrap();
        let with_source = projected_product_adapter_bytes(1, 0, 0, true, false).unwrap();

        assert_eq!(
            with_source - without_source,
            projected_credential_io_operation_bytes()
        );
    }
}
