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
mod tests {
    #[cfg(unix)]
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use credential_core::{
        CredentialDescriptor, CredentialLimits, CredentialProfile, CredentialPurpose,
    };
    use http_access_runtime::{
        prepare_standalone_exchange, BodyBounds, BodyBudget, BoxFuture, Clock, ForwardingAdmission,
        ForwardingCancellation, ForwardingDevHarness, ForwardingError, ForwardingExecutor,
        ForwardingNetworkFacts, ForwardingNetworkGuard, ForwardingResources, ForwardingResponse,
        ForwardingRetention, ForwardingTerminal, ForwardingTerminalOutcome,
        ForwardingTerminalOwner, RuntimeBody, RuntimeError, RuntimeRequest, RuntimeResourceLimits,
        SnapshotLease, SnapshotLeaseInput, SnapshotRegistries, StandaloneExchange,
        StandaloneTrusted,
    };
    use http_access_types::{
        BodyFraming, BodyLimits, BodyMetadata, BodyRepresentation, CanonicalAuthority,
        CanonicalHost, CanonicalUrl, CredentialMutation, CredentialRef, DecisionProvenance,
        DecisionReason, DecisionReasonCategory, EffectivePolicy, ForwardingPlan,
        ForwardingPlanInput, HeaderName, HttpMethod, HttpProtocol, HttpProtocolSet, HttpScheme,
        HttpVersion, IngressMode, InterceptedRequestFacts, PolicyGeneration, PolicyHeaderFacts,
        RedirectPolicy, RequestBodyPolicy, ResponsePolicy, Route, SnapshotIdentity, StableId,
        StageTimeouts, TlsTrust, TrailerPolicy, TransportSecurity, UpgradePolicy,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        projected_product_adapter_bytes, ProductCredentialBinding, ProductCredentialPreparation,
    };
    use crate::credential_buffers::ProductCredentialBufferContext;
    use crate::credential_io_runtime::{
        projected_credential_io_operation_bytes, CredentialIoRuntime,
    };
    use crate::credentials::OutboundCredentialSource;
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    const CREDENTIAL_HEADER: &str = "x-late-token";

    struct TestClock(Instant);

    impl Clock for TestClock {
        fn monotonic_millis(&self) -> u64 {
            u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
        }

        fn unix_millis(&self) -> u64 {
            0
        }

        fn sleep_until(&self, deadline_millis: u64) -> BoxFuture<'static, ()> {
            let delay = deadline_millis.saturating_sub(self.monotonic_millis());
            Box::pin(tokio::time::sleep(Duration::from_millis(delay)))
        }
    }

    struct TestTerminal;

    impl ForwardingTerminal for TestTerminal {
        fn finish(
            &mut self,
            _outcome: ForwardingTerminalOutcome,
        ) -> BoxFuture<'static, Result<(), RuntimeError>> {
            Box::pin(std::future::ready(Ok(())))
        }

        fn abandon(&mut self) {}
    }

    struct CredentialForwardingFixture {
        executor: ForwardingExecutor,
        exchange: StandaloneExchange,
        target: http_access_runtime::ResolvedForwardingTarget,
        resources: ForwardingResources,
        io: Arc<CredentialIoRuntime>,
    }

    impl CredentialForwardingFixture {
        async fn execute(
            self,
        ) -> (
            Result<ForwardingResponse, ForwardingError>,
            Arc<CredentialIoRuntime>,
        ) {
            let result = self
                .executor
                .execute(self.exchange, self.target, self.resources)
                .await;
            (result, self.io)
        }
    }

    fn semantic_url(scheme: HttpScheme, host: &str, port: u16, path: &str) -> CanonicalUrl {
        CanonicalUrl::new(
            scheme,
            CanonicalAuthority::new(scheme, CanonicalHost::new(host.to_owned()).unwrap(), port)
                .unwrap(),
            path,
            None,
        )
        .unwrap()
    }

    fn credential_guard() -> crate::safety::HttpWireBodyGuard {
        let peak = 8 * 1024 * 1024;
        WireBodyPool::new(peak, peak).begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    async fn fixture(
        network: Arc<ForwardingNetworkGuard>,
        origin: CanonicalUrl,
        route: Route,
        origin_security: TransportSecurity,
        source: OutboundCredentialSource,
    ) -> CredentialForwardingFixture {
        let clock: Arc<dyn Clock> = Arc::new(TestClock(Instant::now()));
        let absolute_deadline_millis = 30_000;
        let body = RuntimeBody::from_chunks(
            Vec::new(),
            BodyBounds::new(1024, 1024, 1024, 0, 0, 1_000).unwrap(),
            Arc::clone(&clock),
            BodyBudget::new(4096).unwrap(),
            absolute_deadline_millis,
        )
        .unwrap();
        let facts = InterceptedRequestFacts::new(
            IngressMode::ExplicitHttp,
            HttpVersion::Http11,
            HttpMethod::new("GET").unwrap(),
            origin.clone(),
            Vec::new(),
            BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap();
        let request = RuntimeRequest::new(
            facts.clone(),
            Ipv4Addr::new(192, 0, 2, 10).into(),
            PolicyHeaderFacts::new(facts.headers().to_vec(), Vec::new()).unwrap(),
            BodyRepresentation::PreservedContentCoded,
            body,
            absolute_deadline_millis,
        )
        .unwrap();
        let lineage = request.begin_provider_invocation();
        let identity = SnapshotIdentity::new();
        let generation = PolicyGeneration::new(1).unwrap();
        let reference = CredentialRef::new(
            identity.clone(),
            StableId::new("transport-test-credential").unwrap(),
            1,
        )
        .unwrap();
        let destination = HeaderName::new(CREDENTIAL_HEADER.to_owned()).unwrap();
        let mutation =
            CredentialMutation::custom_header(destination.clone(), reference.clone()).unwrap();
        let body_limits = BodyLimits::new(1024, 1024, 1, 1, 1024, 0, 0).unwrap();
        let plan = ForwardingPlan::new(ForwardingPlanInput {
            snapshot_identity: identity.clone(),
            request_binding: request.binding().unwrap(),
            origin: origin.clone(),
            origin_protocol: HttpProtocol::Http1,
            route: route.clone(),
            origin_security,
            managed_network_policy: None,
            timeouts: StageTimeouts::new(2_000, 2_000, 2_000, 2_000).unwrap(),
            request_body: RequestBodyPolicy::new(
                BodyRepresentation::PreservedContentCoded,
                body_limits,
                TrailerPolicy::Deny,
            )
            .unwrap(),
            response: ResponsePolicy::new(body_limits, 2_000, RedirectPolicy::ReturnToCaller)
                .unwrap(),
            request_mutation_batches: Vec::new(),
            response_mutation_batches: Vec::new(),
            redaction: None,
            capture: None,
            upgrade: UpgradePolicy::Deny,
            provenance: DecisionProvenance::new(
                generation,
                EffectivePolicy::Default,
                DecisionReason::new(DecisionReasonCategory::Policy, 1),
                None,
            ),
            credential_mutations: vec![mutation],
        })
        .unwrap();
        let snapshot = SnapshotLease::new(SnapshotLeaseInput {
            identity: identity.clone(),
            generation,
            sensitive_headers: Vec::new(),
            registries: SnapshotRegistries::new(
                &identity,
                std::slice::from_ref(&reference),
                &[],
                &[],
            )
            .unwrap(),
            managed_network_policies: Vec::new(),
            tls_roots: Vec::new(),
            resource_limits: RuntimeResourceLimits::new(1024 * 1024, 1024 * 1024, 0).unwrap(),
            templates: Vec::new(),
            handles: Vec::new(),
        })
        .unwrap();
        let prepared = network
            .preflight(&origin, HttpProtocol::Http1, HttpProtocol::Http1, &route)
            .unwrap()
            .bind_for_request(&request, HttpProtocol::Http1, &route, &network)
            .unwrap();
        let cancellation = ForwardingCancellation::new();
        let target = network.resolve(prepared, &cancellation).await.unwrap();
        let standalone = StandaloneTrusted::validate(plan, &request, &snapshot).unwrap();
        let plan = standalone.forwarding_plan_arc();
        let descriptor = CredentialDescriptor::new(
            reference.clone(),
            CredentialPurpose::CustomHeader(destination),
            CredentialProfile::StandaloneTrusted,
            CredentialLimits::new(
                source.maximum_material_bytes(),
                source.maximum_staging_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        let io = CredentialIoRuntime::new().unwrap();
        let credentials = ProductCredentialPreparation::prepare(
            Arc::clone(&plan),
            vec![descriptor],
            vec![ProductCredentialBinding::source(reference, source)],
            ProductCredentialBufferContext::new(credential_guard()),
            Arc::clone(&io),
        )
        .unwrap()
        .admit_for_plan(&plan)
        .unwrap();
        let resources = ForwardingResources::new(
            ForwardingAdmission::new(&plan, ()),
            ForwardingRetention::new(&plan, ()),
            cancellation,
            ForwardingTerminalOwner::new(TestTerminal),
        )
        .with_credentials(credentials);
        let executor = ForwardingExecutor::activate(
            network,
            HttpProtocolSet::new(vec![HttpProtocol::Http1]).unwrap(),
            TlsTrust::Insecure,
            route,
            &snapshot,
            &ForwardingCancellation::new(),
        )
        .unwrap();
        let exchange = prepare_standalone_exchange(lineage, standalone, request).unwrap();
        CredentialForwardingFixture {
            executor,
            exchange,
            target,
            resources,
            io,
        }
    }

    async fn read_http_head(stream: &mut tokio::net::TcpStream) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
                .await
                .expect("HTTP head read timed out")
                .expect("HTTP head ended early");
            head.push(byte[0]);
            assert!(head.len() <= 32 * 1024);
        }
        String::from_utf8(head).unwrap()
    }

    async fn finish_empty_response(response: ForwardingResponse) {
        let (_, mut body) = response.into_parts().expect("expected ordinary response");
        assert!(std::future::poll_fn(|context| body.poll_data(context))
            .await
            .unwrap()
            .is_none());
        assert!(std::future::poll_fn(|context| body.poll_trailers(context))
            .await
            .unwrap()
            .is_none());
    }

    fn expect_error(result: Result<ForwardingResponse, ForwardingError>) -> ForwardingError {
        match result {
            Ok(_) => panic!("forwarding unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn direct_network(origin: &CanonicalUrl, endpoint: SocketAddr) -> Arc<ForwardingNetworkGuard> {
        Arc::new(
            ForwardingDevHarness::new(
                ForwardingNetworkFacts::new(Vec::new(), None, None, None).unwrap(),
            )
            .map_prebound(origin, endpoint)
            .unwrap()
            .into_standalone_guard(),
        )
    }

    fn parent_network(parent: &CanonicalUrl, endpoint: SocketAddr) -> Arc<ForwardingNetworkGuard> {
        Arc::new(
            ForwardingDevHarness::new(
                ForwardingNetworkFacts::new(Vec::new(), None, None, None).unwrap(),
            )
            .map_local_parent(parent, endpoint)
            .unwrap()
            .into_standalone_guard(),
        )
    }

    #[test]
    fn external_source_projection_reserves_one_bounded_io_operation() {
        let without_source = projected_product_adapter_bytes(1, 0, 0, false, false).unwrap();
        let with_source = projected_product_adapter_bytes(1, 0, 0, true, false).unwrap();

        assert_eq!(
            with_source - without_source,
            projected_credential_io_operation_bytes()
        );
    }

    #[tokio::test]
    async fn connect_failure_precedes_environment_credential_resolution() {
        const VARIABLE: &str = "ACL_PROXY_FORWARD_CONNECT_FAILURE_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::remove_var(VARIABLE);
        let unused = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = unused.local_addr().unwrap();
        drop(unused);
        let origin = semantic_url(HttpScheme::Http, "origin.example", 80, "/fail");
        let fixture = fixture(
            direct_network(&origin, endpoint),
            origin,
            Route::Direct,
            TransportSecurity::Cleartext,
            OutboundCredentialSource::environment_for_test(VARIABLE),
        )
        .await;

        let (result, io) = fixture.execute().await;
        assert_eq!(expect_error(result), ForwardingError::Network);
        io.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn credential_rotation_and_disappearance_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let mut prepared = Vec::new();
        for suffix in ["old", "new", "missing"] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let origin = semantic_url(
                HttpScheme::Http,
                "origin.example",
                80,
                &format!("/{suffix}"),
            );
            let fixture = fixture(
                direct_network(&origin, endpoint),
                origin,
                Route::Direct,
                TransportSecurity::Cleartext,
                OutboundCredentialSource::file_for_test(PathBuf::from(&path)),
            )
            .await;
            prepared.push((listener, fixture));
        }

        for expected in ["old-secret", "new-secret"] {
            let replacement = directory.path().join(format!("replacement-{expected}"));
            fs::write(&replacement, expected).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&replacement, &path).unwrap();
            let (listener, fixture) = prepared.remove(0);
            let expected = expected.to_owned();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let head = read_http_head(&mut stream).await.to_ascii_lowercase();
                assert_eq!(
                    head.matches(&format!("\r\n{CREDENTIAL_HEADER}: {expected}\r\n"))
                        .count(),
                    1,
                    "{head}"
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            });
            let (result, io) = fixture.execute().await;
            finish_empty_response(result.unwrap()).await;
            server.await.unwrap();
            io.shutdown_and_wait(None).await;
        }

        fs::remove_file(&path).unwrap();
        let (listener, fixture) = prepared.remove(0);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
                .await
                .expect("credential failure did not close the connection")
                .unwrap();
            assert!(bytes.is_empty(), "credential failure emitted request bytes");
        });
        let (result, io) = fixture.execute().await;
        assert_eq!(expect_error(result), ForwardingError::Credential);
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    async fn parent_connect_rejection_precedes_environment_credential_resolution() {
        const VARIABLE: &str = "ACL_PROXY_PARENT_REJECTION_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::remove_var(VARIABLE);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let parent = semantic_url(HttpScheme::Http, "parent.example", endpoint.port(), "/");
        let origin = semantic_url(HttpScheme::Https, "origin.example", 443, "/rejected");
        let route = Route::Parent {
            target: parent.clone(),
            security: TransportSecurity::Cleartext,
        };
        let fixture = fixture(
            parent_network(&parent, endpoint),
            origin.clone(),
            route,
            TransportSecurity::Tls(http_access_types::ClientTlsIntent::new(
                origin.authority().host().clone(),
                TlsTrust::Insecure,
            )),
            OutboundCredentialSource::environment_for_test(VARIABLE),
        )
        .await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_http_head(&mut stream).await.to_ascii_lowercase();
            assert!(head.starts_with("connect origin.example:443 http/1.1\r\n"));
            assert!(!head.contains(CREDENTIAL_HEADER), "{head}");
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let (result, io) = fixture.execute().await;
        assert_eq!(expect_error(result), ForwardingError::Network);
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
    }
}
