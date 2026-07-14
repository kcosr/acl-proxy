mod connector;
pub(crate) mod local;

use std::collections::TryReserveError;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::StaticProductConfig;
use crate::network::socket_binds_overlap;
use crate::url::{canonicalize_http_url, CanonicalAuthority, CanonicalUrl};

pub(crate) use connector::{DestinationConnector, TcpDestinationConnector};
pub(crate) use local::{LocalAddressSnapshot, LocalAddressSource, SystemLocalAddressSource};

use local::normalize_endpoint;

const MAX_RESOLVED_ADDRESSES: usize = 256;

pub(crate) type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, DestinationResolveError>> + Send + 'a>>;

pub(crate) trait DestinationResolver: Send + Sync {
    /// Perform one complete resolution. Callers never resolve an accepted token again.
    fn resolve(&self, host: &str, port: u16, max_addresses: usize) -> ResolveFuture<'_>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemDestinationResolver;

impl DestinationResolver for SystemDestinationResolver {
    fn resolve(&self, host: &str, port: u16, max_addresses: usize) -> ResolveFuture<'_> {
        let host = host.to_owned();
        Box::pin(async move {
            if max_addresses == 0 || max_addresses > MAX_RESOLVED_ADDRESSES {
                return Err(DestinationResolveError::InvalidLimit {
                    limit: max_addresses,
                    maximum: MAX_RESOLVED_ADDRESSES,
                });
            }
            let resolved = tokio::net::lookup_host((host, port))
                .await
                .map_err(DestinationResolveError::Lookup)?;
            let mut answers = Vec::new();
            answers
                .try_reserve_exact(max_addresses + 1)
                .map_err(DestinationResolveError::Allocation)?;
            for answer in resolved {
                let answer = normalize_endpoint(answer);
                if answers.contains(&answer) {
                    continue;
                }
                if answers.len() <= max_addresses {
                    answers.push(answer);
                }
            }
            Ok(answers)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationRoute {
    Direct,
    Webhook,
    Parent,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DestinationTarget {
    route: DestinationRoute,
    resolution_host: String,
    resolution_port: u16,
    semantic_authority: String,
    semantic_path: String,
    literal_origin: Option<SocketAddr>,
}

impl DestinationTarget {
    pub(crate) fn direct(url: &CanonicalUrl) -> Self {
        Self::from_url(DestinationRoute::Direct, url)
    }

    pub(crate) fn webhook(url: &CanonicalUrl) -> Self {
        Self::from_url(DestinationRoute::Webhook, url)
    }

    pub(crate) fn parent(parent_hop: &CanonicalAuthority, origin: &CanonicalUrl) -> Self {
        Self {
            route: DestinationRoute::Parent,
            resolution_host: parent_hop.host.clone(),
            resolution_port: parent_hop.port,
            semantic_authority: origin.authority.clone(),
            semantic_path: origin.path.clone(),
            literal_origin: literal_endpoint(origin),
        }
    }

    fn from_url(route: DestinationRoute, url: &CanonicalUrl) -> Self {
        Self {
            route,
            resolution_host: url.host.clone(),
            resolution_port: url.port,
            semantic_authority: url.authority.clone(),
            semantic_path: url.path.clone(),
            literal_origin: literal_endpoint(url),
        }
    }

    pub(crate) fn resolution_host(&self) -> &str {
        &self.resolution_host
    }

    pub(crate) fn resolution_port(&self) -> u16 {
        self.resolution_port
    }

    pub(crate) fn semantic_authority(&self) -> &str {
        &self.semantic_authority
    }

    pub(crate) fn semantic_path(&self) -> &str {
        &self.semantic_path
    }
}

fn literal_endpoint(url: &CanonicalUrl) -> Option<SocketAddr> {
    url.host
        .parse()
        .ok()
        .map(|ip| normalize_endpoint(SocketAddr::new(ip, url.port)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReservedControlSubtree {
    canonical_authority: String,
    canonical_base_path: String,
}

impl ReservedControlSubtree {
    pub(crate) fn new(public_url: &CanonicalUrl, canonical_base_path: impl Into<String>) -> Self {
        Self {
            canonical_authority: public_url.authority.clone(),
            canonical_base_path: canonical_base_path.into(),
        }
    }

    fn contains(&self, target: &DestinationTarget) -> bool {
        if self.canonical_authority != target.semantic_authority {
            return false;
        }

        let base = self.canonical_base_path.as_str();
        target.semantic_path == base
            || base == "/"
            || target
                .semantic_path
                .strip_prefix(base)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DestinationFacts {
    listener_binds: Vec<SocketAddr>,
    control_bind: Option<SocketAddr>,
    reserved_control: Option<ReservedControlSubtree>,
    max_resolved_addresses: usize,
}

impl DestinationFacts {
    pub(crate) fn from_static(config: &StaticProductConfig) -> Result<Self, DestinationGuardError> {
        let listeners = &config.listeners;
        let listener_binds = [
            listeners
                .explicit_http
                .as_ref()
                .map(|listener| listener.bind),
            listeners
                .transparent_http
                .as_ref()
                .map(|listener| listener.bind),
            listeners
                .explicit_https
                .as_ref()
                .map(|listener| listener.bind),
            listeners
                .transparent_https
                .as_ref()
                .map(|listener| listener.bind),
        ]
        .into_iter()
        .flatten()
        .map(normalize_endpoint)
        .collect::<Vec<_>>();

        if listener_binds.iter().any(|bind| bind.port() == 0)
            || listener_binds.iter().enumerate().any(|(index, bind)| {
                listener_binds[index + 1..]
                    .iter()
                    .any(|other| socket_binds_overlap(*bind, *other))
            })
        {
            return Err(DestinationGuardError::InconsistentStaticFacts(
                "proxy listener binds are zero or overlap",
            ));
        }

        let control_bind = config
            .control
            .as_ref()
            .map(|control| normalize_endpoint(control.bind));
        if control_bind.is_some_and(|control| {
            control.port() == 0
                || control.ip().is_unspecified()
                || listener_binds
                    .iter()
                    .any(|listener| socket_binds_overlap(control, *listener))
        }) {
            return Err(DestinationGuardError::InconsistentStaticFacts(
                "control bind is wildcard, zero, or overlaps a proxy listener",
            ));
        }

        let reserved_control = match (&config.control, &config.callback_public_url) {
            (Some(control), Some(public_url)) => {
                let public_url = canonicalize_http_url(public_url).map_err(|_| {
                    DestinationGuardError::InconsistentStaticFacts(
                        "callback public URL is not canonical HTTP/HTTPS",
                    )
                })?;
                let expected_path = format!(
                    "{}/external-auth/callback",
                    control.base_path.trim_end_matches('/')
                );
                if public_url.path != expected_path || public_url.query.is_some() {
                    return Err(DestinationGuardError::InconsistentStaticFacts(
                        "callback public URL does not identify the control callback route",
                    ));
                }
                Some(ReservedControlSubtree::new(
                    &public_url,
                    control.base_path.clone(),
                ))
            }
            (None, Some(_)) => {
                return Err(DestinationGuardError::InconsistentStaticFacts(
                    "callback public URL exists without a control listener",
                ));
            }
            (_, None) => None,
        };

        Ok(Self {
            listener_binds,
            control_bind,
            reserved_control,
            max_resolved_addresses: MAX_RESOLVED_ADDRESSES,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        listener_binds: impl IntoIterator<Item = SocketAddr>,
        control_bind: Option<SocketAddr>,
        reserved_control: Option<ReservedControlSubtree>,
        max_resolved_addresses: usize,
    ) -> Result<Self, DestinationGuardError> {
        if max_resolved_addresses == 0 {
            return Err(DestinationGuardError::InvalidResolutionLimit);
        }
        if max_resolved_addresses > MAX_RESOLVED_ADDRESSES {
            return Err(DestinationGuardError::ResolutionLimitTooLarge {
                limit: max_resolved_addresses,
                maximum: MAX_RESOLVED_ADDRESSES,
            });
        }

        let listener_binds = listener_binds.into_iter().map(normalize_endpoint).collect();
        Ok(Self {
            listener_binds,
            control_bind: control_bind.map(normalize_endpoint),
            reserved_control,
            max_resolved_addresses,
        })
    }
}

pub(crate) struct DestinationGuard {
    brand: Arc<()>,
    facts: DestinationFacts,
    resolver: Arc<dyn DestinationResolver>,
    local_addresses: Arc<dyn LocalAddressSource>,
}

impl fmt::Debug for DestinationGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DestinationGuard")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl DestinationGuard {
    pub(crate) fn system(facts: DestinationFacts) -> Self {
        Self::with_sources(
            facts,
            Arc::new(SystemDestinationResolver),
            Arc::new(SystemLocalAddressSource),
        )
    }

    pub(crate) fn with_sources(
        facts: DestinationFacts,
        resolver: Arc<dyn DestinationResolver>,
        local_addresses: Arc<dyn LocalAddressSource>,
    ) -> Self {
        Self {
            brand: Arc::new(()),
            facts,
            resolver,
            local_addresses,
        }
    }

    /// Performs route-shape and literal-endpoint checks without consulting DNS.
    pub(crate) fn preflight(
        &self,
        target: DestinationTarget,
    ) -> Result<PreparedDestination, DestinationGuardError> {
        if self
            .facts
            .reserved_control
            .as_ref()
            .is_some_and(|reserved| reserved.contains(&target))
        {
            return Err(DestinationGuardError::ReservedControlSubtree);
        }

        if target.route == DestinationRoute::Parent {
            if self
                .facts
                .control_bind
                .is_some_and(|control| target.literal_origin == Some(control))
            {
                return Err(DestinationGuardError::LiteralControlOrigin);
            }
            if let Some(origin) = target.literal_origin {
                let snapshot = self.local_snapshot()?;
                self.validate(DestinationRoute::Direct, origin, &snapshot)?;
            }
        }

        if let Ok(ip) = target.resolution_host.parse() {
            let endpoint = normalize_endpoint(SocketAddr::new(ip, target.resolution_port));
            let snapshot = self.local_snapshot()?;
            self.validate(target.route, endpoint, &snapshot)?;
        }

        Ok(PreparedDestination {
            brand: self.brand.clone(),
            target,
        })
    }

    /// Completes exactly one resolution for a destination that passed semantic preflight.
    pub(crate) async fn complete_resolution(
        &self,
        prepared: PreparedDestination,
    ) -> Result<ResolvedDestination, DestinationGuardError> {
        let PreparedDestination { brand, target } = prepared;
        if !Arc::ptr_eq(&brand, &self.brand) {
            return Err(DestinationGuardError::ForeignDestinationToken);
        }
        let answers = self
            .resolver
            .resolve(
                target.resolution_host(),
                target.resolution_port(),
                self.facts.max_resolved_addresses,
            )
            .await
            .map_err(DestinationGuardError::Resolution)?;
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(self.facts.max_resolved_addresses + 1)
            .map_err(DestinationGuardError::Allocation)?;
        for answer in answers {
            let answer = normalize_endpoint(answer);
            if !addresses.contains(&answer) {
                if addresses.len() == self.facts.max_resolved_addresses {
                    return Err(DestinationGuardError::ResolutionLimitExceeded {
                        limit: self.facts.max_resolved_addresses,
                    });
                }
                addresses.push(answer);
            }
        }
        if addresses.is_empty() {
            return Err(DestinationGuardError::EmptyResolution);
        }

        let snapshot = self.local_snapshot()?;
        for &address in &addresses {
            self.validate(target.route, address, &snapshot)?;
        }

        Ok(ResolvedDestination {
            brand,
            target,
            addresses,
        })
    }

    pub(crate) async fn connect<C>(
        &self,
        resolved: ResolvedDestination,
        connector: &C,
    ) -> Result<ConnectedDestination<C::Stream>, DestinationGuardError>
    where
        C: DestinationConnector,
    {
        let ResolvedDestination {
            brand,
            target,
            addresses,
        } = resolved;
        if !Arc::ptr_eq(&brand, &self.brand) {
            return Err(DestinationGuardError::ForeignDestinationToken);
        }
        let mut last_error = None;
        for candidate in addresses {
            let before = self.local_snapshot()?;
            self.validate(target.route, candidate, &before)?;

            let stream = match connector.connect(candidate).await {
                Ok(stream) => stream,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let peer = connector
                .peer_addr(&stream)
                .map(normalize_endpoint)
                .map_err(DestinationGuardError::PeerAddress)?;
            let after = self.local_snapshot()?;
            self.validate(target.route, peer, &after)?;
            if peer != candidate {
                return Err(DestinationGuardError::PeerMismatch {
                    expected: candidate,
                    actual: peer,
                });
            }
            return Ok(ConnectedDestination { target, stream });
        }

        Err(DestinationGuardError::ConnectionAttemptsExhausted {
            last: last_error.expect("a nonempty resolved destination attempted at least one dial"),
        })
    }

    pub(crate) async fn connect_system(
        &self,
        resolved: ResolvedDestination,
    ) -> Result<ConnectedDestination<tokio::net::TcpStream>, DestinationGuardError> {
        self.connect(resolved, &TcpDestinationConnector).await
    }

    fn local_snapshot(&self) -> Result<LocalAddressSnapshot, DestinationGuardError> {
        self.local_addresses
            .snapshot()
            .map_err(DestinationGuardError::LocalAddressEnumeration)
    }

    fn validate(
        &self,
        route: DestinationRoute,
        endpoint: SocketAddr,
        local: &LocalAddressSnapshot,
    ) -> Result<(), DestinationGuardError> {
        let endpoint = normalize_endpoint(endpoint);
        if matches!(
            endpoint,
            SocketAddr::V6(address)
                if address.ip().is_unicast_link_local() && address.scope_id() == 0
        ) {
            return Err(DestinationGuardError::ProtectedDestination {
                endpoint,
                reason: ProtectedReason::UnscopedIpv6LinkLocal,
            });
        }
        if endpoint.ip().is_unspecified() {
            return Err(DestinationGuardError::ProtectedDestination {
                endpoint,
                reason: ProtectedReason::Unspecified,
            });
        }

        if self.facts.control_bind.is_some_and(|bind| endpoint == bind) {
            return Err(DestinationGuardError::ProtectedDestination {
                endpoint,
                reason: ProtectedReason::Control,
            });
        }

        for &bind in &self.facts.listener_binds {
            let protected = if bind.ip().is_unspecified() {
                bind.port() == endpoint.port() && local.contains(endpoint)
            } else {
                bind == endpoint
            };
            if protected {
                return Err(DestinationGuardError::ProtectedDestination {
                    endpoint,
                    reason: ProtectedReason::Listener,
                });
            }
        }

        if route == DestinationRoute::Parent {
            if endpoint.ip().is_loopback() {
                return Err(DestinationGuardError::ProtectedDestination {
                    endpoint,
                    reason: ProtectedReason::LoopbackParent,
                });
            }
            if local.contains(endpoint) {
                return Err(DestinationGuardError::ProtectedDestination {
                    endpoint,
                    reason: ProtectedReason::LocalParent,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct PreparedDestination {
    brand: Arc<()>,
    target: DestinationTarget,
}

#[derive(Debug)]
pub(crate) struct ResolvedDestination {
    brand: Arc<()>,
    target: DestinationTarget,
    addresses: Vec<SocketAddr>,
}

#[derive(Debug)]
pub(crate) struct ConnectedDestination<S> {
    target: DestinationTarget,
    stream: S,
}

impl<S> ConnectedDestination<S> {
    pub(crate) fn resolution_host(&self) -> &str {
        self.target.resolution_host()
    }

    pub(crate) fn resolution_port(&self) -> u16 {
        self.target.resolution_port()
    }

    pub(crate) fn semantic_authority(&self) -> &str {
        self.target.semantic_authority()
    }

    pub(crate) fn semantic_path(&self) -> &str {
        self.target.semantic_path()
    }

    pub(crate) fn stream(&self) -> &S {
        &self.stream
    }

    pub(crate) fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub(crate) fn into_stream(self) -> S {
        self.stream
    }

    pub(crate) fn map_stream<T>(self, map: impl FnOnce(S) -> T) -> ConnectedDestination<T> {
        ConnectedDestination {
            target: self.target,
            stream: map(self.stream),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedReason {
    UnscopedIpv6LinkLocal,
    Unspecified,
    Control,
    Listener,
    LoopbackParent,
    LocalParent,
}

#[derive(Debug)]
pub(crate) enum DestinationGuardError {
    InconsistentStaticFacts(&'static str),
    InvalidResolutionLimit,
    ResolutionLimitTooLarge {
        limit: usize,
        maximum: usize,
    },
    ReservedControlSubtree,
    LiteralControlOrigin,
    ForeignDestinationToken,
    Allocation(TryReserveError),
    Resolution(DestinationResolveError),
    EmptyResolution,
    ResolutionLimitExceeded {
        limit: usize,
    },
    LocalAddressEnumeration(io::Error),
    ProtectedDestination {
        endpoint: SocketAddr,
        reason: ProtectedReason,
    },
    PeerAddress(io::Error),
    PeerMismatch {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    ConnectionAttemptsExhausted {
        last: io::Error,
    },
}

impl fmt::Display for DestinationGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InconsistentStaticFacts(reason) => {
                write!(
                    formatter,
                    "inconsistent compiled destination facts: {reason}"
                )
            }
            Self::InvalidResolutionLimit => write!(formatter, "resolution limit must be nonzero"),
            Self::ResolutionLimitTooLarge { limit, maximum } => write!(
                formatter,
                "resolution limit {limit} exceeds the internal maximum {maximum}"
            ),
            Self::ReservedControlSubtree => {
                write!(formatter, "destination is in the reserved control subtree")
            }
            Self::LiteralControlOrigin => {
                write!(
                    formatter,
                    "parent-route origin is the local control destination"
                )
            }
            Self::ForeignDestinationToken => {
                write!(formatter, "destination token belongs to another guard")
            }
            Self::Allocation(error) => write!(formatter, "destination allocation failed: {error}"),
            Self::Resolution(error) => write!(formatter, "destination resolution failed: {error}"),
            Self::EmptyResolution => {
                write!(formatter, "destination resolution returned no addresses")
            }
            Self::ResolutionLimitExceeded { limit } => {
                write!(
                    formatter,
                    "destination resolution exceeded the {limit}-address limit"
                )
            }
            Self::LocalAddressEnumeration(error) => {
                write!(formatter, "local address enumeration failed: {error}")
            }
            Self::ProtectedDestination { endpoint, reason } => {
                write!(
                    formatter,
                    "destination {endpoint} is protected ({reason:?})"
                )
            }
            Self::PeerAddress(error) => write!(formatter, "connected peer lookup failed: {error}"),
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "connected peer {actual} does not equal pinned destination {expected}"
            ),
            Self::ConnectionAttemptsExhausted { last } => {
                write!(
                    formatter,
                    "all destination connection attempts failed: {last}"
                )
            }
        }
    }
}

impl std::error::Error for DestinationGuardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Resolution(error) => Some(error),
            Self::LocalAddressEnumeration(error)
            | Self::PeerAddress(error)
            | Self::ConnectionAttemptsExhausted { last: error } => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum DestinationResolveError {
    InvalidLimit { limit: usize, maximum: usize },
    Lookup(io::Error),
    Allocation(TryReserveError),
}

impl fmt::Display for DestinationResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { limit, maximum } => write!(
                formatter,
                "resolution limit {limit} is outside 1..={maximum}"
            ),
            Self::Lookup(error) => write!(formatter, "lookup failed: {error}"),
            Self::Allocation(error) => write!(formatter, "allocation failed: {error}"),
        }
    }
}

impl std::error::Error for DestinationResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLimit { .. } => None,
            Self::Lookup(error) => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use super::*;

    #[derive(Debug)]
    struct FixedResolver {
        answers: Vec<SocketAddr>,
        calls: AtomicUsize,
        queries: Mutex<Vec<(String, u16)>>,
    }

    impl FixedResolver {
        fn new(answers: impl IntoIterator<Item = SocketAddr>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
                calls: AtomicUsize::new(0),
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl DestinationResolver for FixedResolver {
        fn resolve(&self, host: &str, port: u16, _max_addresses: usize) -> ResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.queries
                .lock()
                .expect("resolver query lock")
                .push((host.to_owned(), port));
            let answers = self.answers.clone();
            Box::pin(async move { Ok(answers) })
        }
    }

    #[derive(Clone, Debug)]
    enum LocalStep {
        Addresses(Vec<local::LocalAddress>),
        Failure(io::ErrorKind),
    }

    #[derive(Debug)]
    struct SequenceLocalAddresses {
        steps: Mutex<VecDeque<LocalStep>>,
    }

    impl SequenceLocalAddresses {
        fn new(steps: impl IntoIterator<Item = LocalStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into_iter().collect()),
            }
        }
    }

    impl LocalAddressSource for SequenceLocalAddresses {
        fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
            let mut steps = self.steps.lock().expect("local sequence lock");
            let step = if steps.len() > 1 {
                steps.pop_front().expect("nonempty local sequence")
            } else {
                steps.front().expect("local sequence exhausted").clone()
            };
            match step {
                LocalStep::Addresses(addresses) => Ok(LocalAddressSnapshot::new(addresses)),
                LocalStep::Failure(kind) => {
                    Err(io::Error::new(kind, "injected enumeration failure"))
                }
            }
        }
    }

    enum ConnectAction {
        Success(SocketAddr),
        Failure(io::ErrorKind),
    }

    struct FakeStream {
        peer: SocketAddr,
        dropped: Arc<AtomicBool>,
        bytes_written: Arc<AtomicUsize>,
    }

    impl Drop for FakeStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl tokio::io::AsyncWrite for FakeStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes_written.fetch_add(buffer.len(), Ordering::SeqCst);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FakeConnector {
        actions: Mutex<VecDeque<ConnectAction>>,
        attempts: Mutex<Vec<SocketAddr>>,
        dropped: Arc<AtomicBool>,
        bytes_written: Arc<AtomicUsize>,
    }

    impl FakeConnector {
        fn new(actions: impl IntoIterator<Item = ConnectAction>) -> Self {
            Self {
                actions: Mutex::new(actions.into_iter().collect()),
                attempts: Mutex::new(Vec::new()),
                dropped: Arc::new(AtomicBool::new(false)),
                bytes_written: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl DestinationConnector for FakeConnector {
        type Stream = FakeStream;

        fn connect(&self, endpoint: SocketAddr) -> connector::ConnectFuture<'_, Self::Stream> {
            self.attempts.lock().expect("attempt lock").push(endpoint);
            let action = self
                .actions
                .lock()
                .expect("action lock")
                .pop_front()
                .expect("connect action");
            let dropped = Arc::clone(&self.dropped);
            let bytes_written = Arc::clone(&self.bytes_written);
            Box::pin(async move {
                match action {
                    ConnectAction::Success(peer) => Ok(FakeStream {
                        peer,
                        dropped,
                        bytes_written,
                    }),
                    ConnectAction::Failure(kind) => {
                        Err(io::Error::new(kind, "injected connect failure"))
                    }
                }
            })
        }

        fn peer_addr(&self, stream: &Self::Stream) -> io::Result<SocketAddr> {
            Ok(stream.peer)
        }
    }

    fn endpoint(value: &str) -> SocketAddr {
        value.parse().expect("test endpoint")
    }

    fn local(value: &str) -> local::LocalAddress {
        local::LocalAddress::new(value.parse().expect("test local IP"), 0)
    }

    fn target(route: DestinationRoute, port: u16) -> DestinationTarget {
        let url = crate::url::canonicalize_http_url(&format!(
            "https://destination.example:{port}/resource"
        ))
        .expect("canonical destination URL");
        match route {
            DestinationRoute::Direct => DestinationTarget::direct(&url),
            DestinationRoute::Webhook => DestinationTarget::webhook(&url),
            DestinationRoute::Parent => {
                let parent = crate::url::canonicalize_http_authority(
                    "https",
                    &format!("parent.example:{port}"),
                )
                .expect("canonical parent authority");
                DestinationTarget::parent(&parent, &url)
            }
        }
    }

    fn facts(
        listener_binds: impl IntoIterator<Item = SocketAddr>,
        control_bind: Option<SocketAddr>,
    ) -> DestinationFacts {
        DestinationFacts::for_test(listener_binds, control_bind, None, 8)
            .expect("destination facts")
    }

    fn guard(
        facts: DestinationFacts,
        resolver: Arc<FixedResolver>,
        locals: impl IntoIterator<Item = LocalStep>,
    ) -> DestinationGuard {
        DestinationGuard::with_sources(
            facts,
            resolver,
            Arc::new(SequenceLocalAddresses::new(locals)),
        )
    }

    async fn resolve(
        guard: &DestinationGuard,
        target: DestinationTarget,
    ) -> Result<ResolvedDestination, DestinationGuardError> {
        let prepared = guard.preflight(target)?;
        guard.complete_resolution(prepared).await
    }

    #[tokio::test]
    async fn live_local_address_guard_tracks_interface_changes() {
        let candidate = endpoint("192.0.2.10:8443");
        let resolver = Arc::new(FixedResolver::new([candidate]));
        let guard = guard(
            facts([endpoint("0.0.0.0:8443")], None),
            Arc::clone(&resolver),
            [
                LocalStep::Addresses(vec![local("192.0.2.10")]),
                LocalStep::Addresses(vec![]),
                LocalStep::Addresses(vec![]),
                LocalStep::Addresses(vec![]),
            ],
        );

        let first = resolve(&guard, target(DestinationRoute::Direct, 8443)).await;
        assert!(matches!(
            first,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));

        let accepted = resolve(&guard, target(DestinationRoute::Direct, 8443))
            .await
            .expect("removed interface address is no longer protected");
        let connector = FakeConnector::new([ConnectAction::Success(candidate)]);
        guard
            .connect(accepted, &connector)
            .await
            .expect("fresh snapshots permit the destination");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn complete_resolution_rejects_mixed_protected_answers() {
        let resolver = Arc::new(FixedResolver::new([
            endpoint("192.0.2.20:443"),
            endpoint("127.0.0.1:443"),
        ]));
        let guard = guard(
            facts([endpoint("127.0.0.1:443")], None),
            resolver,
            [LocalStep::Addresses(vec![])],
        );

        let result = resolve(&guard, target(DestinationRoute::Webhook, 443)).await;
        assert!(matches!(
            result,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn webhook_provider_cannot_target_self_or_control_plane() {
        for (facts, resolved, reason, port) in [
            (
                facts([endpoint("127.0.0.1:8443")], None),
                endpoint("127.0.0.1:8443"),
                ProtectedReason::Listener,
                8443,
            ),
            (
                facts([], Some(endpoint("127.0.0.1:8898"))),
                endpoint("127.0.0.1:8898"),
                ProtectedReason::Control,
                8898,
            ),
        ] {
            let resolver = Arc::new(FixedResolver::new([resolved]));
            let guard = guard(facts, Arc::clone(&resolver), [LocalStep::Addresses(vec![])]);

            assert!(matches!(
                resolve(&guard, target(DestinationRoute::Webhook, port)).await,
                Err(DestinationGuardError::ProtectedDestination {
                    reason: actual,
                    ..
                }) if actual == reason
            ));
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        }

        let callback_url = crate::url::canonicalize_http_url(
            "https://control.example/_acl/external-auth/callback",
        )
        .expect("canonical callback URL");
        let resolver = Arc::new(FixedResolver::new([endpoint("192.0.2.60:443")]));
        let guard = guard(
            DestinationFacts::for_test(
                [],
                None,
                Some(ReservedControlSubtree::new(&callback_url, "/_acl")),
                8,
            )
            .expect("destination facts"),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );

        assert!(matches!(
            resolve(&guard, DestinationTarget::webhook(&callback_url)).await,
            Err(DestinationGuardError::ReservedControlSubtree)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resolved_destination_is_pinned_without_second_lookup() {
        let first = endpoint("192.0.2.30:443");
        let second = endpoint("192.0.2.31:443");
        let resolver = Arc::new(FixedResolver::new([first, second, first]));
        let guard = guard(
            facts([], None),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 443))
            .await
            .expect("resolution");
        let connector = FakeConnector::new([
            ConnectAction::Failure(io::ErrorKind::ConnectionRefused),
            ConnectAction::Success(second),
        ]);

        guard
            .connect(resolved, &connector)
            .await
            .expect("second pinned candidate connects");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *connector.attempts.lock().expect("attempt lock"),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn mapped_ipv6_matches_ipv4_listener_and_control() {
        let mapped_listener = endpoint("[::ffff:127.0.0.1]:8080");
        let listener_guard = guard(
            facts([endpoint("127.0.0.1:8080")], None),
            Arc::new(FixedResolver::new([mapped_listener])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&listener_guard, target(DestinationRoute::Direct, 8080)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));

        let mapped_control = endpoint("[::ffff:127.0.0.1]:8898");
        let control_guard = guard(
            facts([], Some(endpoint("127.0.0.1:8898"))),
            Arc::new(FixedResolver::new([mapped_control])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&control_guard, target(DestinationRoute::Webhook, 8898)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Control,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn wildcard_listener_expands_against_each_live_snapshot() {
        let candidate = endpoint("198.51.100.9:8881");
        let resolver = Arc::new(FixedResolver::new([candidate]));
        let guard = guard(
            facts([endpoint("0.0.0.0:8881")], None),
            resolver,
            [
                LocalStep::Addresses(vec![local("198.51.100.8")]),
                LocalStep::Addresses(vec![local("198.51.100.9")]),
            ],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 8881))
            .await
            .expect("candidate was not local in the resolution snapshot");
        let connector = FakeConnector::new([ConnectAction::Success(candidate)]);

        assert!(matches!(
            guard.connect(resolved, &connector).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));
        assert!(connector.attempts.lock().expect("attempt lock").is_empty());
    }

    #[tokio::test]
    async fn wildcard_listener_blocks_cross_family_live_address() {
        let candidate = endpoint("[2001:db8::8]:8881");
        let guard = guard(
            facts([endpoint("0.0.0.0:8881")], None),
            Arc::new(FixedResolver::new([candidate])),
            [LocalStep::Addresses(vec![local("2001:db8::8")])],
        );

        assert!(matches!(
            resolve(&guard, target(DestinationRoute::Direct, 8881)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn parent_rejects_any_loopback_or_local_address() {
        let loopback_guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([endpoint("127.0.0.2:3128")])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&loopback_guard, target(DestinationRoute::Parent, 3128)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::LoopbackParent,
                ..
            })
        ));

        let local_guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([endpoint("10.0.0.8:3128")])),
            [LocalStep::Addresses(vec![local("10.0.0.8")])],
        );
        assert!(matches!(
            resolve(&local_guard, target(DestinationRoute::Parent, 3128)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::LocalParent,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn local_address_enumeration_failure_denies() {
        let guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([endpoint("192.0.2.40:443")])),
            [LocalStep::Failure(io::ErrorKind::PermissionDenied)],
        );

        assert!(matches!(
            resolve(&guard, target(DestinationRoute::Direct, 443)).await,
            Err(DestinationGuardError::LocalAddressEnumeration(_))
        ));
    }

    #[tokio::test]
    async fn pre_dial_local_address_enumeration_failure_denies_without_dial() {
        let candidate = endpoint("192.0.2.41:443");
        let guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([candidate])),
            [
                LocalStep::Addresses(vec![]),
                LocalStep::Failure(io::ErrorKind::PermissionDenied),
            ],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 443))
            .await
            .expect("initial local enumeration succeeds");
        let connector = FakeConnector::new([ConnectAction::Success(candidate)]);

        assert!(matches!(
            guard.connect(resolved, &connector).await,
            Err(DestinationGuardError::LocalAddressEnumeration(_))
        ));
        assert!(connector.attempts.lock().expect("attempt lock").is_empty());
        assert!(!connector.dropped.load(Ordering::SeqCst));
        assert_eq!(connector.bytes_written.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn post_connect_local_address_enumeration_failure_closes_before_bytes() {
        let candidate = endpoint("192.0.2.42:443");
        let guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([candidate])),
            [
                LocalStep::Addresses(vec![]),
                LocalStep::Addresses(vec![]),
                LocalStep::Failure(io::ErrorKind::PermissionDenied),
            ],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 443))
            .await
            .expect("initial local enumeration succeeds");
        let connector = FakeConnector::new([ConnectAction::Success(candidate)]);

        assert!(matches!(
            guard.connect(resolved, &connector).await,
            Err(DestinationGuardError::LocalAddressEnumeration(_))
        ));
        assert_eq!(
            *connector.attempts.lock().expect("attempt lock"),
            vec![candidate]
        );
        assert!(connector.dropped.load(Ordering::SeqCst));
        assert_eq!(connector.bytes_written.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn address_added_before_connect_denies_without_dial() {
        let candidate = endpoint("203.0.113.41:8443");
        let guard = guard(
            facts([endpoint("0.0.0.0:8443")], None),
            Arc::new(FixedResolver::new([candidate])),
            [
                LocalStep::Addresses(vec![]),
                LocalStep::Addresses(vec![local("203.0.113.41")]),
            ],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 8443))
            .await
            .expect("initial resolution");
        let connector = FakeConnector::new([ConnectAction::Success(candidate)]);

        assert!(matches!(
            guard.connect(resolved, &connector).await,
            Err(DestinationGuardError::ProtectedDestination { .. })
        ));
        assert!(connector.attempts.lock().expect("attempt lock").is_empty());
    }

    #[tokio::test]
    async fn address_added_after_connect_closes_before_bytes() {
        let candidate = endpoint("203.0.113.42:8443");
        let guard = guard(
            facts([endpoint("0.0.0.0:8443")], None),
            Arc::new(FixedResolver::new([candidate])),
            [
                LocalStep::Addresses(vec![]),
                LocalStep::Addresses(vec![]),
                LocalStep::Addresses(vec![local("203.0.113.42")]),
            ],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 8443))
            .await
            .expect("initial resolution");
        let connector = FakeConnector::new([ConnectAction::Success(candidate)]);

        assert!(matches!(
            guard.connect(resolved, &connector).await,
            Err(DestinationGuardError::ProtectedDestination { .. })
        ));
        assert!(connector.dropped.load(Ordering::SeqCst));
        assert_eq!(connector.bytes_written.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn connected_peer_must_equal_pinned_candidate() {
        let candidate = endpoint("192.0.2.50:443");
        let different_peer = endpoint("192.0.2.51:443");
        let guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([candidate])),
            [LocalStep::Addresses(vec![])],
        );
        let resolved = resolve(&guard, target(DestinationRoute::Direct, 443))
            .await
            .expect("resolution");
        let connector = FakeConnector::new([ConnectAction::Success(different_peer)]);

        assert!(matches!(
            guard.connect(resolved, &connector).await,
            Err(DestinationGuardError::PeerMismatch {
                expected,
                actual
            }) if expected == candidate && actual == different_peer
        ));
        assert!(connector.dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn reserved_control_subtree_denies_before_dns() {
        let resolver = Arc::new(FixedResolver::new([endpoint("192.0.2.60:443")]));
        let callback_url = crate::url::canonicalize_http_url(
            "https://control.example/_acl/external-auth/callback",
        )
        .expect("canonical callback URL");
        let facts = DestinationFacts::for_test(
            [],
            None,
            Some(ReservedControlSubtree::new(&callback_url, "/_acl")),
            8,
        )
        .expect("destination facts");
        let guard = guard(facts, Arc::clone(&resolver), [LocalStep::Addresses(vec![])]);
        let reserved = DestinationTarget::webhook(&callback_url);

        assert!(matches!(
            resolve(&guard, reserved).await,
            Err(DestinationGuardError::ReservedControlSubtree)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn preflight_rejects_literal_listener_without_resolution() {
        let resolver = Arc::new(FixedResolver::new([endpoint("127.0.0.1:8443")]));
        let guard = guard(
            facts([endpoint("127.0.0.1:8443")], None),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );
        let url = crate::url::canonicalize_http_url("http://127.0.0.1:8443/resource")
            .expect("literal canonical URL");

        assert!(matches!(
            guard.preflight(DestinationTarget::direct(&url)),
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn preflight_rejects_literal_unspecified_endpoint_without_resolution() {
        let resolver = Arc::new(FixedResolver::new([endpoint("192.0.2.60:8080")]));
        let guard = guard(
            facts([], None),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );
        let url = crate::url::canonicalize_http_url("http://0.0.0.0:8080/resource")
            .expect("literal canonical URL");

        assert!(matches!(
            guard.preflight(DestinationTarget::direct(&url)),
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Unspecified,
                ..
            })
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn parent_preflight_rejects_literal_self_hop_without_resolution() {
        let resolver = Arc::new(FixedResolver::new([endpoint("192.0.2.61:3128")]));
        let guard = guard(
            facts([], None),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );
        let parent = crate::url::canonicalize_http_authority("http", "127.0.0.2:3128")
            .expect("literal parent authority");
        let origin = crate::url::canonicalize_http_url("https://origin.example/private")
            .expect("canonical origin URL");

        assert!(matches!(
            guard.preflight(DestinationTarget::parent(&parent, &origin)),
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::LoopbackParent,
                ..
            })
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn parent_preflight_defers_one_parent_hop_resolution() {
        let resolver = Arc::new(FixedResolver::new([endpoint("192.0.2.61:3128")]));
        let guard = guard(
            facts([], None),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );
        let parent = crate::url::canonicalize_http_authority("http", "parent.example:3128")
            .expect("canonical parent authority");
        let origin = crate::url::canonicalize_http_url("https://origin.example:8443/private")
            .expect("canonical origin URL");

        let prepared = guard
            .preflight(DestinationTarget::parent(&parent, &origin))
            .expect("parent semantic preflight");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);

        guard
            .complete_resolution(prepared)
            .await
            .expect("parent-hop resolution");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *resolver.queries.lock().expect("resolver query lock"),
            vec![("parent.example".to_owned(), 3128)]
        );
    }

    #[tokio::test]
    async fn parent_literal_control_origin_denies_before_parent_dns() {
        let resolver = Arc::new(FixedResolver::new([endpoint("192.0.2.61:3128")]));
        let guard = guard(
            facts([], Some(endpoint("127.0.0.1:8898"))),
            Arc::clone(&resolver),
            [LocalStep::Addresses(vec![])],
        );
        let parent = crate::url::canonicalize_http_authority("http", "parent.example:3128")
            .expect("canonical parent authority");
        let origin = crate::url::canonicalize_http_url("http://127.0.0.1:8898/ready")
            .expect("canonical origin URL");
        let target = DestinationTarget::parent(&parent, &origin);

        assert!(matches!(
            resolve(&guard, target).await,
            Err(DestinationGuardError::LiteralControlOrigin)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn prepared_and_resolved_tokens_reject_a_foreign_guard() {
        let endpoint = endpoint("192.0.2.62:8443");
        let first_resolver = Arc::new(FixedResolver::new([endpoint]));
        let second_resolver = Arc::new(FixedResolver::new([endpoint]));
        let first = guard(
            facts([], None),
            first_resolver.clone(),
            [LocalStep::Addresses(vec![])],
        );
        let second = guard(
            facts([], None),
            second_resolver.clone(),
            [LocalStep::Addresses(vec![])],
        );

        let prepared = first
            .preflight(target(DestinationRoute::Direct, 8443))
            .unwrap();
        assert!(matches!(
            second.complete_resolution(prepared).await,
            Err(DestinationGuardError::ForeignDestinationToken)
        ));
        assert_eq!(second_resolver.calls.load(Ordering::SeqCst), 0);

        let prepared = first
            .preflight(target(DestinationRoute::Direct, 8443))
            .unwrap();
        let resolved = first.complete_resolution(prepared).await.unwrap();
        let connector = FakeConnector::new([ConnectAction::Success(endpoint)]);
        assert!(matches!(
            second.connect(resolved, &connector).await,
            Err(DestinationGuardError::ForeignDestinationToken)
        ));
        assert!(connector.attempts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn scoped_ipv6_listener_identity_is_preserved() {
        let scoped = |scope_id| {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::1".parse().expect("link-local address"),
                8443,
                0,
                scope_id,
            ))
        };
        let different_scope = guard(
            facts([scoped(7)], None),
            Arc::new(FixedResolver::new([scoped(8)])),
            [LocalStep::Addresses(vec![])],
        );
        resolve(&different_scope, target(DestinationRoute::Direct, 8443))
            .await
            .expect("a distinct IPv6 scope is a distinct listener tuple");

        let same_scope = guard(
            facts([scoped(7)], None),
            Arc::new(FixedResolver::new([scoped(7)])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&same_scope, target(DestinationRoute::Direct, 8443)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Listener,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn unscoped_link_local_resolution_denies_before_scoped_bind_comparison() {
        let scoped = |scope_id| {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::2".parse().expect("link-local address"),
                8443,
                0,
                scope_id,
            ))
        };
        for facts in [facts([scoped(7)], None), facts([], Some(scoped(7)))] {
            let guard = guard(
                facts,
                Arc::new(FixedResolver::new([scoped(0)])),
                [LocalStep::Addresses(vec![])],
            );
            assert!(matches!(
                resolve(&guard, target(DestinationRoute::Direct, 8443)).await,
                Err(DestinationGuardError::ProtectedDestination {
                    reason: ProtectedReason::UnscopedIpv6LinkLocal,
                    ..
                })
            ));
        }
    }

    #[tokio::test]
    async fn unscoped_link_local_peer_closes_before_bytes() {
        let scoped = |scope_id| {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::3".parse().expect("link-local address"),
                8443,
                0,
                scope_id,
            ))
        };
        for facts in [facts([scoped(7)], None), facts([], Some(scoped(7)))] {
            let guard = guard(
                facts,
                Arc::new(FixedResolver::new([scoped(8)])),
                [LocalStep::Addresses(vec![])],
            );
            let resolved = resolve(&guard, target(DestinationRoute::Direct, 8443))
                .await
                .expect("scoped candidate resolves");
            let connector = FakeConnector::new([ConnectAction::Success(scoped(0))]);

            assert!(matches!(
                guard.connect(resolved, &connector).await,
                Err(DestinationGuardError::ProtectedDestination {
                    reason: ProtectedReason::UnscopedIpv6LinkLocal,
                    ..
                })
            ));
            assert!(connector.dropped.load(Ordering::SeqCst));
            assert_eq!(connector.bytes_written.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn connected_destination_retains_resolved_target_identity() {
        let candidate = endpoint("192.0.2.80:443");
        let guard = guard(
            facts([], None),
            Arc::new(FixedResolver::new([candidate])),
            [LocalStep::Addresses(vec![])],
        );

        let direct_url =
            crate::url::canonicalize_http_url("https://direct.example:8443/direct/path?mode=one")
                .expect("direct URL");
        let direct = resolve(&guard, DestinationTarget::direct(&direct_url))
            .await
            .expect("direct resolution");
        let direct = guard
            .connect(
                direct,
                &FakeConnector::new([ConnectAction::Success(candidate)]),
            )
            .await
            .expect("direct connect");
        assert_eq!(direct.resolution_host(), "direct.example");
        assert_eq!(direct.resolution_port(), 8443);
        assert_eq!(direct.semantic_authority(), "direct.example:8443");
        assert_eq!(direct.semantic_path(), "/direct/path");
        assert_eq!(direct.stream().peer, candidate);

        let webhook_url =
            crate::url::canonicalize_http_url("https://webhook.example:9443/provider/decision")
                .expect("webhook URL");
        let webhook = resolve(&guard, DestinationTarget::webhook(&webhook_url))
            .await
            .expect("webhook resolution");
        let mut webhook = guard
            .connect(
                webhook,
                &FakeConnector::new([ConnectAction::Success(candidate)]),
            )
            .await
            .expect("webhook connect");
        assert_eq!(webhook.resolution_host(), "webhook.example");
        assert_eq!(webhook.resolution_port(), 9443);
        assert_eq!(webhook.semantic_authority(), "webhook.example:9443");
        assert_eq!(webhook.semantic_path(), "/provider/decision");
        assert_eq!(webhook.stream_mut().peer, candidate);

        let parent_hop = crate::url::canonicalize_http_authority("https", "parent.example:3128")
            .expect("parent authority");
        let origin =
            crate::url::canonicalize_http_url("https://origin.example:10443/parent/origin")
                .expect("parent origin");
        let parent = resolve(&guard, DestinationTarget::parent(&parent_hop, &origin))
            .await
            .expect("parent resolution");
        let parent = guard
            .connect(
                parent,
                &FakeConnector::new([ConnectAction::Success(candidate)]),
            )
            .await
            .expect("parent connect")
            .map_stream(|stream| stream.peer);
        assert_eq!(parent.resolution_host(), "parent.example");
        assert_eq!(parent.resolution_port(), 3128);
        assert_eq!(parent.semantic_authority(), "origin.example:10443");
        assert_eq!(parent.semantic_path(), "/parent/origin");
        assert_eq!(*parent.stream(), candidate);
    }

    #[test]
    fn destination_facts_derive_from_compiled_static_config() {
        use std::path::Path;

        let mut compiled = crate::config::compile_config_text(crate::config::ConfigTextInput {
            text: include_str!("../../tests/fixtures/production/host-proxy.toml"),
            source_path: Path::new("host-proxy.toml"),
            config_root: Path::new("/etc/acl-proxy"),
        })
        .expect("production fixture compiles");
        compiled.static_config.callback_public_url =
            Some("https://control.example/_acl-proxy/external-auth/callback".to_string());

        let facts = DestinationFacts::from_static(&compiled.static_config)
            .expect("validated static facts derive");
        assert_eq!(
            facts.listener_binds,
            vec![endpoint("0.0.0.0:8881"), endpoint("0.0.0.0:8889")]
        );
        assert_eq!(facts.control_bind, Some(endpoint("127.0.0.1:8898")));
        assert_eq!(facts.max_resolved_addresses, MAX_RESOLVED_ADDRESSES);
        let callback = crate::url::canonicalize_http_url(
            "https://control.example/_acl-proxy/external-auth/callback",
        )
        .expect("callback URL");
        assert!(facts
            .reserved_control
            .as_ref()
            .expect("reserved control subtree")
            .contains(&DestinationTarget::webhook(&callback)));

        let mut wrong_route = compiled.static_config.clone();
        wrong_route.callback_public_url =
            Some("https://control.example/not-the-control-route/callback".to_string());
        assert!(matches!(
            DestinationFacts::from_static(&wrong_route),
            Err(DestinationGuardError::InconsistentStaticFacts(_))
        ));

        let mut callback_without_control = compiled.static_config.clone();
        callback_without_control.control = None;
        assert!(matches!(
            DestinationFacts::from_static(&callback_without_control),
            Err(DestinationGuardError::InconsistentStaticFacts(_))
        ));

        let mut overlapping = compiled.static_config;
        overlapping
            .listeners
            .explicit_http
            .as_mut()
            .expect("explicit HTTP listener")
            .bind = endpoint("127.0.0.1:8898");
        assert!(matches!(
            DestinationFacts::from_static(&overlapping),
            Err(DestinationGuardError::InconsistentStaticFacts(_))
        ));
    }

    #[tokio::test]
    async fn empty_oversized_and_unspecified_resolution_fail_closed() {
        assert!(matches!(
            DestinationFacts::for_test([], None, None, MAX_RESOLVED_ADDRESSES + 1),
            Err(DestinationGuardError::ResolutionLimitTooLarge { .. })
        ));

        let empty = guard(
            facts([], None),
            Arc::new(FixedResolver::new([])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&empty, target(DestinationRoute::Direct, 443)).await,
            Err(DestinationGuardError::EmptyResolution)
        ));

        let oversized_facts = DestinationFacts::for_test([], None, None, 1).expect("facts");
        let oversized = guard(
            oversized_facts,
            Arc::new(FixedResolver::new([
                endpoint("192.0.2.70:443"),
                endpoint("192.0.2.71:443"),
            ])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&oversized, target(DestinationRoute::Direct, 443)).await,
            Err(DestinationGuardError::ResolutionLimitExceeded { limit: 1 })
        ));

        let unspecified = guard(
            facts([], None),
            Arc::new(FixedResolver::new([endpoint("0.0.0.0:443")])),
            [LocalStep::Addresses(vec![])],
        );
        assert!(matches!(
            resolve(&unspecified, target(DestinationRoute::Direct, 443)).await,
            Err(DestinationGuardError::ProtectedDestination {
                reason: ProtectedReason::Unspecified,
                ..
            })
        ));
    }
}
