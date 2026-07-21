use std::collections::TryReserveError;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use http_access_types::CanonicalUrl;

use crate::config::StaticProductConfig;
use crate::network::{canonical_ip, canonical_socket_addr, socket_binds_overlap};

const MAX_WEBHOOK_RESOLVED_ADDRESSES: usize = 256;

type WebhookDialFuture<'a, S> = Pin<Box<dyn Future<Output = io::Result<S>> + Send + 'a>>;

trait WebhookDialer: Send + Sync {
    type Stream: Send;

    fn connect(&self, endpoint: SocketAddr) -> WebhookDialFuture<'_, Self::Stream>;
    fn peer_addr(&self, stream: &Self::Stream) -> io::Result<SocketAddr>;
}

#[derive(Clone, Copy, Debug, Default)]
struct SystemWebhookDialer;

impl WebhookDialer for SystemWebhookDialer {
    type Stream = tokio::net::TcpStream;

    fn connect(&self, endpoint: SocketAddr) -> WebhookDialFuture<'_, Self::Stream> {
        Box::pin(tokio::net::TcpStream::connect(endpoint))
    }

    fn peer_addr(&self, stream: &Self::Stream) -> io::Result<SocketAddr> {
        stream.peer_addr()
    }
}

pub(crate) type WebhookResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, WebhookResolveError>> + Send + 'a>>;

pub(crate) trait WebhookResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16, max_addresses: usize) -> WebhookResolveFuture<'_>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemWebhookResolver;

impl WebhookResolver for SystemWebhookResolver {
    fn resolve(&self, host: &str, port: u16, max_addresses: usize) -> WebhookResolveFuture<'_> {
        let host = host.to_owned();
        Box::pin(async move {
            if max_addresses == 0 || max_addresses > MAX_WEBHOOK_RESOLVED_ADDRESSES {
                return Err(WebhookResolveError::InvalidLimit);
            }
            let resolved = tokio::net::lookup_host((host, port))
                .await
                .map_err(WebhookResolveError::Lookup)?;
            let mut answers = Vec::new();
            answers
                .try_reserve_exact(max_addresses + 1)
                .map_err(WebhookResolveError::Allocation)?;
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

pub(crate) trait WebhookLocalAddressSource: Send + Sync {
    fn snapshot(&self) -> io::Result<WebhookLocalAddressSnapshot>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WebhookLocalAddress {
    ip: IpAddr,
    scope_id: u32,
}

impl WebhookLocalAddress {
    pub(crate) fn new(ip: IpAddr, scope_id: u32) -> Self {
        let ip = canonical_ip(ip);
        let scope_id = match ip {
            IpAddr::V6(ip) if ip.is_unicast_link_local() => scope_id,
            _ => 0,
        };
        Self { ip, scope_id }
    }

    fn matches(self, endpoint: SocketAddr) -> bool {
        let endpoint = canonical_socket_addr(endpoint);
        self.ip == endpoint.ip()
            && !matches!(
                endpoint,
                SocketAddr::V6(endpoint)
                    if endpoint.ip().is_unicast_link_local()
                        && endpoint.scope_id() != 0
                        && endpoint.scope_id() != self.scope_id
            )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WebhookLocalAddressSnapshot {
    addresses: Vec<WebhookLocalAddress>,
}

impl WebhookLocalAddressSnapshot {
    #[cfg(test)]
    pub(crate) fn new(addresses: impl IntoIterator<Item = WebhookLocalAddress>) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
        }
    }

    fn contains(&self, endpoint: SocketAddr) -> bool {
        self.addresses
            .iter()
            .any(|address| address.matches(endpoint))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemWebhookLocalAddressSource;

impl WebhookLocalAddressSource for SystemWebhookLocalAddressSource {
    fn snapshot(&self) -> io::Result<WebhookLocalAddressSnapshot> {
        let interfaces = if_addrs::get_if_addrs()?;
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(interfaces.len())
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    format!("cannot reserve webhook local address snapshot: {error}"),
                )
            })?;
        for interface in interfaces {
            let scope_id = match interface.ip() {
                IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                    interface.index.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "link-local IPv6 interface {} has no interface index",
                                interface.name
                            ),
                        )
                    })?
                }
                _ => 0,
            };
            addresses.push(WebhookLocalAddress::new(interface.ip(), scope_id));
        }
        Ok(WebhookLocalAddressSnapshot { addresses })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReservedWebhookControlSubtree {
    canonical_authority: String,
    canonical_base_path: String,
}

impl ReservedWebhookControlSubtree {
    fn new(public_url: &CanonicalUrl, canonical_base_path: impl Into<String>) -> Self {
        Self {
            canonical_authority: public_url.authority().as_str().to_owned(),
            canonical_base_path: canonical_base_path.into(),
        }
    }

    fn contains(&self, url: &CanonicalUrl) -> bool {
        if self.canonical_authority != url.authority().as_str() {
            return false;
        }
        let base = self.canonical_base_path.as_str();
        url.path() == base
            || base == "/"
            || url
                .path()
                .strip_prefix(base)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebhookDestinationFacts {
    listener_binds: Vec<SocketAddr>,
    control_bind: Option<SocketAddr>,
    reserved_control: Option<ReservedWebhookControlSubtree>,
    max_resolved_addresses: usize,
}

impl WebhookDestinationFacts {
    pub(crate) fn from_static(config: &StaticProductConfig) -> Result<Self, WebhookConnectorError> {
        let listeners = &config.listeners;
        let listener_binds = [
            listeners
                .explicit_http
                .as_ref()
                .and_then(|listener| tcp_listener_address(&listener.endpoint)),
            listeners
                .transparent_http
                .as_ref()
                .and_then(|listener| tcp_listener_address(&listener.endpoint)),
            listeners
                .explicit_https
                .as_ref()
                .and_then(|listener| tcp_listener_address(&listener.endpoint)),
            listeners
                .transparent_https
                .as_ref()
                .and_then(|listener| tcp_listener_address(&listener.endpoint)),
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
            return Err(WebhookConnectorError::InconsistentFacts);
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
            return Err(WebhookConnectorError::InconsistentFacts);
        }
        let reserved_control = match (&config.control, &config.callback_public_url) {
            (Some(control), Some(public_url)) => {
                let expected_path = format!(
                    "{}/external-auth/callback",
                    control.base_path.trim_end_matches('/')
                );
                if public_url.path() != expected_path || public_url.query().is_some() {
                    return Err(WebhookConnectorError::InconsistentFacts);
                }
                Some(ReservedWebhookControlSubtree::new(
                    public_url,
                    control.base_path.clone(),
                ))
            }
            (None, Some(_)) => return Err(WebhookConnectorError::InconsistentFacts),
            (_, None) => None,
        };
        Ok(Self {
            listener_binds,
            control_bind,
            reserved_control,
            max_resolved_addresses: MAX_WEBHOOK_RESOLVED_ADDRESSES,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        listener_binds: impl IntoIterator<Item = SocketAddr>,
        control_bind: Option<SocketAddr>,
        reserved_control: Option<(&CanonicalUrl, &str)>,
        max_resolved_addresses: usize,
    ) -> Result<Self, WebhookConnectorError> {
        if max_resolved_addresses == 0 || max_resolved_addresses > MAX_WEBHOOK_RESOLVED_ADDRESSES {
            return Err(WebhookConnectorError::InconsistentFacts);
        }
        Ok(Self {
            listener_binds: listener_binds.into_iter().map(normalize_endpoint).collect(),
            control_bind: control_bind.map(normalize_endpoint),
            reserved_control: reserved_control
                .map(|(url, base)| ReservedWebhookControlSubtree::new(url, base.to_owned())),
            max_resolved_addresses,
        })
    }
}

fn tcp_listener_address(
    endpoint: &crate::config::compiler::StaticListenerEndpoint,
) -> Option<SocketAddr> {
    match endpoint {
        crate::config::compiler::StaticListenerEndpoint::Tcp { address } => Some(*address),
        crate::config::compiler::StaticListenerEndpoint::UnixProxyV2 { .. } => None,
    }
}

pub(crate) struct WebhookConnector {
    brand: Arc<()>,
    facts: WebhookDestinationFacts,
    resolver: Arc<dyn WebhookResolver>,
    local_addresses: Arc<dyn WebhookLocalAddressSource>,
}

impl WebhookConnector {
    pub(crate) fn system(
        static_config: &StaticProductConfig,
    ) -> Result<Arc<Self>, WebhookConnectorError> {
        Ok(Arc::new(Self::new(
            WebhookDestinationFacts::from_static(static_config)?,
            Arc::new(SystemWebhookResolver),
            Arc::new(SystemWebhookLocalAddressSource),
        )))
    }

    fn new(
        facts: WebhookDestinationFacts,
        resolver: Arc<dyn WebhookResolver>,
        local_addresses: Arc<dyn WebhookLocalAddressSource>,
    ) -> Self {
        Self {
            brand: Arc::new(()),
            facts,
            resolver,
            local_addresses,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_sources(
        facts: WebhookDestinationFacts,
        resolver: Arc<dyn WebhookResolver>,
        local_addresses: Arc<dyn WebhookLocalAddressSource>,
    ) -> Self {
        Self::new(facts, resolver, local_addresses)
    }

    pub(crate) async fn connect<C>(
        &self,
        url: &CanonicalUrl,
        mut cancellation: Pin<&mut C>,
    ) -> Result<WebhookConnection, WebhookConnectorError>
    where
        C: Future<Output = ()> + Send,
    {
        let prepared = self.preflight(url)?;
        let resolved = tokio::select! {
            biased;
            _ = cancellation.as_mut() => return Err(WebhookConnectorError::Cancelled),
            result = self.complete_resolution(prepared) => result?,
        };
        tokio::select! {
            biased;
            _ = cancellation.as_mut() => Err(WebhookConnectorError::Cancelled),
            result = self.connect_system(resolved) => result,
        }
    }

    fn preflight(
        &self,
        url: &CanonicalUrl,
    ) -> Result<PreparedWebhookDestination, WebhookConnectorError> {
        if self
            .facts
            .reserved_control
            .as_ref()
            .is_some_and(|reserved| reserved.contains(url))
        {
            return Err(WebhookConnectorError::ReservedControlSubtree);
        }
        let target = WebhookTarget {
            resolution_host: url.authority().host().as_str().to_owned(),
            resolution_port: url.authority().effective_port(),
        };
        if let Ok(ip) = target.resolution_host.parse() {
            self.validate(
                normalize_endpoint(SocketAddr::new(ip, target.resolution_port)),
                &self.local_snapshot()?,
            )?;
        }
        Ok(PreparedWebhookDestination {
            brand: self.brand.clone(),
            target,
        })
    }

    async fn complete_resolution(
        &self,
        prepared: PreparedWebhookDestination,
    ) -> Result<ResolvedWebhookDestination, WebhookConnectorError> {
        if !Arc::ptr_eq(&prepared.brand, &self.brand) {
            return Err(WebhookConnectorError::ForeignToken);
        }
        let answers = self
            .resolver
            .resolve(
                &prepared.target.resolution_host,
                prepared.target.resolution_port,
                self.facts.max_resolved_addresses,
            )
            .await?;
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(self.facts.max_resolved_addresses + 1)
            .map_err(WebhookConnectorError::Allocation)?;
        for answer in answers {
            let answer = normalize_endpoint(answer);
            if !addresses.contains(&answer) {
                if addresses.len() == self.facts.max_resolved_addresses {
                    return Err(WebhookConnectorError::ResolutionLimit {
                        limit: self.facts.max_resolved_addresses,
                    });
                }
                addresses.push(answer);
            }
        }
        if addresses.is_empty() {
            return Err(WebhookConnectorError::EmptyResolution);
        }
        let local = self.local_snapshot()?;
        for &address in &addresses {
            self.validate(address, &local)?;
        }
        Ok(ResolvedWebhookDestination {
            brand: prepared.brand,
            target: prepared.target,
            addresses,
        })
    }

    async fn connect_system(
        &self,
        resolved: ResolvedWebhookDestination,
    ) -> Result<WebhookConnection, WebhookConnectorError> {
        let connected = self.connect_with(resolved, &SystemWebhookDialer).await?;
        Ok(WebhookConnection {
            resolution_host: connected.target.resolution_host,
            stream: connected.stream,
        })
    }

    async fn connect_with<D>(
        &self,
        resolved: ResolvedWebhookDestination,
        dialer: &D,
    ) -> Result<ConnectedWebhookDestination<D::Stream>, WebhookConnectorError>
    where
        D: WebhookDialer,
    {
        if !Arc::ptr_eq(&resolved.brand, &self.brand) {
            return Err(WebhookConnectorError::ForeignToken);
        }
        let mut last_error = None;
        for candidate in resolved.addresses {
            self.validate(candidate, &self.local_snapshot()?)?;
            let stream = match dialer.connect(candidate).await {
                Ok(stream) => stream,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let peer = normalize_endpoint(
                dialer
                    .peer_addr(&stream)
                    .map_err(WebhookConnectorError::PeerAddress)?,
            );
            self.validate(peer, &self.local_snapshot()?)?;
            if peer != candidate {
                return Err(WebhookConnectorError::PeerMismatch {
                    expected: candidate,
                    actual: peer,
                });
            }
            return Ok(ConnectedWebhookDestination {
                target: resolved.target,
                stream,
            });
        }
        Err(WebhookConnectorError::ConnectionAttemptsExhausted(
            last_error.expect("a nonempty webhook resolution attempted at least one dial"),
        ))
    }

    fn local_snapshot(&self) -> Result<WebhookLocalAddressSnapshot, WebhookConnectorError> {
        self.local_addresses
            .snapshot()
            .map_err(WebhookConnectorError::LocalAddressEnumeration)
    }

    fn validate(
        &self,
        endpoint: SocketAddr,
        local: &WebhookLocalAddressSnapshot,
    ) -> Result<(), WebhookConnectorError> {
        let endpoint = normalize_endpoint(endpoint);
        if matches!(endpoint, SocketAddr::V6(address) if address.ip().is_unicast_link_local() && address.scope_id() == 0)
            || endpoint.ip().is_unspecified()
        {
            return Err(WebhookConnectorError::ProtectedDestination(endpoint));
        }
        if self.facts.control_bind == Some(endpoint) {
            return Err(WebhookConnectorError::ProtectedDestination(endpoint));
        }
        for &bind in &self.facts.listener_binds {
            let protected = if bind.ip().is_unspecified() {
                bind.port() == endpoint.port() && local.contains(endpoint)
            } else {
                bind == endpoint
            };
            if protected {
                return Err(WebhookConnectorError::ProtectedDestination(endpoint));
            }
        }
        Ok(())
    }
}

struct WebhookTarget {
    resolution_host: String,
    resolution_port: u16,
}

struct PreparedWebhookDestination {
    brand: Arc<()>,
    target: WebhookTarget,
}

struct ResolvedWebhookDestination {
    brand: Arc<()>,
    target: WebhookTarget,
    addresses: Vec<SocketAddr>,
}

struct ConnectedWebhookDestination<S> {
    target: WebhookTarget,
    stream: S,
}

pub(crate) struct WebhookConnection {
    resolution_host: String,
    stream: tokio::net::TcpStream,
}

impl WebhookConnection {
    pub(crate) fn resolution_host(&self) -> &str {
        &self.resolution_host
    }

    pub(crate) fn into_stream(self) -> tokio::net::TcpStream {
        self.stream
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookConnectorError {
    #[error("webhook destination facts are inconsistent")]
    InconsistentFacts,
    #[error("webhook targets the reserved control subtree")]
    ReservedControlSubtree,
    #[error("webhook destination token belongs to another connector")]
    ForeignToken,
    #[error("webhook destination allocation failed")]
    Allocation(#[source] TryReserveError),
    #[error("webhook destination resolution failed")]
    Resolution(#[source] WebhookResolveError),
    #[error("webhook destination resolution was empty")]
    EmptyResolution,
    #[error("webhook destination resolution exceeded the {limit}-address limit")]
    ResolutionLimit { limit: usize },
    #[error("webhook local address enumeration failed")]
    LocalAddressEnumeration(#[source] io::Error),
    #[error("webhook destination {0} is protected")]
    ProtectedDestination(SocketAddr),
    #[error("webhook connected peer lookup failed")]
    PeerAddress(#[source] io::Error),
    #[error("webhook connected peer {actual} differs from pinned address {expected}")]
    PeerMismatch {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    #[error("all webhook connection attempts failed")]
    ConnectionAttemptsExhausted(#[source] io::Error),
    #[error("webhook connection was cancelled")]
    Cancelled,
}

impl From<WebhookResolveError> for WebhookConnectorError {
    fn from(error: WebhookResolveError) -> Self {
        Self::Resolution(error)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookResolveError {
    #[error("webhook resolution limit is invalid")]
    InvalidLimit,
    #[error("webhook lookup failed")]
    Lookup(#[source] io::Error),
    #[error("webhook resolution allocation failed")]
    Allocation(#[source] TryReserveError),
}

fn normalize_endpoint(endpoint: SocketAddr) -> SocketAddr {
    match canonical_socket_addr(endpoint) {
        SocketAddr::V6(endpoint) => SocketAddr::V6(std::net::SocketAddrV6::new(
            *endpoint.ip(),
            endpoint.port(),
            0,
            endpoint.scope_id(),
        )),
        endpoint => endpoint,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::error::Error as _;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;

    struct FixedResolver {
        answers: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    struct HangingResolver {
        calls: AtomicUsize,
    }

    impl WebhookResolver for HangingResolver {
        fn resolve(&self, _host: &str, _port: u16, _max: usize) -> WebhookResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }
    }

    impl WebhookResolver for FixedResolver {
        fn resolve(&self, _host: &str, _port: u16, _max: usize) -> WebhookResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answers = self.answers.clone();
            Box::pin(async move { Ok(answers) })
        }
    }

    struct NoLocalAddresses;

    impl WebhookLocalAddressSource for NoLocalAddresses {
        fn snapshot(&self) -> io::Result<WebhookLocalAddressSnapshot> {
            Ok(WebhookLocalAddressSnapshot::new([]))
        }
    }

    struct FailingLocalAddresses;

    impl WebhookLocalAddressSource for FailingLocalAddresses {
        fn snapshot(&self) -> io::Result<WebhookLocalAddressSnapshot> {
            Err(io::Error::other("injected failure"))
        }
    }

    struct SequenceLocalAddresses {
        snapshots: Mutex<VecDeque<WebhookLocalAddressSnapshot>>,
    }

    impl WebhookLocalAddressSource for SequenceLocalAddresses {
        fn snapshot(&self) -> io::Result<WebhookLocalAddressSnapshot> {
            let mut snapshots = self.snapshots.lock().unwrap();
            Ok(if snapshots.len() > 1 {
                snapshots.pop_front().unwrap()
            } else {
                snapshots.front().unwrap().clone()
            })
        }
    }

    struct FakeStream {
        peer: SocketAddr,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for FakeStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct FakeDialer {
        peer: SocketAddr,
        attempts: AtomicUsize,
        dropped: Arc<AtomicBool>,
    }

    impl WebhookDialer for FakeDialer {
        type Stream = FakeStream;

        fn connect(&self, _endpoint: SocketAddr) -> WebhookDialFuture<'_, Self::Stream> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let peer = self.peer;
            let dropped = self.dropped.clone();
            Box::pin(async move { Ok(FakeStream { peer, dropped }) })
        }

        fn peer_addr(&self, stream: &Self::Stream) -> io::Result<SocketAddr> {
            Ok(stream.peer)
        }
    }

    fn make_connector(
        facts: WebhookDestinationFacts,
        answers: impl IntoIterator<Item = SocketAddr>,
    ) -> (WebhookConnector, Arc<FixedResolver>) {
        let resolver = Arc::new(FixedResolver {
            answers: answers.into_iter().collect(),
            calls: AtomicUsize::new(0),
        });
        (
            WebhookConnector::with_sources(facts, resolver.clone(), Arc::new(NoLocalAddresses)),
            resolver,
        )
    }

    #[tokio::test]
    async fn webhook_protected_endpoints_and_mixed_answers_fail_closed() {
        let facts = WebhookDestinationFacts::for_test(
            ["127.0.0.1:8443".parse().unwrap()],
            Some("127.0.0.1:8898".parse().unwrap()),
            None,
            8,
        )
        .unwrap();
        for answers in [
            vec!["127.0.0.1:8443".parse().unwrap()],
            vec![
                "192.0.2.1:8443".parse().unwrap(),
                "127.0.0.1:8443".parse().unwrap(),
            ],
            vec!["127.0.0.1:8898".parse().unwrap()],
        ] {
            let (connector, resolver) = make_connector(facts.clone(), answers);
            let url =
                http_access_url::canonicalize_http_url("http://provider.test:8443/a").unwrap();
            let mut cancellation = Box::pin(std::future::pending());
            assert!(matches!(
                connector.connect(&url, cancellation.as_mut()).await,
                Err(WebhookConnectorError::ProtectedDestination(_))
            ));
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        }

        let mapped: SocketAddr = "[::ffff:127.0.0.1]:8443".parse().unwrap();
        let (connector, _) = make_connector(facts, [mapped]);
        let url = http_access_url::canonicalize_http_url("http://provider.test:8443/a").unwrap();
        let mut cancellation = Box::pin(std::future::pending());
        assert!(matches!(
            connector.connect(&url, cancellation.as_mut()).await,
            Err(WebhookConnectorError::ProtectedDestination(_))
        ));
    }

    #[tokio::test]
    async fn reserved_control_subtree_denies_before_dns() {
        let callback = http_access_url::canonicalize_http_url(
            "https://control.example/_acl/external-auth/callback",
        )
        .unwrap();
        let facts =
            WebhookDestinationFacts::for_test([], None, Some((&callback, "/_acl")), 8).unwrap();
        let (connector, resolver) = make_connector(facts, ["192.0.2.60:443".parse().unwrap()]);
        let mut cancellation = Box::pin(std::future::pending());
        assert!(matches!(
            connector.connect(&callback, cancellation.as_mut()).await,
            Err(WebhookConnectorError::ReservedControlSubtree)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn live_listener_policy_is_rechecked_before_and_after_dial() {
        let candidate: SocketAddr = "192.0.2.10:8443".parse().unwrap();
        let facts =
            WebhookDestinationFacts::for_test(["0.0.0.0:8443".parse().unwrap()], None, None, 8)
                .unwrap();
        for (snapshots, expected_attempts) in [
            (
                vec![
                    WebhookLocalAddressSnapshot::default(),
                    WebhookLocalAddressSnapshot::new([WebhookLocalAddress::new(candidate.ip(), 0)]),
                ],
                0,
            ),
            (
                vec![
                    WebhookLocalAddressSnapshot::default(),
                    WebhookLocalAddressSnapshot::default(),
                    WebhookLocalAddressSnapshot::new([WebhookLocalAddress::new(candidate.ip(), 0)]),
                ],
                1,
            ),
        ] {
            let resolver = Arc::new(FixedResolver {
                answers: vec![candidate],
                calls: AtomicUsize::new(0),
            });
            let connector = WebhookConnector::with_sources(
                facts.clone(),
                resolver,
                Arc::new(SequenceLocalAddresses {
                    snapshots: Mutex::new(snapshots.into()),
                }),
            );
            let url = http_access_url::canonicalize_http_url("http://provider.test:8443/authorize")
                .unwrap();
            let prepared = connector.preflight(&url).unwrap();
            let resolved = connector.complete_resolution(prepared).await.unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let dialer = FakeDialer {
                peer: candidate,
                attempts: AtomicUsize::new(0),
                dropped: dropped.clone(),
            };
            assert!(matches!(
                connector.connect_with(resolved, &dialer).await,
                Err(WebhookConnectorError::ProtectedDestination(_))
            ));
            assert_eq!(dialer.attempts.load(Ordering::SeqCst), expected_attempts);
            assert_eq!(dropped.load(Ordering::SeqCst), expected_attempts == 1);
        }
    }

    #[tokio::test]
    async fn connected_peer_must_equal_the_pinned_address() {
        let candidate: SocketAddr = "192.0.2.20:443".parse().unwrap();
        let actual: SocketAddr = "192.0.2.21:443".parse().unwrap();
        let (connector, _) = make_connector(
            WebhookDestinationFacts::for_test([], None, None, 8).unwrap(),
            [candidate],
        );
        let url =
            http_access_url::canonicalize_http_url("https://provider.test/authorize").unwrap();
        let prepared = connector.preflight(&url).unwrap();
        let resolved = connector.complete_resolution(prepared).await.unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let dialer = FakeDialer {
            peer: actual,
            attempts: AtomicUsize::new(0),
            dropped: dropped.clone(),
        };
        assert!(matches!(
            connector.connect_with(resolved, &dialer).await,
            Err(WebhookConnectorError::PeerMismatch { expected, actual: observed })
                if expected == candidate && observed == actual
        ));
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn one_lookup_is_pinned_and_foreign_tokens_are_rejected() {
        let candidate: SocketAddr = "192.0.2.30:443".parse().unwrap();
        let (connector, resolver) = make_connector(
            WebhookDestinationFacts::for_test([], None, None, 8).unwrap(),
            [candidate, candidate],
        );
        let (foreign, _) = make_connector(
            WebhookDestinationFacts::for_test([], None, None, 8).unwrap(),
            [candidate],
        );
        let url =
            http_access_url::canonicalize_http_url("https://provider.test/authorize").unwrap();
        let foreign_prepared = foreign.preflight(&url).unwrap();
        assert!(matches!(
            connector.complete_resolution(foreign_prepared).await,
            Err(WebhookConnectorError::ForeignToken)
        ));

        let prepared = connector.preflight(&url).unwrap();
        let resolved = connector.complete_resolution(prepared).await.unwrap();
        let dialer = FakeDialer {
            peer: candidate,
            attempts: AtomicUsize::new(0),
            dropped: Arc::new(AtomicBool::new(false)),
        };
        let connected = connector.connect_with(resolved, &dialer).await.unwrap();
        assert_eq!(connected.target.resolution_host, "provider.test");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_and_local_enumeration_failure_stop_before_dial() {
        let facts = WebhookDestinationFacts::for_test([], None, None, 8).unwrap();
        let hanging = Arc::new(HangingResolver {
            calls: AtomicUsize::new(0),
        });
        let connector = WebhookConnector::with_sources(
            facts.clone(),
            hanging.clone(),
            Arc::new(NoLocalAddresses),
        );
        let url =
            http_access_url::canonicalize_http_url("https://provider.test/authorize").unwrap();
        let mut cancellation = Box::pin(std::future::ready(()));
        assert!(matches!(
            connector.connect(&url, cancellation.as_mut()).await,
            Err(WebhookConnectorError::Cancelled)
        ));
        assert_eq!(hanging.calls.load(Ordering::SeqCst), 0);

        let resolver = Arc::new(FixedResolver {
            answers: vec!["192.0.2.40:443".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let connector =
            WebhookConnector::with_sources(facts, resolver, Arc::new(FailingLocalAddresses));
        let prepared = connector.preflight(&url).unwrap();
        assert!(matches!(
            connector.complete_resolution(prepared).await,
            Err(WebhookConnectorError::LocalAddressEnumeration(_))
        ));
    }

    #[test]
    fn connector_errors_preserve_sanitized_source_chains() {
        let allocation = Vec::<u8>::new().try_reserve(usize::MAX).unwrap_err();
        let allocation = WebhookConnectorError::Allocation(allocation);
        assert!(allocation.source().is_some());

        let resolution = WebhookConnectorError::Resolution(WebhookResolveError::Lookup(
            io::Error::other("sensitive lookup detail"),
        ));
        let resolution_source = resolution.source().unwrap();
        assert!(resolution_source.source().is_some());
        assert!(!resolution.to_string().contains("sensitive lookup detail"));

        for error in [
            WebhookConnectorError::LocalAddressEnumeration(io::Error::other(
                "sensitive interface detail",
            )),
            WebhookConnectorError::PeerAddress(io::Error::other("sensitive peer detail")),
            WebhookConnectorError::ConnectionAttemptsExhausted(io::Error::other(
                "sensitive connect detail",
            )),
        ] {
            assert!(error.source().is_some());
            assert!(!error.to_string().contains("sensitive"));
        }
    }
}
