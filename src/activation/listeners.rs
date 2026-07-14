use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use crate::config::compiler::{
    StaticCleartextListener, StaticExplicitHttpsListener, StaticListenersConfig,
    StaticTransparentHttpsListener,
};
use crate::runtime::BoxFuture;

use super::assets::ProductIngressAssets;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyListenerKind {
    ExplicitHttp,
    TransparentHttp,
    ExplicitHttps,
    TransparentHttps,
}

impl ProxyListenerKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitHttp => "explicit_http",
            Self::TransparentHttp => "transparent_http",
            Self::ExplicitHttps => "explicit_https",
            Self::TransparentHttps => "transparent_https",
        }
    }
}

impl std::fmt::Display for ProxyListenerKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub(crate) trait ProxySupervisorFailureObserver: Send + Sync {
    fn failed(&self, error: Arc<ProxySupervisorFailure>);
}

pub(crate) trait ProxySupervisor: Send + Sync {
    fn begin_shutdown(&self);
    fn close_and_join(&self) -> BoxFuture<'_, Result<(), ProxySupervisorFailure>>;
    fn abort_and_join(&self) -> BoxFuture<'_, Result<(), ProxySupervisorFailure>>;
}

pub(crate) trait ProxySupervisorStarter {
    fn start(
        &mut self,
        listener: PreparedProxyListener,
        assets: &Arc<ProductIngressAssets>,
        failure_observer: Arc<dyn ProxySupervisorFailureObserver>,
    ) -> Result<Arc<dyn ProxySupervisor>, ProxySupervisorStartError>;
}

#[derive(Debug, thiserror::Error)]
#[error("{listener} proxy supervisor startup failed: {message}")]
pub(crate) struct ProxySupervisorStartError {
    pub(crate) listener: ProxyListenerKind,
    pub(crate) message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{listener} proxy supervisor failed: {message}")]
pub(crate) struct ProxySupervisorFailure {
    pub(crate) listener: ProxyListenerKind,
    pub(crate) message: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ProxyListenerConfig {
    ExplicitHttp(Box<StaticCleartextListener>),
    TransparentHttp(Box<StaticCleartextListener>),
    ExplicitHttps(Box<StaticExplicitHttpsListener>),
    TransparentHttps(Box<StaticTransparentHttpsListener>),
}

impl ProxyListenerConfig {
    pub(crate) fn kind(&self) -> ProxyListenerKind {
        match self {
            Self::ExplicitHttp(_) => ProxyListenerKind::ExplicitHttp,
            Self::TransparentHttp(_) => ProxyListenerKind::TransparentHttp,
            Self::ExplicitHttps(_) => ProxyListenerKind::ExplicitHttps,
            Self::TransparentHttps(_) => ProxyListenerKind::TransparentHttps,
        }
    }

    fn bind(&self) -> SocketAddr {
        match self {
            Self::ExplicitHttp(config) | Self::TransparentHttp(config) => config.bind,
            Self::ExplicitHttps(config) => config.bind,
            Self::TransparentHttps(config) => config.bind,
        }
    }
}

pub(crate) struct PreparedProxyListener {
    pub(crate) config: ProxyListenerConfig,
    pub(crate) listener: TcpListener,
}

impl PreparedProxyListener {
    pub(crate) fn kind(&self) -> ProxyListenerKind {
        self.config.kind()
    }
}

#[derive(Default)]
pub(super) struct PreparedProxyListeners {
    pub(super) explicit_http: Option<PreparedProxyListener>,
    pub(super) transparent_http: Option<PreparedProxyListener>,
    pub(super) explicit_https: Option<PreparedProxyListener>,
    pub(super) transparent_https: Option<PreparedProxyListener>,
}

impl PreparedProxyListeners {
    pub(super) fn bind(
        config: &StaticListenersConfig,
        mut bind: impl FnMut(SocketAddr) -> io::Result<TcpListener>,
    ) -> Result<Self, ProxyListenerBindError> {
        let explicit_http = bind_configured(
            config
                .explicit_http
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::ExplicitHttp),
            &mut bind,
        )?;
        let transparent_http = bind_configured(
            config
                .transparent_http
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::TransparentHttp),
            &mut bind,
        )?;
        let explicit_https = bind_configured(
            config
                .explicit_https
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::ExplicitHttps),
            &mut bind,
        )?;
        let transparent_https = bind_configured(
            config
                .transparent_https
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::TransparentHttps),
            &mut bind,
        )?;

        Ok(Self {
            explicit_http,
            transparent_http,
            explicit_https,
            transparent_https,
        })
    }

    pub(super) fn into_entries(self) -> Vec<PreparedProxyListener> {
        [
            self.explicit_http,
            self.transparent_http,
            self.explicit_https,
            self.transparent_https,
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

fn bind_configured(
    config: Option<ProxyListenerConfig>,
    bind: &mut impl FnMut(SocketAddr) -> io::Result<TcpListener>,
) -> Result<Option<PreparedProxyListener>, ProxyListenerBindError> {
    config
        .map(|config| {
            let address = config.bind();
            let name = config.kind().as_str();
            bind(address)
                .map(|listener| PreparedProxyListener { config, listener })
                .map_err(|source| ProxyListenerBindError {
                    name,
                    address,
                    source,
                })
        })
        .transpose()
}

#[derive(Debug, thiserror::Error)]
#[error("failed to bind {name} proxy listener {address}: {source}")]
pub(crate) struct ProxyListenerBindError {
    pub(crate) name: &'static str,
    pub(crate) address: SocketAddr,
    #[source]
    pub(crate) source: io::Error,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::config::compiler::{
        CompiledHttp1ConnectPolicy, CompiledHttpVersion, CompiledTlsIdentity, StaticConnectPolicy,
    };

    fn prebound_listeners<const N: usize>() -> [TcpListener; N] {
        (0..N)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }

    #[test]
    fn prepared_entries_retain_each_exact_compiled_listener_config() {
        let listeners = prebound_listeners::<4>();
        let addresses: [SocketAddr; 4] =
            std::array::from_fn(|index| listeners[index].local_addr().unwrap());
        let cleartext_connect = StaticConnectPolicy {
            http1: Some(CompiledHttp1ConnectPolicy::Deny),
            http2_denied: true,
        };
        let config = StaticListenersConfig {
            explicit_http: Some(StaticCleartextListener {
                bind: addresses[0],
                http_versions: vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
                request_header_timeout: Duration::from_secs(5),
                max_connections: 17,
                max_concurrent_streams: 19,
                connect: Some(cleartext_connect.clone()),
            }),
            transparent_http: Some(StaticCleartextListener {
                bind: addresses[1],
                http_versions: vec![CompiledHttpVersion::Http1],
                request_header_timeout: Duration::from_secs(7),
                max_connections: 23,
                max_concurrent_streams: 29,
                connect: None,
            }),
            explicit_https: Some(StaticExplicitHttpsListener {
                bind: addresses[2],
                http_versions: vec![CompiledHttpVersion::Http2],
                handshake_timeout: Duration::from_secs(3),
                request_header_timeout: Duration::from_secs(5),
                max_connections: 17,
                max_concurrent_streams: 19,
                connect: cleartext_connect,
                tls: CompiledTlsIdentity {
                    certificate_chain: PathBuf::from("server.pem"),
                    private_key: PathBuf::from("server-key.pem"),
                },
            }),
            transparent_https: Some(StaticTransparentHttpsListener {
                bind: addresses[3],
                http_versions: vec![CompiledHttpVersion::Http1],
                handshake_timeout: Duration::from_secs(7),
                request_header_timeout: Duration::from_secs(11),
                max_connections: 23,
                max_concurrent_streams: 29,
            }),
        };

        let mut listeners = listeners.into_iter();
        let entries = PreparedProxyListeners::bind(&config, |_| {
            Ok(listeners.next().expect("one prebound listener per config"))
        })
        .unwrap()
        .into_entries();
        assert_eq!(entries.len(), 4);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.kind(),
                [
                    ProxyListenerKind::ExplicitHttp,
                    ProxyListenerKind::TransparentHttp,
                    ProxyListenerKind::ExplicitHttps,
                    ProxyListenerKind::TransparentHttps,
                ][index]
            );
            assert_eq!(entry.listener.local_addr().unwrap(), addresses[index]);
        }
        assert!(matches!(
            &entries[0].config,
            ProxyListenerConfig::ExplicitHttp(actual)
                if Some(actual.as_ref()) == config.explicit_http.as_ref()
        ));
        assert!(matches!(
            &entries[1].config,
            ProxyListenerConfig::TransparentHttp(actual)
                if Some(actual.as_ref()) == config.transparent_http.as_ref()
        ));
        assert!(matches!(
            &entries[2].config,
            ProxyListenerConfig::ExplicitHttps(actual)
                if Some(actual.as_ref()) == config.explicit_https.as_ref()
        ));
        assert!(matches!(
            &entries[3].config,
            ProxyListenerConfig::TransparentHttps(actual)
                if Some(actual.as_ref()) == config.transparent_https.as_ref()
        ));
    }
}
