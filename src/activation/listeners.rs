use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use crate::config::compiler::StaticListenersConfig;
use crate::runtime::BoxFuture;

use super::assets::ProductIngressAssets;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyListenerKind {
    ExplicitHttp,
    TransparentHttp,
    ExplicitHttps,
    TransparentHttps,
}

impl std::fmt::Display for ProxyListenerKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ExplicitHttp => "explicit_http",
            Self::TransparentHttp => "transparent_http",
            Self::ExplicitHttps => "explicit_https",
            Self::TransparentHttps => "transparent_https",
        })
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
        kind: ProxyListenerKind,
        listener: TcpListener,
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

#[derive(Default)]
pub(super) struct PreparedProxyListeners {
    pub(super) explicit_http: Option<TcpListener>,
    pub(super) transparent_http: Option<TcpListener>,
    pub(super) explicit_https: Option<TcpListener>,
    pub(super) transparent_https: Option<TcpListener>,
}

impl PreparedProxyListeners {
    pub(super) fn bind(
        config: &StaticListenersConfig,
        mut bind: impl FnMut(SocketAddr) -> io::Result<TcpListener>,
    ) -> Result<Self, ProxyListenerBindError> {
        let explicit_http = bind_configured(
            "explicit_http",
            config.explicit_http.as_ref().map(|listener| listener.bind),
            &mut bind,
        )?;
        let transparent_http = bind_configured(
            "transparent_http",
            config
                .transparent_http
                .as_ref()
                .map(|listener| listener.bind),
            &mut bind,
        )?;
        let explicit_https = bind_configured(
            "explicit_https",
            config.explicit_https.as_ref().map(|listener| listener.bind),
            &mut bind,
        )?;
        let transparent_https = bind_configured(
            "transparent_https",
            config
                .transparent_https
                .as_ref()
                .map(|listener| listener.bind),
            &mut bind,
        )?;

        Ok(Self {
            explicit_http,
            transparent_http,
            explicit_https,
            transparent_https,
        })
    }

    pub(super) fn into_entries(self) -> Vec<(ProxyListenerKind, TcpListener)> {
        [
            (ProxyListenerKind::ExplicitHttp, self.explicit_http),
            (ProxyListenerKind::TransparentHttp, self.transparent_http),
            (ProxyListenerKind::ExplicitHttps, self.explicit_https),
            (ProxyListenerKind::TransparentHttps, self.transparent_https),
        ]
        .into_iter()
        .filter_map(|(kind, listener)| listener.map(|listener| (kind, listener)))
        .collect()
    }
}

fn bind_configured(
    name: &'static str,
    address: Option<SocketAddr>,
    bind: &mut impl FnMut(SocketAddr) -> io::Result<TcpListener>,
) -> Result<Option<TcpListener>, ProxyListenerBindError> {
    address
        .map(|address| {
            bind(address).map_err(|source| ProxyListenerBindError {
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
