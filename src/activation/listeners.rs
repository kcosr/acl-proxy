use std::io;
use std::net::{SocketAddr, TcpListener};

use crate::config::compiler::StaticListenersConfig;

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
