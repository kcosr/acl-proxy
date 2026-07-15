use std::io;
use std::net::{IpAddr, SocketAddr};

use crate::network::{canonical_ip, canonical_socket_addr};

pub(crate) trait LocalAddressSource: Send + Sync {
    /// Enumerate the addresses assigned in the process network namespace now.
    fn snapshot(&self) -> io::Result<LocalAddressSnapshot>;
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct LocalAddress {
    ip: IpAddr,
    scope_id: u32,
}

impl LocalAddress {
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
        if self.ip != endpoint.ip() {
            return false;
        }

        match endpoint {
            SocketAddr::V6(endpoint) if endpoint.ip().is_unicast_link_local() => {
                endpoint.scope_id() == 0 || endpoint.scope_id() == self.scope_id
            }
            _ => true,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct LocalAddressSnapshot {
    addresses: Vec<LocalAddress>,
}

impl LocalAddressSnapshot {
    #[cfg(test)]
    pub(crate) fn new(addresses: impl IntoIterator<Item = LocalAddress>) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
        }
    }

    pub(crate) fn contains(&self, endpoint: SocketAddr) -> bool {
        self.addresses
            .iter()
            .any(|address| address.matches(endpoint))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemLocalAddressSource;

impl LocalAddressSource for SystemLocalAddressSource {
    fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
        let interfaces = if_addrs::get_if_addrs()?;
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(interfaces.len())
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    format!("cannot reserve local address snapshot: {error}"),
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
            addresses.push(LocalAddress::new(interface.ip(), scope_id));
        }
        Ok(LocalAddressSnapshot { addresses })
    }
}

pub(super) fn normalize_endpoint(endpoint: SocketAddr) -> SocketAddr {
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
