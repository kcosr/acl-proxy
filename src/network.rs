use std::net::{IpAddr, SocketAddr};

pub(crate) fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

pub(crate) fn canonical_socket_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map(|mapped| SocketAddr::new(IpAddr::V4(mapped), address.port()))
            .unwrap_or(SocketAddr::V6(address)),
        address => address,
    }
}

pub(crate) fn socket_binds_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    let left = canonical_socket_addr(left);
    let right = canonical_socket_addr(right);
    left.port() == right.port()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ipv6_addresses_use_their_ipv4_identity() {
        assert_eq!(
            canonical_socket_addr("[::ffff:127.0.0.1]:8080".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
        );
    }

    #[test]
    fn wildcard_binds_overlap_specific_addresses_on_the_same_port() {
        assert!(socket_binds_overlap(
            "0.0.0.0:8080".parse().unwrap(),
            "192.0.2.1:8080".parse().unwrap(),
        ));
        assert!(!socket_binds_overlap(
            "0.0.0.0:8080".parse().unwrap(),
            "192.0.2.1:8081".parse().unwrap(),
        ));
    }

    #[test]
    fn canonical_socket_address_preserves_ipv6_scope() {
        let address = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            8080,
            7,
            42,
        ));
        assert_eq!(canonical_socket_addr(address), address);
    }
}
