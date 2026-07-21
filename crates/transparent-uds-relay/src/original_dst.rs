use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
};

use thiserror::Error;
use tokio::net::TcpStream;

const SO_ORIGINAL_DST: libc::c_int = 80;

#[derive(Debug, Error)]
pub enum OriginalDestinationError {
    #[error("SO_ORIGINAL_DST is unavailable: {0}")]
    Unavailable(#[source] io::Error),
    #[error("SO_ORIGINAL_DST returned an invalid address length")]
    InvalidLength,
    #[error("SO_ORIGINAL_DST did not return an IPv4 address")]
    UnsupportedFamily,
    #[error("SO_ORIGINAL_DST returned an unspecified IPv4 address")]
    UnspecifiedAddress,
    #[error("SO_ORIGINAL_DST returned port zero")]
    InvalidPort,
}

pub fn original_destination(stream: &TcpStream) -> Result<SocketAddrV4, OriginalDestinationError> {
    let mut address = libc::sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: the socket descriptor is live and address/length point to writable storage.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    };
    decode_getsockopt_result(result, address, length, io::Error::last_os_error())
}

fn decode_getsockopt_result(
    result: libc::c_int,
    address: libc::sockaddr_in,
    length: libc::socklen_t,
    error: io::Error,
) -> Result<SocketAddrV4, OriginalDestinationError> {
    if result != 0 {
        return Err(OriginalDestinationError::Unavailable(error));
    }
    decode_original_destination(address, length)
}

fn decode_original_destination(
    address: libc::sockaddr_in,
    length: libc::socklen_t,
) -> Result<SocketAddrV4, OriginalDestinationError> {
    if length as usize != size_of::<libc::sockaddr_in>() {
        return Err(OriginalDestinationError::InvalidLength);
    }
    parse_sockaddr(address)
}

fn parse_sockaddr(address: libc::sockaddr_in) -> Result<SocketAddrV4, OriginalDestinationError> {
    if i32::from(address.sin_family) != libc::AF_INET {
        return Err(OriginalDestinationError::UnsupportedFamily);
    }
    let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
    if ip.is_unspecified() {
        return Err(OriginalDestinationError::UnspecifiedAddress);
    }
    let port = u16::from_be(address.sin_port);
    if port == 0 {
        return Err(OriginalDestinationError::InvalidPort);
    }
    Ok(SocketAddrV4::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr(ip: [u8; 4], port: u16, family: libc::sa_family_t) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: family,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip),
            },
            sin_zero: [0; 8],
        }
    }

    #[test]
    fn parses_ipv4_original_destination_in_network_order() {
        let parsed = parse_sockaddr(sockaddr([203, 0, 113, 9], 443, libc::AF_INET as _)).unwrap();
        assert_eq!(parsed, "203.0.113.9:443".parse().unwrap());
    }

    #[test]
    fn rejects_ipv6_unspecified_address_and_zero_port() {
        assert!(matches!(
            parse_sockaddr(sockaddr([1, 2, 3, 4], 80, libc::AF_INET6 as _)),
            Err(OriginalDestinationError::UnsupportedFamily)
        ));
        assert!(matches!(
            parse_sockaddr(sockaddr([0, 0, 0, 0], 80, libc::AF_INET as _)),
            Err(OriginalDestinationError::UnspecifiedAddress)
        ));
        assert!(matches!(
            parse_sockaddr(sockaddr([1, 2, 3, 4], 0, libc::AF_INET as _)),
            Err(OriginalDestinationError::InvalidPort)
        ));
    }

    #[test]
    fn rejects_incomplete_original_destination_result() {
        assert!(matches!(
            decode_original_destination(
                sockaddr([1, 2, 3, 4], 80, libc::AF_INET as _),
                (size_of::<libc::sockaddr_in>() - 1) as libc::socklen_t,
            ),
            Err(OriginalDestinationError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_missing_kernel_original_destination() {
        let error = io::Error::from_raw_os_error(libc::ENOENT);
        assert!(matches!(
            decode_getsockopt_result(
                -1,
                sockaddr([1, 2, 3, 4], 80, libc::AF_INET as _),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
                error,
            ),
            Err(OriginalDestinationError::Unavailable(_))
        ));
    }
}
