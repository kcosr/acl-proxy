use std::net::SocketAddr;

use thiserror::Error;

pub const IPV4_STREAM_HEADER_LEN: usize = 28;
const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EncodeError {
    #[error("PROXY v2 source and destination must both be IPv4")]
    UnsupportedAddressFamily,
    #[error("PROXY v2 source and destination ports must be nonzero")]
    InvalidPort,
}

pub fn encode_ipv4_stream(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<[u8; IPV4_STREAM_HEADER_LEN], EncodeError> {
    let (source, destination) = match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => (source, destination),
        _ => return Err(EncodeError::UnsupportedAddressFamily),
    };
    if source.port() == 0 || destination.port() == 0 {
        return Err(EncodeError::InvalidPort);
    }

    let mut header = [0_u8; IPV4_STREAM_HEADER_LEN];
    header[..12].copy_from_slice(&SIGNATURE);
    header[12] = 0x21; // version 2, PROXY command
    header[13] = 0x11; // IPv4, STREAM transport
    header[14..16].copy_from_slice(&12_u16.to_be_bytes());
    header[16..20].copy_from_slice(&source.ip().octets());
    header[20..24].copy_from_slice(&destination.ip().octets());
    header[24..26].copy_from_slice(&source.port().to_be_bytes());
    header[26..28].copy_from_slice(&destination.port().to_be_bytes());
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_exact_proxy_v2_ipv4_stream_header() {
        let header = encode_ipv4_stream(
            "192.0.2.4:4660".parse().unwrap(),
            "203.0.113.7:443".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            header,
            [
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
                0x00, 0x0c, 192, 0, 2, 4, 203, 0, 113, 7, 0x12, 0x34, 0x01, 0xbb,
            ]
        );
    }

    #[test]
    fn rejects_ipv6_and_zero_ports() {
        assert_eq!(
            encode_ipv4_stream("[::1]:1000".parse().unwrap(), "1.2.3.4:80".parse().unwrap()),
            Err(EncodeError::UnsupportedAddressFamily)
        );
        assert_eq!(
            encode_ipv4_stream(
                "127.0.0.1:0".parse().unwrap(),
                "1.2.3.4:80".parse().unwrap()
            ),
            Err(EncodeError::InvalidPort)
        );
    }
}
