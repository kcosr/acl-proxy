use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::network::canonical_socket_addr;

pub(crate) trait OriginalDestinationResolver: Send + Sync {
    fn resolve(&self, socket: &TcpStream) -> Result<SocketAddr, OriginalDestinationError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemOriginalDestinationResolver;

impl OriginalDestinationResolver for SystemOriginalDestinationResolver {
    fn resolve(&self, socket: &TcpStream) -> Result<SocketAddr, OriginalDestinationError> {
        resolve_system(socket)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalDestinationError {
    #[cfg(not(target_os = "linux"))]
    #[error("original-destination lookup is unsupported on {platform}")]
    UnsupportedPlatform { platform: &'static str },
    #[error("failed to inspect the accepted socket address: {0}")]
    LocalAddress(#[source] io::Error),
    #[error("failed to recover the {family} original destination: {source}")]
    Lookup {
        family: AddressFamily,
        #[source]
        source: io::Error,
    },
    #[error("the {family} original-destination lookup returned a non-IP socket address")]
    NonIpAddress { family: AddressFamily },
    #[error("the recovered original destination has port zero")]
    ZeroPort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        })
    }
}

#[cfg(target_os = "linux")]
fn resolve_system(socket: &TcpStream) -> Result<SocketAddr, OriginalDestinationError> {
    resolve_linux(&LinuxAcceptedSocket(socket))
}

#[cfg(not(target_os = "linux"))]
fn resolve_system(_socket: &TcpStream) -> Result<SocketAddr, OriginalDestinationError> {
    Err(OriginalDestinationError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(target_os = "linux")]
trait OriginalDestinationSocket {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn original_destination_v4(&self) -> io::Result<Option<SocketAddr>>;
    fn original_destination_v6(&self) -> io::Result<Option<SocketAddr>>;
}

#[cfg(target_os = "linux")]
struct LinuxAcceptedSocket<'socket>(&'socket TcpStream);

#[cfg(target_os = "linux")]
impl OriginalDestinationSocket for LinuxAcceptedSocket<'_> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn original_destination_v4(&self) -> io::Result<Option<SocketAddr>> {
        socket2::SockRef::from(self.0)
            .original_dst_v4()
            .map(|address| address.as_socket())
    }

    fn original_destination_v6(&self) -> io::Result<Option<SocketAddr>> {
        socket2::SockRef::from(self.0)
            .original_dst_v6()
            .map(|address| address.as_socket())
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux(
    socket: &impl OriginalDestinationSocket,
) -> Result<SocketAddr, OriginalDestinationError> {
    let family = match socket
        .local_addr()
        .map_err(OriginalDestinationError::LocalAddress)?
    {
        SocketAddr::V4(_) => AddressFamily::Ipv4,
        SocketAddr::V6(_) => AddressFamily::Ipv6,
    };
    let destination = match family {
        AddressFamily::Ipv4 => socket.original_destination_v4(),
        AddressFamily::Ipv6 => socket.original_destination_v6(),
    }
    .map_err(|source| OriginalDestinationError::Lookup { family, source })?
    .ok_or(OriginalDestinationError::NonIpAddress { family })?;
    let destination = canonical_socket_addr(destination);
    if destination.port() == 0 {
        return Err(OriginalDestinationError::ZeroPort);
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedResolver(SocketAddr);

    impl OriginalDestinationResolver for FixedResolver {
        fn resolve(&self, _socket: &TcpStream) -> Result<SocketAddr, OriginalDestinationError> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn resolver_is_injectable_for_accepted_sockets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(address).await.unwrap() });
        let (accepted, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap();
        let resolver: &dyn OriginalDestinationResolver =
            &FixedResolver("192.0.2.10:8443".parse().unwrap());

        assert_eq!(
            resolver.resolve(&accepted).unwrap(),
            "192.0.2.10:8443".parse().unwrap()
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_error_is_explicit() {
        let error = OriginalDestinationError::UnsupportedPlatform {
            platform: "test-os",
        };
        assert_eq!(
            error.to_string(),
            "original-destination lookup is unsupported on test-os"
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::cell::Cell;

        use super::*;

        struct FakeSocket {
            local: io::Result<SocketAddr>,
            ipv4: io::Result<Option<SocketAddr>>,
            ipv6: io::Result<Option<SocketAddr>>,
            ipv4_calls: Cell<usize>,
            ipv6_calls: Cell<usize>,
        }

        impl FakeSocket {
            fn new(local: SocketAddr, destination: SocketAddr) -> Self {
                Self {
                    local: Ok(local),
                    ipv4: Ok(Some(destination)),
                    ipv6: Ok(Some(destination)),
                    ipv4_calls: Cell::new(0),
                    ipv6_calls: Cell::new(0),
                }
            }
        }

        impl OriginalDestinationSocket for FakeSocket {
            fn local_addr(&self) -> io::Result<SocketAddr> {
                self.local
                    .as_ref()
                    .copied()
                    .map_err(|error| io::Error::new(error.kind(), error.to_string()))
            }

            fn original_destination_v4(&self) -> io::Result<Option<SocketAddr>> {
                self.ipv4_calls.set(self.ipv4_calls.get() + 1);
                self.ipv4
                    .as_ref()
                    .copied()
                    .map_err(|error| io::Error::new(error.kind(), error.to_string()))
            }

            fn original_destination_v6(&self) -> io::Result<Option<SocketAddr>> {
                self.ipv6_calls.set(self.ipv6_calls.get() + 1);
                self.ipv6
                    .as_ref()
                    .copied()
                    .map_err(|error| io::Error::new(error.kind(), error.to_string()))
            }
        }

        #[test]
        fn accepted_socket_family_selects_the_kernel_lookup() {
            let ipv4 = FakeSocket::new(
                "127.0.0.1:8888".parse().unwrap(),
                "203.0.113.8:8443".parse().unwrap(),
            );
            assert_eq!(
                resolve_linux(&ipv4).unwrap(),
                "203.0.113.8:8443".parse().unwrap()
            );
            assert_eq!(ipv4.ipv4_calls.get(), 1);
            assert_eq!(ipv4.ipv6_calls.get(), 0);

            let ipv6 = FakeSocket::new(
                "[::1]:8889".parse().unwrap(),
                "[2001:db8::8]:9443".parse().unwrap(),
            );
            assert_eq!(
                resolve_linux(&ipv6).unwrap(),
                "[2001:db8::8]:9443".parse().unwrap()
            );
            assert_eq!(ipv6.ipv4_calls.get(), 0);
            assert_eq!(ipv6.ipv6_calls.get(), 1);
        }

        #[test]
        fn mapped_ipv6_original_destination_is_canonicalized() {
            let socket = FakeSocket::new(
                "[::1]:8889".parse().unwrap(),
                "[::ffff:192.0.2.9]:443".parse().unwrap(),
            );

            assert_eq!(
                resolve_linux(&socket).unwrap(),
                "192.0.2.9:443".parse().unwrap()
            );
        }

        #[test]
        fn lookup_errors_and_invalid_results_fail_closed() {
            let failed = FakeSocket {
                local: Ok("127.0.0.1:8888".parse().unwrap()),
                ipv4: Err(io::Error::from_raw_os_error(libc::ENOPROTOOPT)),
                ipv6: Ok(None),
                ipv4_calls: Cell::new(0),
                ipv6_calls: Cell::new(0),
            };
            assert!(matches!(
                resolve_linux(&failed),
                Err(OriginalDestinationError::Lookup {
                    family: AddressFamily::Ipv4,
                    ..
                })
            ));

            let non_ip = FakeSocket {
                local: Ok("[::1]:8889".parse().unwrap()),
                ipv4: Ok(None),
                ipv6: Ok(None),
                ipv4_calls: Cell::new(0),
                ipv6_calls: Cell::new(0),
            };
            assert!(matches!(
                resolve_linux(&non_ip),
                Err(OriginalDestinationError::NonIpAddress {
                    family: AddressFamily::Ipv6
                })
            ));

            let zero_port = FakeSocket::new(
                "127.0.0.1:8888".parse().unwrap(),
                "192.0.2.9:0".parse().unwrap(),
            );
            assert!(matches!(
                resolve_linux(&zero_port),
                Err(OriginalDestinationError::ZeroPort)
            ));
        }
    }
}
