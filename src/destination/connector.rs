use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::net::TcpStream;

pub(crate) type ConnectFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

pub(crate) trait DestinationConnector: Send + Sync {
    type Stream: Send;

    fn connect(&self, endpoint: SocketAddr) -> ConnectFuture<'_, Self::Stream>;
    fn peer_addr(&self, stream: &Self::Stream) -> io::Result<SocketAddr>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpDestinationConnector;

impl DestinationConnector for TcpDestinationConnector {
    type Stream = TcpStream;

    fn connect(&self, endpoint: SocketAddr) -> ConnectFuture<'_, Self::Stream> {
        Box::pin(TcpStream::connect(endpoint))
    }

    fn peer_addr(&self, stream: &Self::Stream) -> io::Result<SocketAddr> {
        stream.peer_addr()
    }
}
