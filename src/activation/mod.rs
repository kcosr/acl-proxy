pub(crate) mod assets;
pub(crate) mod listeners;
pub(crate) mod owner;
pub(crate) mod product;
pub(crate) mod runner;
pub(crate) mod source;
pub(crate) mod static_resources;

#[cfg(test)]
pub(super) static LISTENER_TEST_LOCK: ListenerTestLock = ListenerTestLock::new();

#[cfg(test)]
pub(super) struct ListenerTestLock(tokio::sync::Mutex<()>);

#[cfg(test)]
impl ListenerTestLock {
    const fn new() -> Self {
        Self(tokio::sync::Mutex::const_new(()))
    }

    pub(super) async fn lock(&self) -> ListenerTestGuard<'_> {
        let process_guard = self.0.lock().await;
        let file = tokio::task::spawn_blocking(|| {
            use fs2::FileExt;
            use std::fs::OpenOptions;

            #[cfg(unix)]
            let lock_name = format!("acl-proxy-listener-tests-{}.lock", unsafe {
                libc::geteuid()
            });
            #[cfg(not(unix))]
            let lock_name = "acl-proxy-listener-tests.lock".to_string();

            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(std::env::temp_dir().join(lock_name))
                .expect("open listener test lock file");
            file.lock_exclusive()
                .expect("acquire listener test file lock");
            file
        })
        .await
        .expect("listener test file-lock task completed");

        ListenerTestGuard {
            _process_guard: process_guard,
            _file: file,
        }
    }
}

#[cfg(test)]
pub(super) struct ListenerTestGuard<'a> {
    _process_guard: tokio::sync::MutexGuard<'a, ()>,
    _file: std::fs::File,
}

#[cfg(test)]
pub(super) struct ListenerReservations<const N: usize> {
    listeners: [std::net::TcpListener; N],
}

#[cfg(test)]
impl<const N: usize> ListenerReservations<N> {
    pub(super) fn addresses(&self) -> [std::net::SocketAddr; N] {
        std::array::from_fn(|index| {
            self.listeners[index]
                .local_addr()
                .expect("fixture listener has an address")
        })
    }

    pub(super) fn into_listeners(self) -> Vec<std::net::TcpListener> {
        self.listeners.into_iter().collect()
    }

    pub(super) fn into_binder(
        self,
    ) -> impl FnMut(std::net::SocketAddr) -> std::io::Result<std::net::TcpListener> {
        let mut listeners = self
            .listeners
            .into_iter()
            .map(|listener| {
                let address = listener
                    .local_addr()
                    .expect("fixture listener has an address");
                (address, listener)
            })
            .collect::<std::collections::HashMap<_, _>>();
        move |address| {
            listeners.remove(&address).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("no fixture listener reserved for {address}"),
                )
            })
        }
    }
}

#[cfg(test)]
pub(super) fn reserve_listeners<const N: usize>(
    _guard: &ListenerTestGuard<'_>,
) -> ListenerReservations<N> {
    use std::io::ErrorKind;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Stay below the default ephemeral range so unrelated outbound sockets
    // cannot claim a fixture port between reservation and product binding.
    const PORT_START: usize = 30_000;
    const PORT_END: usize = 31_000;
    const PORT_COUNT: usize = PORT_END - PORT_START;
    static NEXT_PORT: AtomicUsize = AtomicUsize::new(0);

    assert!(
        N <= PORT_COUNT,
        "listener fixture request exceeds port range"
    );

    let mut listeners = Vec::with_capacity(N);
    for _ in 0..PORT_COUNT {
        let offset = NEXT_PORT.fetch_add(1, Ordering::Relaxed) % PORT_COUNT;
        let address = SocketAddr::from(([127, 0, 0, 2], (PORT_START + offset) as u16));
        match TcpListener::bind(address) {
            Ok(listener) => listeners.push(listener),
            Err(error) if error.kind() == ErrorKind::AddrInUse => continue,
            Err(error) => panic!("reserve listener fixture address {address}: {error}"),
        }
        if listeners.len() == N {
            break;
        }
    }

    assert_eq!(listeners.len(), N, "listener fixture port range exhausted");
    let listeners = listeners
        .try_into()
        .expect("fixture listener count matches requested array");
    ListenerReservations { listeners }
}

#[cfg(test)]
pub(super) fn assert_listener_addresses_released(
    _guard: &ListenerTestGuard<'_>,
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) {
    use std::net::TcpListener;

    for address in addresses {
        TcpListener::bind(address)
            .unwrap_or_else(|error| panic!("expected {address} to be released: {error}"));
    }
}
