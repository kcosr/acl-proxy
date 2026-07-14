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
    use std::net::{SocketAddr, TcpListener};

    let mut listeners = Vec::with_capacity(N);
    for _ in 0..N {
        listeners.push(
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 2], 0)))
                .expect("reserve listener fixture address"),
        );
    }

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
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    const RELEASE_TIMEOUT: Duration = Duration::from_millis(250);
    const RETRY_DELAY: Duration = Duration::from_millis(1);

    for address in addresses {
        let deadline = Instant::now() + RELEASE_TIMEOUT;
        loop {
            match TcpListener::bind(address) {
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::AddrInUse && Instant::now() < deadline => {
                    std::thread::yield_now();
                    std::thread::sleep(RETRY_DELAY);
                }
                Err(error) => panic!("expected {address} to be released: {error}"),
            }
        }
    }
}
