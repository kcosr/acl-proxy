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
