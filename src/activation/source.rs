use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::config::{load_and_compile_exact_config, ConfigFileMetadata};
use crate::runtime::{ActivationCancellation, BoxFuture, CandidateSource, RuntimeError};

/// Reloads the exact configuration file selected during process startup.
///
/// File reads and strict configuration compilation are bounded and side-effect free. They
/// run off the async executor, while cancellation checks bracket the complete
/// blocking operation so a cancelled result can never enter activation.
pub(crate) struct FileCandidateSource {
    path: PathBuf,
    #[cfg(test)]
    blocking_spawned: Option<std::sync::Arc<tokio::sync::Notify>>,
}

#[derive(Clone, Copy)]
enum BlockingLoadState {
    Queued,
    Running,
    Cancelled,
}

impl FileCandidateSource {
    pub(crate) fn new(metadata: &ConfigFileMetadata) -> Self {
        Self {
            path: metadata.path.clone(),
            #[cfg(test)]
            blocking_spawned: None,
        }
    }

    #[cfg(test)]
    fn with_blocking_spawn_observer(
        metadata: &ConfigFileMetadata,
        blocking_spawned: std::sync::Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            path: metadata.path.clone(),
            blocking_spawned: Some(blocking_spawned),
        }
    }
}

impl CandidateSource for FileCandidateSource {
    fn load_latest(
        &self,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<crate::config::RuntimeCandidate, RuntimeError>> {
        let path = self.path.clone();
        Box::pin(async move {
            cancellation.check()?;
            let load_state = Arc::new(Mutex::new(BlockingLoadState::Queued));
            let worker_state = load_state.clone();
            let load = tokio::task::spawn_blocking(move || {
                let mut state = worker_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if matches!(*state, BlockingLoadState::Cancelled) {
                    return None;
                }
                *state = BlockingLoadState::Running;
                drop(state);
                Some(load_and_compile_exact_config(path.as_path()))
            });
            #[cfg(test)]
            if let Some(blocking_spawned) = &self.blocking_spawned {
                blocking_spawned.notify_one();
            }
            tokio::pin!(load);
            let loaded = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    let running = {
                        let mut state = load_state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        match *state {
                            BlockingLoadState::Queued => {
                                *state = BlockingLoadState::Cancelled;
                                false
                            }
                            BlockingLoadState::Running => true,
                            BlockingLoadState::Cancelled => false,
                        }
                    };
                    load.abort();
                    if running {
                        let _ = load.await;
                    }
                    return Err(RuntimeError::ActivationCancelled);
                }
                result = &mut load => result
                    .map_err(|_| RuntimeError::CandidateSource(
                        "configuration reload worker did not complete".to_string(),
                    ))?
                    .ok_or(RuntimeError::ActivationCancelled)?
                    .map_err(|error| RuntimeError::CandidateSource(error.to_string()))?,
            };
            cancellation.check()?;
            Ok(loaded.compiled.into_runtime_candidate())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;
    use crate::config::load_and_compile_config;

    const MINIMAL: &str = r#"schema_version = 4

[service]
request_timeout = "30s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;

    #[tokio::test]
    async fn reload_reads_the_exact_startup_path_and_returns_strict_compiler_output() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, MINIMAL).unwrap();
        let initial = load_and_compile_config(Some(&path)).unwrap();
        let source = FileCandidateSource::new(&initial.metadata);
        fs::write(&path, MINIMAL.replace("30s", "17s")).unwrap();

        let reloaded = source
            .load_latest(ActivationCancellation::new_for_test())
            .await
            .unwrap();

        assert_eq!(
            reloaded.reloadable_plan.request_timeout,
            Duration::from_secs(17)
        );
        assert_eq!(reloaded.static_config.config_root, directory.path());
        assert_eq!(reloaded.static_config.schema_version, 4);
    }

    #[tokio::test]
    async fn pre_cancelled_reload_never_observes_the_file_system() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, MINIMAL).unwrap();
        let initial = load_and_compile_config(Some(&path)).unwrap();
        let source = FileCandidateSource::new(&initial.metadata);
        fs::remove_file(path).unwrap();
        let cancellation = ActivationCancellation::new_for_test();
        cancellation.cancel_for_test();

        let result = source.load_latest(cancellation).await;

        assert!(matches!(result, Err(RuntimeError::ActivationCancelled)));
    }

    #[tokio::test]
    async fn load_and_compile_errors_are_sanitized_into_candidate_source_failure() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, MINIMAL).unwrap();
        let initial = load_and_compile_config(Some(&path)).unwrap();
        let source = FileCandidateSource::new(&initial.metadata);
        fs::write(&path, "schema_version = 2\nsecret = \"do-not-echo\"\n").unwrap();

        let error = match source
            .load_latest(ActivationCancellation::new_for_test())
            .await
        {
            Ok(_) => panic!("invalid reload unexpectedly compiled"),
            Err(error) => error,
        };

        assert!(matches!(error, RuntimeError::CandidateSource(_)));
        assert!(!error.to_string().contains("do-not-echo"));
    }

    #[test]
    fn cancellation_removes_a_queued_blocking_reload_before_shutdown_waits() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, MINIMAL).unwrap();
        let initial = load_and_compile_config(Some(&path)).unwrap();
        let blocking_spawned = std::sync::Arc::new(tokio::sync::Notify::new());
        let source = std::sync::Arc::new(FileCandidateSource::with_blocking_spawn_observer(
            &initial.metadata,
            blocking_spawned.clone(),
        ));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async move {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.blocking_recv();
            });
            entered_rx.await.unwrap();

            let cancellation = ActivationCancellation::new_for_test();
            let reload_cancellation = cancellation.clone();
            let reload = tokio::spawn(async move { source.load_latest(reload_cancellation).await });
            blocking_spawned.notified().await;
            cancellation.cancel_for_test();

            let result = tokio::time::timeout(Duration::from_secs(1), reload)
                .await
                .expect("queued blocking reload is removed on cancellation")
                .unwrap();
            assert!(matches!(result, Err(RuntimeError::ActivationCancelled)));
            let _ = release_tx.send(());
            blocker.await.unwrap();
        });
    }
}
