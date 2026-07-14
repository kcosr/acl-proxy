use std::path::PathBuf;

use crate::config::{load_and_compile_config, ConfigFileMetadata};
use crate::runtime::{ActivationCancellation, BoxFuture, CandidateSource, RuntimeError};

/// Reloads the exact configuration file selected during process startup.
///
/// File reads and strict-v3 compilation are bounded and side-effect free. They
/// run off the async executor, while cancellation checks bracket the complete
/// blocking operation so a cancelled result can never enter activation.
pub(crate) struct FileCandidateSource {
    path: PathBuf,
}

impl FileCandidateSource {
    pub(crate) fn new(metadata: &ConfigFileMetadata) -> Self {
        Self {
            path: metadata.path.clone(),
        }
    }
}

impl CandidateSource for FileCandidateSource {
    fn load_latest(
        &self,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<crate::config::CompiledConfig, RuntimeError>> {
        let path = self.path.clone();
        Box::pin(async move {
            cancellation.check()?;
            let loaded =
                tokio::task::spawn_blocking(move || load_and_compile_config(Some(path.as_path())))
                    .await
                    .map_err(|_| {
                        RuntimeError::CandidateSource(
                            "configuration reload worker did not complete".to_string(),
                        )
                    })?
                    .map_err(|error| RuntimeError::CandidateSource(error.to_string()))?;
            cancellation.check()?;
            Ok(loaded.compiled)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;

    const MINIMAL: &str = r#"schema_version = 3

[service]
request_timeout = "30s"

[listeners.explicit_http]
bind = "127.0.0.1:8881"
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
        assert_eq!(reloaded.static_config.schema_version, 3);
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

        let error = source
            .load_latest(ActivationCancellation::new_for_test())
            .await
            .unwrap_err();

        assert!(matches!(error, RuntimeError::CandidateSource(_)));
        assert!(!error.to_string().contains("do-not-echo"));
    }
}
