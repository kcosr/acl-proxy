use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use super::facade::CompiledConfig;
use crate::runtime::ActivationCancellation;
use crate::tls::TlsActivationError;
use crate::tls_io_runtime::{TlsIoRuntime, TlsTrustPreflightFailure};

pub(crate) struct TlsTrustSourceSpec {
    scope: String,
    authored: PathBuf,
    resolved: PathBuf,
}

impl TlsTrustSourceSpec {
    pub(crate) fn new(scope: String, authored: PathBuf, resolved: PathBuf) -> Self {
        Self {
            scope,
            authored,
            resolved,
        }
    }
}

pub(crate) struct TlsTrustSourcePreflightError {
    scope: String,
    authored: Option<PathBuf>,
    category: &'static str,
}

impl fmt::Display for TlsTrustSourcePreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "TLS trust source preflight failed at {}",
            self.scope
        )?;
        if let Some(authored) = &self.authored {
            write!(formatter, " (ca_certificate = {authored:?})")?;
        }
        write!(formatter, ": {}", self.category)
    }
}

impl fmt::Debug for TlsTrustSourcePreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TlsTrustSourcePreflightError")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl std::error::Error for TlsTrustSourcePreflightError {}

pub(crate) async fn validate_tls_trust_sources(
    compiled: &CompiledConfig,
    runtime: Arc<TlsIoRuntime>,
    cancellation: &ActivationCancellation,
) -> Result<(), TlsTrustSourcePreflightError> {
    let mut seen = std::collections::BTreeSet::new();
    let source_indices = compiled
        .tls_trust_sources
        .iter()
        .enumerate()
        .filter_map(|(index, source)| seen.insert(source.resolved.clone()).then_some(index))
        .collect::<Vec<_>>();
    runtime
        .preflight_custom_sources(
            source_indices
                .iter()
                .map(|index| compiled.tls_trust_sources[*index].resolved.clone())
                .collect(),
            cancellation,
        )
        .await
        .map_err(|failure| map_failure(&compiled.tls_trust_sources, &source_indices, failure))
}

fn map_failure(
    sources: &[TlsTrustSourceSpec],
    source_indices: &[usize],
    failure: TlsTrustPreflightFailure,
) -> TlsTrustSourcePreflightError {
    let source = failure
        .source_index()
        .and_then(|index| source_indices.get(index))
        .and_then(|index| sources.get(*index));
    TlsTrustSourcePreflightError {
        scope: source.map_or_else(
            || "tls_trust_sources".to_owned(),
            |source| source.scope.clone(),
        ),
        authored: source.map(|source| source.authored.clone()),
        category: category(failure.error()),
    }
}

fn category(error: TlsActivationError) -> &'static str {
    match error {
        TlsActivationError::UntrustedSource => "tls_trust_source_custody",
        TlsActivationError::InvalidMaterial => "tls_trust_material_invalid",
        TlsActivationError::ResourceLimit => "tls_trust_resource_limit",
        TlsActivationError::TrustGenerationLimit => "tls_trust_generation_limit",
        TlsActivationError::InvalidPlan => "tls_trust_source_invalid",
        TlsActivationError::ActivationCancelled => "tls_trust_preflight_cancelled",
        TlsActivationError::ReloadBlocked => "tls_trust_reload_blocked",
        TlsActivationError::LoaderUnavailable
        | TlsActivationError::SystemStoreEmpty
        | TlsActivationError::SystemStoreUnavailable
        | TlsActivationError::Internal => "tls_trust_preflight_unavailable",
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;
    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::test_certificates::TestTlsIdentity;

    fn secure_tempdir() -> TempDir {
        let base = PathBuf::from(std::env::var_os("HOME").expect("HOME is set"))
            .join(".cache/acl-proxy-test-fixtures");
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("tls-preflight-")
            .tempdir_in(base)
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn compile_with_ca(directory: &Path, authored: &Path) -> CompiledConfig {
        let source = directory.join("acl-proxy.toml");
        let text = format!(
            r#"
schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[egress.origin_tls]
trust = "custom"
ca_certificate = "{}"

[policy]
default = "deny"
"#,
            authored.display()
        );
        compile_config_text(ConfigTextInput {
            text: &text,
            source_path: &source,
            config_root: directory,
        })
        .unwrap()
    }

    fn assert_custody_failure(compiled: &CompiledConfig, authored: &Path) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let message =
            runtime.block_on(async { validate_for_test(compiled).await.unwrap_err().to_string() });
        assert!(message.contains("egress.origin_tls.ca_certificate"));
        assert!(message.contains(&format!("{authored:?}")));
        assert!(message.contains("tls_trust_source_custody"));
    }

    async fn validate_for_test(
        compiled: &CompiledConfig,
    ) -> Result<(), TlsTrustSourcePreflightError> {
        let runtime = TlsIoRuntime::new().unwrap();
        let result = validate_tls_trust_sources(
            compiled,
            Arc::clone(&runtime),
            &ActivationCancellation::new_for_test(),
        )
        .await;
        runtime.shutdown_and_wait(None).await;
        result
    }

    #[tokio::test]
    async fn preflight_accepts_valid_custom_trust_material() {
        let directory = secure_tempdir();
        let ca = directory.path().join("ca.pem");
        crate::filesystem::write_public_file(
            &ca,
            TestTlsIdentity::new("preflight.test").root_certificate_pem(),
        )
        .unwrap();
        validate_for_test(&compile_with_ca(directory.path(), &ca))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn shared_origin_parent_and_webhook_source_is_acquired_once() {
        let directory = secure_tempdir();
        let ca = directory.path().join("ca.pem");
        crate::filesystem::write_public_file(
            &ca,
            TestTlsIdentity::new("shared-preflight.test").root_certificate_pem(),
        )
        .unwrap();
        let source_path = directory.path().join("acl-proxy.toml");
        let text = format!(
            r#"
schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[egress]
route = "parent_proxy"

[egress.origin_tls]
trust = "custom"
ca_certificate = "{ca}"

[egress.parent_proxy]
kind = "generic"
url = "https://parent.example.test:8443"

[egress.parent_proxy.tls]
trust = "custom"
ca_certificate = "{ca}"

[authorization.providers.shared]
kind = "webhook"
url = "https://authorization.example.test/check"

[authorization.providers.shared.tls]
trust = "custom"
ca_certificate = "{ca}"

[policy]
default = "deny"
"#,
            ca = ca.display()
        );
        let compiled = compile_config_text(ConfigTextInput {
            text: &text,
            source_path: &source_path,
            config_root: directory.path(),
        })
        .unwrap();
        let runtime = TlsIoRuntime::new().unwrap();
        validate_tls_trust_sources(
            &compiled,
            Arc::clone(&runtime),
            &ActivationCancellation::new_for_test(),
        )
        .await
        .unwrap();
        assert_eq!(runtime.custom_acquisitions_for_test(), 1);
        runtime.shutdown_and_wait(None).await;
    }

    #[test]
    fn preflight_rejects_symlink_group_writable_and_hard_link_sources() {
        let directory = secure_tempdir();
        let certificate = TestTlsIdentity::new("preflight.test").root_certificate_pem();

        let target = directory.path().join("target.pem");
        crate::filesystem::write_public_file(&target, certificate.clone()).unwrap();
        let link = directory.path().join("link.pem");
        symlink(&target, &link).unwrap();
        assert_custody_failure(&compile_with_ca(directory.path(), &link), &link);

        let writable = directory.path().join("writable.pem");
        crate::filesystem::write_public_file(&writable, certificate).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o660)).unwrap();
        assert_custody_failure(&compile_with_ca(directory.path(), &writable), &writable);

        let hardlink = directory.path().join("hardlink.pem");
        fs::hard_link(&target, &hardlink).unwrap();
        assert_custody_failure(&compile_with_ca(directory.path(), &hardlink), &hardlink);
    }

    #[test]
    fn preflight_rejects_nonregular_source_without_blocking() {
        let directory = secure_tempdir();
        let fifo = directory.path().join("ca.fifo");
        let encoded = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        assert_custody_failure(&compile_with_ca(directory.path(), &fifo), &fifo);
    }

    #[tokio::test]
    async fn diagnostic_preserves_relative_authored_value() {
        let directory = secure_tempdir();
        let authored = Path::new("missing.pem");
        let message = validate_for_test(&compile_with_ca(directory.path(), authored))
            .await
            .unwrap_err()
            .to_string();
        assert!(message.contains("ca_certificate = \"missing.pem\""));
        assert!(!message.contains(directory.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn global_preflight_failures_do_not_name_an_unattributed_ca_source() {
        let directory = secure_tempdir();
        let authored = Path::new("sensitive-ca.pem");
        let compiled = compile_with_ca(directory.path(), authored);
        let source_indices = vec![0];

        for failure in [
            TlsActivationError::ReloadBlocked,
            TlsActivationError::TrustGenerationLimit,
        ] {
            let message = map_failure(
                &compiled.tls_trust_sources,
                &source_indices,
                TlsTrustPreflightFailure::new_for_test(None, failure),
            )
            .to_string();
            assert!(message.contains("at tls_trust_sources:"));
            assert!(!message.contains("ca_certificate"));
            assert!(!message.contains("sensitive-ca.pem"));
        }
    }
}
