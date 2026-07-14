use std::sync::{Arc, Mutex};

use crate::config::{CompiledConfig, LoadedCompiledConfig};
use crate::runtime::{GenerationId, Runtime, RuntimeError, StaticOwnership, StaticResources};

use super::listeners::PreparedProxyListeners;
use super::source::FileCandidateSource;
use super::static_resources::{ProductStaticResources, ProductStaticResourcesError};

/// Staged ownership for one product runtime.
///
/// Preparation reserves every configured ingress socket, but deliberately does
/// not assert that proxy supervisors are serving them. Initial publication and
/// ingress confirmation remain separate gates so neither ordering can expose a
/// prematurely ready process.
pub(crate) struct ProductRuntime {
    runtime: Arc<Runtime>,
    static_resources: Arc<ProductStaticResources>,
    initial: Mutex<Option<CompiledConfig>>,
}

impl ProductRuntime {
    pub(crate) async fn prepare(
        loaded: LoadedCompiledConfig,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        let LoadedCompiledConfig { metadata, compiled } = loaded;
        let static_resources = ProductStaticResources::try_new(&compiled.static_config)?;

        if let Err(error) = static_resources.prepare_ingress() {
            StaticResources::shutdown(static_resources.as_ref()).await;
            return Err(error.into());
        }

        let source = Arc::new(FileCandidateSource::new(&metadata));
        let activator = static_resources.activator();
        let static_ownership = StaticOwnership::new(
            compiled.static_config.clone(),
            compiled.static_fingerprint.clone(),
            static_resources.clone(),
        );
        let runtime = Runtime::new(static_ownership, source, activator).await?;

        Ok(Arc::new(Self {
            runtime,
            static_resources,
            initial: Mutex::new(Some(compiled)),
        }))
    }

    pub(crate) fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Transfers the atomically prepared proxy socket bundle to the future
    /// synchronous supervisor-start path. That path must retain joined
    /// supervisor ownership before it confirms ingress startup.
    pub(super) fn take_prepared_proxy_listeners_for_supervisor_start(
        &self,
    ) -> Result<PreparedProxyListeners, ProductRuntimeError> {
        self.static_resources
            .take_prepared_proxy_listeners_for_supervisor_start()
            .map_err(Into::into)
    }

    pub(crate) async fn activate_initial(&self) -> Result<GenerationId, ProductRuntimeError> {
        let initial = self
            .initial
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(ProductRuntimeError::InitialActivationAlreadyAttempted)?;
        let runtime = self.runtime.clone();
        let activation_runtime = runtime.clone();

        let activation = tokio::spawn(async move {
            match activation_runtime.start(initial).await {
                Ok(generation) => Ok(generation),
                Err(error) => {
                    activation_runtime.shutdown().await;
                    Err(error)
                }
            }
        });

        match activation.await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => {
                runtime.shutdown().await;
                Err(ProductRuntimeError::InitialActivationCoordinator)
            }
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    #[cfg(test)]
    fn confirm_ingress_started_for_test(&self) {
        StaticResources::readiness(self.static_resources.as_ref()).mark_ingress_started();
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductRuntimeError {
    #[error(transparent)]
    StaticResources(#[from] ProductStaticResourcesError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error("initial activation has already been attempted")]
    InitialActivationAlreadyAttempted,
    #[error("initial activation coordinator did not complete")]
    InitialActivationCoordinator,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;
    use crate::config::load_and_compile_exact_config;

    static LISTENER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn available_addresses<const N: usize>() -> [SocketAddr; N] {
        let listeners: Vec<_> = (0..N)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect();
        let addresses = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        drop(listeners);
        addresses
    }

    fn config(explicit_http: SocketAddr, control: SocketAddr, extra: &str) -> String {
        format!(
            r#"schema_version = 3

[service]
shutdown_drain_timeout = "1s"

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 2
max_request_body_bytes = 65536

[listeners.explicit_http]
bind = "{explicit_http}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

{extra}
"#
        )
    }

    fn loaded(text: &str) -> (tempfile::TempDir, LoadedCompiledConfig) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, text).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        (directory, loaded)
    }

    fn assert_bindable(addresses: impl IntoIterator<Item = SocketAddr>) {
        for address in addresses {
            TcpListener::bind(address)
                .unwrap_or_else(|error| panic!("expected {address} to be released: {error}"));
        }
    }

    #[tokio::test]
    async fn publication_before_ingress_confirmation_stays_not_ready() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<2>();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare(loaded).await.unwrap();

        assert!(!product.runtime().is_ready());
        for address in addresses {
            assert!(TcpListener::bind(address).is_err());
        }
        product.activate_initial().await.unwrap();
        assert!(!product.runtime().is_ready());

        product.confirm_ingress_started_for_test();
        assert!(product.runtime().is_ready());

        product.shutdown().await;
        assert_bindable(addresses);
    }

    #[tokio::test]
    async fn ingress_confirmation_before_publication_stays_not_ready() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<2>();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare(loaded).await.unwrap();

        product.confirm_ingress_started_for_test();
        assert!(!product.runtime().is_ready());

        product.activate_initial().await.unwrap();
        assert!(product.runtime().is_ready());

        product.shutdown().await;
        assert_bindable(addresses);
    }

    #[tokio::test]
    async fn failed_initial_activation_joins_shutdown_and_releases_every_socket() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<2>();
        let missing_variable = "ACL_PROXY_RUNNER_TEST_MISSING_REDACTION_LITERAL";
        std::env::remove_var(missing_variable);
        let extra = format!(
            r#"[redaction.profiles.secrets]
rules = [{{ literal_environment_variables = ["{missing_variable}"] }}]
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare(loaded).await.unwrap();

        let result = product.activate_initial().await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::Runtime(
                RuntimeError::CandidateActivation(_)
            ))
        ));
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Stopped
        );
        assert!(!product.runtime().is_ready());
        assert_bindable(addresses);
    }

    #[tokio::test]
    async fn later_prebind_failure_releases_earlier_proxy_and_control_sockets() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<2>();
        let blocker = TcpListener::bind(addresses[1]).unwrap();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));

        let result = ProductRuntime::prepare(loaded).await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::StaticResources(
                ProductStaticResourcesError::Control(_)
            ))
        ));
        assert_bindable([addresses[0]]);
        drop(blocker);
        assert_bindable([addresses[1]]);
    }

    #[test]
    fn runner_module_and_api_names_are_versionless() {
        assert_eq!(Path::new(file!()).file_name().unwrap(), "runner.rs");
        assert!(!std::any::type_name::<ProductRuntime>().contains("V3"));
    }
}
