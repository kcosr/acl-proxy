use std::sync::Arc;
use std::time::Duration;

use http::HeaderName;
use http_access_types::{CanonicalUrl, HttpScheme, PolicyGeneration};
use rustls::ClientConfig;

use crate::authorization::protocol::ProviderOutputRegistry;
use crate::config::compiler::{
    CompiledProviderFailureMode, CompiledTlsTrust, WebhookProviderPlan, WebhookTlsPlan,
};
use crate::tls::{build_client_config, load_client_trust, ClientAlpn, TlsActivationError};

pub(crate) struct WebhookProvider {
    url: CanonicalUrl,
    timeout: Duration,
    failure_mode: CompiledProviderFailureMode,
    include_headers: Box<[HeaderName]>,
    max_request_bytes: usize,
    max_response_bytes: usize,
    outputs: ProviderOutputRegistry,
    tls: Option<Arc<ClientConfig>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookActivationError {
    #[error("webhook TLS activation failed")]
    Tls(#[source] TlsActivationError),
    #[error("webhook activation was cancelled")]
    Cancelled,
}

impl WebhookProvider {
    pub(crate) fn activate(
        plan: WebhookProviderPlan,
        generation: PolicyGeneration,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Arc<Self>, WebhookActivationError> {
        if is_cancelled() {
            return Err(WebhookActivationError::Cancelled);
        }
        let url = plan.url;
        let tls = if url.scheme() == HttpScheme::Https {
            let WebhookTlsPlan {
                trust,
                ca_certificate,
            } = plan.tls.unwrap_or(WebhookTlsPlan {
                trust: CompiledTlsTrust::System,
                ca_certificate: None,
            });
            if trust == CompiledTlsTrust::Insecure {
                tracing::warn!("webhook TLS certificate verification is disabled");
            }
            let trust = load_client_trust(
                trust,
                ca_certificate.as_deref(),
                generation,
                &mut is_cancelled,
            )
            .map_err(|error| {
                if error == TlsActivationError::ActivationCancelled {
                    WebhookActivationError::Cancelled
                } else {
                    WebhookActivationError::Tls(error)
                }
            })?;
            Some(Arc::new(
                build_client_config(&trust, ClientAlpn::Http1, true)
                    .map_err(WebhookActivationError::Tls)?,
            ))
        } else {
            debug_assert!(plan.tls.is_none(), "HTTP webhook TLS was compile-rejected");
            None
        };
        if is_cancelled() {
            return Err(WebhookActivationError::Cancelled);
        }

        Ok(Arc::new(Self {
            url,
            timeout: plan.timeout,
            failure_mode: plan.on_failure,
            include_headers: plan.include_headers.into_boxed_slice(),
            max_request_bytes: plan.max_request_bytes,
            max_response_bytes: plan.max_response_bytes,
            outputs: ProviderOutputRegistry::activate(plan.outputs),
            tls,
        }))
    }

    pub(crate) fn url(&self) -> &CanonicalUrl {
        &self.url
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn failure_mode(&self) -> CompiledProviderFailureMode {
        self.failure_mode
    }

    pub(crate) fn include_headers(&self) -> &[HeaderName] {
        &self.include_headers
    }

    pub(crate) fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    pub(crate) fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub(crate) fn outputs(&self) -> &ProviderOutputRegistry {
        &self.outputs
    }

    pub(crate) fn tls(&self) -> Option<Arc<ClientConfig>> {
        self.tls.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use http_access_url::canonicalize_http_url;

    use super::*;

    fn plan(url: &str, tls: Option<WebhookTlsPlan>) -> WebhookProviderPlan {
        WebhookProviderPlan {
            url: canonicalize_http_url(url).unwrap(),
            timeout: Duration::from_secs(3),
            on_failure: CompiledProviderFailureMode::Deny,
            include_headers: vec![HeaderName::from_static("x-context")],
            max_request_bytes: 8192,
            max_response_bytes: 4096,
            outputs: BTreeMap::new(),
            tls,
        }
    }

    #[test]
    fn http_provider_activation_is_typed_and_has_no_tls_client() {
        let provider = WebhookProvider::activate(
            plan("http://localhost:8080/a/../authorize?mode=one", None),
            PolicyGeneration::new(7).unwrap(),
            || false,
        )
        .unwrap();
        assert_eq!(
            provider.url().as_str(),
            "http://localhost:8080/authorize?mode=one"
        );
        assert_eq!(provider.timeout(), Duration::from_secs(3));
        assert_eq!(provider.include_headers(), ["x-context"]);
        assert!(provider.tls().is_none());
    }

    #[test]
    fn https_provider_uses_exact_http1_tls_policy_and_honors_cancellation() {
        let provider = WebhookProvider::activate(
            plan(
                "https://provider.test/authorize",
                Some(WebhookTlsPlan {
                    trust: CompiledTlsTrust::Insecure,
                    ca_certificate: None,
                }),
            ),
            PolicyGeneration::new(7).unwrap(),
            || false,
        )
        .unwrap();
        assert_eq!(
            provider.tls().unwrap().alpn_protocols,
            [b"http/1.1".to_vec()]
        );
        assert!(matches!(
            WebhookProvider::activate(
                plan(
                    "https://provider.test/authorize",
                    Some(WebhookTlsPlan {
                        trust: CompiledTlsTrust::Custom,
                        ca_certificate: Some(PathBuf::from("unused.pem")),
                    }),
                ),
                PolicyGeneration::new(7).unwrap(),
                || true,
            ),
            Err(WebhookActivationError::Cancelled)
        ));
    }
}
