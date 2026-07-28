use std::sync::Arc;
use std::time::Duration;

use http::HeaderName;
#[cfg(test)]
use http_access_types::PolicyGeneration;
use http_access_types::{CanonicalUrl, HttpScheme};
use rustls::ClientConfig;

use crate::authorization::protocol::ProviderOutputRegistry;
use crate::candidate_tls::CandidateTlsResolver;
use crate::config::compiler::{
    CompiledProviderFailureMode, TlsClientTrustMode, WebhookProviderPlan, WebhookTlsPlan,
};
use crate::tls::{build_client_config, ClientAlpn, TlsActivationError};

pub(crate) struct WebhookProvider {
    url: CanonicalUrl,
    timeout: Duration,
    failure_mode: CompiledProviderFailureMode,
    include_headers: Box<[HeaderName]>,
    include_identity: bool,
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
    pub(crate) async fn activate(
        plan: WebhookProviderPlan,
        tls_resolver: &mut CandidateTlsResolver,
    ) -> Result<Arc<Self>, WebhookActivationError> {
        if tls_resolver.cancellation().is_cancelled() {
            return Err(WebhookActivationError::Cancelled);
        }
        let url = plan.url;
        let tls = if url.scheme() == HttpScheme::Https {
            let WebhookTlsPlan {
                trust,
                ca_certificate,
            } = plan.tls.unwrap_or(WebhookTlsPlan {
                trust: TlsClientTrustMode::System,
                ca_certificate: None,
            });
            if trust == TlsClientTrustMode::Insecure {
                tracing::warn!("webhook TLS certificate verification is disabled");
            }
            let prepared = tls_resolver
                .prepared(trust, ca_certificate.as_deref())
                .map_err(|error| {
                    if error == TlsActivationError::ActivationCancelled {
                        WebhookActivationError::Cancelled
                    } else {
                        WebhookActivationError::Tls(error)
                    }
                })?;
            Some(Arc::new(
                build_client_config(&prepared, ClientAlpn::Http1, true)
                    .map_err(WebhookActivationError::Tls)?,
            ))
        } else {
            debug_assert!(plan.tls.is_none(), "HTTP webhook TLS was compile-rejected");
            None
        };
        if tls_resolver.cancellation().is_cancelled() {
            return Err(WebhookActivationError::Cancelled);
        }

        Ok(Arc::new(Self {
            url,
            timeout: plan.timeout,
            failure_mode: plan.on_failure,
            include_headers: plan.include_headers.into_boxed_slice(),
            include_identity: plan.include_identity,
            max_request_bytes: plan.max_request_bytes,
            max_response_bytes: plan.max_response_bytes,
            outputs: ProviderOutputRegistry::activate(plan.outputs),
            tls,
        }))
    }

    #[cfg(test)]
    pub(crate) fn activate_for_test(
        plan: WebhookProviderPlan,
        generation: PolicyGeneration,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Arc<Self>, WebhookActivationError> {
        assert!(
            plan.url.scheme() != HttpScheme::Https
                || matches!(
                    plan.tls.as_ref().map(|tls| tls.trust),
                    Some(TlsClientTrustMode::Insecure)
                ),
            "file-loading webhook plans must use async production activation"
        );
        if is_cancelled() {
            return Err(WebhookActivationError::Cancelled);
        }
        let url = plan.url;
        let tls = if url.scheme() == HttpScheme::Https {
            let WebhookTlsPlan {
                trust,
                ca_certificate: _,
            } = plan.tls.unwrap_or(WebhookTlsPlan {
                trust: TlsClientTrustMode::System,
                ca_certificate: None,
            });
            let trust = access_tls_trust::prepare_tls_client_trust_from_conformance_der(
                trust,
                access_tls_trust::TlsTrustGeneration::new(generation.get())
                    .map_err(TlsActivationError::from)
                    .map_err(WebhookActivationError::Tls)?,
                &[],
                &[],
            )
            .map_err(TlsActivationError::from)
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
            include_identity: plan.include_identity,
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

    pub(crate) fn include_identity(&self) -> bool {
        self.include_identity
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
    use crate::candidate_tls::CandidateTlsPlanSet;
    use crate::runtime::ActivationCancellation;
    use crate::tls_io_runtime::TlsIoRuntime;

    async fn resolver(
        tls_io: &Arc<TlsIoRuntime>,
        cancellation: ActivationCancellation,
    ) -> CandidateTlsResolver {
        let mut plans = CandidateTlsPlanSet::new();
        plans.register(TlsClientTrustMode::System, None).unwrap();
        plans.register(TlsClientTrustMode::Insecure, None).unwrap();
        CandidateTlsResolver::activate_with_plans(
            Arc::clone(tls_io),
            cancellation,
            http_access_types::PolicyGeneration::new(7).unwrap(),
            plans,
        )
        .await
        .expect("test host system roots load")
    }

    fn plan(url: &str, tls: Option<WebhookTlsPlan>) -> WebhookProviderPlan {
        WebhookProviderPlan {
            url: canonicalize_http_url(url).unwrap(),
            timeout: Duration::from_secs(3),
            on_failure: CompiledProviderFailureMode::Deny,
            include_headers: vec![HeaderName::from_static("x-context")],
            include_identity: false,
            max_request_bytes: 8192,
            max_response_bytes: 4096,
            outputs: BTreeMap::new(),
            tls,
        }
    }

    #[tokio::test]
    async fn http_provider_activation_is_typed_and_has_no_tls_client() {
        let tls_io = TlsIoRuntime::new().unwrap();
        let mut tls_resolver = resolver(&tls_io, ActivationCancellation::new_for_test()).await;
        let provider = WebhookProvider::activate(
            plan("http://localhost:8080/a/../authorize?mode=one", None),
            &mut tls_resolver,
        )
        .await
        .unwrap();
        assert_eq!(
            provider.url().as_str(),
            "http://localhost:8080/authorize?mode=one"
        );
        assert_eq!(provider.timeout(), Duration::from_secs(3));
        assert_eq!(provider.include_headers(), ["x-context"]);
        assert!(provider.tls().is_none());
        tls_io.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    async fn https_provider_uses_exact_http1_tls_policy_and_honors_cancellation() {
        let tls_io = TlsIoRuntime::new().unwrap();
        let mut tls_resolver = resolver(&tls_io, ActivationCancellation::new_for_test()).await;
        let provider = WebhookProvider::activate(
            plan(
                "https://provider.test/authorize",
                Some(WebhookTlsPlan {
                    trust: TlsClientTrustMode::Insecure,
                    ca_certificate: None,
                }),
            ),
            &mut tls_resolver,
        )
        .await
        .unwrap();
        assert_eq!(
            provider.tls().unwrap().alpn_protocols,
            [b"http/1.1".to_vec()]
        );
        let cancellation = ActivationCancellation::new_for_test();
        let mut cancelled_resolver = resolver(&tls_io, cancellation.clone()).await;
        cancellation.cancel_for_test();
        assert!(matches!(
            WebhookProvider::activate(
                plan(
                    "https://provider.test/authorize",
                    Some(WebhookTlsPlan {
                        trust: TlsClientTrustMode::Custom,
                        ca_certificate: Some(PathBuf::from("unused.pem")),
                    }),
                ),
                &mut cancelled_resolver,
            )
            .await,
            Err(WebhookActivationError::Cancelled)
        ));
        tls_io.shutdown_and_wait(None).await;
    }
}
