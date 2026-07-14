use std::net::IpAddr;

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use tokio::time::Instant;

use crate::authorization::protocol::{
    GuardedProviderBody, IncludedHeader, ProviderBodyReplacement, ProviderCredentialInjectionError,
    ProviderRequest, ProviderRequestHeaders, StagedProviderCredentialMutation,
};
use crate::authorization::{AuthorizationDecision, AuthorizationDispatchError};
use crate::config::compiler::{CompiledProviderFailureMode, HeaderEffectPlan};
use crate::credentials::{CredentialError, InboundCredentials, ResolvedCredentialAction};
use crate::policy::{PolicyEvaluation, PolicyOutcome, PolicyRuleMatch};
use crate::runtime::{GenerationLease, ProviderIndex};
use crate::safety::wire_body::WireBodyBufferError;
use crate::safety::{GuardedBody, HttpWireBodyGuard, UnknownHttpWireBodyPlan, WireBodyQuotaKey};
use crate::url::CanonicalUrl;

/// Strict request head. Body-bearing ingress prepares this first, then decodes
/// only through the selected guard before completing the decision.
pub(crate) struct RequestInput<'request> {
    pub(crate) request_id: &'request str,
    pub(crate) url: &'request CanonicalUrl,
    pub(crate) method: &'request Method,
    pub(crate) peer_ip: IpAddr,
    pub(crate) headers: HeaderMap,
    pub(crate) quota_key: WireBodyQuotaKey,
    pub(crate) deadline: Instant,
}

pub(crate) enum RequestDecision<'generation> {
    Allow(Box<AllowedRequest<'generation>>),
    Deny(DeniedRequest<'generation>),
}

pub(crate) struct AllowedRequest<'generation> {
    pub(crate) common: DecidedRequest,
    pub(crate) rule: Option<PolicyRuleMatch<'generation>>,
    pub(crate) provider_credentials: Option<StagedProviderCredentialMutation>,
    pub(crate) body: Option<GuardedRequestBody>,
}

pub(crate) struct DeniedRequest<'generation> {
    pub(crate) common: DecidedRequest,
    pub(crate) rule: Option<PolicyRuleMatch<'generation>>,
    pub(crate) reason: DenyReason,
}

pub(crate) struct DecidedRequest {
    pub(crate) headers: HeaderMap,
    pub(crate) body_guard: HttpWireBodyGuard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenyReason {
    LoopDetected,
    Policy,
    Provider,
    ProviderFailure,
    ProviderBodyLimit,
    RedactionFailure,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestDecisionError {
    #[error("inbound credential processing failed")]
    Credential(#[from] CredentialError),
    #[error("the policy wire-body plan does not belong to this generation")]
    BodyPlan(#[from] UnknownHttpWireBodyPlan),
    #[error("request body was not allocated by the selected policy guard")]
    BodyGuard(#[from] WireBodyBufferError),
    #[error("authorization provider metadata is missing")]
    MissingProvider,
    #[error("the policy redaction profile is missing from this generation")]
    MissingRedactionProfile,
    #[error("authorization request headers are invalid")]
    ProviderRequestHeaders,
    #[error("authorization provider dispatch failed")]
    Provider(#[source] AuthorizationDispatchError),
    #[error("authorization provider credential injection failed")]
    ProviderCredentialInjection(#[from] ProviderCredentialInjectionError),
    #[error("authorization provider replacement decode failed")]
    ProviderReplacementDecode,
}

impl<'generation> AllowedRequest<'generation> {
    pub(crate) fn request_header_effects(&self) -> &[HeaderEffectPlan] {
        self.rule
            .as_ref()
            .map(PolicyRuleMatch::request_header_effects)
            .unwrap_or_default()
    }

    pub(crate) fn response_header_effects(&self) -> &[HeaderEffectPlan] {
        self.rule
            .as_ref()
            .map(PolicyRuleMatch::response_header_effects)
            .unwrap_or_default()
    }

    pub(crate) fn credential_actions(&self) -> &[ResolvedCredentialAction] {
        self.rule
            .as_ref()
            .map(PolicyRuleMatch::credential_actions)
            .unwrap_or_default()
    }
}

pub(crate) async fn decide_request<'generation>(
    lease: &'generation GenerationLease,
    input: RequestInput<'_>,
) -> Result<RequestDecision<'generation>, RequestDecisionError> {
    prepare_request(lease, input)?.decide(None).await
}

pub(crate) struct GuardedRequestBody {
    pub(crate) content_type: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) decoded: GuardedBody,
}

pub(crate) struct PreparedRequest<'generation, 'request> {
    lease: &'generation GenerationLease,
    identity: RequestIdentity<'request>,
    headers: HeaderMap,
    inbound: InboundCredentials<'generation>,
    internal_context: HeaderMap,
    evaluation: PolicyEvaluation<'generation>,
    guard: HttpWireBodyGuard,
    early_deny: Option<DenyReason>,
}

impl<'generation, 'request> PreparedRequest<'generation, 'request> {
    pub(crate) fn body_guard(&self) -> &HttpWireBodyGuard {
        &self.guard
    }

    pub(crate) async fn decide(
        self,
        body: Option<GuardedRequestBody>,
    ) -> Result<RequestDecision<'generation>, RequestDecisionError> {
        let body = body
            .map(|body| -> Result<_, WireBodyBufferError> {
                Ok(GuardedRequestBody {
                    content_type: body.content_type,
                    content_encoding: body.content_encoding,
                    decoded: self.guard.transfer_body(body.decoded)?,
                })
            })
            .transpose()?;
        if let Some(reason) = self.early_deny {
            return Ok(RequestDecision::Deny(DeniedRequest {
                common: DecidedRequest {
                    headers: self.headers,
                    body_guard: self.guard,
                },
                rule: None,
                reason,
            }));
        }
        evaluate_to_terminal(
            self.lease,
            DecisionState {
                identity: self.identity,
                headers: self.headers,
                inbound: self.inbound,
                internal_context: self.internal_context,
                evaluation: self.evaluation,
                guard: self.guard,
                body,
            },
        )
        .await
    }
}

pub(crate) fn prepare_request<'generation, 'request>(
    lease: &'generation GenerationLease,
    mut input: RequestInput<'request>,
) -> Result<PreparedRequest<'generation, 'request>, RequestDecisionError> {
    let inbound = lease.credentials().extract_inbound(&mut input.headers)?;
    let internal_context = strip_internal_context(
        &mut input.headers,
        lease.authorization().internal_context_headers(),
    );

    let evaluation = lease.policy().evaluate(
        input.url,
        input.peer_ip,
        input.method,
        &input.headers,
        &|name| inbound.is_present(name),
    );
    let guard = lease
        .safety()
        .begin_http_body(evaluation.wire_body_plan(), input.quota_key)?;

    if lease.safety().contains_loop_marker(&input.headers) {
        // Loop denial is completed through the same prepared request path so
        // the selected guard remains the sole body authority.
        return Ok(PreparedRequest {
            lease,
            identity: RequestIdentity {
                request_id: input.request_id,
                url: input.url,
                method: input.method,
                peer_ip: input.peer_ip,
                deadline: input.deadline,
            },
            headers: input.headers,
            inbound,
            internal_context,
            evaluation,
            guard,
            early_deny: Some(DenyReason::LoopDetected),
        });
    }

    Ok(PreparedRequest {
        lease,
        identity: RequestIdentity {
            request_id: input.request_id,
            url: input.url,
            method: input.method,
            peer_ip: input.peer_ip,
            deadline: input.deadline,
        },
        headers: input.headers,
        inbound,
        internal_context,
        evaluation,
        guard,
        early_deny: None,
    })
}

#[derive(Clone, Copy)]
struct RequestIdentity<'request> {
    request_id: &'request str,
    url: &'request CanonicalUrl,
    method: &'request Method,
    peer_ip: IpAddr,
    deadline: Instant,
}

struct DecisionState<'generation, 'request> {
    identity: RequestIdentity<'request>,
    headers: HeaderMap,
    inbound: InboundCredentials<'generation>,
    internal_context: HeaderMap,
    evaluation: PolicyEvaluation<'generation>,
    guard: HttpWireBodyGuard,
    body: Option<GuardedRequestBody>,
}

async fn evaluate_to_terminal<'generation>(
    lease: &'generation GenerationLease,
    state: DecisionState<'generation, '_>,
) -> Result<RequestDecision<'generation>, RequestDecisionError> {
    let DecisionState {
        identity: input,
        headers,
        inbound,
        internal_context,
        mut evaluation,
        guard,
        mut body,
    } = state;
    loop {
        match evaluation.outcome {
            PolicyOutcome::Allow => {
                let matched = evaluation.matched;
                let body = select_terminal_body(&guard, body, None)?;
                let body = match redact_terminal_body(lease, matched.as_ref(), &guard, body)? {
                    TerminalBody::Ready(body) => body,
                    TerminalBody::RedactionDenied => {
                        return Ok(RequestDecision::Deny(DeniedRequest {
                            common: DecidedRequest {
                                headers,
                                body_guard: guard,
                            },
                            rule: matched,
                            reason: DenyReason::RedactionFailure,
                        }));
                    }
                };
                return Ok(RequestDecision::Allow(Box::new(AllowedRequest {
                    common: DecidedRequest {
                        headers,
                        body_guard: guard,
                    },
                    rule: matched,
                    provider_credentials: None,
                    body,
                })));
            }
            PolicyOutcome::Deny => {
                return Ok(RequestDecision::Deny(DeniedRequest {
                    common: DecidedRequest {
                        headers,
                        body_guard: guard,
                    },
                    rule: evaluation.matched,
                    reason: DenyReason::Policy,
                }));
            }
            PolicyOutcome::Delegate => {}
        }

        let matched = evaluation
            .matched
            .take()
            .expect("delegate policy outcomes always identify their rule");
        let provider = matched
            .authorization_provider()
            .expect("activated delegate rules always bind an authorization provider");
        let metadata = lease
            .authorization()
            .provider_metadata(provider)
            .ok_or(RequestDecisionError::MissingProvider)?;
        let failure_mode = metadata.failure_mode;
        if metadata.include_request_body && body.is_none() {
            body = Some(GuardedRequestBody {
                content_type: None,
                content_encoding: None,
                decoded: guard.buffer().finish(),
            });
        }
        if metadata.include_request_body
            && body
                .as_ref()
                .is_some_and(|body| body.decoded.len() > metadata.max_decoded_request_body_bytes)
        {
            return Ok(RequestDecision::Deny(DeniedRequest {
                common: DecidedRequest {
                    headers,
                    body_guard: guard,
                },
                rule: Some(matched),
                reason: DenyReason::ProviderBodyLimit,
            }));
        }
        let provider_header_values = provider_header_values(
            metadata.include_headers,
            &headers,
            &internal_context,
            &inbound,
            provider,
        )?;
        let included_headers = provider_header_values
            .iter()
            .map(|(name, values)| IncludedHeader::new(name, values))
            .collect::<Vec<_>>();
        let provider_headers = ProviderRequestHeaders::new(&included_headers)
            .map_err(|_| RequestDecisionError::ProviderRequestHeaders)?;
        let peer_ip = input.peer_ip.to_string();
        let provider_body = metadata.include_request_body.then(|| {
            let body = body
                .as_ref()
                .expect("body-including providers receive at least an empty guarded body");
            GuardedProviderBody {
                content_type: body.content_type.as_deref(),
                content_encoding: body.content_encoding.as_deref(),
                decoded: &body.decoded,
            }
        });
        let provider_request = ProviderRequest {
            request_id: input.request_id,
            url: &input.url.url,
            method: input.method.as_str(),
            client_ip: &peer_ip,
            headers: (!included_headers.is_empty()).then_some(&provider_headers),
            body: provider_body,
        };

        let decision = match lease
            .dispatch_authorization(
                provider,
                matched.id(),
                provider_request,
                &guard,
                input.deadline,
            )
            .await
        {
            Ok(decision) => decision,
            Err(_error) if failure_mode == CompiledProviderFailureMode::Deny => {
                return Ok(RequestDecision::Deny(DeniedRequest {
                    common: DecidedRequest {
                        headers,
                        body_guard: guard,
                    },
                    rule: Some(matched),
                    reason: DenyReason::ProviderFailure,
                }));
            }
            Err(error) => return Err(RequestDecisionError::Provider(error)),
        };

        match decision {
            AuthorizationDecision::Allow {
                credentials,
                replacement,
            } => {
                let body = select_terminal_body(&guard, body, replacement)?;
                let provider_credentials = credentials
                    .as_ref()
                    .map(|credentials| {
                        lease.authorization().stage_provider_credentials(
                            provider,
                            credentials,
                            &guard,
                        )
                    })
                    .transpose()?;
                drop(credentials);
                let body = match redact_terminal_body(lease, Some(&matched), &guard, body)? {
                    TerminalBody::Ready(body) => body,
                    TerminalBody::RedactionDenied => {
                        return Ok(RequestDecision::Deny(DeniedRequest {
                            common: DecidedRequest {
                                headers,
                                body_guard: guard,
                            },
                            rule: Some(matched),
                            reason: DenyReason::RedactionFailure,
                        }));
                    }
                };
                return Ok(RequestDecision::Allow(Box::new(AllowedRequest {
                    common: DecidedRequest {
                        headers,
                        body_guard: guard,
                    },
                    rule: Some(matched),
                    provider_credentials,
                    body,
                })));
            }
            AuthorizationDecision::Deny => {
                return Ok(RequestDecision::Deny(DeniedRequest {
                    common: DecidedRequest {
                        headers,
                        body_guard: guard,
                    },
                    rule: Some(matched),
                    reason: DenyReason::Provider,
                }));
            }
            AuthorizationDecision::Pass => {
                evaluation = matched.resume_cursor().resume(
                    input.url,
                    input.peer_ip,
                    input.method,
                    &headers,
                    |name| inbound.is_present(name),
                );
            }
        }
    }
}

enum TerminalBody {
    Ready(Option<GuardedRequestBody>),
    RedactionDenied,
}

fn select_terminal_body(
    guard: &HttpWireBodyGuard,
    mut body: Option<GuardedRequestBody>,
    replacement: Option<ProviderBodyReplacement>,
) -> Result<Option<GuardedRequestBody>, RequestDecisionError> {
    if let Some(replacement) = replacement {
        drop(body.take());
        let (content_type, content_encoding, decoded) = replacement
            .decode(guard)
            .map_err(|_| RequestDecisionError::ProviderReplacementDecode)?;
        body = Some(GuardedRequestBody {
            content_type,
            content_encoding,
            decoded,
        });
    }
    Ok(body)
}

fn redact_terminal_body(
    lease: &GenerationLease,
    rule: Option<&PolicyRuleMatch<'_>>,
    guard: &HttpWireBodyGuard,
    mut body: Option<GuardedRequestBody>,
) -> Result<TerminalBody, RequestDecisionError> {
    let Some(profile_index) = rule.and_then(PolicyRuleMatch::redaction_profile) else {
        return Ok(TerminalBody::Ready(body));
    };
    let Some(profile) = lease.redaction().profile(profile_index) else {
        return Err(RequestDecisionError::MissingRedactionProfile);
    };
    let Some(current) = body.take() else {
        return Ok(TerminalBody::Ready(body));
    };
    let redacted = match profile.redact_guarded_decoded_http_body(guard, current.decoded) {
        Ok(redacted) => redacted,
        Err(_) => return Ok(TerminalBody::RedactionDenied),
    };
    body = Some(GuardedRequestBody {
        content_type: current.content_type,
        content_encoding: current.content_encoding,
        decoded: redacted.body,
    });
    Ok(TerminalBody::Ready(body))
}

fn provider_header_values(
    include_headers: &[HeaderName],
    request_headers: &HeaderMap,
    internal_context: &HeaderMap,
    inbound: &InboundCredentials<'_>,
    provider: ProviderIndex,
) -> Result<Vec<(HeaderName, Vec<HeaderValue>)>, RequestDecisionError> {
    let mut selected = HeaderMap::new();
    for name in include_headers {
        for value in request_headers
            .get_all(name)
            .iter()
            .chain(internal_context.get_all(name))
        {
            selected.append(name.clone(), value.clone());
        }
    }
    inbound.copy_for_process_provider(provider, &mut selected)?;

    Ok(selected
        .keys()
        .map(|name| {
            (
                name.clone(),
                selected.get_all(name).iter().cloned().collect(),
            )
        })
        .collect())
}

fn strip_internal_context(headers: &mut HeaderMap, names: &[HeaderName]) -> HeaderMap {
    let mut retained = HeaderMap::new();
    for name in names {
        for value in headers.get_all(name) {
            retained.append(name.clone(), value.clone());
        }
        headers.remove(name);
    }
    retained
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use http::header::HeaderValue;

    use super::*;
    use crate::activation::static_resources::ProductStaticResources;
    use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput};
    use crate::runtime::{
        ActivationCancellation, BoxFuture, CandidateSource, ReloadTriggerResult, Runtime,
        RuntimeError, StaticOwnership,
    };
    use crate::url::canonicalize_http_url;

    struct QueueSource(Mutex<VecDeque<CompiledConfig>>);

    impl QueueSource {
        fn push(&self, config: CompiledConfig) {
            self.0.lock().unwrap().push_back(config);
        }
    }

    impl CandidateSource for QueueSource {
        fn load_latest(
            &self,
            cancellation: ActivationCancellation,
        ) -> BoxFuture<'_, Result<CompiledConfig, RuntimeError>> {
            Box::pin(async move {
                cancellation.check()?;
                self.0
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| RuntimeError::CandidateSource("empty test queue".into()))
            })
        }
    }

    fn config(policy: &str, extra: &str) -> String {
        format!(
            r#"schema_version = 3

[service]
request_timeout = "5s"
max_retiring_generations = 4

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

{policy}

[observation.logging]
level = "info"
console = true

[safety.loop_detection]
inject = true
header = "x-test-loop"

{extra}
"#
        )
    }

    fn compile(text: &str) -> CompiledConfig {
        std::fs::create_dir_all("/tmp/request-decision").unwrap();
        compile_config_text(ConfigTextInput {
            text,
            source_path: Path::new("/tmp/request-decision/acl-proxy.toml"),
            config_root: Path::new("/tmp/request-decision"),
        })
        .expect("strict request-decision test config compiles")
    }

    async fn runtime(
        initial: CompiledConfig,
    ) -> (
        Arc<Runtime>,
        Arc<QueueSource>,
        crate::runtime::GenerationId,
        Arc<crate::safety::WireBodyPool>,
    ) {
        let source = Arc::new(QueueSource(Mutex::new(VecDeque::new())));
        let resources = ProductStaticResources::try_new(&initial.static_config).unwrap();
        let pool = resources.wire_body_pool();
        let activator = resources.activator();
        let ownership = StaticOwnership::new(
            initial.static_config.clone(),
            initial.static_fingerprint.clone(),
            resources,
        );
        let runtime = Runtime::new(ownership, source.clone(), activator)
            .await
            .unwrap();
        let generation = runtime.start(initial).await.unwrap();
        (runtime, source, generation, pool)
    }

    fn input<'a>(
        request_id: &'a str,
        url: &'a CanonicalUrl,
        headers: HeaderMap,
    ) -> RequestInput<'a> {
        let peer_ip = "192.0.2.10".parse().unwrap();
        RequestInput {
            request_id,
            url,
            method: &Method::GET,
            peer_ip,
            headers,
            quota_key: WireBodyQuotaKey::from_peer(peer_ip, |_| false),
            deadline: Instant::now() + Duration::from_secs(3),
        }
    }

    #[tokio::test]
    async fn retained_lease_stays_consistent_and_inbound_presence_survives_stripping() {
        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "credential-present"
decision = "allow"
methods = ["GET"]

[policy.rules.headers]
present_all = ["x-test-identity"]"#,
            r#"[[egress.request_headers]]
operation = "remove"
when = "always"
name = "x-internal-context"

[authorization]
internal_context_headers = ["x-internal-context"]

[authorization.providers.identity_sink]
kind = "process"
command = "/bin/cat"
retire_timeout = "6s"
include_headers = ["x-test-identity"]

[credentials.inbound.identity]
header = "x-test-identity"
process_providers = ["identity_sink"]"#,
        ));
        let updated = compile(&config(
            r#"[policy]
default = "allow""#,
            r#"[[egress.request_headers]]
operation = "remove"
when = "always"
name = "x-internal-context"

[authorization]
internal_context_headers = ["x-internal-context"]

[authorization.providers.identity_sink]
kind = "process"
command = "/bin/cat"
retire_timeout = "6s"
include_headers = ["x-test-identity"]

[credentials.inbound.identity]
header = "x-test-identity"
process_providers = ["identity_sink"]"#,
        ));
        let (runtime, source, first_id, _pool) = runtime(initial).await;
        let old = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/resource").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-test-identity", HeaderValue::from_static("secret"));
        headers.insert("x-internal-context", HeaderValue::from_static("untrusted"));

        let RequestDecision::Allow(allowed) = decide_request(&old, input("before", &url, headers))
            .await
            .unwrap()
        else {
            panic!("the captured inbound credential should satisfy policy");
        };
        assert_eq!(allowed.rule.as_ref().unwrap().id(), "credential-present");
        assert!(!allowed.common.headers.contains_key("x-test-identity"));
        assert!(!allowed.common.headers.contains_key("x-internal-context"));
        drop(allowed);

        source.push(updated);
        let ReloadTriggerResult::Completed {
            generation: second_id,
            ..
        } = runtime.trigger_reload().await.unwrap()
        else {
            panic!("the test reload must be owned by this trigger");
        };
        assert_ne!(first_id, second_id);

        let RequestDecision::Deny(old_decision) =
            decide_request(&old, input("old-after-reload", &url, HeaderMap::new()))
                .await
                .unwrap()
        else {
            panic!("the retained generation still has its deny default");
        };
        assert_eq!(old_decision.reason, DenyReason::Policy);
        drop(old_decision);

        let current = runtime.lease().await.unwrap();
        let RequestDecision::Allow(current_decision) = decide_request(
            &current,
            input("current-after-reload", &url, HeaderMap::new()),
        )
        .await
        .unwrap() else {
            panic!("the current generation has its allow default");
        };
        assert!(current_decision.rule.is_none());
        drop(current_decision);
        drop(current);
        drop(old);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_pass_reuses_the_cursor_guard_for_terminal_allow_and_deny() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let pass = directory.path().join("pass.sh");
        let terminal = directory.path().join("terminal.sh");
        std::fs::write(
            &pass,
            r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  decision=pass
  case "$line" in
    *exact-body*ZXhhY3QtYm9keQ==*) ;;
    *exact-body*) decision=deny ;;
  esac
  [ -n "$id" ] && printf '{"id":"%s","type":"response","decision":"%s"}\n' "$id" "$decision"
done
"#,
        )
        .unwrap();
        std::fs::write(
            &terminal,
            r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  case "$line" in
    *deny*) decision=deny ;;
    *exact-body*ZXhhY3QtYm9keQ==*) decision=allow ;;
    *exact-body*) decision=deny ;;
    *) decision=allow ;;
  esac
  [ -n "$id" ] && printf '{"id":"%s","type":"response","decision":"%s"}\n' "$id" "$decision"
done
"#,
        )
        .unwrap();
        for script in [&pass, &terminal] {
            let mut permissions = std::fs::metadata(script).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(script, permissions).unwrap();
        }

        let providers = format!(
            r#"[authorization.providers.first]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024

[authorization.providers.terminal]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024"#,
            pass.display(),
            terminal.display()
        );
        let policy = r#"[policy]
default = "deny"

[[policy.rules]]
id = "pass-first"
decision = "delegate"
methods = ["GET"]
authorization_provider = "first"

[[policy.rules]]
id = "terminal"
decision = "delegate"
methods = ["GET"]
authorization_provider = "terminal""#;
        let initial = compile(&config(policy, &providers));
        let (runtime, _source, _, pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();

        for (path, expected_allow) in [("allow", true), ("deny", false)] {
            let url = canonicalize_http_url(&format!("https://example.test/{path}")).unwrap();
            let decision = decide_request(&lease, input(path, &url, HeaderMap::new()))
                .await
                .unwrap();
            match (decision, expected_allow) {
                (RequestDecision::Allow(allowed), true) => {
                    assert_eq!(allowed.rule.as_ref().unwrap().id(), "terminal");
                    assert!(allowed.common.body_guard.cursor_peak_bytes() > 0);
                }
                (RequestDecision::Deny(denied), false) => {
                    assert_eq!(denied.rule.as_ref().unwrap().id(), "terminal");
                    assert_eq!(denied.reason, DenyReason::Provider);
                    assert!(denied.common.body_guard.cursor_peak_bytes() > 0);
                }
                _ => panic!("unexpected terminal provider decision"),
            }
        }

        let url = canonicalize_http_url("https://example.test/exact-body").unwrap();
        let prepared =
            prepare_request(&lease, input("exact-body", &url, HeaderMap::new())).unwrap();
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"exact-body").unwrap();
        let RequestDecision::Allow(allowed) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: None,
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("both providers must observe the exact preserved body");
        };
        assert_eq!(allowed.rule.as_ref().unwrap().id(), "terminal");
        let forwarded = allowed
            .body
            .as_ref()
            .unwrap()
            .decoded
            .segments()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(forwarded, b"exact-body");
        drop(allowed);
        assert_eq!(pool.global_charge(), 0);

        drop(lease);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_provider_replacement_is_selected_then_redacted_or_denied() {
        use std::os::unix::fs::PermissionsExt;

        for (max_body_bytes, expect_allow) in [(128, true), (4, false)] {
            let directory = tempfile::tempdir().unwrap();
            let provider = directory.path().join("replacement.sh");
            std::fs::write(
                &provider,
                r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{"id":"%s","type":"response","decision":"allow","values":{"token":"secret-marker"},"requestBody":{"encoding":"base64","contentType":"text/plain","data":"cmVwbGFjZW1lbnQgc2VjcmV0"}}\n' "$id"
done
"#,
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&provider).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&provider, permissions).unwrap();

            let extra = format!(
                r#"[authorization.providers.replacing]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 128
max_decoded_request_body_bytes = 128
max_stdout_line_bytes = 1024

[authorization.providers.replacing.outputs.token]
kind = "bearer"
required = true

[redaction.profiles.wire]
replacement = "[MASKED]"
max_body_bytes = {max_body_bytes}
max_decoded_body_bytes = {max_body_bytes}
rules = [{{ literals = ["secret"], payloads = "text" }}]"#,
                provider.display()
            );
            let policy = r#"[policy]
default = "deny"

[[policy.rules]]
id = "replace"
decision = "delegate"
methods = ["GET"]
authorization_provider = "replacing"
redaction_profile = "wire""#;
            let initial = compile(&config(policy, &extra));
            let (runtime, _source, _, pool) = runtime(initial).await;
            let lease = runtime.lease().await.unwrap();
            let url = canonicalize_http_url("https://example.test/replacement").unwrap();
            let prepared =
                prepare_request(&lease, input("replacement", &url, HeaderMap::new())).unwrap();
            let one_guarded_chunk =
                crate::safety::wire_body::guarded_body_allocation_bytes(1).unwrap();
            assert_eq!(
                prepared.body_guard().cursor_peak_bytes(),
                4 * one_guarded_chunk,
                "the exact terminal peak retains compact guarded credentials beside decoded input, matcher scratch, and redacted output"
            );
            let mut original = prepared.body_guard().buffer();
            original.try_extend_from_slice(b"original body").unwrap();
            let decision = prepared
                .decide(Some(GuardedRequestBody {
                    content_type: Some("text/plain".into()),
                    content_encoding: None,
                    decoded: original.finish(),
                }))
                .await
                .unwrap();

            if expect_allow {
                let RequestDecision::Allow(mut allowed) = decision else {
                    panic!("bounded replacement must be allowed");
                };
                assert!(allowed
                    .common
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .is_none());
                let staged = allowed.provider_credentials.take().unwrap();
                assert!(!format!("{staged:?}").contains("secret-marker"));
                let mut origin_headers = HeaderMap::new();
                staged.apply(&mut origin_headers).unwrap();
                assert_eq!(
                    origin_headers.get(http::header::AUTHORIZATION).unwrap(),
                    "Bearer secret-marker"
                );
                assert!(origin_headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .is_sensitive());
                let body = allowed.body.as_ref().unwrap();
                assert_eq!(body.content_type.as_deref(), Some("text/plain"));
                assert_eq!(
                    body.decoded
                        .segments()
                        .flatten()
                        .copied()
                        .collect::<Vec<_>>(),
                    b"replacement [MASKED]"
                );
                drop(allowed);
            } else {
                let RequestDecision::Deny(denied) = decision else {
                    panic!("replacement redaction limit failure must deny");
                };
                assert_eq!(denied.reason, DenyReason::RedactionFailure);
                assert_eq!(denied.rule.as_ref().unwrap().id(), "replace");
                assert!(denied
                    .common
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .is_none());
                drop(denied);
            }
            assert_eq!(pool.global_charge(), 0);
            drop(lease);
            runtime.shutdown().await;
        }
    }
}
