use std::net::IpAddr;

use http::{HeaderMap, HeaderName, HeaderValue};
use http_access_types::InterceptedRequestFacts;
use tokio::time::Instant;

use crate::authorization::protocol::{
    GuardedProviderBody, IncludedHeader, ProviderBodyReplacement,
    ProviderBodyReplacementDecodeError, ProviderCredentialInjectionError, ProviderRequest,
    ProviderRequestHeaders, StagedProviderCredentialMutation,
};
use crate::authorization::{AuthorizationDecision, AuthorizationDispatchError};
use crate::config::compiler::{CompiledProviderFailureMode, HeaderEffectPlan, HttpBodyReadPlan};
use crate::credentials::{CredentialError, InboundCredentials, ResolvedCredentialAction};
use crate::policy::{PolicyEvaluation, PolicyOutcome, PolicyRuleMatch};
use crate::proxy::facts::{product_headers, FactsError, ValidatedRequestFactShape};
use crate::redaction::ProfileHandle;
use crate::runtime::{GenerationLease, ProviderIndex};
use crate::safety::wire_body::WireBodyBufferError;
use crate::safety::{GuardedBody, HttpWireBodyGuard, UnknownHttpWireBodyPlan, WireBodyQuotaKey};
use crate::upgrade::UpgradeAllocation;

/// Strict request head. Body-bearing ingress prepares this first, then decodes
/// only through the selected guard before completing the decision.
pub(crate) struct RequestInput<'generation, 'request> {
    pub(crate) request_id: &'request str,
    pub(crate) facts: InterceptedRequestFacts,
    pub(crate) peer_ip: IpAddr,
    pub(crate) quota_key: WireBodyQuotaKey,
    pub(crate) started_at: Instant,
    inbound: InboundCredentials<'generation>,
    internal_context: HeaderMap,
}

impl<'generation, 'request> RequestInput<'generation, 'request> {
    pub(crate) fn from_validated_shape(
        lease: &'generation GenerationLease,
        request_id: &'request str,
        shape: ValidatedRequestFactShape,
        sanitized_headers: &mut HeaderMap,
        peer_ip: IpAddr,
        quota_key: WireBodyQuotaKey,
        started_at: Instant,
    ) -> Result<Self, RequestDecisionError> {
        let inbound = lease.credentials().extract_inbound(sanitized_headers)?;
        let internal_context = strip_internal_context(
            sanitized_headers,
            lease.authorization().internal_context_headers(),
        );
        let facts = shape.into_facts(sanitized_headers)?;
        Ok(Self {
            request_id,
            facts,
            peer_ip,
            quota_key,
            started_at,
            inbound,
            internal_context,
        })
    }
}

pub(crate) enum RequestDecision<'generation> {
    Allow(Box<AllowedRequest<'generation>>),
    Deny(Box<DeniedRequest<'generation>>),
}

pub(crate) struct AllowedRequest<'generation> {
    pub(crate) common: DecidedRequest,
    pub(crate) rule: Option<PolicyRuleMatch<'generation>>,
    pub(crate) provider_credentials: Option<StagedProviderCredentialMutation>,
    pub(crate) upgrade: Option<UpgradeBinding>,
    pub(crate) body: Option<GuardedRequestBody>,
    pub(crate) body_provenance: TerminalRequestBodyProvenance,
}

pub(crate) struct UpgradeBinding {
    pub(crate) allocation: UpgradeAllocation,
    pub(crate) wire_redaction: Option<ProfileHandle>,
}

pub(crate) struct DeniedRequest<'generation> {
    pub(crate) common: DecidedRequest,
    pub(crate) _rule: Option<PolicyRuleMatch<'generation>>,
    pub(crate) _reason: DenyReason,
    pub(crate) body_provenance: TerminalRequestBodyProvenance,
    body: Option<GuardedRequestBody>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TerminalRequestBodyProvenance {
    Unconsumed,
    CompleteOriginal,
    CompleteWireRedacted,
    ProviderReplacement { size: usize },
}

pub(crate) struct DecidedRequest {
    pub(crate) headers: HeaderMap,
    pub(crate) _body_guard: HttpWireBodyGuard,
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
    #[error("the matched upgrade rule has no compiled upgrade allocation")]
    MissingUpgradeAllocation,
    #[error("authorization request headers are invalid")]
    ProviderRequestHeaders,
    #[error("authorization provider dispatch failed")]
    Provider(#[source] AuthorizationDispatchError),
    #[error("authorization provider credential injection failed")]
    ProviderCredentialInjection {
        #[source]
        source: ProviderCredentialInjectionError,
        body_provenance: TerminalRequestBodyProvenance,
    },
    #[error("authorization provider replacement decode failed")]
    ProviderReplacementDecode {
        body_provenance: TerminalRequestBodyProvenance,
    },
    #[error("the effective request deadline exceeds the monotonic clock range")]
    RequestDeadlineOverflow,
    #[error("checked request facts cannot be materialized")]
    Facts(#[from] FactsError),
}

impl RequestDecisionError {
    pub(crate) fn body_provenance(&self) -> Option<TerminalRequestBodyProvenance> {
        match self {
            Self::ProviderCredentialInjection {
                body_provenance, ..
            }
            | Self::ProviderReplacementDecode { body_provenance } => Some(*body_provenance),
            _ => None,
        }
    }
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

impl DeniedRequest<'_> {
    /// Transfers an ingress-owned complete body to the observation path.
    /// Provider replacement bytes are never retained by a denied request.
    pub(crate) fn take_body_for_observation(&mut self) -> Option<GuardedRequestBody> {
        self.body.take()
    }
}

#[cfg(test)]
pub(crate) async fn decide_request<'generation>(
    lease: &'generation GenerationLease,
    input: RequestInput<'generation, '_>,
) -> Result<RequestDecision<'generation>, RequestDecisionError> {
    prepare_request(lease, input)?.decide(None).await
}

pub(crate) struct GuardedRequestBody {
    pub(crate) content_type: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) encoded_len: usize,
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
    pub(crate) fn deadline(&self) -> Instant {
        self.identity.deadline
    }

    pub(crate) fn body_guard(&self) -> &HttpWireBodyGuard {
        &self.guard
    }

    pub(crate) fn headers_for_observation(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn body_read_plan(&self) -> HttpBodyReadPlan {
        if self.early_deny.is_some()
            || upgrade_is_disallowed(self.identity.facts.upgrade().is_some(), &self.evaluation)
        {
            HttpBodyReadPlan::Disabled
        } else {
            self.evaluation.body_read_plan()
        }
    }

    pub(crate) fn denies_without_resolution(&self) -> bool {
        self.early_deny.is_some()
            || self.evaluation.outcome == PolicyOutcome::Deny
            || upgrade_is_disallowed(self.identity.facts.upgrade().is_some(), &self.evaluation)
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
                    encoded_len: body.encoded_len,
                    decoded: self.guard.transfer_body(body.decoded)?,
                })
            })
            .transpose()?;
        let body_provenance = if body.is_some() {
            TerminalRequestBodyProvenance::CompleteOriginal
        } else {
            TerminalRequestBodyProvenance::Unconsumed
        };
        if let Some(reason) = self.early_deny {
            let body = denied_observation_body(body, body_provenance);
            return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                common: DecidedRequest {
                    headers: self.headers,
                    _body_guard: self.guard,
                },
                _rule: None,
                _reason: reason,
                body_provenance,
                body,
            })));
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
                body_provenance,
            },
        )
        .await
    }
}

pub(crate) fn prepare_request<'generation, 'request>(
    lease: &'generation GenerationLease,
    input: RequestInput<'generation, 'request>,
) -> Result<PreparedRequest<'generation, 'request>, RequestDecisionError> {
    let headers = product_headers(input.facts.headers())?;

    let evaluation = lease.policy().evaluate(
        input.facts.url(),
        input.peer_ip,
        input.facts.method(),
        &headers,
        &|name| input.inbound.is_present(name),
    );
    let request_timeout = evaluation
        .matched
        .as_ref()
        .and_then(PolicyRuleMatch::request_timeout)
        .unwrap_or_else(|| lease.request_timeout());
    let deadline = input
        .started_at
        .checked_add(request_timeout)
        .ok_or(RequestDecisionError::RequestDeadlineOverflow)?;
    let guard = lease
        .safety()
        .begin_http_body(evaluation.wire_body_plan(), input.quota_key)?;

    let identity = RequestIdentity {
        request_id: input.request_id,
        facts: input.facts,
        peer_ip: input.peer_ip,
        deadline,
    };

    if lease.safety().contains_loop_marker(&headers) {
        // Loop denial is completed through the same prepared request path so
        // the selected guard remains the sole body authority.
        return Ok(PreparedRequest {
            lease,
            identity,
            headers,
            inbound: input.inbound,
            internal_context: input.internal_context,
            evaluation,
            guard,
            early_deny: Some(DenyReason::LoopDetected),
        });
    }

    Ok(PreparedRequest {
        lease,
        identity,
        headers,
        inbound: input.inbound,
        internal_context: input.internal_context,
        evaluation,
        guard,
        early_deny: None,
    })
}

struct RequestIdentity<'request> {
    request_id: &'request str,
    facts: InterceptedRequestFacts,
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
    body_provenance: TerminalRequestBodyProvenance,
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
        mut body_provenance,
    } = state;
    loop {
        if upgrade_is_disallowed(input.facts.upgrade().is_some(), &evaluation) {
            let body = denied_observation_body(body, body_provenance);
            return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                common: DecidedRequest {
                    headers,
                    _body_guard: guard,
                },
                _rule: evaluation.matched,
                _reason: DenyReason::Policy,
                body_provenance,
                body,
            })));
        }
        match evaluation.outcome {
            PolicyOutcome::Allow => {
                let matched = evaluation.matched;
                let upgrade =
                    bind_upgrade(lease, input.facts.upgrade().is_some(), matched.as_ref())?;
                let local_failure = match matched.as_ref() {
                    Some(matched) => {
                        validate_local_body_limits(lease, matched, None, body.as_ref())?
                    }
                    None => None,
                };
                if let Some(reason) = local_failure {
                    let body = denied_observation_body(body, body_provenance);
                    return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                        common: DecidedRequest {
                            headers,
                            _body_guard: guard,
                        },
                        _rule: matched,
                        _reason: reason,
                        body_provenance,
                        body,
                    })));
                }
                let (body, selected_provenance) = match select_terminal_body(
                    &guard,
                    body,
                    body_provenance,
                    None,
                    TerminalBodyLimits::unbounded(),
                )? {
                    TerminalBody::Ready { body, provenance } => (body, provenance),
                    TerminalBody::ProviderDenied { .. } | TerminalBody::RedactionDenied { .. } => {
                        unreachable!("no replacement was selected")
                    }
                };
                let (body, body_provenance) = match redact_terminal_body(
                    lease,
                    matched.as_ref(),
                    &guard,
                    body,
                    selected_provenance,
                )? {
                    TerminalBody::Ready { body, provenance } => (body, provenance),
                    TerminalBody::ProviderDenied { .. } => {
                        unreachable!("redaction does not enforce provider limits")
                    }
                    TerminalBody::RedactionDenied { provenance } => {
                        return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                            common: DecidedRequest {
                                headers,
                                _body_guard: guard,
                            },
                            _rule: matched,
                            _reason: DenyReason::RedactionFailure,
                            body_provenance: provenance,
                            body: None,
                        })));
                    }
                };
                return Ok(RequestDecision::Allow(Box::new(AllowedRequest {
                    common: DecidedRequest {
                        headers,
                        _body_guard: guard,
                    },
                    rule: matched,
                    provider_credentials: None,
                    upgrade,
                    body,
                    body_provenance,
                })));
            }
            PolicyOutcome::Deny => {
                let body = denied_observation_body(body, body_provenance);
                return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                    common: DecidedRequest {
                        headers,
                        _body_guard: guard,
                    },
                    _rule: evaluation.matched,
                    _reason: DenyReason::Policy,
                    body_provenance,
                    body,
                })));
            }
            PolicyOutcome::Delegate => {}
        }

        let matched = evaluation
            .matched
            .take()
            .expect("delegate policy outcomes always identify their rule");
        let upgrade = bind_upgrade(lease, input.facts.upgrade().is_some(), Some(&matched))?;
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
                encoded_len: 0,
                decoded: guard.buffer().finish(),
            });
            body_provenance = TerminalRequestBodyProvenance::CompleteOriginal;
        }
        if let Some(reason) =
            validate_local_body_limits(lease, &matched, Some(metadata), body.as_ref())?
        {
            let body = denied_observation_body(body, body_provenance);
            return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                common: DecidedRequest {
                    headers,
                    _body_guard: guard,
                },
                _rule: Some(matched),
                _reason: reason,
                body_provenance,
                body,
            })));
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
            url: input.facts.url().as_str(),
            method: input.facts.method().as_str(),
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
                let body = denied_observation_body(body, body_provenance);
                return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                    common: DecidedRequest {
                        headers,
                        _body_guard: guard,
                    },
                    _rule: Some(matched),
                    _reason: DenyReason::ProviderFailure,
                    body_provenance,
                    body,
                })));
            }
            Err(error) => return Err(RequestDecisionError::Provider(error)),
        };

        match decision {
            AuthorizationDecision::Allow {
                credentials,
                replacement,
            } => {
                let replacement_limits = terminal_decoded_body_limits(
                    lease,
                    Some(&matched),
                    metadata.max_decoded_request_body_bytes,
                )?;
                let (body, selected_provenance) = match select_terminal_body(
                    &guard,
                    body,
                    body_provenance,
                    replacement,
                    replacement_limits,
                )? {
                    TerminalBody::Ready { body, provenance } => (body, provenance),
                    TerminalBody::ProviderDenied { provenance } => {
                        return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                            common: DecidedRequest {
                                headers,
                                _body_guard: guard,
                            },
                            _rule: Some(matched),
                            _reason: DenyReason::ProviderBodyLimit,
                            body_provenance: provenance,
                            body: None,
                        })));
                    }
                    TerminalBody::RedactionDenied { provenance } => {
                        return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                            common: DecidedRequest {
                                headers,
                                _body_guard: guard,
                            },
                            _rule: Some(matched),
                            _reason: DenyReason::RedactionFailure,
                            body_provenance: provenance,
                            body: None,
                        })));
                    }
                };
                let provider_credentials = credentials
                    .as_ref()
                    .map(|credentials| {
                        lease.authorization().stage_provider_credentials(
                            provider,
                            credentials,
                            &guard,
                        )
                    })
                    .transpose()
                    .map_err(|source| {
                        provider_credential_injection_error(source, selected_provenance)
                    })?;
                drop(credentials);
                let (body, body_provenance) = match redact_terminal_body(
                    lease,
                    Some(&matched),
                    &guard,
                    body,
                    selected_provenance,
                )? {
                    TerminalBody::Ready { body, provenance } => (body, provenance),
                    TerminalBody::ProviderDenied { .. } => {
                        unreachable!("redaction does not enforce provider limits")
                    }
                    TerminalBody::RedactionDenied { provenance } => {
                        return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                            common: DecidedRequest {
                                headers,
                                _body_guard: guard,
                            },
                            _rule: Some(matched),
                            _reason: DenyReason::RedactionFailure,
                            body_provenance: provenance,
                            body: None,
                        })));
                    }
                };
                return Ok(RequestDecision::Allow(Box::new(AllowedRequest {
                    common: DecidedRequest {
                        headers,
                        _body_guard: guard,
                    },
                    rule: Some(matched),
                    provider_credentials,
                    upgrade,
                    body,
                    body_provenance,
                })));
            }
            AuthorizationDecision::Deny => {
                let body = denied_observation_body(body, body_provenance);
                return Ok(RequestDecision::Deny(Box::new(DeniedRequest {
                    common: DecidedRequest {
                        headers,
                        _body_guard: guard,
                    },
                    _rule: Some(matched),
                    _reason: DenyReason::Provider,
                    body_provenance,
                    body,
                })));
            }
            AuthorizationDecision::Pass => {
                evaluation = matched.resume_cursor().resume(
                    input.facts.url(),
                    input.peer_ip,
                    input.facts.method(),
                    &headers,
                    |name| inbound.is_present(name),
                );
            }
        }
    }
}

fn upgrade_is_disallowed(upgrade_intent: bool, evaluation: &PolicyEvaluation<'_>) -> bool {
    upgrade_intent
        && evaluation.outcome != PolicyOutcome::Deny
        && !evaluation
            .matched
            .as_ref()
            .is_some_and(PolicyRuleMatch::allows_upgrades)
}

fn bind_upgrade(
    lease: &GenerationLease,
    upgrade_intent: bool,
    rule: Option<&PolicyRuleMatch<'_>>,
) -> Result<Option<UpgradeBinding>, RequestDecisionError> {
    if !upgrade_intent {
        return Ok(None);
    }
    let rule = rule.ok_or(RequestDecisionError::MissingUpgradeAllocation)?;
    let compiled_wire_bytes = lease
        .resource_plan()
        .upgrade_wire_working_set_bytes_by_rule
        .get(rule.index())
        .copied()
        .flatten();
    let allocation = UpgradeAllocation::from_compiled_rule(rule.index(), compiled_wire_bytes)
        .map_err(|_| RequestDecisionError::MissingUpgradeAllocation)?;
    let wire_redaction = rule
        .redaction_profile()
        .map(|profile| {
            lease
                .redaction()
                .profile(profile)
                .ok_or(RequestDecisionError::MissingRedactionProfile)
        })
        .transpose()?;
    Ok(Some(UpgradeBinding {
        allocation,
        wire_redaction,
    }))
}

fn denied_observation_body(
    body: Option<GuardedRequestBody>,
    provenance: TerminalRequestBodyProvenance,
) -> Option<GuardedRequestBody> {
    match provenance {
        TerminalRequestBodyProvenance::CompleteOriginal
        | TerminalRequestBodyProvenance::CompleteWireRedacted => body,
        TerminalRequestBodyProvenance::Unconsumed
        | TerminalRequestBodyProvenance::ProviderReplacement { .. } => None,
    }
}

fn provider_credential_injection_error(
    source: ProviderCredentialInjectionError,
    body_provenance: TerminalRequestBodyProvenance,
) -> RequestDecisionError {
    RequestDecisionError::ProviderCredentialInjection {
        source,
        body_provenance,
    }
}

enum TerminalBody {
    Ready {
        body: Option<GuardedRequestBody>,
        provenance: TerminalRequestBodyProvenance,
    },
    ProviderDenied {
        provenance: TerminalRequestBodyProvenance,
    },
    RedactionDenied {
        provenance: TerminalRequestBodyProvenance,
    },
}

#[derive(Clone, Copy)]
struct TerminalBodyLimits {
    provider: usize,
    redaction: usize,
}

impl TerminalBodyLimits {
    fn unbounded() -> Self {
        Self {
            provider: usize::MAX,
            redaction: usize::MAX,
        }
    }
}

fn select_terminal_body(
    guard: &HttpWireBodyGuard,
    mut body: Option<GuardedRequestBody>,
    mut provenance: TerminalRequestBodyProvenance,
    replacement: Option<ProviderBodyReplacement>,
    limits: TerminalBodyLimits,
) -> Result<TerminalBody, RequestDecisionError> {
    if let Some(replacement) = replacement {
        let size = replacement.decoded_size();
        provenance = TerminalRequestBodyProvenance::ProviderReplacement { size };
        drop(body.take());
        let (content_type, content_encoding, decoded) =
            match replacement.decode_with_limits(guard, limits.provider, limits.redaction) {
                Ok(decoded) => decoded,
                Err(ProviderBodyReplacementDecodeError::ProviderBodyLimit) => {
                    return Ok(TerminalBody::ProviderDenied { provenance })
                }
                Err(ProviderBodyReplacementDecodeError::RedactionBodyLimit) => {
                    return Ok(TerminalBody::RedactionDenied { provenance })
                }
                Err(ProviderBodyReplacementDecodeError::InvalidBody) => {
                    return Err(RequestDecisionError::ProviderReplacementDecode {
                        body_provenance: provenance,
                    })
                }
            };
        body = Some(GuardedRequestBody {
            content_type,
            content_encoding,
            encoded_len: decoded.len(),
            decoded,
        });
    }
    Ok(TerminalBody::Ready { body, provenance })
}

fn terminal_decoded_body_limits(
    lease: &GenerationLease,
    rule: Option<&PolicyRuleMatch<'_>>,
    provider_limit: usize,
) -> Result<TerminalBodyLimits, RequestDecisionError> {
    let Some(profile_index) = rule.and_then(PolicyRuleMatch::redaction_profile) else {
        return Ok(TerminalBodyLimits {
            provider: provider_limit,
            redaction: usize::MAX,
        });
    };
    let Some(profile) = lease.redaction().profile(profile_index) else {
        return Err(RequestDecisionError::MissingRedactionProfile);
    };
    Ok(TerminalBodyLimits {
        provider: provider_limit,
        redaction: profile.limits().max_decoded_body_bytes,
    })
}

fn redact_terminal_body(
    lease: &GenerationLease,
    rule: Option<&PolicyRuleMatch<'_>>,
    guard: &HttpWireBodyGuard,
    mut body: Option<GuardedRequestBody>,
    mut provenance: TerminalRequestBodyProvenance,
) -> Result<TerminalBody, RequestDecisionError> {
    let Some(profile_index) = rule.and_then(PolicyRuleMatch::redaction_profile) else {
        return Ok(TerminalBody::Ready { body, provenance });
    };
    let Some(profile) = lease.redaction().profile(profile_index) else {
        return Err(RequestDecisionError::MissingRedactionProfile);
    };
    let Some(current) = body.take() else {
        return Ok(TerminalBody::Ready { body, provenance });
    };
    let redacted = match profile.redact_guarded_decoded_http_body(guard, current.decoded) {
        Ok(redacted) => redacted,
        Err(_) => return Ok(TerminalBody::RedactionDenied { provenance }),
    };
    if !matches!(
        provenance,
        TerminalRequestBodyProvenance::ProviderReplacement { .. }
    ) {
        provenance = TerminalRequestBodyProvenance::CompleteWireRedacted;
    }
    body = Some(GuardedRequestBody {
        content_type: current.content_type,
        content_encoding: current.content_encoding,
        encoded_len: current.encoded_len,
        decoded: redacted.body,
    });
    Ok(TerminalBody::Ready { body, provenance })
}

fn validate_local_body_limits(
    lease: &GenerationLease,
    rule: &PolicyRuleMatch<'_>,
    provider: Option<crate::authorization::AuthorizationProviderMetadata<'_>>,
    body: Option<&GuardedRequestBody>,
) -> Result<Option<DenyReason>, RequestDecisionError> {
    let Some(body) = body else {
        return Ok(None);
    };
    if provider.is_some_and(|provider| {
        provider.include_request_body
            && (body.encoded_len > provider.max_request_body_bytes
                || body.decoded.len() > provider.max_decoded_request_body_bytes)
    }) {
        return Ok(Some(DenyReason::ProviderBodyLimit));
    }
    let Some(profile_index) = rule.redaction_profile() else {
        return Ok(None);
    };
    let profile = lease
        .redaction()
        .profile(profile_index)
        .ok_or(RequestDecisionError::MissingRedactionProfile)?;
    let limits = profile.limits();
    Ok((body.encoded_len > limits.max_body_bytes
        || body.decoded.len() > limits.max_decoded_body_bytes)
        .then_some(DenyReason::RedactionFailure))
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
    use std::collections::{BTreeMap, VecDeque};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use http::header::HeaderValue;
    use http::Method;
    use http_access_types::{BodyFraming, BodyMetadata, HttpMethod, IngressMode, UpgradeIntent};

    use super::*;
    use crate::activation::static_resources::ProductStaticResources;
    use crate::authorization::protocol::ProviderOutputRegistry;
    use crate::config::compiler::ProviderOutputPlan;
    use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput};
    use crate::runtime::{
        ActivationCancellation, BoxFuture, CandidateSource, ReloadTriggerResult, Runtime,
        RuntimeError, StaticOwnership,
    };
    use http_access_url::{canonicalize_http_url, CanonicalUrl};

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

    fn input<'generation, 'request>(
        lease: &'generation GenerationLease,
        request_id: &'request str,
        url: &CanonicalUrl,
        mut headers: HeaderMap,
    ) -> RequestInput<'generation, 'request> {
        let peer_ip = "192.0.2.10".parse().unwrap();
        let shape = crate::proxy::facts::validate_request_fact_shape(
            IngressMode::ExplicitHttps,
            http::Version::HTTP_11,
            &Method::GET,
            url.clone(),
            &headers,
            BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap();
        RequestInput::from_validated_shape(
            lease,
            request_id,
            shape,
            &mut headers,
            peer_ip,
            WireBodyQuotaKey::from_peer(peer_ip, |_| false),
            Instant::now(),
        )
        .unwrap()
    }

    fn upgrade_input<'generation, 'request>(
        lease: &'generation GenerationLease,
        request_id: &'request str,
        url: &CanonicalUrl,
        headers: HeaderMap,
    ) -> RequestInput<'generation, 'request> {
        let mut input = input(lease, request_id, url, headers);
        input.facts = InterceptedRequestFacts::new(
            input.facts.ingress_mode(),
            input.facts.version(),
            input.facts.method().clone(),
            input.facts.url().clone(),
            input.facts.headers().to_vec(),
            input.facts.body(),
            Some(UpgradeIntent::WebSocket),
        )
        .unwrap();
        input
    }

    #[test]
    fn replacement_decode_resource_failure_preserves_omission_provenance() {
        let allocation = crate::safety::wire_body::guarded_body_allocation_bytes(1).unwrap();
        let pool = crate::safety::WireBodyPool::new(2 * allocation, allocation);
        let first_key = WireBodyQuotaKey::from_peer("192.0.2.1".parse().unwrap(), |_| false);
        let second_key = WireBodyQuotaKey::from_peer("192.0.2.2".parse().unwrap(), |_| false);
        let first = pool.begin_for_test(allocation, first_key);
        let second = pool.begin_for_test(allocation, second_key);
        let mut decoded = first.buffer();
        decoded.try_extend_from_slice(b"secret").unwrap();
        let replacement = ProviderBodyReplacement::from_decoded_for_test(decoded.finish());

        let error = match select_terminal_body(
            &second,
            None,
            TerminalRequestBodyProvenance::Unconsumed,
            Some(replacement),
            TerminalBodyLimits::unbounded(),
        ) {
            Ok(_) => panic!("a replacement owned by another guard must fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            RequestDecisionError::ProviderReplacementDecode { .. }
        ));
        assert_eq!(
            error.body_provenance(),
            Some(TerminalRequestBodyProvenance::ProviderReplacement { size: 6 })
        );
        assert!(!format!("{error:?} {error}").contains("secret"));
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn credential_staging_failure_after_replacement_preserves_omission_provenance() {
        let allocation = crate::safety::wire_body::guarded_body_allocation_bytes(1).unwrap();
        let pool = crate::safety::WireBodyPool::new(allocation, allocation);
        let key = WireBodyQuotaKey::from_peer("192.0.2.3".parse().unwrap(), |_| false);
        let guard = pool.begin_for_test(allocation, key);
        let mut decoded = guard.buffer();
        decoded.try_extend_from_slice(b"replacement").unwrap();
        let replacement = ProviderBodyReplacement::from_decoded_for_test(decoded.finish());
        let TerminalBody::Ready { body, provenance } = select_terminal_body(
            &guard,
            None,
            TerminalRequestBodyProvenance::Unconsumed,
            Some(replacement),
            TerminalBodyLimits::unbounded(),
        )
        .unwrap() else {
            panic!("the same-guard replacement must be selected");
        };
        assert_eq!(
            provenance,
            TerminalRequestBodyProvenance::ProviderReplacement { size: 11 }
        );

        let outputs = ProviderOutputRegistry::activate(BTreeMap::from([(
            "token".to_owned(),
            ProviderOutputPlan::Bearer { required: true },
        )]));
        let index = outputs.index("token").unwrap();
        let credentials = outputs.single_credential_for_test(index, b"secret-marker");
        let source = outputs.stage_credentials(&credentials, &guard).unwrap_err();
        assert_eq!(source, ProviderCredentialInjectionError::AllocationFailed);
        let error = provider_credential_injection_error(source, provenance);
        assert_eq!(error.body_provenance(), Some(provenance));
        assert!(!format!("{error:?} {error}").contains("secret-marker"));

        for provenance in [
            TerminalRequestBodyProvenance::Unconsumed,
            TerminalRequestBodyProvenance::CompleteOriginal,
        ] {
            let error = provider_credential_injection_error(
                ProviderCredentialInjectionError::InvalidCredential,
                provenance,
            );
            assert_eq!(error.body_provenance(), Some(provenance));
        }

        drop(body);
        assert_eq!(pool.global_charge(), 0);
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

        let request_input = input(&old, "before", &url, headers);
        assert!(request_input
            .facts
            .headers()
            .iter()
            .all(|field| field.name().as_str() != "x-test-identity"));
        assert!(!format!("{:?}", request_input.facts).contains("secret"));
        assert!(request_input
            .inbound
            .is_present(&HeaderName::from_static("x-test-identity")));
        assert!(request_input
            .internal_context
            .contains_key("x-internal-context"));

        let RequestDecision::Allow(allowed) = decide_request(&old, request_input).await.unwrap()
        else {
            panic!("the captured inbound credential should satisfy policy");
        };
        assert_eq!(allowed.rule.as_ref().unwrap().id(), "credential-present");
        assert_eq!(
            allowed.body_provenance,
            TerminalRequestBodyProvenance::Unconsumed
        );
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

        let RequestDecision::Deny(old_decision) = decide_request(
            &old,
            input(&old, "old-after-reload", &url, HeaderMap::new()),
        )
        .await
        .unwrap() else {
            panic!("the retained generation still has its deny default");
        };
        assert_eq!(old_decision._reason, DenyReason::Policy);
        assert_eq!(
            old_decision.body_provenance,
            TerminalRequestBodyProvenance::Unconsumed
        );
        drop(old_decision);

        let current = runtime.lease().await.unwrap();
        let RequestDecision::Allow(current_decision) = decide_request(
            &current,
            input(&current, "current-after-reload", &url, HeaderMap::new()),
        )
        .await
        .unwrap() else {
            panic!("the current generation has its allow default");
        };
        assert!(current_decision.rule.is_none());
        assert_eq!(
            current_decision.body_provenance,
            TerminalRequestBodyProvenance::Unconsumed
        );
        drop(current_decision);
        drop(current);
        drop(old);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn prepared_request_exposes_cursor_body_plan_but_early_deny_stays_body_free() {
        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "body-aware"
decision = "allow"
methods = ["GET"]
redaction_profile = "wire""#,
            r#"[redaction.profiles.wire]
max_body_bytes = 16
max_decoded_body_bytes = 32
rules = [{ literals = ["secret"], payloads = "text" }]"#,
        ));
        let (runtime, _source, _, _pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/body").unwrap();

        let prepared =
            prepare_request(&lease, input(&lease, "ordinary", &url, HeaderMap::new())).unwrap();
        assert!(!prepared.denies_without_resolution());
        assert_eq!(
            prepared
                .body_read_plan()
                .limits()
                .map(|limits| (limits.max_encoded_bytes(), limits.max_decoded_bytes())),
            Some((16, 32))
        );
        drop(prepared);

        let mut looped_headers = HeaderMap::new();
        looped_headers.insert("x-test-loop", HeaderValue::from_static("already-seen"));
        let looped =
            prepare_request(&lease, input(&lease, "looped", &url, looped_headers)).unwrap();
        assert!(looped.denies_without_resolution());
        assert_eq!(looped.body_read_plan(), HttpBodyReadPlan::Disabled);
        let RequestDecision::Deny(denied) = looped.decide(None).await.unwrap() else {
            panic!("a loop-marked request must deny without reading its body");
        };
        assert_eq!(denied._reason, DenyReason::LoopDetected);
        assert_eq!(
            denied.body_provenance,
            TerminalRequestBodyProvenance::Unconsumed
        );

        drop(denied);
        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn default_allow_does_not_authorize_an_upgrade() {
        let initial = compile(&config(
            r#"[policy]
default = "allow""#,
            "",
        ));
        let (runtime, _source, _, _pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/socket").unwrap();

        let prepared = prepare_request(
            &lease,
            upgrade_input(&lease, "default-allow-upgrade", &url, HeaderMap::new()),
        )
        .unwrap();
        assert!(prepared.denies_without_resolution());
        assert_eq!(prepared.body_read_plan(), HttpBodyReadPlan::Disabled);
        let RequestDecision::Deny(denied) = prepared.decide(None).await.unwrap() else {
            panic!("default allow must not authorize an upgrade");
        };
        assert_eq!(denied._reason, DenyReason::Policy);
        assert!(denied._rule.is_none());

        drop(denied);
        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn opted_in_rule_binds_compiled_upgrade_resources() {
        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "socket"
decision = "allow"
methods = ["GET"]
allow_upgrades = true
redaction_profile = "wire""#,
            r#"[redaction.profiles.wire]
max_message_bytes = 1048576
allow_permessage_deflate = false
rules = [{ literals = ["secret"] }]"#,
        ));
        let (runtime, _source, _, _pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/socket").unwrap();

        let RequestDecision::Allow(allowed) = decide_request(
            &lease,
            upgrade_input(&lease, "bound-upgrade", &url, HeaderMap::new()),
        )
        .await
        .unwrap() else {
            panic!("the opted-in rule must authorize the upgrade");
        };
        let binding = allowed.upgrade.as_ref().expect("upgrade binding");
        assert_eq!(binding.allocation.rule_index(), 0);
        assert!(binding.allocation.wire_bytes() > 0);
        assert!(binding.wire_redaction.is_some());

        drop(allowed);
        drop(lease);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delegate_without_upgrade_opt_in_denies_before_provider_dispatch() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("provider-dispatched");
        let provider = directory.path().join("provider.sh");
        std::fs::write(
            &provider,
            format!(
                r#"#!/bin/sh
while IFS= read -r line; do
  printf x >> "{}"
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{{"id":"%s","type":"response","decision":"allow"}}\n' "$id"
done
"#,
                marker.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&provider).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&provider, permissions).unwrap();

        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "ordinary-delegate"
decision = "delegate"
methods = ["GET"]
authorization_provider = "provider""#,
            &format!(
                r#"[authorization.providers.provider]
kind = "process"
command = "{}"
retire_timeout = "6s""#,
                provider.display()
            ),
        ));
        let (runtime, _source, _, _pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/socket").unwrap();

        let RequestDecision::Deny(denied) = decide_request(
            &lease,
            upgrade_input(&lease, "delegate-upgrade", &url, HeaderMap::new()),
        )
        .await
        .unwrap() else {
            panic!("a delegate rule without upgrade opt-in must deny");
        };
        assert_eq!(denied._reason, DenyReason::Policy);
        assert_eq!(denied._rule.as_ref().unwrap().id(), "ordinary-delegate");
        assert!(!marker.exists(), "provider dispatch must not begin");

        drop(denied);
        drop(lease);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn merged_suffix_profile_limit_denies_before_provider_dispatch() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("provider-dispatched");
        let provider = directory.path().join("provider.sh");
        std::fs::write(
            &provider,
            format!(
                r#"#!/bin/sh
while IFS= read -r line; do
  printf x >> "{}"
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{{"id":"%s","type":"response","decision":"allow"}}\n' "$id"
done
"#,
                marker.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&provider).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&provider, permissions).unwrap();

        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "strict-profile"
decision = "delegate"
methods = ["GET"]
authorization_provider = "generous"
redaction_profile = "strict"

[[policy.rules]]
id = "larger-suffix"
decision = "delegate"
methods = ["GET"]
authorization_provider = "larger""#,
            &format!(
                r#"[authorization.providers.generous]
kind = "process"
command = "{}"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 16
max_decoded_request_body_bytes = 16

[authorization.providers.larger]
kind = "process"
command = "/bin/cat"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 16
max_decoded_request_body_bytes = 16

[redaction.profiles.strict]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{{ literals = ["x"] }}]"#,
                provider.display()
            ),
        ));
        let (runtime, _source, _, pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/profile-limit").unwrap();
        let prepared = prepare_request(
            &lease,
            input(&lease, "profile-limit", &url, HeaderMap::new()),
        )
        .expect("the suffix cursor prepares");
        assert_eq!(
            prepared
                .body_read_plan()
                .limits()
                .map(|limits| (limits.max_encoded_bytes(), limits.max_decoded_bytes())),
            Some((16, 16))
        );
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"xx").unwrap();

        let RequestDecision::Deny(mut denied) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: Some("identity".into()),
                encoded_len: 2,
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("the current profile limit must deny");
        };
        assert_eq!(denied._reason, DenyReason::RedactionFailure);
        assert_eq!(
            denied.body_provenance,
            TerminalRequestBodyProvenance::CompleteOriginal
        );
        assert_eq!(denied._rule.as_ref().unwrap().id(), "strict-profile");
        assert!(!marker.exists(), "provider dispatch must not begin");
        let retained = denied.take_body_for_observation().unwrap();
        assert_eq!(retained.decoded.len(), 2);
        assert_eq!(retained.encoded_len, 2);
        assert!(denied.take_body_for_observation().is_none());
        drop(retained);
        drop(denied);
        assert_eq!(pool.global_charge(), 0);

        drop(lease);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resumed_cursor_enforces_provider_encoded_limit_before_dispatch() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let pass_marker = directory.path().join("pass-dispatched");
        let denied_marker = directory.path().join("denied-dispatched");
        let pass_provider = directory.path().join("pass.sh");
        let denied_provider = directory.path().join("denied.sh");
        for (path, marker, decision) in [
            (&pass_provider, &pass_marker, "pass"),
            (&denied_provider, &denied_marker, "allow"),
        ] {
            std::fs::write(
                path,
                format!(
                    r#"#!/bin/sh
while IFS= read -r line; do
  printf x >> "{}"
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{{"id":"%s","type":"response","decision":"{}"}}\n' "$id"
done
"#,
                    marker.display(),
                    decision
                ),
            )
            .unwrap();
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(path, permissions).unwrap();
        }

        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "pass-first"
decision = "delegate"
methods = ["GET"]
authorization_provider = "pass"

[[policy.rules]]
id = "strict-encoded"
decision = "delegate"
methods = ["GET"]
authorization_provider = "strict"

[[policy.rules]]
id = "larger-suffix"
decision = "delegate"
methods = ["GET"]
authorization_provider = "larger""#,
            &format!(
                r#"[authorization.providers.pass]
kind = "process"
command = "{}"
retire_timeout = "6s"

[authorization.providers.strict]
kind = "process"
command = "{}"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 16

[authorization.providers.larger]
kind = "process"
command = "/bin/cat"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 16
max_decoded_request_body_bytes = 16"#,
                pass_provider.display(),
                denied_provider.display()
            ),
        ));
        let (runtime, _source, _, pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/resumed-limit").unwrap();
        let prepared = prepare_request(
            &lease,
            input(&lease, "resumed-limit", &url, HeaderMap::new()),
        )
        .expect("the suffix cursor prepares");
        assert_eq!(
            prepared
                .body_read_plan()
                .limits()
                .map(|limits| (limits.max_encoded_bytes(), limits.max_decoded_bytes())),
            Some((16, 16))
        );
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"x").unwrap();

        let RequestDecision::Deny(mut denied) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: Some("identity".into()),
                encoded_len: 2,
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("the resumed provider encoded limit must deny");
        };
        assert_eq!(denied._reason, DenyReason::ProviderBodyLimit);
        assert_eq!(
            denied.body_provenance,
            TerminalRequestBodyProvenance::CompleteOriginal
        );
        assert_eq!(denied._rule.as_ref().unwrap().id(), "strict-encoded");
        assert_eq!(std::fs::read(&pass_marker).unwrap(), b"x");
        assert!(
            !denied_marker.exists(),
            "rejected provider must not dispatch"
        );
        let retained = denied.take_body_for_observation().unwrap();
        assert_eq!(retained.decoded.len(), 1);
        assert_eq!(retained.encoded_len, 2);
        drop(retained);
        drop(denied);
        assert_eq!(pool.global_charge(), 0);

        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn terminal_allow_enforces_profile_encoded_limit_before_redaction() {
        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "strict-terminal"
decision = "allow"
methods = ["GET"]
redaction_profile = "strict"

[[policy.rules]]
id = "larger-suffix"
decision = "allow"
methods = ["POST"]
redaction_profile = "larger""#,
            r#"[redaction.profiles.strict]
max_body_bytes = 1
max_decoded_body_bytes = 16
rules = [{ literals = ["x"] }]

[redaction.profiles.larger]
max_body_bytes = 16
max_decoded_body_bytes = 16
rules = [{ literals = ["x"] }]"#,
        ));
        let (runtime, _source, _, pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/terminal-limit").unwrap();
        let prepared = prepare_request(
            &lease,
            input(&lease, "terminal-limit", &url, HeaderMap::new()),
        )
        .expect("the suffix cursor prepares");
        assert_eq!(
            prepared
                .body_read_plan()
                .limits()
                .map(|limits| (limits.max_encoded_bytes(), limits.max_decoded_bytes())),
            Some((16, 16))
        );
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"x").unwrap();

        let RequestDecision::Deny(mut denied) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: Some("identity".into()),
                encoded_len: 2,
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("the terminal profile encoded limit must deny");
        };
        assert_eq!(denied._reason, DenyReason::RedactionFailure);
        assert_eq!(
            denied.body_provenance,
            TerminalRequestBodyProvenance::CompleteOriginal
        );
        assert_eq!(denied._rule.as_ref().unwrap().id(), "strict-terminal");
        let retained = denied.take_body_for_observation().unwrap();
        assert_eq!(retained.decoded.len(), 1);
        assert_eq!(retained.encoded_len, 2);
        drop(retained);
        drop(denied);
        assert_eq!(pool.global_charge(), 0);

        let prepared = prepare_request(
            &lease,
            input(&lease, "terminal-within-limit", &url, HeaderMap::new()),
        )
        .unwrap();
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"x").unwrap();
        let RequestDecision::Allow(allowed) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: Some("identity".into()),
                encoded_len: 1,
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("the exact encoded boundary must redact and allow");
        };
        assert_eq!(allowed.body.as_ref().unwrap().encoded_len, 1);
        assert_eq!(
            allowed.body_provenance,
            TerminalRequestBodyProvenance::CompleteWireRedacted
        );
        drop(allowed);
        assert_eq!(pool.global_charge(), 0);

        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn initial_policy_match_owns_the_immutable_request_deadline() {
        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "first-delegate"
decision = "delegate"
methods = ["GET"]
request_timeout = "2s"
authorization_provider = "approval"

[[policy.rules]]
id = "later-allow"
decision = "allow"
methods = ["GET"]
request_timeout = "9s""#,
            r#"[authorization.providers.approval]
kind = "process"
command = "/bin/cat"
timeout = "1s"
retire_timeout = "10s""#,
        ));
        let (runtime, _source, _, _pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/deadline").unwrap();
        let started_at = Instant::now();
        let mut request = input(&lease, "deadline", &url, HeaderMap::new());
        request.started_at = started_at;

        let prepared = prepare_request(&lease, request).unwrap();

        assert_eq!(prepared.deadline(), started_at + Duration::from_secs(2));
        assert!(!prepared.denies_without_resolution());
        drop(prepared);

        let default_started_at = Instant::now();
        let mut unmatched = input(&lease, "default-deadline", &url, HeaderMap::new());
        unmatched.facts = InterceptedRequestFacts::new(
            unmatched.facts.ingress_mode(),
            unmatched.facts.version(),
            HttpMethod::new(Method::POST.as_str()).unwrap(),
            unmatched.facts.url().clone(),
            unmatched.facts.headers().to_vec(),
            unmatched.facts.body(),
            unmatched.facts.upgrade().cloned(),
        )
        .unwrap();
        unmatched.started_at = default_started_at;
        let prepared = prepare_request(&lease, unmatched).unwrap();
        assert_eq!(
            prepared.deadline(),
            default_started_at + Duration::from_secs(5)
        );
        assert!(prepared.denies_without_resolution());
        drop(prepared);
        drop(lease);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delegate_outcome_and_default_fallthrough_corpus() {
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
urls = [
  "https://example.test/allow",
  "https://example.test/deny",
  "https://example.test/exact-body",
]
authorization_provider = "terminal""#;
        let initial = compile(&config(policy, &providers));
        let (runtime, _source, _, pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();

        for (path, expected_allow) in [("allow", true), ("deny", false)] {
            let url = canonicalize_http_url(&format!("https://example.test/{path}")).unwrap();
            let decision = decide_request(&lease, input(&lease, path, &url, HeaderMap::new()))
                .await
                .unwrap();
            match (decision, expected_allow) {
                (RequestDecision::Allow(allowed), true) => {
                    assert_eq!(allowed.rule.as_ref().unwrap().id(), "terminal");
                    assert_eq!(
                        allowed.body_provenance,
                        TerminalRequestBodyProvenance::CompleteOriginal
                    );
                    assert!(allowed.common._body_guard.cursor_peak_bytes() > 0);
                }
                (RequestDecision::Deny(mut denied), false) => {
                    assert_eq!(denied._rule.as_ref().unwrap().id(), "terminal");
                    assert_eq!(denied._reason, DenyReason::Provider);
                    assert_eq!(
                        denied.body_provenance,
                        TerminalRequestBodyProvenance::CompleteOriginal
                    );
                    assert!(denied.common._body_guard.cursor_peak_bytes() > 0);
                    let retained = denied.take_body_for_observation().unwrap();
                    assert_eq!(retained.decoded.len(), 0);
                }
                _ => panic!("unexpected terminal provider decision"),
            }
        }

        let url = canonicalize_http_url("https://example.test/exact-body").unwrap();
        let prepared =
            prepare_request(&lease, input(&lease, "exact-body", &url, HeaderMap::new())).unwrap();
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"exact-body").unwrap();
        let RequestDecision::Allow(allowed) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: None,
                encoded_len: b"exact-body".len(),
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("both providers must observe the exact preserved body");
        };
        assert_eq!(allowed.rule.as_ref().unwrap().id(), "terminal");
        assert_eq!(
            allowed.body_provenance,
            TerminalRequestBodyProvenance::CompleteOriginal
        );
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

        let url = canonicalize_http_url("https://example.test/default-deny").unwrap();
        let RequestDecision::Deny(mut default) = decide_request(
            &lease,
            input(&lease, "default-deny", &url, HeaderMap::new()),
        )
        .await
        .unwrap() else {
            panic!("provider pass must resume through the deny default");
        };
        assert!(default._rule.is_none());
        assert_eq!(default._reason, DenyReason::Policy);
        assert_eq!(
            default.body_provenance,
            TerminalRequestBodyProvenance::CompleteOriginal
        );
        let retained = default.take_body_for_observation().unwrap();
        assert_eq!(retained.decoded.len(), 0);
        drop(retained);
        drop(default);
        assert_eq!(pool.global_charge(), 0);

        drop(lease);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_failure_denial_retains_complete_original_body() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let provider = directory.path().join("invalid-response.sh");
        std::fs::write(
            &provider,
            r#"#!/bin/sh
while IFS= read -r line; do
  printf 'not-json\n'
done
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&provider).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&provider, permissions).unwrap();

        let initial = compile(&config(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "provider-failure"
decision = "delegate"
methods = ["GET"]
authorization_provider = "invalid""#,
            &format!(
                r#"[authorization.providers.invalid]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
on_failure = "deny"
include_request_body = true
max_request_body_bytes = 128
max_decoded_request_body_bytes = 128"#,
                provider.display()
            ),
        ));
        let (runtime, _source, _, pool) = runtime(initial).await;
        let lease = runtime.lease().await.unwrap();
        let url = canonicalize_http_url("https://example.test/provider-failure").unwrap();
        let prepared = prepare_request(
            &lease,
            input(&lease, "provider-failure", &url, HeaderMap::new()),
        )
        .unwrap();
        let mut decoded = prepared.body_guard().buffer();
        decoded.try_extend_from_slice(b"failure-body").unwrap();

        let RequestDecision::Deny(mut denied) = prepared
            .decide(Some(GuardedRequestBody {
                content_type: Some("text/plain".into()),
                content_encoding: None,
                encoded_len: b"failure-body".len(),
                decoded: decoded.finish(),
            }))
            .await
            .unwrap()
        else {
            panic!("the configured provider failure mode must deny");
        };
        assert_eq!(denied._reason, DenyReason::ProviderFailure);
        assert_eq!(
            denied.body_provenance,
            TerminalRequestBodyProvenance::CompleteOriginal
        );
        let retained = denied.take_body_for_observation().unwrap();
        assert_eq!(
            retained
                .decoded
                .segments()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"failure-body"
        );
        drop(retained);
        drop(denied);
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
            let expected_cursor_peak = initial
                .reloadable_plan
                .resource_plan
                .http_wire_body_peak_bytes_by_cursor[0];
            let (runtime, _source, _, pool) = runtime(initial).await;
            let lease = runtime.lease().await.unwrap();
            let url = canonicalize_http_url("https://example.test/replacement").unwrap();
            let prepared =
                prepare_request(&lease, input(&lease, "replacement", &url, HeaderMap::new()))
                    .unwrap();
            let one_guarded_chunk =
                crate::safety::wire_body::guarded_body_allocation_bytes(1).unwrap();
            assert_eq!(
                prepared.body_guard().cursor_peak_bytes(),
                expected_cursor_peak,
                "the runtime guard must preserve the compiler's exact terminal peak"
            );
            assert!(
                expected_cursor_peak >= 4 * one_guarded_chunk,
                "the compiled terminal peak must retain compact guarded credentials beside decoded input, matcher scratch, and redacted output"
            );
            let mut original = prepared.body_guard().buffer();
            original.try_extend_from_slice(b"x").unwrap();
            let decision = prepared
                .decide(Some(GuardedRequestBody {
                    content_type: Some("text/plain".into()),
                    content_encoding: None,
                    encoded_len: 1,
                    decoded: original.finish(),
                }))
                .await
                .unwrap();

            if expect_allow {
                let RequestDecision::Allow(mut allowed) = decision else {
                    panic!("bounded replacement must be allowed");
                };
                assert_eq!(
                    allowed.body_provenance,
                    TerminalRequestBodyProvenance::ProviderReplacement {
                        size: b"replacement secret".len()
                    }
                );
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
                let RequestDecision::Deny(mut denied) = decision else {
                    panic!("replacement redaction limit failure must deny");
                };
                assert_eq!(denied._reason, DenyReason::RedactionFailure);
                assert_eq!(
                    denied.body_provenance,
                    TerminalRequestBodyProvenance::ProviderReplacement {
                        size: b"replacement secret".len()
                    }
                );
                assert_eq!(denied._rule.as_ref().unwrap().id(), "replace");
                assert!(denied
                    .common
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .is_none());
                assert!(denied.take_body_for_observation().is_none());
                drop(denied);
            }
            assert_eq!(pool.global_charge(), 0);
            drop(lease);
            runtime.shutdown().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_and_profile_limits_classify_multichunk_replacement_before_decode() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let provider = directory.path().join("large-replacement.sh");
        let encoded = BASE64_STANDARD.encode(vec![b'x'; 64 * 1024 + 1]);
        let script = r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{"id":"%s","type":"response","decision":"allow","requestBody":{"encoding":"base64","contentType":"text/plain","data":"__DATA__"}}\n' "$id"
done
"#
        .replace("__DATA__", &encoded);
        std::fs::write(&provider, script).unwrap();
        let mut permissions = std::fs::metadata(&provider).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&provider, permissions).unwrap();

        for (provider_limit, redaction_limit, expected_reason) in [
            (64 * 1024, 131_072, DenyReason::ProviderBodyLimit),
            (131_072, 1, DenyReason::RedactionFailure),
        ] {
            let extra = format!(
                r#"[authorization.providers.replacing]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = {provider_limit}
max_decoded_request_body_bytes = {provider_limit}
max_stdout_line_bytes = 100000

[redaction.profiles.wire]
max_body_bytes = {redaction_limit}
max_decoded_body_bytes = {redaction_limit}
rules = [{{ literals = ["x"], payloads = "text" }}]"#,
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

            let decision =
                decide_request(&lease, input(&lease, "replacement", &url, HeaderMap::new()))
                    .await
                    .expect("a replacement limit is a terminal denial, not a provider failure");
            let RequestDecision::Deny(mut denied) = decision else {
                panic!("the over-limit replacement must deny");
            };
            assert_eq!(denied._reason, expected_reason);
            assert_eq!(
                denied.body_provenance,
                TerminalRequestBodyProvenance::ProviderReplacement {
                    size: 64 * 1024 + 1
                }
            );
            assert_eq!(denied._rule.as_ref().unwrap().id(), "replace");
            assert!(denied.take_body_for_observation().is_none());
            drop(denied);
            assert_eq!(pool.global_charge(), 0);

            drop(lease);
            runtime.shutdown().await;
        }
    }
}
