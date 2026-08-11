use std::collections::BTreeMap;

use access_identity::{IdentityState, IdentitySubject};
use serde::Serialize;

use super::compiler::{
    AuthorizationProviderPlan, CompiledDefaultDecision, CompiledHeaderEffectWhen,
    CompiledRuleDecision, CompiledTransportSecurity, CredentialActionPlan, HeaderEffectPlan,
    HeaderValuePredicatePlan, PolicyPlan, ProviderOutputPlan,
};
use super::facade::CompiledConfig;
use super::provenance::{PolicyProvenance, PolicySourceKind};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyDump {
    pub(crate) default: PolicyDumpDefaultDecision,
    pub(crate) global_credential_mutations: Vec<PolicyDumpCredentialMutation>,
    pub(crate) provider_credential_outputs:
        BTreeMap<String, BTreeMap<String, PolicyDumpProviderCredentialOutput>>,
    pub(crate) rules: Vec<PolicyDumpRule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PolicyDumpDefaultDecision {
    Allow,
    Deny,
}

impl PolicyDumpDefaultDecision {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyDumpRule {
    pub(crate) index: usize,
    pub(crate) id: String,
    pub(crate) source: PolicyDumpSource,
    pub(crate) description: Option<String>,
    pub(crate) decision: PolicyDumpRuleDecision,
    pub(crate) urls: Vec<String>,
    pub(crate) methods: Vec<String>,
    pub(crate) client_cidrs: Vec<String>,
    pub(crate) identity_states: Vec<PolicyDumpIdentityState>,
    pub(crate) identity_subjects: Vec<PolicyDumpIdentitySubject>,
    pub(crate) execution_contexts: Vec<String>,
    pub(crate) headers: PolicyDumpHeaderPredicates,
    pub(crate) request_timeout_ms: Option<u64>,
    pub(crate) allow_upgrades: bool,
    pub(crate) authorization_provider: Option<String>,
    pub(crate) redaction_profile: Option<String>,
    pub(crate) request_header_mutations: Vec<PolicyDumpHeaderMutation>,
    pub(crate) response_header_mutations: Vec<PolicyDumpHeaderMutation>,
    pub(crate) credential_mutations: Vec<PolicyDumpCredentialMutation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum PolicyDumpSource {
    Main {
        source_rule_index: usize,
    },
    Fragment {
        file: String,
        source_rule_index: usize,
    },
}

impl PolicyDumpSource {
    fn display_name(&self) -> String {
        match self {
            Self::Main { .. } => "main".to_owned(),
            Self::Fragment { file, .. } => format!("rules.d/{file}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PolicyDumpIdentityState {
    Disabled,
    Anonymous,
    Authenticated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum PolicyDumpIdentitySubject {
    Principal { authority: String, id: String },
    Group { authority: String, id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PolicyDumpRuleDecision {
    Allow,
    Deny,
    Delegate,
}

impl PolicyDumpRuleDecision {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Delegate => "delegate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyDumpHeaderPredicates {
    pub(crate) absent_any: Vec<String>,
    pub(crate) present_all: Vec<String>,
    pub(crate) all: Vec<PolicyDumpHeaderValuePredicate>,
    pub(crate) none: Vec<PolicyDumpHeaderValuePredicate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyDumpHeaderValuePredicate {
    pub(crate) name: String,
    pub(crate) values: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyDumpHeaderMutation {
    pub(crate) operation: PolicyDumpHeaderOperation,
    pub(crate) when: PolicyDumpHeaderWhen,
    pub(crate) name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PolicyDumpHeaderOperation {
    Set,
    Append,
    Remove,
    Replace,
}

impl PolicyDumpHeaderOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Append => "append",
            Self::Remove => "remove",
            Self::Replace => "replace",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyDumpHeaderWhen {
    Always,
    IfPresent,
    IfAbsent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum PolicyDumpCredentialMutation {
    Bearer {
        credential: String,
        transport_security: CompiledTransportSecurity,
    },
    Basic {
        password_credential: String,
        transport_security: CompiledTransportSecurity,
    },
    CustomHeader {
        header: String,
        credential: String,
        transport_security: CompiledTransportSecurity,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum PolicyDumpProviderCredentialOutput {
    Bearer {
        required: bool,
        transport_security: CompiledTransportSecurity,
    },
    Basic {
        username: String,
        required: bool,
        transport_security: CompiledTransportSecurity,
    },
    CustomHeader {
        header: String,
        required: bool,
        transport_security: CompiledTransportSecurity,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyDumpTableRow {
    pub(crate) index: usize,
    pub(crate) rule_id: String,
    pub(crate) source: String,
    pub(crate) decision: &'static str,
    pub(crate) urls: String,
    pub(crate) methods: String,
    pub(crate) client_cidrs: String,
    pub(crate) identity_predicates: String,
    pub(crate) execution_contexts: String,
    pub(crate) header_predicates: String,
    pub(crate) description: String,
    pub(crate) authorization_provider: String,
    pub(crate) redaction_profile: String,
    pub(crate) mutations: String,
}

impl PolicyDump {
    pub(crate) fn from_compiled(compiled: &CompiledConfig) -> Self {
        let mut dump = Self::from_plan(
            &compiled.reloadable_plan.policy,
            &compiled.policy_provenance,
        );
        dump.global_credential_mutations = compiled
            .reloadable_plan
            .egress
            .credential_actions
            .iter()
            .map(project_credential_mutation)
            .collect();
        dump.provider_credential_outputs = compiled
            .reloadable_plan
            .authorization
            .providers
            .iter()
            .map(|(provider_name, provider)| {
                let outputs = match provider {
                    AuthorizationProviderPlan::Webhook(provider) => &provider.outputs,
                    AuthorizationProviderPlan::Process(provider) => &provider.outputs,
                    AuthorizationProviderPlan::UnixSocket(provider) => &provider.outputs,
                };
                (
                    provider_name.clone(),
                    outputs
                        .iter()
                        .map(|(output_name, output)| {
                            (output_name.clone(), project_provider_output(output))
                        })
                        .collect(),
                )
            })
            .collect();
        dump
    }

    fn from_plan(plan: &PolicyPlan, provenance: &PolicyProvenance) -> Self {
        assert_eq!(
            plan.rules.len(),
            provenance.rules().len(),
            "compiled policy and provenance must remain exactly aligned"
        );
        Self {
            default: match plan.default {
                CompiledDefaultDecision::Allow => PolicyDumpDefaultDecision::Allow,
                CompiledDefaultDecision::Deny => PolicyDumpDefaultDecision::Deny,
            },
            global_credential_mutations: Vec::new(),
            provider_credential_outputs: BTreeMap::new(),
            rules: plan
                .rules
                .iter()
                .zip(provenance.rules())
                .enumerate()
                .map(|(index, (rule, rule_source))| {
                    assert_eq!(
                        rule_source.global_cursor(),
                        index,
                        "compiled policy provenance cursor must remain aligned"
                    );
                    let source = provenance.source(*rule_source);
                    PolicyDumpRule {
                        index,
                        id: rule.id.clone(),
                        source: match source {
                            PolicySourceKind::Main => PolicyDumpSource::Main {
                                source_rule_index: (*rule_source).source_rule_index(),
                            },
                            PolicySourceKind::Fragment { file } => PolicyDumpSource::Fragment {
                                file: file.clone(),
                                source_rule_index: (*rule_source).source_rule_index(),
                            },
                        },
                        description: rule.description.clone(),
                        decision: match rule.decision {
                            CompiledRuleDecision::Allow => PolicyDumpRuleDecision::Allow,
                            CompiledRuleDecision::Deny => PolicyDumpRuleDecision::Deny,
                            CompiledRuleDecision::Delegate => PolicyDumpRuleDecision::Delegate,
                        },
                        urls: rule
                            .urls
                            .iter()
                            .map(|pattern| pattern.authored().to_string())
                            .collect(),
                        methods: rule.methods.iter().map(ToString::to_string).collect(),
                        client_cidrs: rule.client_cidrs.iter().map(ToString::to_string).collect(),
                        identity_states: rule
                            .identity
                            .as_ref()
                            .map_or(&[][..], |identity| identity.states.as_slice())
                            .iter()
                            .map(|state| match state {
                                IdentityState::Disabled => PolicyDumpIdentityState::Disabled,
                                IdentityState::Anonymous => PolicyDumpIdentityState::Anonymous,
                                IdentityState::Authenticated => {
                                    PolicyDumpIdentityState::Authenticated
                                }
                            })
                            .collect(),
                        identity_subjects: rule
                            .identity
                            .as_ref()
                            .map_or(&[][..], |identity| identity.subjects.as_slice())
                            .iter()
                            .map(|subject| match subject {
                                IdentitySubject::Principal { authority, id } => {
                                    PolicyDumpIdentitySubject::Principal {
                                        authority: authority.as_str().to_owned(),
                                        id: id.as_str().to_owned(),
                                    }
                                }
                                IdentitySubject::Group { authority, id } => {
                                    PolicyDumpIdentitySubject::Group {
                                        authority: authority.as_str().to_owned(),
                                        id: id.as_str().to_owned(),
                                    }
                                }
                            })
                            .collect(),
                        execution_contexts: rule
                            .execution_contexts
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|context| context.as_str().to_owned())
                            .collect(),
                        headers: PolicyDumpHeaderPredicates {
                            absent_any: rule
                                .headers
                                .absent_any
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                            present_all: rule
                                .headers
                                .present_all
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                            all: project_header_predicates(&rule.headers.all),
                            none: project_header_predicates(&rule.headers.none),
                        },
                        request_timeout_ms: rule.request_timeout.map(|timeout| {
                            u64::try_from(timeout.as_millis())
                                .expect("validated request timeout must fit in u64 milliseconds")
                        }),
                        allow_upgrades: rule.allow_upgrades,
                        authorization_provider: rule.authorization_provider.clone(),
                        redaction_profile: rule.redaction_profile.clone(),
                        request_header_mutations: rule
                            .request_headers
                            .iter()
                            .map(project_header_mutation)
                            .collect(),
                        response_header_mutations: rule
                            .response_headers
                            .iter()
                            .map(project_header_mutation)
                            .collect(),
                        credential_mutations: rule
                            .credential_actions
                            .iter()
                            .map(project_credential_mutation)
                            .collect(),
                    }
                })
                .collect(),
        }
    }

    pub(crate) fn table_rows(&self) -> Vec<PolicyDumpTableRow> {
        self.rules
            .iter()
            .map(|rule| PolicyDumpTableRow {
                index: rule.index,
                rule_id: rule.id.clone(),
                source: rule.source.display_name(),
                decision: rule.decision.as_str(),
                urls: rule.urls.join(","),
                methods: rule.methods.join(","),
                client_cidrs: rule.client_cidrs.join(","),
                identity_predicates: format_identity_predicates(rule),
                execution_contexts: rule.execution_contexts.join(","),
                header_predicates: format_header_predicates(&rule.headers),
                description: rule.description.clone().unwrap_or_default(),
                authorization_provider: rule.authorization_provider.clone().unwrap_or_default(),
                redaction_profile: rule.redaction_profile.clone().unwrap_or_default(),
                mutations: format_mutations(rule),
            })
            .collect()
    }
}

fn format_identity_predicates(rule: &PolicyDumpRule) -> String {
    let mut values = rule
        .identity_states
        .iter()
        .map(|state| match state {
            PolicyDumpIdentityState::Disabled => "state=disabled".to_owned(),
            PolicyDumpIdentityState::Anonymous => "state=anonymous".to_owned(),
            PolicyDumpIdentityState::Authenticated => "state=authenticated".to_owned(),
        })
        .collect::<Vec<_>>();
    values.extend(rule.identity_subjects.iter().map(|subject| match subject {
        PolicyDumpIdentitySubject::Principal { authority, id } => {
            format!("principal={authority}:{id}")
        }
        PolicyDumpIdentitySubject::Group { authority, id } => {
            format!("group={authority}:{id}")
        }
    }));
    values.join(",")
}

fn project_provider_output(output: &ProviderOutputPlan) -> PolicyDumpProviderCredentialOutput {
    match output {
        ProviderOutputPlan::Bearer {
            required,
            transport_security,
        } => PolicyDumpProviderCredentialOutput::Bearer {
            required: *required,
            transport_security: *transport_security,
        },
        ProviderOutputPlan::Basic {
            username,
            required,
            transport_security,
        } => PolicyDumpProviderCredentialOutput::Basic {
            username: username.clone(),
            required: *required,
            transport_security: *transport_security,
        },
        ProviderOutputPlan::CustomHeader {
            header,
            required,
            transport_security,
        } => PolicyDumpProviderCredentialOutput::CustomHeader {
            header: header.to_string(),
            required: *required,
            transport_security: *transport_security,
        },
    }
}

fn project_header_predicates(
    predicates: &[HeaderValuePredicatePlan],
) -> Vec<PolicyDumpHeaderValuePredicate> {
    predicates
        .iter()
        .map(|predicate| PolicyDumpHeaderValuePredicate {
            name: predicate.name.to_string(),
            values: predicate
                .values
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect(),
        })
        .collect()
}

fn project_header_mutation(effect: &HeaderEffectPlan) -> PolicyDumpHeaderMutation {
    let (operation, when, name) = match effect {
        HeaderEffectPlan::Set { when, name, .. } => (PolicyDumpHeaderOperation::Set, *when, name),
        HeaderEffectPlan::Append { when, name, .. } => {
            (PolicyDumpHeaderOperation::Append, *when, name)
        }
        HeaderEffectPlan::Remove { when, name } => (PolicyDumpHeaderOperation::Remove, *when, name),
        HeaderEffectPlan::Replace { when, name, .. } => {
            (PolicyDumpHeaderOperation::Replace, *when, name)
        }
    };
    PolicyDumpHeaderMutation {
        operation,
        when: match when {
            CompiledHeaderEffectWhen::Always => PolicyDumpHeaderWhen::Always,
            CompiledHeaderEffectWhen::IfPresent => PolicyDumpHeaderWhen::IfPresent,
            CompiledHeaderEffectWhen::IfAbsent => PolicyDumpHeaderWhen::IfAbsent,
        },
        name: name.to_string(),
    }
}

fn project_credential_mutation(action: &CredentialActionPlan) -> PolicyDumpCredentialMutation {
    match action {
        CredentialActionPlan::Bearer {
            credential,
            transport_security,
        } => PolicyDumpCredentialMutation::Bearer {
            credential: credential.clone(),
            transport_security: *transport_security,
        },
        CredentialActionPlan::Basic {
            password_credential,
            transport_security,
            ..
        } => PolicyDumpCredentialMutation::Basic {
            password_credential: password_credential.clone(),
            transport_security: *transport_security,
        },
        CredentialActionPlan::CustomHeader {
            header,
            credential,
            transport_security,
        } => PolicyDumpCredentialMutation::CustomHeader {
            header: header.to_string(),
            credential: credential.clone(),
            transport_security: *transport_security,
        },
    }
}

fn format_header_predicates(headers: &PolicyDumpHeaderPredicates) -> String {
    let mut fields = Vec::new();
    fields.extend(
        headers
            .absent_any
            .iter()
            .map(|name| format!("absent:{name}")),
    );
    fields.extend(
        headers
            .present_all
            .iter()
            .map(|name| format!("present:{name}")),
    );
    fields.extend(
        headers
            .all
            .iter()
            .map(|predicate| format!("{}={}", predicate.name, predicate.values.join("|"))),
    );
    fields.extend(
        headers
            .none
            .iter()
            .map(|predicate| format!("{}!={}", predicate.name, predicate.values.join("|"))),
    );
    fields.join(";")
}

fn format_mutations(rule: &PolicyDumpRule) -> String {
    let mut mutations = Vec::new();
    mutations.extend(
        rule.request_header_mutations
            .iter()
            .map(|mutation| format!("request:{}:{}", mutation.operation.as_str(), mutation.name)),
    );
    mutations.extend(
        rule.response_header_mutations
            .iter()
            .map(|mutation| format!("response:{}:{}", mutation.operation.as_str(), mutation.name)),
    );
    mutations.extend(
        rule.credential_mutations
            .iter()
            .map(|mutation| match mutation {
                PolicyDumpCredentialMutation::Bearer {
                    credential,
                    transport_security,
                } => {
                    format!(
                        "credential:bearer:{credential}:{}",
                        transport_security.as_str()
                    )
                }
                PolicyDumpCredentialMutation::Basic {
                    password_credential,
                    transport_security,
                } => format!(
                    "credential:basic:{password_credential}:{}",
                    transport_security.as_str()
                ),
                PolicyDumpCredentialMutation::CustomHeader {
                    header,
                    credential,
                    transport_security,
                } => {
                    format!(
                        "credential:custom_header:{header}:{credential}:{}",
                        transport_security.as_str()
                    )
                }
            }),
    );
    mutations.join(",")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;
    use crate::config::{compile_config_text, ConfigTextInput};

    #[test]
    fn projection_is_pure_table_ready_and_omits_secret_locators_and_values() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("provider-spawned");
        let input = format!(
            r#"schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.local]
kind = "process"
command = "/bin/sh"
args = ["-c", "printf spawned > {}"]
environment = {{ PROVIDER_SECRET = "provider-secret-value" }}

[authorization.providers.local.outputs.provider_token]
kind = "custom_header"
transport_security = "tls_required"
header = "x-provider-token"

[credentials]
allowed_custom_headers = ["x-api-key", "x-global-token", "x-provider-token"]

[credentials.sources.environment_source]
source = "environment"
variable = "MISSING_POLICY_DUMP_SECRET"

[credentials.sources.file_source]
source = "file"
path = "missing-secret-file"

[credentials.sources.global_source]
source = "environment"
variable = "MISSING_GLOBAL_SECRET"

[[egress.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-global-token"
credential = "global_source"

[redaction.profiles.secrets]
rules = [{{ literals = ["literal-secret-value"], literal_environment_variables = ["MISSING_REDACTION_SECRET"] }}]

[policy]
default = "deny"

[[policy.rules]]
id = "delegated"
description = "delegate through local provider"
decision = "delegate"
urls = ["https://example.test/**"]
methods = ["get"]
client_cidrs = ["192.0.2.0/24"]
authorization_provider = "local"
redaction_profile = "secrets"

[policy.rules.headers]
absent_any = ["x-blocked"]
all = {{ x-tenant = ["engineering"] }}

[[policy.rules.request_headers]]
operation = "set"
when = "always"
name = "x-route"
value = "literal-secret-value"

[[policy.rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "environment_source"

[[policy.rules.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-api-key"
credential = "file_source"
"#,
            marker.display()
        );

        let compiled = compile_config_text(ConfigTextInput {
            text: &input,
            source_path: &directory.path().join("acl-proxy.toml"),
            config_root: directory.path(),
        })
        .expect("validate and dump compilation must remain pure");
        let dump = PolicyDump::from_compiled(&compiled);
        let json = serde_json::to_string_pretty(&dump).unwrap();

        assert!(!marker.exists(), "static compilation spawned a provider");
        for excluded in [
            "MISSING_POLICY_DUMP_SECRET",
            "MISSING_GLOBAL_SECRET",
            "missing-secret-file",
            "MISSING_REDACTION_SECRET",
            "literal-secret-value",
            "provider-secret-value",
            "/bin/sh",
            marker.to_str().unwrap(),
        ] {
            assert!(
                !json.contains(excluded),
                "dump disclosed {excluded}: {json}"
            );
        }
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["rules"][0]["source"],
            serde_json::json!({
                "kind": "main",
                "source_rule_index": 0
            })
        );
        let mutations = value["rules"][0]["credential_mutations"]
            .as_array()
            .unwrap();
        assert_eq!(mutations[0]["kind"], "bearer");
        assert_eq!(mutations[0]["credential"], "environment_source");
        assert_eq!(mutations[0]["transport_security"], "tls_required");
        assert_eq!(mutations[1]["kind"], "custom_header");
        assert_eq!(mutations[1]["credential"], "file_source");
        assert_eq!(mutations[1]["transport_security"], "tls_required");
        assert_eq!(
            value["global_credential_mutations"][0]["transport_security"],
            "tls_required"
        );
        assert_eq!(
            value["provider_credential_outputs"]["local"]["provider_token"]["transport_security"],
            "tls_required"
        );

        let rows = dump.table_rows();
        assert_eq!(dump.default.as_str(), "deny");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule_id, "delegated");
        assert_eq!(rows[0].source, "main");
        assert_eq!(rows[0].decision, "delegate");
        assert_eq!(rows[0].urls, "https://example.test/**");
        assert_eq!(rows[0].methods, "GET");
        assert_eq!(rows[0].client_cidrs, "192.0.2.0/24");
        assert!(rows[0].header_predicates.contains("x-tenant=engineering"));
        assert!(rows[0]
            .mutations
            .contains("credential:bearer:environment_source:tls_required"));
        assert!(!rows[0].mutations.contains("literal-secret-value"));
    }

    #[test]
    fn unix_provider_dump_projects_outputs_without_disclosing_socket_path() {
        let input = r#"schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.local]
kind = "unix_socket"
socket_path = "/run/private/authorization-provider.sock"
timeout = "2s"
on_failure = "deny"
include_headers = []
max_request_bytes = 262144
max_response_bytes = 65536
max_pending_requests = 128

[authorization.providers.local.outputs.api_token]
kind = "bearer"
transport_security = "tls_required"
required = true

[policy]
default = "deny"
"#;
        let compiled = compile_config_text(ConfigTextInput {
            text: input,
            source_path: Path::new("/etc/acl-proxy/acl-proxy.toml"),
            config_root: Path::new("/etc/acl-proxy"),
        })
        .unwrap();
        let json = serde_json::to_string(&PolicyDump::from_compiled(&compiled)).unwrap();
        assert!(!json.contains("/run/private/authorization-provider.sock"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["provider_credential_outputs"]["local"]["api_token"]["kind"],
            "bearer"
        );
        assert_eq!(
            value["provider_credential_outputs"]["local"]["api_token"]["transport_security"],
            "tls_required"
        );
        assert_eq!(
            value["provider_credential_outputs"]["local"]["api_token"]["required"],
            true
        );
    }

    #[test]
    fn match_all_pattern_has_a_stable_dump_representation() {
        let compiled = compile_config_text(ConfigTextInput {
            text: r#"schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "all"
decision = "allow"
urls = ["**"]
"#,
            source_path: Path::new("/tmp/acl-proxy.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap();

        assert_eq!(PolicyDump::from_compiled(&compiled).rules[0].urls, ["**"]);
    }

    #[test]
    #[should_panic(expected = "compiled policy and provenance must remain exactly aligned")]
    fn projection_refuses_misaligned_policy_provenance() {
        let mut compiled = compile_config_text(ConfigTextInput {
            text: r#"schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "one"
decision = "deny"
methods = ["GET"]
"#,
            source_path: Path::new("/tmp/acl-proxy.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap();
        compiled.policy_provenance = PolicyProvenance::main_only(0).unwrap();

        let _ = PolicyDump::from_compiled(&compiled);
    }
}
