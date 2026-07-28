use std::fmt;
use std::path::{Path, PathBuf};

use super::compiler::{
    compile_config, CompiledProductConfig, ReloadableProductPlan, StaticFingerprint,
    StaticProductConfig,
};
use super::loader;
use super::provenance::{PolicyProvenance, PolicySourceSummary};
use super::tls_trust_preflight::TlsTrustSourceSpec;

pub(crate) use super::loader::ConfigPathSource;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ConfigFileMetadata {
    pub(crate) path: PathBuf,
    pub(crate) config_root: PathBuf,
    pub(crate) path_source: ConfigPathSource,
}

impl fmt::Debug for ConfigFileMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigFileMetadata")
            .field("path_source", &self.path_source)
            .finish_non_exhaustive()
    }
}

/// Pure compiler output. Activation consumes `reloadable_plan`; validation and
/// policy-dump commands may inspect these artifacts without resolving material
/// or starting runtime resources.
pub(crate) struct CompiledConfig {
    pub(crate) static_config: StaticProductConfig,
    pub(crate) static_fingerprint: StaticFingerprint,
    pub(crate) reloadable_plan: ReloadableProductPlan,
    pub(crate) policy_provenance: PolicyProvenance,
    pub(crate) policy_source_summary: PolicySourceSummary,
    pub(crate) tls_trust_sources: Vec<TlsTrustSourceSpec>,
}

impl fmt::Debug for CompiledConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledConfig")
            .field("static_fingerprint", &self.static_fingerprint)
            .field("reloadable_plan", &self.reloadable_plan)
            .field("rule_source_count", &self.policy_provenance.rules().len())
            .field("source_summary", &self.policy_source_summary)
            .field("tls_trust_source_count", &self.tls_trust_sources.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct LoadedCompiledConfig {
    pub(crate) metadata: ConfigFileMetadata,
    pub(crate) compiled: CompiledConfig,
}

pub(crate) struct RuntimeCandidate {
    pub(crate) static_config: StaticProductConfig,
    pub(crate) static_fingerprint: StaticFingerprint,
    pub(crate) reloadable_plan: ReloadableProductPlan,
    pub(crate) policy_source_summary: PolicySourceSummary,
}

impl CompiledConfig {
    pub(crate) fn into_runtime_candidate(self) -> RuntimeCandidate {
        RuntimeCandidate {
            static_config: self.static_config,
            static_fingerprint: self.static_fingerprint,
            reloadable_plan: self.reloadable_plan,
            policy_source_summary: self.policy_source_summary,
        }
    }
}

impl fmt::Debug for LoadedCompiledConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedCompiledConfig")
            .field("compiled", &self.compiled)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct ConfigTextInput<'a> {
    pub(crate) text: &'a str,
    pub(crate) source_path: &'a Path,
    pub(crate) config_root: &'a Path,
}

pub(crate) enum ConfigFacadeError {
    Load {
        message: String,
    },
    Compile {
        message: String,
    },
    WriteTemplate {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for ConfigFacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load { message } => formatter.write_str(message),
            Self::Compile { message } => {
                write!(formatter, "configuration failed validation: {message}")
            }
            Self::WriteTemplate { path, source } => {
                write!(
                    formatter,
                    "failed to write configuration template {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl fmt::Debug for ConfigFacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConfigFacadeError")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl std::error::Error for ConfigFacadeError {}

pub(crate) fn load_and_compile_config(
    explicit_path: Option<&Path>,
) -> Result<LoadedCompiledConfig, ConfigFacadeError> {
    let loaded = loader::load_config(explicit_path).map_err(load_error)?;
    let metadata = ConfigFileMetadata {
        path: loaded.path,
        config_root: loaded.config_root,
        path_source: loaded.path_source,
    };
    let compiled = compile_authored(
        loaded.authored,
        loaded.provenance,
        loaded.source_summary,
        &metadata.config_root,
    )?;
    Ok(LoadedCompiledConfig { metadata, compiled })
}

pub(crate) fn load_and_compile_exact_config(
    path: &Path,
) -> Result<LoadedCompiledConfig, ConfigFacadeError> {
    let loaded = loader::load_exact_config(path).map_err(load_error)?;
    let metadata = ConfigFileMetadata {
        path: loaded.path,
        config_root: loaded.config_root,
        path_source: loaded.path_source,
    };
    let compiled = compile_authored(
        loaded.authored,
        loaded.provenance,
        loaded.source_summary,
        &metadata.config_root,
    )?;
    Ok(LoadedCompiledConfig { metadata, compiled })
}

#[cfg(test)]
pub(crate) fn compile_config_text(
    input: ConfigTextInput<'_>,
) -> Result<CompiledConfig, ConfigFacadeError> {
    let authored = loader::parse_config_text(input.text, input.source_path).map_err(load_error)?;
    let main_rule_count = authored.policy.rules.len();
    let policy_provenance =
        PolicyProvenance::main_only(main_rule_count).map_err(|source| ConfigFacadeError::Load {
            message: source.to_string(),
        })?;
    compile_authored(
        authored,
        policy_provenance,
        PolicySourceSummary::main_only(main_rule_count),
        input.config_root,
    )
}

pub(crate) fn write_default_config_template(path: &Path) -> Result<(), ConfigFacadeError> {
    super::template::write_default_config(path).map_err(|source| ConfigFacadeError::WriteTemplate {
        path: path.to_path_buf(),
        source,
    })
}

fn compile_authored(
    authored: super::authoring::AuthoringConfig,
    policy_provenance: PolicyProvenance,
    policy_source_summary: PolicySourceSummary,
    config_root: &Path,
) -> Result<CompiledConfig, ConfigFacadeError> {
    let authored_tls_sources = collect_authored_tls_sources(&authored);
    let compiled =
        compile_config(authored, config_root).map_err(|source| ConfigFacadeError::Compile {
            message: format_compile_error(&source, &policy_provenance),
        })?;
    if compiled.reloadable_plan.policy.rules.len() != policy_provenance.rules().len() {
        return Err(ConfigFacadeError::Compile {
            message: "compiled policy and source provenance are misaligned".to_owned(),
        });
    }
    Ok(split_compiled(
        compiled,
        policy_provenance,
        policy_source_summary,
        authored_tls_sources,
    ))
}

fn collect_authored_tls_sources(
    authored: &super::authoring::AuthoringConfig,
) -> Vec<(String, PathBuf)> {
    use super::authoring::AuthorizationProviderConfig;

    let mut sources = Vec::new();
    if let Some(path) = &authored.egress.origin_tls.ca_certificate {
        sources.push(("egress.origin_tls.ca_certificate".to_owned(), path.clone()));
    }
    if let Some(path) = authored
        .egress
        .parent_proxy
        .as_ref()
        .and_then(|parent| parent.tls.as_ref())
        .and_then(|tls| tls.ca_certificate.as_ref())
    {
        sources.push((
            "egress.parent_proxy.tls.ca_certificate".to_owned(),
            path.clone(),
        ));
    }
    for (name, provider) in &authored.authorization.providers {
        if let AuthorizationProviderConfig::Webhook(webhook) = provider {
            if let Some(path) = webhook
                .tls
                .as_ref()
                .and_then(|tls| tls.ca_certificate.as_ref())
            {
                sources.push((
                    format!("authorization.providers.{name}.tls.ca_certificate"),
                    path.clone(),
                ));
            }
        }
    }
    sources
}

fn format_compile_error(
    error: &super::compiler::ConfigCompileError,
    provenance: &PolicyProvenance,
) -> String {
    if let Some(duplicate) = error.duplicate_rule_id_diagnostic() {
        let first = format_rule_location(provenance, duplicate.first_cursor());
        let second = format_rule_location(provenance, duplicate.duplicate_cursor());
        return match duplicate.safe_rule_id() {
            Some(rule_id) => {
                format!("duplicate rule ID {rule_id:?}: first at {first}; duplicate at {second}")
            }
            None => format!("duplicate rule ID: first at {first}; duplicate at {second}"),
        };
    }

    let category = match error.category() {
        super::compiler::ConfigCompileDiagnosticCategory::InvalidValue => "invalid_value",
        super::compiler::ConfigCompileDiagnosticCategory::UnknownReference => "unknown_reference",
        super::compiler::ConfigCompileDiagnosticCategory::DuplicateRuleId => "duplicate_rule_id",
        super::compiler::ConfigCompileDiagnosticCategory::LimitExceeded => "limit_exceeded",
        super::compiler::ConfigCompileDiagnosticCategory::SecurityConstraint => {
            "security_constraint"
        }
        super::compiler::ConfigCompileDiagnosticCategory::ResourceProjection => {
            "resource_projection"
        }
        super::compiler::ConfigCompileDiagnosticCategory::InternalInvariant => "internal_invariant",
    };
    let field = error.path().field();
    let rule_id = error
        .safe_rule_id()
        .map_or_else(String::new, |rule_id| format!(" [rule_id={rule_id:?}]"));
    match error.path().rule_cursor() {
        Some(cursor) => {
            let location = format_rule_location(provenance, cursor);
            if field.is_empty() {
                format!("{category} at {location}: {}{rule_id}", error.message())
            } else {
                format!(
                    "{category} at {location}.{field}: {}{rule_id}",
                    error.message()
                )
            }
        }
        None if field.is_empty() => format!("{category} at main: {}", error.message()),
        None => format!("{category} at main.{field}: {}", error.message()),
    }
}

fn format_rule_location(provenance: &PolicyProvenance, cursor: usize) -> String {
    match provenance.resolve_cursor(cursor) {
        Some((source, rule)) => format!(
            "{} rule {}",
            source.display_name(),
            rule.source_rule_index()
        ),
        None => format!("unknown policy cursor {cursor}"),
    }
}

fn load_error(source: super::loader::ConfigLoadError) -> ConfigFacadeError {
    ConfigFacadeError::Load {
        message: source.to_string(),
    }
}

fn split_compiled(
    compiled: CompiledProductConfig,
    policy_provenance: PolicyProvenance,
    policy_source_summary: PolicySourceSummary,
    authored_tls_sources: Vec<(String, PathBuf)>,
) -> CompiledConfig {
    use super::compiler::AuthorizationProviderPlan;

    let mut resolved = std::collections::BTreeMap::new();
    if let Some(path) = &compiled.reloadable_plan.egress.origin_tls.ca_certificate {
        resolved.insert("egress.origin_tls.ca_certificate".to_owned(), path.clone());
    }
    if let Some(path) = compiled
        .reloadable_plan
        .egress
        .parent_proxy
        .as_ref()
        .and_then(|parent| parent.tls.as_ref())
        .and_then(|tls| tls.ca_certificate.as_ref())
    {
        resolved.insert(
            "egress.parent_proxy.tls.ca_certificate".to_owned(),
            path.clone(),
        );
    }
    for (name, provider) in &compiled.reloadable_plan.authorization.providers {
        if let AuthorizationProviderPlan::Webhook(webhook) = provider {
            if let Some(path) = webhook
                .tls
                .as_ref()
                .and_then(|tls| tls.ca_certificate.as_ref())
            {
                resolved.insert(
                    format!("authorization.providers.{name}.tls.ca_certificate"),
                    path.clone(),
                );
            }
        }
    }
    let tls_trust_sources = authored_tls_sources
        .into_iter()
        .map(|(scope, authored)| {
            let resolved = resolved
                .remove(&scope)
                .expect("compiled TLS trust source corresponds to authored source");
            TlsTrustSourceSpec::new(scope, authored, resolved)
        })
        .collect();
    debug_assert!(resolved.is_empty());
    CompiledConfig {
        static_config: compiled.static_config,
        static_fingerprint: compiled.static_fingerprint,
        reloadable_plan: compiled.reloadable_plan,
        policy_provenance,
        policy_source_summary,
        tls_trust_sources,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::config::compiler::AuthorizationProviderPlan;

    const MINIMAL: &str = r#"
schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;

    #[test]
    fn load_and_compile_returns_selected_file_metadata_and_compiled_artifacts() {
        let directory = tempdir().unwrap();
        let config_root = directory.path().join("config");
        fs::create_dir(&config_root).unwrap();
        let path = config_root.join("acl-proxy.toml");
        fs::write(&path, MINIMAL).unwrap();

        let loaded = load_and_compile_config(Some(&path)).unwrap();
        assert_eq!(loaded.metadata.path, path);
        assert_eq!(loaded.metadata.config_root, config_root);
        assert_eq!(loaded.metadata.path_source, ConfigPathSource::Explicit);
        assert_eq!(loaded.compiled.static_config.schema_version, 4);
        assert_eq!(
            loaded.compiled.static_config.config_root,
            loaded.metadata.config_root
        );
        assert!(format!("{loaded:?}").contains("StaticFingerprint("));
    }

    #[test]
    fn text_compilation_is_pure_and_yields_validate_and_dump_inputs() {
        let input = MINIMAL.replace(
            "[policy]",
            r#"[control]
bind = "127.0.0.1:8898"

[control.tls]
certificate_chain = "missing-control-cert.pem"
private_key = "missing-control-key.pem"

[authorization.providers.local]
kind = "process"
command = "missing-provider-that-must-not-run"

[credentials.sources.environment]
source = "environment"
variable = "MISSING_FACADE_TEST_SECRET"

[credentials.sources.file]
source = "file"
path = "missing-secret-file"

[redaction.profiles.secrets]
rules = [{ literal_environment_variables = ["MISSING_REDACTION_SECRET"] }]

[policy]"#,
        );
        let source_path = Path::new("/etc/acl-proxy/acl-proxy.toml");
        let compiled = compile_config_text(ConfigTextInput {
            text: &input,
            source_path,
            config_root: source_path.parent().unwrap(),
        })
        .expect("pure compilation must not open material, resolve secrets, or spawn providers");

        let AuthorizationProviderPlan::Process(provider) = compiled
            .reloadable_plan
            .authorization
            .providers
            .get("local")
            .unwrap()
        else {
            panic!("local must be a process provider");
        };
        assert_eq!(
            provider.command,
            Path::new("/etc/acl-proxy/missing-provider-that-must-not-run")
        );
        assert_eq!(compiled.reloadable_plan.credentials.sources.len(), 2);
        assert_eq!(compiled.reloadable_plan.redaction.profiles.len(), 1);
    }

    #[test]
    fn facade_projects_webhook_and_control_compiler_contract() {
        let input = MINIMAL.replace(
            "[policy]",
            r#"[service]
max_active_webhook_deliveries = 32
webhook_transport_buffer_bytes = 65536
max_webhook_transport_bytes = 4194304

[control]
bind = "127.0.0.1:8898"
request_body_timeout = "7s"
max_connections = 16

[authorization.callback]
public_url = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback"

[authorization.providers.approval]
kind = "webhook"
url = "https://approval.example.test/authorize"
max_request_bytes = 4097
max_response_bytes = 97

[policy]"#,
        );
        let compiled = compile_config_text(ConfigTextInput {
            text: &input,
            source_path: Path::new("/tmp/config.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap();

        assert_eq!(
            compiled.static_config.service.max_active_webhook_deliveries,
            32
        );
        assert_eq!(
            compiled.static_config.service.max_webhook_transport_bytes,
            4 * 1024 * 1024
        );
        let control = compiled.static_config.control.as_ref().unwrap();
        assert_eq!(
            control.request_body_timeout,
            std::time::Duration::from_secs(7)
        );
        assert_eq!(control.parser_arena_bytes, 16 * 64 * 1024);
        let AuthorizationProviderPlan::Webhook(provider) =
            &compiled.reloadable_plan.authorization.providers["approval"]
        else {
            panic!("approval must be a webhook provider");
        };
        assert_eq!(provider.max_request_bytes, 4097);
        assert_eq!(provider.max_response_bytes, 97);
    }

    #[test]
    fn compiled_policy_plan_is_ready_for_secret_free_dump_projection() {
        let input = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "health"
description = "Health endpoint"
decision = "allow"
methods = ["GET"]"#,
        );
        let compiled = compile_config_text(ConfigTextInput {
            text: &input,
            source_path: Path::new("/tmp/config.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap();
        let rule = &compiled.reloadable_plan.policy.rules[0];
        assert_eq!(rule.id, "health");
        assert_eq!(rule.description.as_deref(), Some("Health endpoint"));
        assert_eq!(rule.methods, [http::Method::GET]);
    }

    #[test]
    fn production_v1_shapes_are_rejected_by_v4_runtime() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/production");
        for name in [
            "v1-host-shape.toml",
            "v1-common-container-shape.toml",
            "v1-internal-container-shape.toml",
        ] {
            let error = load_and_compile_exact_config(&fixture_root.join(name)).unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains("strict schema v4"), "{name}: {rendered}");
            assert!(rendered.contains("invalid value"), "{name}: {rendered}");
        }
    }

    #[test]
    fn text_compilation_enforces_the_loader_byte_ceiling() {
        let oversized = " ".repeat(10 * 1024 * 1024 + 1);
        let error = compile_config_text(ConfigTextInput {
            text: &oversized,
            source_path: Path::new("/tmp/oversized.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap_err();
        assert!(error.to_string().contains("10485760-byte limit"));
    }

    #[test]
    fn combined_parse_and_compile_errors_are_sanitized() {
        const PARSE_SECRET: &str = "parse-secret-marker-37d9";
        let parse_input = format!(
            r#"{MINIMAL}
[credentials.sources.token]
source = "environment"
variable = "{PARSE_SECRET}
"#
        );
        let parse_error = compile_config_text(ConfigTextInput {
            text: &parse_input,
            source_path: Path::new("/tmp/parse.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap_err();
        assert_secret_absent(&parse_error, PARSE_SECRET);
        assert!(parse_error.to_string().contains("syntax error"));

        const REGEX_SECRET: &str = "regex-secret-marker-28ac";
        let compile_input = format!(
            r#"{MINIMAL}
[redaction.profiles.secrets]
rules = [{{ expressions = ["{REGEX_SECRET}("] }}]
"#
        );
        let compile_error = compile_config_text(ConfigTextInput {
            text: &compile_input,
            source_path: Path::new("/tmp/compile.toml"),
            config_root: Path::new("/tmp"),
        })
        .unwrap_err();
        assert_secret_absent(&compile_error, REGEX_SECRET);
        assert!(compile_error
            .to_string()
            .contains("invalid bounded redaction expression"));
    }

    #[test]
    fn validate_rejects_unbounded_regex_without_resolving_environment_sources() {
        const SECRET: &str = "bounded-regex-secret-marker-5a71";
        let input = format!(
            r#"{MINIMAL}
[redaction.profiles.secrets]
rules = [{{ expressions = ['\b{SECRET}\b'], literal_environment_variables = ["MISSING_VALIDATE_REDACTION_SOURCE"] }}]
"#
        );
        let error = compile_config_text(ConfigTextInput {
            text: &input,
            source_path: Path::new("/tmp/bounded-regex.toml"),
            config_root: Path::new("/tmp"),
        })
        .expect_err("validation must reject cache-requiring regex syntax");
        assert_secret_absent(&error, SECRET);
        assert!(error.to_string().contains("expressions[0]"));
        assert!(error
            .to_string()
            .contains("invalid bounded redaction expression"));
    }

    #[test]
    fn strict_init_template_round_trips_through_pure_facade_compilation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config/acl-proxy.toml");

        write_default_config_template(&path).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();

        assert_eq!(loaded.compiled.static_config.schema_version, 4);
        assert_eq!(loaded.metadata.path, path);
        assert_eq!(loaded.compiled.reloadable_plan.policy.rules.len(), 0);
    }

    #[test]
    fn shipped_sample_strictly_loads_and_compiles_through_the_facade() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("acl-proxy.sample.toml");

        let loaded = load_and_compile_exact_config(&path)
            .expect("shipped sample must pass the real strict loader and compiler");

        assert_eq!(loaded.metadata.path, path);
        assert_eq!(loaded.compiled.static_config.schema_version, 4);
        assert_eq!(loaded.compiled.reloadable_plan.policy.rules.len(), 0);
        assert_eq!(
            loaded
                .compiled
                .static_config
                .service
                .max_inflight_wire_body_bytes,
            16 * 1024 * 1024 * 1024
        );
        assert_eq!(
            loaded
                .compiled
                .static_config
                .service
                .max_inflight_wire_body_bytes_per_quota_key,
            2 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn sanitized_production_v4_fixtures_load_through_the_exact_facade() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/production");
        for (name, expected_rule_count) in [
            ("host-proxy-tcp.toml", 44),
            ("host-proxy-uds.toml", 1),
            ("common-container-proxy.toml", 1),
            ("internal-container-proxy.toml", 8),
        ] {
            let path = fixture_root.join(name);
            let loaded = load_and_compile_exact_config(&path)
                .unwrap_or_else(|error| panic!("{name} failed the exact facade: {error}"));

            assert_eq!(loaded.metadata.path, path, "{name}");
            assert_eq!(loaded.compiled.static_config.schema_version, 4, "{name}");
            assert_eq!(
                loaded.compiled.reloadable_plan.policy.rules.len(),
                expected_rule_count,
                "{name}"
            );
            assert_eq!(
                loaded.compiled.policy_source_summary.main_rule_count, expected_rule_count,
                "{name}"
            );
        }
    }

    #[test]
    fn fragment_compile_diagnostics_use_source_local_rule_locations() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        fs::write(&config_path, MINIMAL).unwrap();
        fs::write(
            rules_path.join("10-invalid.toml"),
            r#"schema_version = 4

[[rules]]
id = "invalid-url"
decision = "deny"
methods = ["GET"]
urls = ["https://example.test/empty//segment"]
"#,
        )
        .unwrap();

        let error = load_and_compile_exact_config(&config_path).unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains(
                "invalid_value at rules.d/10-invalid.toml rule 0.urls[0]: path must not contain an empty segment"
            ),
            "{rendered}"
        );
        assert!(rendered.contains("[rule_id=\"invalid-url\"]"), "{rendered}");
        assert!(
            !rendered.contains(directory.path().to_str().unwrap()),
            "{rendered}"
        );

        fs::write(
            rules_path.join("10-invalid.toml"),
            r#"schema_version = 4

[[rules]]
id = "unknown-provider"
decision = "delegate"
methods = ["GET"]
authorization_provider = "missing"
"#,
        )
        .unwrap();
        let error = load_and_compile_exact_config(&config_path).unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains(
                "unknown_reference at rules.d/10-invalid.toml rule 0.authorization_provider"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("[rule_id=\"unknown-provider\"]"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(directory.path().to_str().unwrap()),
            "{rendered}"
        );

        fs::write(
            rules_path.join("10-invalid.toml"),
            r#"schema_version = 4

[[rules]]
id = "unknown-credential"
decision = "allow"
urls = ["https://example.test/**"]

[[rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "missing"
"#,
        )
        .unwrap();
        let error = load_and_compile_exact_config(&config_path).unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered
                .contains("unknown_reference at rules.d/10-invalid.toml rule 0.credential_actions"),
            "{rendered}"
        );
        assert!(
            rendered.contains("[rule_id=\"unknown-credential\"]"),
            "{rendered}"
        );

        fs::write(
            rules_path.join("10-invalid.toml"),
            "schema_version = 4\n[[rules]]\nid = \"bad\\tid\"\ndecision = \"deny\"\nmethods = [\"GET\"]\n",
        )
        .unwrap();
        let error = load_and_compile_exact_config(&config_path).unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("rules.d/10-invalid.toml rule 0.id"),
            "{rendered}"
        );
        assert!(!rendered.contains("bad\tid"), "{rendered}");
        assert!(!rendered.contains("rule_id="), "{rendered}");
    }

    #[test]
    fn duplicate_rule_diagnostics_resolve_both_source_local_locations() {
        let duplicate_error = |fragments: &[(&str, &str)], main: &str| {
            let directory = tempdir().unwrap();
            let config_path = directory.path().join("acl-proxy.toml");
            let rules_path = directory.path().join("rules.d");
            fs::create_dir(&rules_path).unwrap();
            fs::write(&config_path, main).unwrap();
            for (name, contents) in fragments {
                fs::write(rules_path.join(name), contents).unwrap();
            }
            let error = load_and_compile_exact_config(&config_path).unwrap_err();
            let rendered = error.to_string();
            assert!(
                !rendered.contains(directory.path().to_str().unwrap()),
                "{rendered}"
            );
            rendered
        };
        let first = r#"schema_version = 4

[[rules]]
id = "shared"
decision = "deny"
methods = ["GET"]
"#;
        let second = r#"schema_version = 4

[[rules]]
id = "shared"
decision = "allow"
methods = ["GET"]
"#;
        let same_fragment = r#"schema_version = 4

[[rules]]
id = "shared"
decision = "deny"
methods = ["GET"]

[[rules]]
id = "shared"
decision = "allow"
methods = ["GET"]
"#;

        let rendered = duplicate_error(&[("02-policy.toml", same_fragment)], MINIMAL);
        assert!(
            rendered.contains(
                "duplicate rule ID \"shared\": first at rules.d/02-policy.toml rule 0; duplicate at rules.d/02-policy.toml rule 1"
            ),
            "{rendered}"
        );

        let rendered = duplicate_error(
            &[("02-first.toml", first), ("10-second.toml", second)],
            MINIMAL,
        );
        assert!(
            rendered.contains(
                "duplicate rule ID \"shared\": first at rules.d/02-first.toml rule 0; duplicate at rules.d/10-second.toml rule 0"
            ),
            "{rendered}"
        );

        let main = MINIMAL.replace(
            "[policy]",
            "[[policy.rules]]\nid = \"shared\"\ndecision = \"allow\"\nmethods = [\"GET\"]\n\n[policy]",
        );
        let rendered = duplicate_error(&[("02-first.toml", first)], &main);
        assert!(
            rendered.contains(
                "duplicate rule ID \"shared\": first at rules.d/02-first.toml rule 0; duplicate at main rule 0"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn fragment_rules_resolve_main_definitions_in_global_order() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        let main = MINIMAL.replace(
            "[policy]",
            r#"[authorization.providers.approval]
kind = "process"
command = "/bin/approval-provider"

[credentials.sources.api_token]
source = "environment"
variable = "RA03_TEST_API_TOKEN"

[redaction.profiles.secrets]
rules = [{ literals = ["redact-me"] }]

[[policy.rules]]
id = "main-deny"
decision = "deny"
urls = ["https://main.example.test/**"]

[policy]"#,
        );
        fs::write(&config_path, main).unwrap();
        fs::write(
            rules_path.join("10-delegated.toml"),
            r#"schema_version = 4

[[rules]]
id = "fragment-delegate"
decision = "delegate"
urls = ["https://fragment.example.test/**"]
authorization_provider = "approval"
redaction_profile = "secrets"

[[rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "api_token"
"#,
        )
        .unwrap();

        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let rules = &loaded.compiled.reloadable_plan.policy.rules;
        assert_eq!(
            rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            ["fragment-delegate", "main-deny"]
        );
        assert_eq!(rules[0].authorization_provider.as_deref(), Some("approval"));
        assert_eq!(rules[0].redaction_profile.as_deref(), Some("secrets"));
        assert_eq!(rules[0].credential_actions.len(), 1);
        assert_eq!(
            loaded
                .compiled
                .policy_provenance
                .resolve_cursor(0)
                .unwrap()
                .0
                .display_name(),
            "rules.d/10-delegated.toml"
        );
        assert_eq!(
            loaded
                .compiled
                .policy_provenance
                .resolve_cursor(1)
                .unwrap()
                .0
                .display_name(),
            "main"
        );

        let inline = compile_config_text(ConfigTextInput {
            text: r#"schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.approval]
kind = "process"
command = "/bin/approval-provider"

[credentials.sources.api_token]
source = "environment"
variable = "RA03_TEST_API_TOKEN"

[redaction.profiles.secrets]
rules = [{ literals = ["redact-me"] }]

[[policy.rules]]
id = "fragment-delegate"
decision = "delegate"
urls = ["https://fragment.example.test/**"]
authorization_provider = "approval"
redaction_profile = "secrets"

[[policy.rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "api_token"

[[policy.rules]]
id = "main-deny"
decision = "deny"
urls = ["https://main.example.test/**"]

[policy]
default = "deny"
"#,
            source_path: &config_path,
            config_root: directory.path(),
        })
        .unwrap();
        assert_eq!(
            loaded.compiled.static_fingerprint,
            inline.static_fingerprint
        );
        assert_eq!(
            loaded.compiled.reloadable_plan.resource_plan,
            inline.reloadable_plan.resource_plan
        );
        assert_eq!(
            loaded
                .compiled
                .reloadable_plan
                .policy
                .http_body_read_plans_by_cursor,
            inline.reloadable_plan.policy.http_body_read_plans_by_cursor
        );
    }

    #[test]
    fn aggregate_identity_budget_is_global_across_fragments() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        fs::write(
            &config_path,
            r#"schema_version = 4

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http1 = "deny"

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "test-authority"

[[identity.resolver.principals]]
id = "test-principal"
kind = "service_account"

[[identity.resolver.tokens]]
id = "test-token"
principal = "test-principal"
source = "environment"
variable = "AW_IDENTITY_TOKEN"

[[identity.resolver.groups]]
id = "developers"
members = ["test-principal"]

[policy]
default = "deny"
"#,
        )
        .unwrap();
        let fragment = |start: usize, count: usize| {
            let mut text = "schema_version = 4\n".to_owned();
            for index in start..start + count {
                text.push_str(&format!(
                    r#"
[[rules]]
id = "identity-{index}"
decision = "allow"
identity_states = ["authenticated"]
identity_subjects = [
  {{ kind = "group", authority = "test-authority", id = "developers" }},
]
"#
                ));
            }
            text
        };
        let bound = http_access_policy_acl::MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT;
        let first_count = bound / 2;
        let second_count = bound - first_count;
        fs::write(rules_path.join("00-first.toml"), fragment(0, first_count)).unwrap();
        fs::write(
            rules_path.join("10-second.toml"),
            fragment(first_count, second_count),
        )
        .unwrap();

        let exact = load_and_compile_exact_config(&config_path).unwrap();
        assert_eq!(exact.compiled.reloadable_plan.policy.rules.len(), bound);

        fs::write(
            rules_path.join("10-second.toml"),
            fragment(first_count, second_count + 1),
        )
        .unwrap();
        let rendered = load_and_compile_exact_config(&config_path)
            .unwrap_err()
            .to_string();
        assert!(
            rendered.contains(&format!(
                "limit_exceeded at rules.d/10-second.toml rule {second_count}.identity_subjects"
            )),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("[rule_id=\"identity-{bound}\"]")),
            "{rendered}"
        );
    }

    fn assert_secret_absent(error: &ConfigFacadeError, secret: &str) {
        assert!(!error.to_string().contains(secret), "{error}");
        assert!(!format!("{error:?}").contains(secret), "{error:?}");
    }
}
