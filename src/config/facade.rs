use std::fmt;
use std::path::{Path, PathBuf};

use super::compiler::{
    compile_config, CompiledProductConfig, ReloadableProductPlan, StaticFingerprint,
    StaticProductConfig,
};
use super::loader;

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
}

impl fmt::Debug for CompiledConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledConfig")
            .field("static_fingerprint", &self.static_fingerprint)
            .field("reloadable_plan", &self.reloadable_plan)
            .finish_non_exhaustive()
    }
}

pub(crate) struct LoadedCompiledConfig {
    pub(crate) metadata: ConfigFileMetadata,
    pub(crate) compiled: CompiledConfig,
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
        source_path: PathBuf,
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
            Self::Compile {
                source_path,
                message,
            } => write!(
                formatter,
                "configuration file {} failed validation: {message}",
                source_path.display()
            ),
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
    let compiled = compile_authored(loaded.authored, &metadata.config_root, &metadata.path)?;
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
    let compiled = compile_authored(loaded.authored, &metadata.config_root, &metadata.path)?;
    Ok(LoadedCompiledConfig { metadata, compiled })
}

#[cfg(test)]
pub(crate) fn compile_config_text(
    input: ConfigTextInput<'_>,
) -> Result<CompiledConfig, ConfigFacadeError> {
    let authored = loader::parse_config_text(input.text, input.source_path).map_err(load_error)?;
    compile_authored(authored, input.config_root, input.source_path)
}

pub(crate) fn write_default_config_template(path: &Path) -> Result<(), ConfigFacadeError> {
    super::template::write_default_config(path).map_err(|source| ConfigFacadeError::WriteTemplate {
        path: path.to_path_buf(),
        source,
    })
}

fn compile_authored(
    authored: super::authoring::AuthoringConfig,
    config_root: &Path,
    source_path: &Path,
) -> Result<CompiledConfig, ConfigFacadeError> {
    let compiled =
        compile_config(authored, config_root).map_err(|source| ConfigFacadeError::Compile {
            source_path: source_path.to_path_buf(),
            message: source.to_string(),
        })?;
    Ok(split_compiled(compiled))
}

fn load_error(source: super::loader::ConfigLoadError) -> ConfigFacadeError {
    ConfigFacadeError::Load {
        message: source.to_string(),
    }
}

fn split_compiled(compiled: CompiledProductConfig) -> CompiledConfig {
    CompiledConfig {
        static_config: compiled.static_config,
        static_fingerprint: compiled.static_fingerprint,
        reloadable_plan: compiled.reloadable_plan,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::config::compiler::AuthorizationProviderPlan;

    const MINIMAL: &str = r#"
schema_version = 3

[listeners.explicit_http]
bind = "127.0.0.1:8881"
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
        assert_eq!(loaded.compiled.static_config.schema_version, 3);
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
    fn production_v1_shapes_are_rejected_by_v3_runtime() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/production");
        for name in [
            "v1-host-shape.toml",
            "v1-common-container-shape.toml",
            "v1-internal-container-shape.toml",
        ] {
            let error = load_and_compile_exact_config(&fixture_root.join(name)).unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains("strict schema v3"), "{name}: {rendered}");
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

        assert_eq!(loaded.compiled.static_config.schema_version, 3);
        assert_eq!(loaded.metadata.path, path);
        assert_eq!(loaded.compiled.reloadable_plan.policy.rules.len(), 0);
    }

    #[test]
    fn shipped_sample_strictly_loads_and_compiles_through_the_facade() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("acl-proxy.sample.toml");

        let loaded = load_and_compile_exact_config(&path)
            .expect("shipped sample must pass the real strict loader and compiler");

        assert_eq!(loaded.metadata.path, path);
        assert_eq!(loaded.compiled.static_config.schema_version, 3);
        assert_eq!(loaded.compiled.reloadable_plan.policy.rules.len(), 0);
    }

    fn assert_secret_absent(error: &ConfigFacadeError, secret: &str) {
        assert!(!error.to_string().contains(secret), "{error}");
        assert!(!format!("{error:?}").contains(secret), "{error:?}");
    }
}
