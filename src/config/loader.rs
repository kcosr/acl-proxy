use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use super::authoring::{AuthoringConfig, RulesFragmentConfig};
use super::source_snapshot::{self, LoadSourcesError, SourceInventorySummary, SourceRef};

const CONFIG_PATH_ENV: &str = "ACL_PROXY_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "config/acl-proxy.toml";
const MAX_CONFIG_BYTES: usize = source_snapshot::MAX_MAIN_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigPathSource {
    Explicit,
    Environment,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SelectedConfigPath {
    pub path: PathBuf,
    pub source: ConfigPathSource,
}

#[derive(Debug)]
pub(super) struct LoadedConfig {
    pub authored: AuthoringConfig,
    pub rule_sources: Vec<RuleSource>,
    pub source_summary: SourceInventorySummary,
    pub path: PathBuf,
    pub config_root: PathBuf,
    pub path_source: ConfigPathSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuleSourceKind {
    Main,
    Fragment(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleSource {
    pub(crate) source: RuleSourceKind,
    pub(crate) source_rule_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TomlErrorCategory {
    Syntax,
    UnknownField,
    MissingField,
    DuplicateField,
    InvalidType,
    InvalidValue,
    UnknownVariant,
    Schema,
}

impl fmt::Display for TomlErrorCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Syntax => "syntax error",
            Self::UnknownField => "unknown field",
            Self::MissingField => "missing required field",
            Self::DuplicateField => "duplicate field",
            Self::InvalidType => "invalid value type",
            Self::InvalidValue => "invalid value",
            Self::UnknownVariant => "unknown variant",
            Self::Schema => "schema error",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SanitizedTomlDiagnostic {
    category: TomlErrorCategory,
    location: Option<TomlLocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TomlLocation {
    line: usize,
    column: usize,
}

impl fmt::Display for SanitizedTomlDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.category)?;
        if let Some(location) = self.location {
            write!(
                formatter,
                " at line {}, column {}",
                location.line, location.column
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub(super) enum ConfigLoadError {
    #[error("failed to determine the current directory while resolving the configuration path: {source}")]
    CurrentDirectory {
        #[source]
        source: io::Error,
    },

    #[error("configuration path {path} does not name a file with a parent directory")]
    InvalidPath { path: PathBuf },

    #[error("configuration file {path} exceeds the {max_bytes}-byte limit")]
    TooLarge { path: PathBuf, max_bytes: usize },

    #[error("configuration file {path} is not valid UTF-8 at byte {valid_up_to}")]
    InvalidUtf8 { path: PathBuf, valid_up_to: usize },

    #[error("configuration file {path} is not valid strict schema v4 TOML: {diagnostic}")]
    ParseToml {
        path: PathBuf,
        diagnostic: SanitizedTomlDiagnostic,
    },

    #[error("{source_name} is not valid strict schema v4 TOML: {diagnostic}")]
    ParseFragmentToml {
        source_name: String,
        diagnostic: SanitizedTomlDiagnostic,
    },

    #[error("{source_name} is not valid UTF-8 at byte {valid_up_to}")]
    InvalidFragmentUtf8 {
        source_name: String,
        valid_up_to: usize,
    },

    #[error("{source_name} must contain at least one rule")]
    EmptyFragment { source_name: String },

    #[error("failed to obtain a stable configuration source snapshot: {source}")]
    Snapshot {
        #[source]
        source: source_snapshot::SourceSnapshotError,
    },

    #[error(
        "configuration file {path} uses the removed data-listener field `bind`; use `endpoint = {{ kind = \"tcp\", address = \"127.0.0.1:8881\" }}` instead"
    )]
    LegacyListenerBind { path: PathBuf },

    #[error(
        "configuration file {path} uses removed configuration surface `{surface}`; {replacement}"
    )]
    RemovedConfigSurface {
        path: PathBuf,
        surface: String,
        replacement: &'static str,
    },
}

pub(super) fn load_config(explicit_path: Option<&Path>) -> Result<LoadedConfig, ConfigLoadError> {
    let environment_path = if explicit_path.is_none() {
        env::var_os(CONFIG_PATH_ENV)
    } else {
        None
    };
    let selected = select_config_path(explicit_path, environment_path.as_deref());
    if selected.path.is_absolute() {
        return load_selected_config(selected, Path::new(""));
    }
    let current_dir =
        env::current_dir().map_err(|source| ConfigLoadError::CurrentDirectory { source })?;
    load_selected_config(selected, &current_dir)
}

pub(super) fn load_exact_config(path: &Path) -> Result<LoadedConfig, ConfigLoadError> {
    if !path.is_absolute() {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }
    load_selected_config(
        SelectedConfigPath {
            path: path.to_path_buf(),
            source: ConfigPathSource::Explicit,
        },
        Path::new(""),
    )
}

pub(super) fn select_config_path(
    explicit_path: Option<&Path>,
    environment_path: Option<&OsStr>,
) -> SelectedConfigPath {
    if let Some(path) = explicit_path {
        SelectedConfigPath {
            path: path.to_path_buf(),
            source: ConfigPathSource::Explicit,
        }
    } else if let Some(path) = environment_path {
        SelectedConfigPath {
            path: PathBuf::from(path),
            source: ConfigPathSource::Environment,
        }
    } else {
        SelectedConfigPath {
            path: PathBuf::from(DEFAULT_CONFIG_PATH),
            source: ConfigPathSource::Default,
        }
    }
}

fn load_selected_config(
    selected: SelectedConfigPath,
    current_dir: &Path,
) -> Result<LoadedConfig, ConfigLoadError> {
    let path = absolute_normalized_path(&selected.path, current_dir);
    let config_root = path
        .parent()
        .ok_or_else(|| ConfigLoadError::InvalidPath { path: path.clone() })?
        .to_path_buf();

    let mut authored = None;
    let mut fragment_rules = Vec::new();
    let mut fragment_sources = Vec::new();
    let source_summary = source_snapshot::load_sources(&path, |source, bytes| match source {
        SourceRef::Main => {
            let text =
                std::str::from_utf8(bytes).map_err(|source| ConfigLoadError::InvalidUtf8 {
                    path: path.clone(),
                    valid_up_to: source.valid_up_to(),
                })?;
            authored = Some(parse_config_text(text, &path)?);
            Ok(())
        }
        SourceRef::Fragment(name) => {
            let source_name = format!("rules.d/{}", name.as_str());
            let text = std::str::from_utf8(bytes).map_err(|source| {
                ConfigLoadError::InvalidFragmentUtf8 {
                    source_name: source_name.clone(),
                    valid_up_to: source.valid_up_to(),
                }
            })?;
            let mut fragment = parse_fragment_text(text, &source_name)?;
            fragment_sources.extend((0..fragment.rules.len()).map(|source_rule_index| {
                RuleSource {
                    source: RuleSourceKind::Fragment(name.as_str().to_owned()),
                    source_rule_index,
                }
            }));
            fragment_rules.append(&mut fragment.rules);
            Ok(())
        }
    })
    .map_err(|source| match source {
        LoadSourcesError::Snapshot(source) => ConfigLoadError::Snapshot { source },
        LoadSourcesError::Consumer(source) => source,
    })?;
    let mut authored = authored.ok_or(ConfigLoadError::Snapshot {
        source: source_snapshot::SourceSnapshotError::MissingMain,
    })?;
    let main_rule_count = authored.policy.rules.len();
    fragment_sources.extend((0..main_rule_count).map(|source_rule_index| RuleSource {
        source: RuleSourceKind::Main,
        source_rule_index,
    }));
    fragment_rules.append(&mut authored.policy.rules);
    authored.policy.rules = fragment_rules;

    Ok(LoadedConfig {
        authored,
        rule_sources: fragment_sources,
        source_summary,
        path,
        config_root,
        path_source: selected.source,
    })
}

fn parse_fragment_text(
    text: &str,
    source_name: &str,
) -> Result<RulesFragmentConfig, ConfigLoadError> {
    let fragment = toml::from_str::<RulesFragmentConfig>(text).map_err(|source| {
        ConfigLoadError::ParseFragmentToml {
            source_name: source_name.to_owned(),
            diagnostic: sanitize_toml_error(text, &source),
        }
    })?;
    let _ = fragment.schema_version.number();
    if fragment.rules.is_empty() {
        return Err(ConfigLoadError::EmptyFragment {
            source_name: source_name.to_owned(),
        });
    }
    Ok(fragment)
}

pub(super) fn parse_config_text(
    text: &str,
    path: &Path,
) -> Result<AuthoringConfig, ConfigLoadError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigLoadError::TooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_CONFIG_BYTES,
        });
    }
    toml::from_str(text).map_err(|source| {
        if let Some((surface, replacement)) = removed_config_surface(text) {
            ConfigLoadError::RemovedConfigSurface {
                path: path.to_path_buf(),
                surface,
                replacement,
            }
        } else if contains_legacy_listener_bind(text) {
            ConfigLoadError::LegacyListenerBind {
                path: path.to_path_buf(),
            }
        } else {
            ConfigLoadError::ParseToml {
                path: path.to_path_buf(),
                diagnostic: sanitize_toml_error(text, &source),
            }
        }
    })
}

fn removed_config_surface(text: &str) -> Option<(String, &'static str)> {
    let config = toml::from_str::<toml::Value>(text).ok()?;
    if let Some(listeners) = config.get("listeners").and_then(toml::Value::as_table) {
        for name in [
            "explicit_http",
            "transparent_http",
            "explicit_https",
            "transparent_https",
        ] {
            let Some(listener) = listeners.get(name).and_then(toml::Value::as_table) else {
                continue;
            };
            if let Some(endpoint) = listener.get("endpoint").and_then(toml::Value::as_table) {
                match endpoint.get("kind").and_then(toml::Value::as_str) {
                    Some("unix_proxy_v2") => {
                        return Some((
                            format!("listeners.{name}.endpoint.kind = \"unix_proxy_v2\""),
                            "use `endpoint.kind = \"access_flow\"` with a nested `endpoint.transport.kind = \"unix\"` instead",
                        ));
                    }
                    Some("unix_proxy_v2_identity") => {
                        return Some((
                            format!(
                                "listeners.{name}.endpoint.kind = \"unix_proxy_v2_identity\""
                            ),
                            "use `endpoint.kind = \"access_flow\"` with a nested `endpoint.transport.kind = \"unix\"` and configure `identity.mode` on the listener instead",
                        ));
                    }
                    _ => {}
                }
                if endpoint.contains_key("proxy_header_timeout") {
                    return Some((
                        format!("listeners.{name}.endpoint.proxy_header_timeout"),
                        "use `endpoint.admission_timeout` instead",
                    ));
                }
            }
            if listener.contains_key("proxy_header_timeout") {
                return Some((
                    format!("listeners.{name}.proxy_header_timeout"),
                    "use `endpoint.admission_timeout` instead",
                ));
            }
        }
    }
    if let Some(rules) = config
        .get("policy")
        .and_then(|policy| policy.get("rules"))
        .and_then(toml::Value::as_array)
    {
        for (index, rule) in rules.iter().enumerate() {
            if rule
                .as_table()
                .is_some_and(|rule| rule.contains_key("identity_state"))
            {
                return Some((
                    format!("policy.rules[{index}].identity_state"),
                    "use the plural `identity_states = [...]` field instead",
                ));
            }
        }
    }
    None
}

fn contains_legacy_listener_bind(text: &str) -> bool {
    let Ok(config) = toml::from_str::<toml::Value>(text) else {
        return false;
    };
    let Some(listeners) = config.get("listeners").and_then(toml::Value::as_table) else {
        return false;
    };
    [
        "explicit_http",
        "transparent_http",
        "explicit_https",
        "transparent_https",
    ]
    .into_iter()
    .any(|name| {
        listeners
            .get(name)
            .and_then(toml::Value::as_table)
            .is_some_and(|listener| listener.contains_key("bind"))
    })
}

fn sanitize_toml_error(text: &str, error: &toml::de::Error) -> SanitizedTomlDiagnostic {
    let category = if toml::from_str::<toml::Value>(text).is_err() {
        TomlErrorCategory::Syntax
    } else {
        classify_schema_error(error.message())
    };
    let location = error
        .span()
        .map(|span| toml_location(text, span.start.min(text.len())));

    SanitizedTomlDiagnostic { category, location }
}

fn classify_schema_error(message: &str) -> TomlErrorCategory {
    if message.contains("unknown field") {
        TomlErrorCategory::UnknownField
    } else if message.contains("missing field") {
        TomlErrorCategory::MissingField
    } else if message.contains("duplicate field") {
        TomlErrorCategory::DuplicateField
    } else if message.contains("invalid type") {
        TomlErrorCategory::InvalidType
    } else if message.contains("invalid value") || message.contains("unsupported schema_version") {
        TomlErrorCategory::InvalidValue
    } else if message.contains("unknown variant") {
        TomlErrorCategory::UnknownVariant
    } else {
        TomlErrorCategory::Schema
    }
}

fn toml_location(text: &str, byte_offset: usize) -> TomlLocation {
    let preceding = &text[..byte_offset];
    let line = preceding.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = preceding.rfind('\n').map_or(0, |index| index + 1);
    let column = text[line_start..byte_offset].chars().count() + 1;
    TomlLocation { line, column }
}

fn absolute_normalized_path(path: &Path, current_dir: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                }
            }
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt};

    use tempfile::tempdir;

    use super::*;
    use crate::config::source_snapshot::RulesDirectoryState;

    const MINIMAL_CONFIG: &str = r#"
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
    fn config_path_precedence_is_explicit_then_environment_then_default() {
        assert_eq!(
            select_config_path(Some(Path::new("cli.toml")), Some(OsStr::new("env.toml")),),
            SelectedConfigPath {
                path: PathBuf::from("cli.toml"),
                source: ConfigPathSource::Explicit,
            }
        );
        assert_eq!(
            select_config_path(None, Some(OsStr::new("env.toml"))),
            SelectedConfigPath {
                path: PathBuf::from("env.toml"),
                source: ConfigPathSource::Environment,
            }
        );
        assert_eq!(
            select_config_path(None, None),
            SelectedConfigPath {
                path: PathBuf::from(DEFAULT_CONFIG_PATH),
                source: ConfigPathSource::Default,
            }
        );
    }

    #[test]
    fn selected_path_and_config_root_are_absolute_and_lexically_normalized() {
        let directory = tempdir().unwrap();
        let config_dir = directory.path().join("configs");
        fs::create_dir(&config_dir).unwrap();
        let config_path = config_dir.join("acl-proxy.toml");
        fs::write(&config_path, MINIMAL_CONFIG).unwrap();

        let selected = SelectedConfigPath {
            path: PathBuf::from("other/../configs/./acl-proxy.toml"),
            source: ConfigPathSource::Explicit,
        };
        let loaded = load_selected_config(selected, directory.path()).unwrap();

        assert_eq!(loaded.path, config_path);
        assert_eq!(loaded.config_root, config_dir);
        assert!(loaded.path.is_absolute());
        assert!(loaded.config_root.is_absolute());
        assert_eq!(loaded.path_source, ConfigPathSource::Explicit);
    }

    #[test]
    fn strict_parse_does_not_resolve_referenced_files_secrets_or_processes() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let config = format!(
            r#"{MINIMAL_CONFIG}

[control]
bind = "127.0.0.1:8898"

[control.tls]
certificate_chain = "missing-control-cert.pem"
private_key = "missing-control-key.pem"

[authorization.providers.local]
kind = "process"
command = "missing-provider"

[credentials.sources.token]
source = "environment"
variable = "MISSING_CONFIG_LOADER_TEST_SECRET"

[credentials.sources.file_token]
source = "file"
path = "missing-secret"

[redaction.profiles.secrets]

[[redaction.profiles.secrets.rules]]
literal_environment_variables = ["MISSING_CONFIG_LOADER_REDACTION_SECRET"]
"#
        );
        fs::write(&config_path, config).unwrap();

        let loaded = load_selected_config(
            SelectedConfigPath {
                path: config_path.clone(),
                source: ConfigPathSource::Explicit,
            },
            directory.path(),
        )
        .unwrap();

        assert_eq!(loaded.path, config_path);
        assert_eq!(loaded.authored.authorization.providers.len(), 1);
        assert_eq!(loaded.authored.credentials.sources.len(), 2);
    }

    #[test]
    fn oversized_input_is_rejected_before_utf8_or_toml_parsing() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("oversized.toml");
        let mut file = File::create(&config_path).unwrap();
        file.seek(SeekFrom::Start(MAX_CONFIG_BYTES as u64)).unwrap();
        file.write_all(&[0xff]).unwrap();
        drop(file);

        let error = load_path(&config_path).unwrap_err();
        assert!(matches!(
            error,
            ConfigLoadError::Snapshot {
                source: source_snapshot::SourceSnapshotError::TooLarge {
                    max_bytes: MAX_CONFIG_BYTES,
                    ..
                }
            }
        ));
    }

    #[test]
    fn exact_size_limit_is_accepted() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("maximum.toml");
        let mut bytes = MINIMAL_CONFIG.as_bytes().to_vec();
        bytes.resize(MAX_CONFIG_BYTES, b' ');
        fs::write(&config_path, bytes).unwrap();

        load_path(&config_path).unwrap();
    }

    #[test]
    fn invalid_utf8_is_reported_before_toml_parsing() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("invalid-utf8.toml");
        fs::write(&config_path, [0xff]).unwrap();

        assert!(matches!(
            load_path(&config_path).unwrap_err(),
            ConfigLoadError::InvalidUtf8 { valid_up_to: 0, .. }
        ));
    }

    #[test]
    fn strict_deserialization_rejects_non_v4_and_unknown_fields() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("invalid.toml");
        fs::write(
            &config_path,
            MINIMAL_CONFIG.replace("schema_version = 4", "schema_version = 2"),
        )
        .unwrap();
        let wrong_version = load_path(&config_path).unwrap_err();
        assert!(matches!(wrong_version, ConfigLoadError::ParseToml { .. }));
        assert!(wrong_version.to_string().contains("invalid value"));

        fs::write(&config_path, format!("{MINIMAL_CONFIG}\nlegacy = true\n")).unwrap();
        let unknown = load_path(&config_path).unwrap_err();
        assert!(matches!(unknown, ConfigLoadError::ParseToml { .. }));
        assert!(unknown.to_string().contains("unknown field"));

        fs::write(
            &config_path,
            MINIMAL_CONFIG.replace(
                "endpoint.kind = \"tcp\"\nendpoint.address = \"127.0.0.1:8881\"",
                "bind = \"127.0.0.1:8881\"",
            ),
        )
        .unwrap();
        let legacy_bind = load_path(&config_path).unwrap_err();
        assert!(matches!(
            legacy_bind,
            ConfigLoadError::LegacyListenerBind { .. }
        ));
        assert!(legacy_bind
            .to_string()
            .contains("endpoint = { kind = \"tcp\""));
    }

    #[test]
    fn removed_identity_and_access_flow_shapes_have_actionable_loader_diagnostics() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("removed.toml");
        for (input, surface, replacement) in [
            (
                MINIMAL_CONFIG.replace(
                    "endpoint.kind = \"tcp\"",
                    "endpoint.kind = \"unix_proxy_v2\"",
                ),
                "listeners.explicit_http.endpoint.kind = \"unix_proxy_v2\"",
                "endpoint.kind = \"access_flow\"",
            ),
            (
                MINIMAL_CONFIG.replace(
                    "endpoint.kind = \"tcp\"",
                    "endpoint.kind = \"unix_proxy_v2_identity\"",
                ),
                "listeners.explicit_http.endpoint.kind = \"unix_proxy_v2_identity\"",
                "identity.mode",
            ),
            (
                MINIMAL_CONFIG.replace(
                    "http_versions = [\"http1\"]",
                    "http_versions = [\"http1\"]\nproxy_header_timeout = \"2s\"",
                ),
                "listeners.explicit_http.proxy_header_timeout",
                "endpoint.admission_timeout",
            ),
            (
                MINIMAL_CONFIG.replace(
                    "endpoint.address = \"127.0.0.1:8881\"",
                    "endpoint.address = \"127.0.0.1:8881\"\nendpoint.proxy_header_timeout = \"2s\"",
                ),
                "listeners.explicit_http.endpoint.proxy_header_timeout",
                "endpoint.admission_timeout",
            ),
            (
                format!(
                    r#"{MINIMAL_CONFIG}

[[policy.rules]]
id = "removed-singular"
decision = "deny"
identity_state = "authenticated"
"#
                ),
                "policy.rules[0].identity_state",
                "identity_states = [...]",
            ),
        ] {
            fs::write(&config_path, input).unwrap();
            let error = load_path(&config_path).unwrap_err();
            assert!(
                matches!(error, ConfigLoadError::RemovedConfigSurface { .. }),
                "{error}"
            );
            assert!(error.to_string().contains(surface), "{error}");
            assert!(error.to_string().contains(replacement), "{error}");
        }
    }

    #[test]
    fn syntax_diagnostic_does_not_disclose_credential_locator_text() {
        const SECRET_MARKER: &str = "credential-locator-secret-9f1b7c";

        let directory = tempdir().unwrap();
        let config_path = directory.path().join("invalid-credential.toml");
        fs::write(
            &config_path,
            format!(
                r#"{MINIMAL_CONFIG}

[credentials.sources.token]
source = "environment"
variable = "{SECRET_MARKER}
"#
            ),
        )
        .unwrap();

        let error = load_path(&config_path).unwrap_err();
        assert_parse_diagnostic_is_sanitized(&error, SECRET_MARKER, "syntax error");
    }

    #[test]
    fn schema_diagnostic_does_not_disclose_redaction_literal_text() {
        const SECRET_MARKER: &str = "redaction-literal-secret-3a6d2e";

        let directory = tempdir().unwrap();
        let config_path = directory.path().join("invalid-redaction.toml");
        fs::write(
            &config_path,
            format!(
                r#"{MINIMAL_CONFIG}

[redaction.profiles.secrets]
rules = [{{ literals = "{SECRET_MARKER}" }}]
"#
            ),
        )
        .unwrap();

        let error = load_path(&config_path).unwrap_err();
        assert_parse_diagnostic_is_sanitized(&error, SECRET_MARKER, "invalid value type");
    }

    #[test]
    fn io_errors_identify_the_main_source_without_disclosing_host_paths() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("missing.toml");

        let error = load_path(&config_path).unwrap_err();
        assert!(matches!(error, ConfigLoadError::Snapshot { .. }));
        assert!(error.to_string().contains("main"));
        assert!(!error.to_string().contains(config_path.to_str().unwrap()));
    }

    #[test]
    fn fragments_are_strict_and_precede_main_rules_in_ascii_order() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        fs::write(
            &config_path,
            MINIMAL_CONFIG.replace(
                "[policy]",
                "[[policy.rules]]\nid = \"main\"\ndecision = \"deny\"\n\n[policy]",
            ),
        )
        .unwrap();
        fs::write(
            rules_path.join("10-second.toml"),
            "schema_version = 4\n[[rules]]\nid = \"second\"\ndecision = \"deny\"\n",
        )
        .unwrap();
        fs::write(
            rules_path.join("02-first.toml"),
            "schema_version = 4\n[[rules]]\nid = \"first\"\ndecision = \"deny\"\n",
        )
        .unwrap();

        let loaded = load_path(&config_path).unwrap();
        let ids = loaded
            .authored
            .policy
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["first", "second", "main"]);
        assert_eq!(loaded.rule_sources.len(), 3);
        assert_eq!(loaded.source_summary.fragment_count, 2);
        assert_eq!(
            loaded.source_summary.rules_directory,
            RulesDirectoryState::Populated
        );
    }

    #[test]
    fn missing_and_empty_rules_directories_are_distinguished() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        fs::write(&config_path, MINIMAL_CONFIG).unwrap();
        let missing = load_path(&config_path).unwrap();
        assert_eq!(
            missing.source_summary.rules_directory,
            RulesDirectoryState::Missing
        );

        fs::create_dir(directory.path().join("rules.d")).unwrap();
        let empty = load_path(&config_path).unwrap();
        assert_eq!(
            empty.source_summary.rules_directory,
            RulesDirectoryState::Empty
        );
    }

    #[test]
    fn fragments_reject_unknown_fields_wrong_schema_and_empty_rules() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        fs::write(&config_path, MINIMAL_CONFIG).unwrap();
        let fragment_path = rules_path.join("10-policy.toml");

        fs::write(&fragment_path, "schema_version = 3\nrules = []\n").unwrap();
        assert!(matches!(
            load_path(&config_path).unwrap_err(),
            ConfigLoadError::ParseFragmentToml { .. }
        ));

        fs::write(&fragment_path, "schema_version = 4\nrules = []\n").unwrap();
        assert!(matches!(
            load_path(&config_path).unwrap_err(),
            ConfigLoadError::EmptyFragment { .. }
        ));

        fs::write(
            &fragment_path,
            "schema_version = 4\nextra = true\n[[rules]]\nid = \"x\"\ndecision = \"deny\"\n",
        )
        .unwrap();
        assert!(matches!(
            load_path(&config_path).unwrap_err(),
            ConfigLoadError::ParseFragmentToml { .. }
        ));
    }

    #[test]
    fn unexpected_names_and_ascii_case_collisions_fail_the_snapshot() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        fs::write(&config_path, MINIMAL_CONFIG).unwrap();
        fs::write(rules_path.join(".editor.tmp"), "").unwrap();
        assert!(matches!(
            load_path(&config_path).unwrap_err(),
            ConfigLoadError::Snapshot { .. }
        ));
        fs::remove_file(rules_path.join(".editor.tmp")).unwrap();
        for name in ["10-Users.toml", "10-users.toml"] {
            fs::write(
                rules_path.join(name),
                "schema_version = 4\n[[rules]]\nid = \"x\"\ndecision = \"deny\"\n",
            )
            .unwrap();
        }
        let error = load_path(&config_path).unwrap_err();
        assert!(error.to_string().contains("ASCII case folding"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_directory_fifo_and_hard_link_entries_are_rejected_without_blocking() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let rules_path = directory.path().join("rules.d");
        fs::create_dir(&rules_path).unwrap();
        fs::write(&config_path, MINIMAL_CONFIG).unwrap();
        let target = directory.path().join("target.toml");
        fs::write(
            &target,
            "schema_version = 4\n[[rules]]\nid = \"x\"\ndecision = \"deny\"\n",
        )
        .unwrap();

        symlink(&target, rules_path.join("10-policy.toml")).unwrap();
        assert!(load_path(&config_path).is_err());
        fs::remove_file(rules_path.join("10-policy.toml")).unwrap();

        fs::create_dir(rules_path.join("10-policy.toml")).unwrap();
        assert!(load_path(&config_path).is_err());
        fs::remove_dir(rules_path.join("10-policy.toml")).unwrap();

        fs::hard_link(&target, rules_path.join("10-policy.toml")).unwrap();
        assert!(fs::metadata(&target).unwrap().nlink() > 1);
        assert!(load_path(&config_path).is_err());
        fs::remove_file(rules_path.join("10-policy.toml")).unwrap();

        let fifo = rules_path.join("10-policy.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(load_path(&config_path).is_err());
    }

    fn load_path(path: &Path) -> Result<LoadedConfig, ConfigLoadError> {
        load_selected_config(
            SelectedConfigPath {
                path: path.to_path_buf(),
                source: ConfigPathSource::Explicit,
            },
            path.parent().unwrap(),
        )
    }

    fn assert_parse_diagnostic_is_sanitized(
        error: &ConfigLoadError,
        secret_marker: &str,
        expected_category: &str,
    ) {
        assert!(matches!(error, ConfigLoadError::ParseToml { .. }));

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains(expected_category), "{display}");
        assert!(display.contains("line"), "{display}");
        assert!(display.contains("column"), "{display}");
        assert!(!display.contains(secret_marker), "{display}");
        assert!(!debug.contains(secret_marker), "{debug}");
    }
}
