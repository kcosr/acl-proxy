use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use super::authoring::AuthoringConfig;

const CONFIG_PATH_ENV: &str = "ACL_PROXY_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "config/acl-proxy.toml";
const MAX_CONFIG_BYTES: usize = 10 * 1024 * 1024;

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
    pub path: PathBuf,
    pub config_root: PathBuf,
    pub path_source: ConfigPathSource,
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

    #[error("failed to open configuration file {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("configuration file {path} exceeds the {max_bytes}-byte limit")]
    TooLarge { path: PathBuf, max_bytes: usize },

    #[error("configuration file {path} is not valid UTF-8 at byte {valid_up_to}")]
    InvalidUtf8 { path: PathBuf, valid_up_to: usize },

    #[error("configuration file {path} is not valid strict schema v3 TOML: {diagnostic}")]
    ParseToml {
        path: PathBuf,
        diagnostic: SanitizedTomlDiagnostic,
    },
}

pub(super) fn load_config(explicit_path: Option<&Path>) -> Result<LoadedConfig, ConfigLoadError> {
    let environment_path = if explicit_path.is_none() {
        env::var(CONFIG_PATH_ENV).ok()
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
    environment_path: Option<&str>,
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

    let bytes = read_bounded(&path)?;
    let text = std::str::from_utf8(&bytes).map_err(|source| ConfigLoadError::InvalidUtf8 {
        path: path.clone(),
        valid_up_to: source.valid_up_to(),
    })?;
    let authored = parse_config_text(text, &path)?;

    Ok(LoadedConfig {
        authored,
        path,
        config_root,
        path_source: selected.source,
    })
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
    toml::from_str(text).map_err(|source| ConfigLoadError::ParseToml {
        path: path.to_path_buf(),
        diagnostic: sanitize_toml_error(text, &source),
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

fn read_bounded(path: &Path) -> Result<Vec<u8>, ConfigLoadError> {
    let file = File::open(path).map_err(|source| ConfigLoadError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigLoadError::TooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_CONFIG_BYTES,
        });
    }
    Ok(bytes)
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
    use std::io::{Seek, SeekFrom, Write};

    use tempfile::tempdir;

    use super::*;

    const MINIMAL_CONFIG: &str = r#"
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
    fn config_path_precedence_is_explicit_then_environment_then_default() {
        assert_eq!(
            select_config_path(Some(Path::new("cli.toml")), Some("env.toml")),
            SelectedConfigPath {
                path: PathBuf::from("cli.toml"),
                source: ConfigPathSource::Explicit,
            }
        );
        assert_eq!(
            select_config_path(None, Some("env.toml")),
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
            ConfigLoadError::TooLarge {
                max_bytes: MAX_CONFIG_BYTES,
                ..
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
    fn strict_deserialization_rejects_non_v3_and_unknown_fields() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("invalid.toml");
        fs::write(
            &config_path,
            MINIMAL_CONFIG.replace("schema_version = 3", "schema_version = 2"),
        )
        .unwrap();
        let wrong_version = load_path(&config_path).unwrap_err();
        assert!(matches!(wrong_version, ConfigLoadError::ParseToml { .. }));
        assert!(wrong_version.to_string().contains("invalid value"));

        fs::write(&config_path, format!("{MINIMAL_CONFIG}\nlegacy = true\n")).unwrap();
        let unknown = load_path(&config_path).unwrap_err();
        assert!(matches!(unknown, ConfigLoadError::ParseToml { .. }));
        assert!(unknown.to_string().contains("unknown field"));
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
    fn io_errors_include_the_selected_absolute_path() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("missing.toml");

        let error = load_path(&config_path).unwrap_err();
        assert!(matches!(error, ConfigLoadError::Open { .. }));
        assert!(error.to_string().contains(config_path.to_str().unwrap()));
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
