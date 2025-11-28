use http::header::HeaderName;

use crate::config::LoopProtectionConfig;

#[derive(Debug, thiserror::Error)]
pub enum LoopProtectionError {
    #[error("invalid loop protection header name {0}")]
    InvalidHeaderName(String),
}

#[derive(Debug, Clone)]
pub struct LoopProtectionSettings {
    pub enabled: bool,
    pub add_header: bool,
    pub header_name: HeaderName,
}

impl LoopProtectionSettings {
    pub fn from_config(
        cfg: &LoopProtectionConfig,
    ) -> Result<Self, LoopProtectionError> {
        if !cfg.enabled {
            // When loop protection is disabled, we still construct a settings
            // value but mark add_header=false so no headers are injected.
            let header_name = HeaderName::from_static("x-acl-proxy-request-id");
            return Ok(LoopProtectionSettings {
                enabled: false,
                add_header: false,
                header_name,
            });
        }

        let raw = cfg.header_name.trim();
        if raw.is_empty() {
            return Err(LoopProtectionError::InvalidHeaderName(
                "header name must not be empty".to_string(),
            ));
        }

        let header_name =
            HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
                LoopProtectionError::InvalidHeaderName(raw.to_string())
            })?;

        Ok(LoopProtectionSettings {
            enabled: cfg.enabled,
            add_header: cfg.add_header,
            header_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LoopProtectionConfig;

    #[test]
    fn default_config_builds_settings() {
        let cfg = LoopProtectionConfig::default();
        let settings =
            LoopProtectionSettings::from_config(&cfg).expect("settings");
        assert!(settings.enabled);
        assert!(settings.add_header);
        assert_eq!(
            settings.header_name.as_str(),
            cfg.header_name.to_ascii_lowercase()
        );
    }

    #[test]
    fn disabled_loop_protection_disables_header_injection() {
        let mut cfg = LoopProtectionConfig::default();
        cfg.enabled = false;
        let settings =
            LoopProtectionSettings::from_config(&cfg).expect("settings");
        assert!(!settings.enabled);
        assert!(!settings.add_header);
    }

    #[test]
    fn invalid_header_name_returns_error() {
        let mut cfg = LoopProtectionConfig::default();
        cfg.header_name = "invalid header".to_string();
        let err =
            LoopProtectionSettings::from_config(&cfg).expect_err("error");
        let msg = format!("{err}");
        assert!(msg.contains("invalid loop protection header name"));
    }
}

