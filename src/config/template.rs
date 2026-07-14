use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub(super) const DEFAULT_CONFIG: &str = r#"schema_version = 3

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"
max_retiring_generations = 2
max_active_upgrades = 256
max_active_webhook_deliveries = 256
webhook_transport_buffer_bytes = 65536
max_webhook_transport_bytes = 67108864
upgrade_relay_buffer_bytes = 65536
max_upgrade_buffer_bytes = 2147483648
max_upgrade_lifetime = "8h"
max_inflight_wire_body_bytes = 8589934592
max_inflight_wire_body_bytes_per_quota_key = 1073741824
min_wire_body_concurrency = 64
max_content_decoding_expansion_ratio = 128

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[observation.logging]
level = "info"
console = true

[safety.loop_detection]
inject = true
header = "x-acl-proxy-request-id"
"#;

pub(super) fn write_default_config(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(DEFAULT_CONFIG.as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn generated_template_is_strict_and_purely_compilable() {
        let authored: super::super::authoring::AuthoringConfig =
            toml::from_str(DEFAULT_CONFIG).expect("default template must parse");
        let compiled = super::super::compiler::compile_config(authored, Path::new("/tmp/config"))
            .expect("default template must compile without activation");
        assert_eq!(
            compiled
                .static_config
                .listeners
                .explicit_http
                .unwrap()
                .bind
                .port(),
            8881
        );
        assert!(compiled.static_config.control.is_none());
        assert_eq!(
            compiled.static_config.service.max_active_webhook_deliveries,
            256
        );
        assert_eq!(
            compiled
                .static_config
                .service
                .webhook_transport_buffer_bytes,
            64 * 1024
        );
        assert_eq!(
            compiled.static_config.service.max_webhook_transport_bytes,
            64 * 1024 * 1024
        );
        assert_eq!(compiled.static_config.capture.max_pending_records, 1024);
    }

    #[test]
    fn writer_creates_parent_and_never_overwrites() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/acl-proxy.toml");

        write_default_config(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), DEFAULT_CONFIG);

        let error = write_default_config(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).unwrap(), DEFAULT_CONFIG);
    }
}
