pub(super) const DEFAULT_CONFIG_V3: &str = r#"schema_version = 3

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"
max_retiring_generations = 2
max_active_upgrades = 256
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn generated_template_is_strict_v3_and_purely_compilable() {
        let authored: super::super::authoring::ConfigV3 =
            toml::from_str(DEFAULT_CONFIG_V3).expect("default template must parse");
        let compiled = super::super::v3_compile::compile_v3(authored, Path::new("/tmp/config"))
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
    }
}
