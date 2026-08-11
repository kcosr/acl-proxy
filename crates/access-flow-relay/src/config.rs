use std::{
    collections::HashSet,
    fs,
    fs::File,
    io::Read,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    os::unix::ffi::OsStringExt,
    os::unix::fs::FileTypeExt,
    path::Path,
    time::Duration,
};

use access_flow_relay::{
    AccessFlowRelayPlan, AccessFlowRelayPlanError, AccessFlowRoute, AccessFlowRouteName,
};
use access_flow_unix::{
    NormalizedUnixSocketPath, UnixAccessFlowEndpoint, UnixEndpointExecutionError,
    UnixExecutionTarget,
};
use access_identity::{IdentityPresentation, SensitiveBearer};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const PROCESS_MEMORY_CEILING_BYTES: u64 = 256 * 1024 * 1024;
pub const CONSUMER_MEMORY_RESERVE_BYTES: u64 = 2 * 1024 * 1024;
pub const CONSUMER_DESCRIPTOR_RESERVE: u64 = 16;
pub const MAX_PRESENTATION_ENVIRONMENT_NAME_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub routes: Vec<Route>,
    pub presentation: Presentation,
    #[serde(deserialize_with = "deserialize_duration")]
    pub setup_timeout: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub drain_timeout: Duration,
    pub max_connections: usize,
    pub copy_buffer_bytes_per_direction: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub listen: SocketAddr,
    pub allowed_destination_ports: Vec<u16>,
    pub transport: Transport,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transport {
    Unix { path: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Presentation {
    Disabled {},
    Anonymous {},
    BearerEnvironment { variable: String },
}

pub struct ValidatedConfig {
    pub plan: AccessFlowRelayPlan<UnixAccessFlowEndpoint>,
    pub drain_timeout: Duration,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read Access Flow relay configuration: {0}")]
    Read(#[source] std::io::Error),
    #[error("Access Flow relay configuration is not valid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("invalid Access Flow relay configuration: {0}")]
    Invalid(String),
    #[error("failed to inspect Access Flow relay resource limits: {0}")]
    ResourceLimit(#[source] std::io::Error),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(path).map_err(ConfigError::Read)?;
        let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES.min(64 * 1024));
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(ConfigError::Read)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(invalid(format!(
                "configuration must be at most {MAX_CONFIG_BYTES} bytes"
            )));
        }
        reject_removed_shape(&bytes)?;
        serde_json::from_slice(&bytes).map_err(ConfigError::Json)
    }

    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        self.validate_with_socket_probe(probe_unix_socket_leaf)
    }

    fn validate_with_socket_probe(
        self,
        mut socket_probe: impl FnMut(&str, &str) -> Result<(), ConfigError>,
    ) -> Result<ValidatedConfig, ConfigError> {
        if self.drain_timeout.is_zero() || self.drain_timeout > MAX_DRAIN_TIMEOUT {
            return Err(invalid(
                "drainTimeout must be greater than zero and at most 10m",
            ));
        }
        let max_connections = NonZeroUsize::new(self.max_connections)
            .ok_or_else(|| invalid("maxConnections must be greater than zero"))?;
        let copy_buffer_bytes_per_direction =
            NonZeroUsize::new(self.copy_buffer_bytes_per_direction)
                .ok_or_else(|| invalid("copyBufferBytesPerDirection must be greater than zero"))?;

        let mut endpoints = Vec::with_capacity(self.routes.len());
        for route in self.routes {
            let listen = match route.listen {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => {
                    return Err(invalid(
                        "route listeners must use nonzero IPv4 loopback addresses",
                    ));
                }
            };
            let ports = route
                .allowed_destination_ports
                .into_iter()
                .map(|port| {
                    NonZeroU16::new(port)
                        .ok_or_else(|| invalid("allowedDestinationPorts must not contain zero"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let endpoint = match route.transport {
                Transport::Unix { path } => {
                    let normalized = NormalizedUnixSocketPath::new(&path)
                        .map_err(|error| invalid(error.to_string()))?;
                    let endpoint = UnixAccessFlowEndpoint::new(normalized);
                    endpoint
                        .validate_for(UnixExecutionTarget::Linux)
                        .map_err(map_execution_error)?;
                    socket_probe(endpoint.path().as_str(), &route.name)?;
                    endpoint
                }
            };
            endpoints.push(
                AccessFlowRoute::new(
                    AccessFlowRouteName::new(route.name).map_err(map_plan_error)?,
                    listen,
                    ports,
                    endpoint,
                )
                .map_err(map_plan_error)?,
            );
        }

        let presentation = activate_presentation(self.presentation)?;
        let plan = AccessFlowRelayPlan::new(
            endpoints,
            presentation,
            None,
            self.setup_timeout,
            max_connections,
            copy_buffer_bytes_per_direction,
        )
        .map_err(map_plan_error)?;
        Ok(ValidatedConfig {
            plan,
            drain_timeout: self.drain_timeout,
        })
    }
}

fn activate_presentation(presentation: Presentation) -> Result<IdentityPresentation, ConfigError> {
    match presentation {
        Presentation::Disabled {} => Ok(IdentityPresentation::Disabled),
        Presentation::Anonymous {} => Ok(IdentityPresentation::Anonymous),
        Presentation::BearerEnvironment { variable } => {
            if !valid_presentation_environment_name(&variable) {
                return Err(invalid("bearer presentation environment source is invalid"));
            }
            let value = std::env::var_os(&variable)
                .ok_or_else(|| invalid("bearer presentation environment source is unavailable"))?;
            std::env::remove_var(&variable);
            let scratch = Zeroizing::new(value.into_vec());
            let bearer = SensitiveBearer::new(scratch.as_slice())
                .map_err(|_| invalid("bearer presentation value is invalid"))?;
            Ok(IdentityPresentation::Bearer(bearer))
        }
    }
}

fn valid_presentation_environment_name(value: &str) -> bool {
    value.len() <= MAX_PRESENTATION_ENVIRONMENT_NAME_BYTES
        && valid_environment_name(value)
        && (value == "AW_IDENTITY_TOKEN"
            || value
                .strip_prefix("AW_ACCESS_FLOW_")
                .is_some_and(|suffix| !suffix.is_empty()))
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn relay_descriptor_budget() -> Result<u64, ConfigError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes to the valid rlimit pointer for this process.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(ConfigError::ResourceLimit(std::io::Error::last_os_error()));
    }
    relay_descriptor_budget_from_limit(limit.rlim_cur)
}

fn relay_descriptor_budget_from_limit(soft_limit: u64) -> Result<u64, ConfigError> {
    if soft_limit <= CONSUMER_DESCRIPTOR_RESERVE {
        return Err(invalid(format!(
            "RLIMIT_NOFILE must exceed the {CONSUMER_DESCRIPTOR_RESERVE}-descriptor consumer reserve"
        )));
    }
    Ok(soft_limit - CONSUMER_DESCRIPTOR_RESERVE)
}

pub const fn relay_memory_budget() -> u64 {
    PROCESS_MEMORY_CEILING_BYTES - CONSUMER_MEMORY_RESERVE_BYTES
}

fn probe_unix_socket_leaf(path: &str, route: &str) -> Result<(), ConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        invalid(format!(
            "Unix transport for route {route} is unavailable: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(invalid(format!(
            "Unix transport for route {route} must be an existing socket leaf"
        )));
    }
    Ok(())
}

fn reject_removed_shape(bytes: &[u8]) -> Result<(), ConfigError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(ConfigError::Json)?;
    let mut removed = HashSet::new();
    collect_removed_fields(&value, &mut removed);
    if removed.is_empty() {
        return Ok(());
    }
    let mut removed = removed.into_iter().collect::<Vec<_>>();
    removed.sort_unstable();
    let mut replacements = Vec::new();
    if removed.contains(&"allowedOriginalPorts") {
        replacements.push("replace allowedOriginalPorts with allowedDestinationPorts");
    }
    if removed.contains(&"upstreamSocket") {
        replacements
            .push("replace upstreamSocket with transport {\"kind\":\"unix\",\"path\":\"...\"}");
    }
    if removed.contains(&"identity") {
        replacements.push("replace route identity with top-level presentation");
    }
    Err(invalid(format!(
        "removed field(s) {}: {}",
        removed.join(", "),
        replacements.join("; ")
    )))
}

fn collect_removed_fields<'a>(value: &'a serde_json::Value, removed: &mut HashSet<&'a str>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if matches!(
                    name.as_str(),
                    "allowedOriginalPorts" | "upstreamSocket" | "identity"
                ) {
                    removed.insert(name);
                }
                collect_removed_fields(value, removed);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_removed_fields(value, removed);
            }
        }
        _ => {}
    }
}

fn map_plan_error(error: AccessFlowRelayPlanError) -> ConfigError {
    invalid(error.to_string())
}

fn map_execution_error(error: UnixEndpointExecutionError) -> ConfigError {
    invalid(error.to_string())
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    humantime::parse_duration(&value).map_err(serde::de::Error::custom)
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_flow_conformance::{
        load_adapter_parity_fixture, load_awaf_vector_suite, project_relay_plan, AwafVector,
        FixturePresentationKind, NormalizedAccessFlowTransport,
    };
    use std::net::SocketAddrV4;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::{fs::symlink, net::UnixListener};

    const PRODUCTION_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/production/access-flow-relay.json"
    );
    const SHIPPED_EXAMPLE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/access-flow-relay.json"
    );
    const CONFORMANCE_VARIABLE: &str = "AW_ACCESS_FLOW_CONFORMANCE_VECTOR";
    const CONFORMANCE_BEARER: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";
    const PRODUCT_HTTP_PATH: &str = "/run/acl-proxy/transparent-http.sock";
    const PRODUCT_HTTPS_PATH: &str = "/run/acl-proxy/transparent-https.sock";

    struct EnvironmentCleanup(&'static str);

    impl Drop for EnvironmentCleanup {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    fn no_socket_probe(_path: &str, _route: &str) -> Result<(), ConfigError> {
        Ok(())
    }

    fn load_production_config() -> Config {
        Config::load(Path::new(PRODUCTION_FIXTURE)).unwrap()
    }

    fn normalized_product_transport(
        endpoint: &UnixAccessFlowEndpoint,
    ) -> Result<NormalizedAccessFlowTransport, &'static str> {
        let normalized = match endpoint.path().as_str() {
            PRODUCT_HTTP_PATH => "/run/access-flow/conformance-http.sock",
            PRODUCT_HTTPS_PATH => "/run/access-flow/conformance-https.sock",
            _ => return Err("unrecognized product Access Flow transport"),
        };
        NormalizedAccessFlowTransport::unix(normalized)
            .map_err(|_| "invalid normalized Access Flow transport")
    }

    fn validated_config_for_vector(presentation: FixturePresentationKind) -> ValidatedConfig {
        let mut config = load_production_config();
        config.presentation = match presentation {
            FixturePresentationKind::Disabled => Presentation::Disabled {},
            FixturePresentationKind::Anonymous => Presentation::Anonymous {},
            FixturePresentationKind::Bearer => {
                let _cleanup = EnvironmentCleanup(CONFORMANCE_VARIABLE);
                std::env::set_var(CONFORMANCE_VARIABLE, CONFORMANCE_BEARER);
                config.presentation = Presentation::BearerEnvironment {
                    variable: CONFORMANCE_VARIABLE.to_owned(),
                };
                let validated = config.validate_with_socket_probe(no_socket_probe).unwrap();
                assert!(std::env::var_os(CONFORMANCE_VARIABLE).is_none());
                return validated;
            }
        };
        config.validate_with_socket_probe(no_socket_probe).unwrap()
    }

    fn config_for(path: &Path) -> Config {
        Config {
            routes: vec![Route {
                name: "http".into(),
                listen: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 3128).into(),
                allowed_destination_ports: vec![80],
                transport: Transport::Unix {
                    path: path.to_str().unwrap().to_owned(),
                },
            }],
            presentation: Presentation::Disabled {},
            setup_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_secs(10),
            max_connections: 8,
            copy_buffer_bytes_per_direction: 1024,
        }
    }

    #[test]
    fn shipped_production_fixture_compiles_to_exact_shared_adapter_plan() {
        let validated = load_production_config()
            .validate_with_socket_probe(no_socket_probe)
            .unwrap();
        let routes = validated.plan.routes();
        assert_eq!(
            routes
                .iter()
                .map(|route| route.name().as_str())
                .collect::<Vec<_>>(),
            ["http", "https"]
        );
        assert_eq!(routes[0].endpoint().path().as_str(), PRODUCT_HTTP_PATH);
        assert_eq!(routes[1].endpoint().path().as_str(), PRODUCT_HTTPS_PATH);

        let actual = project_relay_plan(&validated.plan, validated.drain_timeout, |endpoint| {
            normalized_product_transport(endpoint).unwrap()
        });
        let expected = load_adapter_parity_fixture().unwrap();
        assert_eq!(&actual, expected.relay_plan());

        let unknown = UnixAccessFlowEndpoint::new(
            NormalizedUnixSocketPath::new("/run/acl-proxy/unknown.sock").unwrap(),
        );
        let error = normalized_product_transport(&unknown).unwrap_err();
        assert_eq!(error, "unrecognized product Access Flow transport");
        assert!(!error.contains(unknown.path().as_str()));
    }

    #[test]
    fn shipped_example_is_the_validated_production_relay_contract() {
        let shipped_bytes = std::fs::read(SHIPPED_EXAMPLE).unwrap();
        let production_bytes = std::fs::read(PRODUCTION_FIXTURE).unwrap();
        assert_eq!(
            shipped_bytes, production_bytes,
            "the shipped relay example and production fixture drifted"
        );

        let validated = Config::load(Path::new(SHIPPED_EXAMPLE))
            .unwrap()
            .validate_with_socket_probe(no_socket_probe)
            .unwrap();
        let actual = project_relay_plan(&validated.plan, validated.drain_timeout, |endpoint| {
            normalized_product_transport(endpoint).unwrap()
        });
        assert_eq!(actual, *load_adapter_parity_fixture().unwrap().relay_plan());
    }

    #[tokio::test]
    async fn product_relay_encodes_v2_without_an_authored_execution_context() {
        let fixture = load_adapter_parity_fixture().unwrap();
        let suite = load_awaf_vector_suite().unwrap();
        assert_eq!(CONFORMANCE_BEARER.len(), 32);
        assert_eq!(
            suite
                .vectors()
                .iter()
                .map(AwafVector::name)
                .collect::<Vec<_>>(),
            fixture
                .required_awaf_vectors()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
        );
        let vectors = suite
            .vectors()
            .iter()
            .filter(|vector| vector.name() == "v2-absent-context")
            .collect::<Vec<_>>();
        assert_eq!(vectors.len(), 1);
        for vector in vectors {
            let validated = validated_config_for_vector(vector.presentation());
            let matching_routes = validated
                .plan
                .routes()
                .iter()
                .filter(|route| {
                    route
                        .allowed_destination_ports()
                        .contains(&vector.destination().port())
                })
                .collect::<Vec<_>>();
            assert_eq!(
                matching_routes.len(),
                1,
                "{} must map to one product route",
                vector.name()
            );
            let mapped_destination = access_flow::AccessFlowDestination::new(
                vector.destination().address(),
                matching_routes[0]
                    .allowed_destination_ports()
                    .iter()
                    .find(|port| **port == vector.destination().port())
                    .expect("matching route contains the vector port")
                    .get(),
            )
            .unwrap();
            assert_eq!(
                mapped_destination,
                vector.destination(),
                "{}",
                vector.name()
            );
            let mut actual = Zeroizing::new(Vec::new());
            access_flow::write_access_flow_preface(
                &mut *actual,
                mapped_destination,
                validated.plan.presentation(),
                validated.plan.execution_context(),
            )
            .await
            .unwrap();
            assert_eq!(actual.as_slice(), vector.wire(), "{}", vector.name());
        }
    }

    #[test]
    fn old_and_mixed_shapes_receive_actionable_rejection() {
        for input in [
            br#"{"routes":[{"name":"http","listen":"127.0.0.1:3128","allowedOriginalPorts":[80],"upstreamSocket":"/run/acl-proxy/http.sock"}],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1024}"#.as_slice(),
            br#"{"routes":[{"name":"http","listen":"127.0.0.1:3128","allowedDestinationPorts":[80],"allowedOriginalPorts":[80],"transport":{"kind":"unix","path":"/run/acl-proxy/http.sock"}}],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1024}"#.as_slice(),
        ] {
            let error = reject_removed_shape(input).unwrap_err().to_string();
            assert!(error.contains("allowedOriginalPorts"), "{error}");
            assert!(error.contains("allowedDestinationPorts"), "{error}");
        }

        let identity = br#"{"routes":[{"name":"http","listen":"127.0.0.1:3128","allowedDestinationPorts":[80],"transport":{"kind":"unix","path":"/run/acl-proxy/http.sock"},"identity":{"kind":"disabled"}}],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1024}"#;
        let error = reject_removed_shape(identity).unwrap_err().to_string();
        assert!(error.contains("removed field(s) identity"), "{error}");
        assert!(error.contains("top-level presentation"), "{error}");
    }

    #[test]
    fn strict_json_requires_presentation_and_rejects_remote_transport_fields() {
        let base = r#"{"routes":[],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1}"#;
        let mut missing_presentation: serde_json::Value = serde_json::from_str(base).unwrap();
        missing_presentation
            .as_object_mut()
            .unwrap()
            .remove("presentation");
        assert!(serde_json::from_value::<Config>(missing_presentation).is_err());

        let route_base = serde_json::json!({
            "routes": [{
                "name": "http",
                "listen": "127.0.0.1:3128",
                "allowedDestinationPorts": [80],
                "transport": {"kind": "unix", "path": "/run/x"},
            }],
            "presentation": {"kind": "disabled"},
            "setupTimeout": "2s",
            "drainTimeout": "10s",
            "maxConnections": 1,
            "copyBufferBytesPerDirection": 1,
        });
        for field in [
            "remote",
            "tls",
            "cert",
            "server_name",
            "discovery",
            "fallback",
        ] {
            let mut at_root = route_base.clone();
            at_root
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!(true));
            assert!(
                serde_json::from_value::<Config>(at_root).is_err(),
                "accepted root field {field}"
            );

            let mut in_transport = route_base.clone();
            in_transport["routes"][0]["transport"]
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!(true));
            assert!(
                serde_json::from_value::<Config>(in_transport).is_err(),
                "accepted transport field {field}"
            );
        }
    }

    #[test]
    fn strict_json_accepts_exact_presentation_union_and_rejects_extra_fields() {
        let base = r#"{"routes":[],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1}"#;
        assert!(serde_json::from_str::<Config>(&base.replace(
            "\"kind\":\"disabled\"",
            "\"kind\":\"disabled\",\"variable\":\"TOKEN\""
        ))
        .is_err());
        assert!(serde_json::from_str::<Config>(&base.replace(
            "\"routes\":[]",
            "\"routes\":[{\"name\":\"http\",\"listen\":\"127.0.0.1:3128\",\"allowedDestinationPorts\":[80],\"transport\":{\"kind\":\"tls_tcp\",\"path\":\"/run/x\",\"certificate\":\"secret\"}}]"
        ))
        .is_err());
        assert!(serde_json::from_str::<Config>(
            &base.replace("\"kind\":\"disabled\"", "\"kind\":\"anonymous\"")
        )
        .is_ok());
        assert!(serde_json::from_str::<Config>(&base.replace(
            "\"kind\":\"disabled\"",
            "\"kind\":\"bearer_environment\",\"variable\":\"AW_IDENTITY_TOKEN\""
        ))
        .is_ok());
        assert!(serde_json::from_str::<Config>(
            &base.replace("\"kind\":\"disabled\"", "\"kind\":\"bearer_environment\"")
        )
        .is_err());
        assert!(serde_json::from_str::<Config>(&base.replace(
            "\"kind\":\"disabled\"",
            "\"kind\":\"anonymous\",\"variable\":\"TOKEN\""
        ))
        .is_err());
    }

    #[test]
    fn presentation_activation_removes_valid_and_invalid_bearers_from_environment() {
        const VALID_VARIABLE: &str = "AW_ACCESS_FLOW_VALID_BEARER_TEST";
        const INVALID_VARIABLE: &str = "AW_ACCESS_FLOW_INVALID_BEARER_TEST";
        let valid_bearer = "a".repeat(access_identity::MIN_BEARER_LEN);

        std::env::set_var(VALID_VARIABLE, &valid_bearer);
        let presentation = activate_presentation(Presentation::BearerEnvironment {
            variable: VALID_VARIABLE.to_owned(),
        })
        .unwrap();
        assert!(std::env::var_os(VALID_VARIABLE).is_none());
        match presentation {
            IdentityPresentation::Bearer(bearer) => {
                assert_eq!(bearer.expose(<[u8]>::len), valid_bearer.len());
            }
            _ => panic!("valid bearer source did not activate a bearer presentation"),
        }

        std::env::set_var(INVALID_VARIABLE, "invalid bearer with spaces");
        let error = activate_presentation(Presentation::BearerEnvironment {
            variable: INVALID_VARIABLE.to_owned(),
        })
        .err()
        .unwrap();
        assert!(std::env::var_os(INVALID_VARIABLE).is_none());
        assert_eq!(
            error.to_string(),
            "invalid Access Flow relay configuration: bearer presentation value is invalid"
        );
        assert!(!error.to_string().contains(INVALID_VARIABLE));
        assert!(!error.to_string().contains("invalid bearer with spaces"));
    }

    #[test]
    fn presentation_activation_rejects_missing_and_invalid_source_names_without_disclosure() {
        const MISSING_VARIABLE: &str = "AW_ACCESS_FLOW_MISSING_BEARER_TEST";
        std::env::remove_var(MISSING_VARIABLE);
        let error = activate_presentation(Presentation::BearerEnvironment {
            variable: MISSING_VARIABLE.to_owned(),
        })
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "invalid Access Flow relay configuration: bearer presentation environment source is unavailable"
        );
        assert!(!error.to_string().contains(MISSING_VARIABLE));

        let maximum_variable = format!(
            "AW_ACCESS_FLOW_{}",
            "B".repeat(MAX_PRESENTATION_ENVIRONMENT_NAME_BYTES - "AW_ACCESS_FLOW_".len())
        );
        assert_eq!(
            maximum_variable.len(),
            MAX_PRESENTATION_ENVIRONMENT_NAME_BYTES
        );
        std::env::set_var(&maximum_variable, "abcdefghijklmnopqrstuvwxyzABCDEF");
        let presentation = activate_presentation(Presentation::BearerEnvironment {
            variable: maximum_variable.clone(),
        })
        .unwrap();
        assert!(matches!(presentation, IdentityPresentation::Bearer(_)));
        assert!(std::env::var_os(&maximum_variable).is_none());

        let oversized_variable = format!(
            "AW_ACCESS_FLOW_{}",
            "B".repeat(MAX_PRESENTATION_ENVIRONMENT_NAME_BYTES - "AW_ACCESS_FLOW_".len() + 1)
        );
        assert_eq!(
            oversized_variable.len(),
            MAX_PRESENTATION_ENVIRONMENT_NAME_BYTES + 1
        );
        let variables = [
            String::new(),
            "9INVALID".to_owned(),
            "INVALID-NAME".to_owned(),
            "AW_ACCESS_FLOW_".to_owned(),
            "AW_CONTAINER_IDENTITY_TOKEN".to_owned(),
            oversized_variable,
        ];
        for variable in variables {
            let error = activate_presentation(Presentation::BearerEnvironment {
                variable: variable.clone(),
            })
            .err()
            .unwrap();
            assert_eq!(
                error.to_string(),
                "invalid Access Flow relay configuration: bearer presentation environment source is invalid"
            );
            assert!(variable.is_empty() || !error.to_string().contains(&variable));
        }
    }

    #[test]
    fn presentation_environment_name_contract_is_adapter_specific() {
        for accepted in [
            "AW_IDENTITY_TOKEN",
            "AW_ACCESS_FLOW_TOKEN",
            "AW_ACCESS_FLOW_CONTAINER_1_IDENTITY_TOKEN",
        ] {
            assert!(
                valid_presentation_environment_name(accepted),
                "{accepted} should be accepted"
            );
        }
        for rejected in [
            "AW_CONTAINER_IDENTITY_TOKEN",
            "AW_ACCESS_FLOW_",
            "AW-ACCESS-FLOW-TOKEN",
            "_AW_ACCESS_FLOW_TOKEN",
        ] {
            assert!(
                !valid_presentation_environment_name(rejected),
                "{rejected} should be rejected"
            );
        }
    }

    #[test]
    fn socket_probe_accepts_leaf_regardless_of_mode_and_rejects_missing_symlink_and_file() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("proxy.sock");
        let _socket = UnixListener::bind(&socket_path).unwrap();
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o777)).unwrap();
        config_for(&socket_path).validate().unwrap();

        let missing = directory.path().join("missing.sock");
        assert!(config_for(&missing).validate().is_err());

        let link = directory.path().join("link.sock");
        symlink(&socket_path, &link).unwrap();
        assert!(config_for(&link).validate().is_err());

        let file = directory.path().join("plain");
        fs::write(&file, b"plain").unwrap();
        assert!(config_for(&file).validate().is_err());
    }

    #[test]
    fn validation_delegates_common_route_and_resource_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("proxy.sock");
        let _socket = UnixListener::bind(&socket_path).unwrap();

        let mut config = config_for(&socket_path);
        config.routes[0].listen = "[::1]:3128".parse().unwrap();
        assert!(config.validate().is_err());

        let mut config = config_for(&socket_path);
        config.routes[0].allowed_destination_ports = vec![80, 80];
        assert!(config.validate().is_err());

        let mut config = config_for(&socket_path);
        config.drain_timeout = Duration::ZERO;
        assert!(config.validate().is_err());
    }

    #[test]
    fn consumer_reserves_are_exact_and_subtracted_before_shared_projection() {
        assert_eq!(CONSUMER_DESCRIPTOR_RESERVE, 16);
        assert_eq!(CONSUMER_MEMORY_RESERVE_BYTES, 2 * 1024 * 1024);
        assert_eq!(PROCESS_MEMORY_CEILING_BYTES, 256 * 1024 * 1024);
        assert_eq!(relay_memory_budget(), 254 * 1024 * 1024);

        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes to the valid rlimit pointer for this test process.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert_eq!(
            relay_descriptor_budget().unwrap(),
            limit.rlim_cur - CONSUMER_DESCRIPTOR_RESERVE
        );
        for insufficient in [
            0,
            CONSUMER_DESCRIPTOR_RESERVE - 1,
            CONSUMER_DESCRIPTOR_RESERVE,
        ] {
            assert!(relay_descriptor_budget_from_limit(insufficient).is_err());
        }
        assert_eq!(
            relay_descriptor_budget_from_limit(CONSUMER_DESCRIPTOR_RESERVE + 1).unwrap(),
            1
        );
    }
}
