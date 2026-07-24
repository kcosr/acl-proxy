use std::{
    collections::HashSet,
    fs,
    fs::File,
    io::Read,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
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
use access_identity::IdentityPresentation;
use serde::Deserialize;
use thiserror::Error;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const PROCESS_MEMORY_CEILING_BYTES: u64 = 256 * 1024 * 1024;
pub const CONSUMER_MEMORY_RESERVE_BYTES: u64 = 2 * 1024 * 1024;
pub const CONSUMER_DESCRIPTOR_RESERVE: u64 = 16;

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub listen: SocketAddr,
    pub allowed_destination_ports: Vec<u16>,
    pub transport: Transport,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transport {
    Unix { path: String },
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Presentation {
    Disabled {},
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
                    probe_unix_socket_leaf(endpoint.path().as_str(), &route.name)?;
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

        let presentation = match self.presentation {
            Presentation::Disabled {} => IdentityPresentation::Disabled,
        };
        let plan = AccessFlowRelayPlan::new(
            endpoints,
            presentation,
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

pub fn relay_descriptor_budget() -> Result<u64, ConfigError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes to the valid rlimit pointer for this process.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(ConfigError::ResourceLimit(std::io::Error::last_os_error()));
    }
    limit
        .rlim_cur
        .checked_sub(CONSUMER_DESCRIPTOR_RESERVE)
        .ok_or_else(|| {
            invalid(format!(
                "RLIMIT_NOFILE must exceed the {CONSUMER_DESCRIPTOR_RESERVE}-descriptor consumer reserve"
            ))
        })
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
    Err(invalid(format!(
        "removed field(s) {}: replace allowedOriginalPorts with allowedDestinationPorts and upstreamSocket with transport {{\"kind\":\"unix\",\"path\":\"...\"}}",
        removed.join(", ")
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
    use std::net::SocketAddrV4;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::{fs::symlink, net::UnixListener};

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
    fn shipped_production_fixture_parses_strictly() {
        let config: Config = serde_json::from_str(include_str!(
            "../../../tests/fixtures/production/access-flow-relay.json"
        ))
        .unwrap();
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.max_connections, 1024);
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
    }

    #[test]
    fn strict_json_rejects_unknown_remote_and_non_disabled_presentation() {
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
        .is_err());
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
    }
}
