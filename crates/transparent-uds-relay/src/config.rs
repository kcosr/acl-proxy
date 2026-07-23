use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::{ffi::OsStrExt, fs::FileTypeExt},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use thiserror::Error;

pub const MAX_ROUTES: usize = 16;
pub const MAX_CONNECTIONS: usize = 65_536;
pub const MAX_COPY_BUFFER_BYTES: usize = 1024 * 1024;
pub const MAX_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
pub const RESERVED_FILE_DESCRIPTORS: u64 = 64;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_UNIX_PATH_BYTES: usize = 107;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub routes: Vec<Route>,
    #[serde(deserialize_with = "deserialize_duration")]
    pub setup_timeout: Duration,
    pub max_connections: usize,
    pub copy_buffer_bytes_per_direction: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub listen: SocketAddr,
    pub allowed_original_ports: Vec<u16>,
    pub upstream_socket: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceProjection {
    pub copy_buffer_bytes: usize,
    pub relay_stream_descriptors: u64,
    pub connection_tasks: usize,
    pub total_file_descriptors: u64,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read relay configuration: {0}")]
    Read(#[source] std::io::Error),
    #[error("relay configuration is not valid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("invalid relay configuration: {0}")]
    Invalid(String),
    #[error("failed to inspect relay resource limits: {0}")]
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
                "relay configuration must be at most {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let config: Self = serde_json::from_slice(&bytes).map_err(ConfigError::Json)?;
        config.validate_for_fd_budget(open_file_limit()?)?;
        config.validate_upstream_sockets()?;
        Ok(config)
    }

    pub fn validate_for_fd_budget(
        &self,
        file_descriptor_budget: u64,
    ) -> Result<ResourceProjection, ConfigError> {
        if self.routes.is_empty() || self.routes.len() > MAX_ROUTES {
            return Err(invalid(format!(
                "routes must contain between 1 and {MAX_ROUTES} entries"
            )));
        }
        if self.setup_timeout.is_zero() || self.setup_timeout > MAX_SETUP_TIMEOUT {
            return Err(invalid(
                "setupTimeout must be greater than zero and at most 60s",
            ));
        }
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS {
            return Err(invalid(format!(
                "maxConnections must be between 1 and {MAX_CONNECTIONS}"
            )));
        }
        if self.copy_buffer_bytes_per_direction == 0
            || self.copy_buffer_bytes_per_direction > MAX_COPY_BUFFER_BYTES
        {
            return Err(invalid(format!(
                "copyBufferBytesPerDirection must be between 1 and {MAX_COPY_BUFFER_BYTES}"
            )));
        }

        let mut names = HashSet::new();
        let mut listeners = HashSet::new();
        let mut port_sets = HashSet::new();
        let mut sockets = HashSet::new();
        for route in &self.routes {
            validate_route(route)?;
            if !names.insert(route.name.as_str()) {
                return Err(invalid("route names must be unique"));
            }
            if !listeners.insert(route.listen) {
                return Err(invalid("route listener addresses must be unique"));
            }
            let mut ports = route.allowed_original_ports.clone();
            ports.sort_unstable();
            if !port_sets.insert(ports) {
                return Err(invalid("route original-port sets must be unique"));
            }
            if !sockets.insert(route.upstream_socket.as_path()) {
                return Err(invalid("route upstream socket paths must be unique"));
            }
        }

        let copy_buffer_bytes = self
            .max_connections
            .checked_mul(2)
            .and_then(|value| value.checked_mul(self.copy_buffer_bytes_per_direction))
            .ok_or_else(|| invalid("copy-buffer resource projection overflowed"))?;
        let relay_stream_descriptors = u64::try_from(self.max_connections)
            .ok()
            .and_then(|value| value.checked_mul(2))
            .ok_or_else(|| invalid("stream-descriptor resource projection overflowed"))?;
        let listener_descriptors = u64::try_from(self.routes.len())
            .map_err(|_| invalid("listener resource projection overflowed"))?;
        let total_file_descriptors = RESERVED_FILE_DESCRIPTORS
            .checked_add(listener_descriptors)
            .and_then(|value| value.checked_add(relay_stream_descriptors))
            .ok_or_else(|| invalid("file-descriptor resource projection overflowed"))?;
        if total_file_descriptors > file_descriptor_budget {
            return Err(invalid(format!(
                "configured capacity needs {total_file_descriptors} file descriptors but the process limit is {file_descriptor_budget}"
            )));
        }

        Ok(ResourceProjection {
            copy_buffer_bytes,
            relay_stream_descriptors,
            connection_tasks: self.max_connections,
            total_file_descriptors,
        })
    }

    pub fn validate_upstream_sockets(&self) -> Result<(), ConfigError> {
        for route in &self.routes {
            let metadata = fs::symlink_metadata(&route.upstream_socket).map_err(|error| {
                invalid(format!(
                    "upstream socket for route {} is unavailable: {error}",
                    route.name
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err(invalid(format!(
                    "upstream socket for route {} is not a Unix socket",
                    route.name
                )));
            }
        }
        Ok(())
    }
}

fn validate_route(route: &Route) -> Result<(), ConfigError> {
    if route.name.is_empty()
        || route.name.len() > 64
        || !route
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid(
            "route names must be 1-64 ASCII letters, digits, '-' or '_'",
        ));
    }
    match route.listen.ip() {
        IpAddr::V4(address) if address.is_loopback() => {}
        IpAddr::V4(_) => return Err(invalid("route listeners must use IPv4 loopback addresses")),
        IpAddr::V6(_) => return Err(invalid("IPv6 route listeners are unsupported")),
    }
    if route.listen.port() < 1024 {
        return Err(invalid("route listeners must use unprivileged ports"));
    }
    if route.allowed_original_ports.is_empty()
        || route.allowed_original_ports.contains(&0)
        || route
            .allowed_original_ports
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != route.allowed_original_ports.len()
    {
        return Err(invalid(
            "allowedOriginalPorts must be a nonempty set of nonzero ports",
        ));
    }
    validate_unix_path(&route.upstream_socket)
}

fn validate_unix_path(path: &Path) -> Result<(), ConfigError> {
    let bytes = OsStr::new(path).as_bytes();
    if !path.is_absolute()
        || bytes.len() <= 1
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(invalid(
            "upstream socket paths must be absolute and normalized",
        ));
    }
    if bytes.len() > MAX_UNIX_PATH_BYTES || bytes.contains(&0) {
        return Err(invalid("upstream socket path exceeds the Linux path limit"));
    }
    Ok(())
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    humantime::parse_duration(&value).map_err(serde::de::Error::custom)
}

fn open_file_limit() -> Result<u64, ConfigError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes to the valid rlimit pointer for this process.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(ConfigError::ResourceLimit(std::io::Error::last_os_error()));
    }
    Ok(limit.rlim_cur)
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        os::unix::{fs::symlink, net::UnixListener},
    };

    fn config() -> Config {
        Config {
            routes: vec![Route {
                name: "http".into(),
                listen: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3128).into(),
                allowed_original_ports: vec![80],
                upstream_socket: "/run/relay/http.sock".into(),
            }],
            setup_timeout: Duration::from_secs(2),
            max_connections: 8,
            copy_buffer_bytes_per_direction: 1024,
        }
    }

    #[test]
    fn strict_json_rejects_unknown_and_alias_fields() {
        let unknown = r#"{"routes":[],"setupTimeout":"2s","maxConnections":1,"copyBufferBytesPerDirection":1,"parentUrl":"secret"}"#;
        assert!(serde_json::from_str::<Config>(unknown).is_err());
        let alias = r#"{"routes":[],"setup_timeout":"2s","maxConnections":1,"copyBufferBytesPerDirection":1}"#;
        assert!(serde_json::from_str::<Config>(alias).is_err());
    }

    #[test]
    fn shipped_example_parses_and_projects_strictly() {
        let config: Config =
            serde_json::from_str(include_str!("../../../examples/transparent-uds-relay.json"))
                .unwrap();
        let projection = config.validate_for_fd_budget(10_000).unwrap();
        assert_eq!(projection.connection_tasks, 1024);
        assert_eq!(projection.copy_buffer_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn config_file_read_is_bounded_before_json_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.json");
        fs::write(&path, vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
        let error = Config::load(&path).unwrap_err();
        assert!(error.to_string().contains("at most"), "{error}");
    }

    #[test]
    fn resource_projection_is_global_and_checked() {
        let projection = config().validate_for_fd_budget(100).unwrap();
        assert_eq!(projection.copy_buffer_bytes, 8 * 2 * 1024);
        assert_eq!(projection.relay_stream_descriptors, 16);
        assert_eq!(projection.connection_tasks, 8);
        assert_eq!(projection.total_file_descriptors, 81);
        assert!(config().validate_for_fd_budget(80).is_err());
    }

    #[test]
    fn rejects_ipv6_privileged_and_mismatched_routes() {
        let mut value = config();
        value.routes[0].listen = "[::1]:3128".parse().unwrap();
        assert!(value.validate_for_fd_budget(100).is_err());
        value.routes[0].listen = "127.0.0.1:80".parse().unwrap();
        assert!(value.validate_for_fd_budget(100).is_err());

        value = config();
        let mut duplicate = value.routes[0].clone();
        duplicate.name = "https".into();
        duplicate.listen = "127.0.0.1:3129".parse().unwrap();
        duplicate.upstream_socket = "/run/relay/https.sock".into();
        value.routes.push(duplicate);
        assert!(value.validate_for_fd_budget(100).is_err());
    }

    #[test]
    fn rejects_non_normalized_or_oversized_socket_paths() {
        let mut value = config();
        value.routes[0].upstream_socket = "/run/../run/http.sock".into();
        assert!(value.validate_for_fd_budget(100).is_err());
        value.routes[0].upstream_socket = "/run//http.sock".into();
        assert!(value.validate_for_fd_budget(100).is_err());
        value.routes[0].upstream_socket = "/run/./http.sock".into();
        assert!(value.validate_for_fd_budget(100).is_err());
        value.routes[0].upstream_socket = format!("/{}", "a".repeat(108)).into();
        assert!(value.validate_for_fd_budget(100).is_err());
    }

    #[test]
    fn startup_accepts_only_existing_non_symlink_unix_sockets() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("upstream.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let mut value = config();
        value.routes[0].upstream_socket = socket_path.clone();
        value.validate_upstream_sockets().unwrap();

        let symlink_path = directory.path().join("upstream-link.sock");
        symlink(&socket_path, &symlink_path).unwrap();
        value.routes[0].upstream_socket = symlink_path;
        assert!(value.validate_upstream_sockets().is_err());

        value.routes[0].upstream_socket = directory.path().join("plain-file");
        fs::write(&value.routes[0].upstream_socket, b"not a socket").unwrap();
        assert!(value.validate_upstream_sockets().is_err());
    }
}
