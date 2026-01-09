use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;

use tracing::Level;
use tracing_subscriber::fmt::SubscriberBuilder;

use crate::config::{LoggingConfig, LoggingPolicyDecisionsConfig, PolicyDefaultAction};
use crate::policy::PolicyDecision;

const LOG_FILENAME: &str = "acl-proxy.log";
const LOG_QUEUE_CAPACITY: usize = 8192;

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("invalid log level for {field}: {value}")]
    InvalidLevel { field: &'static str, value: String },

    #[error("logging.max_bytes must be greater than zero when logging.directory is set")]
    InvalidMaxBytes { value: u64 },

    #[error("logging.max_files must be greater than zero when logging.directory is set")]
    InvalidMaxFiles { value: usize },

    #[error("failed to create logging directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to open log file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to initialize global tracing subscriber: {0}")]
    InitFailed(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Clone)]
pub struct PolicyDecisionLogging {
    pub log_allows: bool,
    pub log_denies: bool,
    pub level_allows: Level,
    pub level_denies: Level,
}

#[derive(Debug, Clone)]
pub struct LoggingSettings {
    pub level: Level,
    pub policy_decisions: PolicyDecisionLogging,
    pub directory: Option<PathBuf>,
    pub max_bytes: u64,
    pub max_files: usize,
    pub console: bool,
}

pub struct LoggingGuards {
    _worker: Option<WorkerGuard>,
}

impl LoggingSettings {
    pub fn from_config(cfg: &LoggingConfig) -> Result<Self, LoggingError> {
        let level = parse_level(&cfg.level).map_err(|value| LoggingError::InvalidLevel {
            field: "logging.level",
            value,
        })?;

        if cfg.directory.is_some() {
            if cfg.max_bytes == 0 {
                return Err(LoggingError::InvalidMaxBytes {
                    value: cfg.max_bytes,
                });
            }
            if cfg.max_files == 0 {
                return Err(LoggingError::InvalidMaxFiles {
                    value: cfg.max_files,
                });
            }
        }

        let policy_decisions = PolicyDecisionLogging::from_config(&cfg.policy_decisions)?;

        Ok(LoggingSettings {
            level,
            policy_decisions,
            directory: cfg.directory.clone(),
            max_bytes: cfg.max_bytes,
            max_files: cfg.max_files,
            console: cfg.console,
        })
    }

    /// Configure a global tracing subscriber using the configured log level.
    ///
    /// This is kept separate from the pure configuration parsing so that
    /// higher-level code can manage when the global subscriber is installed.
    pub fn init_tracing(&self) -> Result<LoggingGuards, LoggingError> {
        let builder: SubscriberBuilder = tracing_subscriber::fmt()
            .with_max_level(self.level)
            .with_target(true)
            .with_ansi(false);

        if let Some(directory) = &self.directory {
            fs::create_dir_all(directory).map_err(|source| LoggingError::CreateDir {
                path: directory.clone(),
                source,
            })?;

            let log_path = directory.join(LOG_FILENAME);
            let file_writer =
                RotatingFileWriter::new(log_path.clone(), self.max_bytes, self.max_files).map_err(
                    |source| LoggingError::OpenFile {
                        path: log_path,
                        source,
                    },
                )?;

            let sink: Box<dyn Write + Send> = if self.console {
                Box::new(TeeWriter::new(file_writer, io::stdout()))
            } else {
                Box::new(file_writer)
            };

            let (writer, guard) = NonBlockingWriter::new(sink);
            let writer_factory = move || writer.clone();

            builder
                .with_writer(writer_factory)
                .try_init()
                .map_err(LoggingError::InitFailed)?;

            Ok(LoggingGuards {
                _worker: Some(guard),
            })
        } else if self.console {
            builder
                .with_writer(io::stdout)
                .try_init()
                .map_err(LoggingError::InitFailed)?;

            Ok(LoggingGuards { _worker: None })
        } else {
            builder
                .with_writer(io::sink)
                .try_init()
                .map_err(LoggingError::InitFailed)?;

            Ok(LoggingGuards { _worker: None })
        }
    }

    /// Log a policy decision in a structured, configurable way.
    ///
    /// This helper does not assume where the subscriber sends events; it only
    /// emits structured fields that downstream subscribers can consume.
    pub fn log_policy_decision<'a>(&self, ctx: PolicyDecisionLogContext<'a>) {
        let allowed = ctx.decision.allowed;

        if allowed && !self.policy_decisions.log_allows {
            return;
        }
        if !allowed && !self.policy_decisions.log_denies {
            return;
        }

        let level = if allowed {
            self.policy_decisions.level_allows
        } else {
            self.policy_decisions.level_denies
        };
        let (rule_action, rule_pattern, rule_description) = match ctx.decision.matched.as_ref() {
            Some(m) => {
                let action = match m.action {
                    PolicyDefaultAction::Allow => "allow",
                    PolicyDefaultAction::Deny => "deny",
                };
                (Some(action), m.pattern.as_deref(), m.description.as_deref())
            }
            None => (None, None, None),
        };

        let method = ctx.method.unwrap_or_default();
        let client_ip = ctx.client_ip.unwrap_or_default();
        emit_policy_event(
            level,
            ctx.request_id,
            allowed,
            ctx.url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
        );
    }
}

enum LogMessage {
    Line(Vec<u8>),
    Shutdown,
}

#[derive(Clone)]
struct NonBlockingWriter {
    sender: SyncSender<LogMessage>,
    shutdown: Arc<AtomicBool>,
}

impl NonBlockingWriter {
    fn new(sink: Box<dyn Write + Send>) -> (Self, WorkerGuard) {
        let (sender, receiver) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();

        let handle = thread::spawn(move || log_worker(receiver, sink));
        let writer = NonBlockingWriter {
            sender: sender.clone(),
            shutdown: thread_shutdown,
        };

        let guard = WorkerGuard {
            sender,
            shutdown,
            handle: Some(handle),
        };

        (writer, guard)
    }
}

impl Write for NonBlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Ok(buf.len());
        }

        match self.sender.try_send(LogMessage::Line(buf.to_vec())) {
            Ok(()) => Ok(buf.len()),
            Err(TrySendError::Full(_)) => Ok(buf.len()),
            Err(TrySendError::Disconnected(_)) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct WorkerGuard {
    sender: SyncSender<LogMessage>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.sender.send(LogMessage::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn log_worker(receiver: Receiver<LogMessage>, mut sink: Box<dyn Write + Send>) {
    let mut error_reported = false;

    for message in receiver {
        match message {
            LogMessage::Line(buf) => {
                if let Err(err) = sink.write_all(&buf) {
                    if !error_reported {
                        eprintln!("logging write failed: {err}");
                        error_reported = true;
                    }
                }
            }
            LogMessage::Shutdown => break,
        }
    }

    let _ = sink.flush();
}

struct TeeWriter<A, B> {
    primary: A,
    secondary: B,
}

impl<A, B> TeeWriter<A, B> {
    fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }
}

impl<A: Write, B: Write> Write for TeeWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.primary.write_all(buf)?;
        self.secondary.write_all(buf)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.primary.flush()?;
        self.secondary.flush()?;

        Ok(())
    }
}

struct RotatingFileWriter {
    base_path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    file: std::fs::File,
    size: u64,
}

impl RotatingFileWriter {
    fn new(base_path: PathBuf, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)?;
        let size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);

        Ok(Self {
            base_path,
            max_bytes,
            max_files,
            file,
            size,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;

        for index in (1..=self.max_files).rev() {
            let destination = self.rotated_path(index);
            let source = if index == 1 {
                self.base_path.clone()
            } else {
                self.rotated_path(index - 1)
            };

            if source.exists() {
                if destination.exists() {
                    fs::remove_file(&destination)?;
                }
                fs::rename(source, destination)?;
            }
        }

        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.base_path)?;
        self.size = 0;

        Ok(())
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        let mut path = self.base_path.as_os_str().to_os_string();
        path.push(format!(".{index}"));
        PathBuf::from(path)
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }

        self.file.write_all(buf)?;
        self.size += buf.len() as u64;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Debug, Clone)]
pub struct PolicyDecisionLogContext<'a> {
    pub request_id: &'a str,
    pub url: &'a str,
    pub method: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub decision: &'a PolicyDecision,
}

impl PolicyDecisionLogging {
    pub fn from_config(cfg: &LoggingPolicyDecisionsConfig) -> Result<Self, LoggingError> {
        let level_allows =
            parse_level(&cfg.level_allows).map_err(|value| LoggingError::InvalidLevel {
                field: "logging.policy_decisions.level_allows",
                value,
            })?;

        let level_denies =
            parse_level(&cfg.level_denies).map_err(|value| LoggingError::InvalidLevel {
                field: "logging.policy_decisions.level_denies",
                value,
            })?;

        Ok(PolicyDecisionLogging {
            log_allows: cfg.log_allows,
            log_denies: cfg.log_denies,
            level_allows,
            level_denies,
        })
    }
}

fn parse_level(value: &str) -> Result<Level, String> {
    let upper = value.trim().to_ascii_uppercase();
    upper.parse::<Level>().map_err(|_| value.to_string())
}

fn emit_policy_event(
    level: Level,
    request_id: &str,
    allowed: bool,
    url: &str,
    method: &str,
    client_ip: &str,
    rule_action: Option<&str>,
    rule_pattern: Option<&str>,
    rule_description: Option<&str>,
) {
    match level {
        Level::TRACE => tracing::event!(
            target: "acl_proxy::policy",
            Level::TRACE,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::DEBUG => tracing::event!(
            target: "acl_proxy::policy",
            Level::DEBUG,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::INFO => tracing::event!(
            target: "acl_proxy::policy",
            Level::INFO,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::WARN => tracing::event!(
            target: "acl_proxy::policy",
            Level::WARN,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::ERROR => tracing::event!(
            target: "acl_proxy::policy",
            Level::ERROR,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
    }
}

impl fmt::Display for PolicyDecisionLogging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "allows={}, denies={}, level_allows={:?}, level_denies={:?}",
            self.log_allows, self.log_denies, self.level_allows, self.level_denies
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LoggingPolicyDecisionsConfig;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn logging_settings_parses_levels() {
        let cfg = LoggingConfig {
            directory: Some(PathBuf::from("logs")),
            level: "debug".to_string(),
            max_bytes: 104_857_600,
            max_files: 5,
            console: true,
            policy_decisions: LoggingPolicyDecisionsConfig {
                log_allows: true,
                log_denies: true,
                level_allows: "info".to_string(),
                level_denies: "warn".to_string(),
            },
        };

        let settings = LoggingSettings::from_config(&cfg).expect("parse logging config");
        assert_eq!(settings.level, Level::DEBUG);
        assert_eq!(settings.policy_decisions.level_allows, Level::INFO);
        assert_eq!(settings.policy_decisions.level_denies, Level::WARN);
    }

    #[test]
    fn invalid_base_level_fails() {
        let cfg = LoggingConfig {
            directory: Some(PathBuf::from("logs")),
            level: "notalevel".to_string(),
            max_bytes: 104_857_600,
            max_files: 5,
            console: true,
            policy_decisions: LoggingPolicyDecisionsConfig::default(),
        };

        let err = LoggingSettings::from_config(&cfg).expect_err("should fail");
        let msg = format!("{err}");
        assert!(msg.contains("invalid log level"), "unexpected error: {msg}");
    }

    #[test]
    fn invalid_max_bytes_fails_when_directory_set() {
        let cfg = LoggingConfig {
            directory: Some(PathBuf::from("logs")),
            level: "info".to_string(),
            max_bytes: 0,
            max_files: 5,
            console: true,
            policy_decisions: LoggingPolicyDecisionsConfig::default(),
        };

        let err = LoggingSettings::from_config(&cfg).expect_err("should fail");
        let msg = format!("{err}");
        assert!(msg.contains("logging.max_bytes"), "unexpected error: {msg}");
    }

    #[test]
    fn invalid_max_files_fails_when_directory_set() {
        let cfg = LoggingConfig {
            directory: Some(PathBuf::from("logs")),
            level: "info".to_string(),
            max_bytes: 1024,
            max_files: 0,
            console: true,
            policy_decisions: LoggingPolicyDecisionsConfig::default(),
        };

        let err = LoggingSettings::from_config(&cfg).expect_err("should fail");
        let msg = format!("{err}");
        assert!(msg.contains("logging.max_files"), "unexpected error: {msg}");
    }

    #[test]
    fn rotating_file_writer_rotates_by_size() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let base_path = temp_dir.path().join("acl-proxy.log");
        let mut writer = RotatingFileWriter::new(base_path.clone(), 10, 2).expect("writer");

        writer.write_all(b"12345").expect("write");
        writer.write_all(b"67890").expect("write");
        writer.write_all(b"1").expect("write");

        let rotated = PathBuf::from(format!("{}.1", base_path.display()));
        assert!(rotated.exists(), "rotated file should exist");
        let current = std::fs::read_to_string(&base_path).expect("read current");
        assert_eq!(current, "1");
    }
}
