use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread;

use tracing::Level;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

#[cfg(not(test))]
use http_access_runtime::ObservationSink;
use http_access_types::{DecisionAuditFacts, DecisionReasonCategory, EffectivePolicy};

#[cfg(not(test))]
use crate::config::compiler::CompiledDecisionLogLevel;
use crate::config::compiler::{CompiledLogLevel, StaticLoggingConfig};
use crate::filesystem::{
    create_private_dir_all, open_private_file_for_append, open_private_file_for_write,
};
use crate::runtime::{BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError};

const LOG_FILENAME: &str = "acl-proxy.log";
const LOG_QUEUE_CAPACITY: usize = 8192;
static PROCESS_LOGGING_LEVEL: OnceLock<LoggingLevelControl> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct LoggingLevelControl {
    level: Arc<AtomicU8>,
}

impl LoggingLevelControl {
    fn new(level: CompiledLogLevel) -> Self {
        Self {
            level: Arc::new(AtomicU8::new(log_level_code(level))),
        }
    }

    pub(crate) fn current(&self) -> CompiledLogLevel {
        compiled_log_level(self.level.load(Ordering::Acquire))
    }

    fn enabled(&self, target: &str, event: &Level) -> bool {
        target == "acl_proxy::policy" || log_level_admits(self.current(), event)
    }

    pub(crate) fn stage(&self, level: CompiledLogLevel) -> Arc<dyn GenerationOwner> {
        Arc::new(LoggingLevelOwner {
            control: self.clone(),
            proposed: level,
        })
    }

    fn publish(&self, level: CompiledLogLevel) {
        self.level.store(log_level_code(level), Ordering::Release);
    }
}

pub(crate) fn process_logging_level_control() -> LoggingLevelControl {
    PROCESS_LOGGING_LEVEL
        .get()
        .cloned()
        .unwrap_or_else(|| LoggingLevelControl::new(CompiledLogLevel::Info))
}

struct LoggingLevelOwner {
    control: LoggingLevelControl,
    proposed: CompiledLogLevel,
}

struct LoggingLevelPublicationGuard<'a> {
    owner: &'a LoggingLevelOwner,
}

impl PublicationGuard for LoggingLevelPublicationGuard<'_> {
    fn commit(&mut self) {
        self.owner.control.publish(self.owner.proposed);
    }
}

impl GenerationOwner for LoggingLevelOwner {
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
        Ok(Box::new(LoggingLevelPublicationGuard { owner: self }))
    }

    fn retirement_started(&self, _reason: CleanupReason) {}

    fn cleanup(&self, _reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

const fn log_level_code(level: CompiledLogLevel) -> u8 {
    match level {
        CompiledLogLevel::Trace => 0,
        CompiledLogLevel::Debug => 1,
        CompiledLogLevel::Info => 2,
        CompiledLogLevel::Warn => 3,
        CompiledLogLevel::Error => 4,
    }
}

const fn compiled_log_level(code: u8) -> CompiledLogLevel {
    match code {
        0 => CompiledLogLevel::Trace,
        1 => CompiledLogLevel::Debug,
        2 => CompiledLogLevel::Info,
        3 => CompiledLogLevel::Warn,
        _ => CompiledLogLevel::Error,
    }
}

fn log_level_admits(threshold: CompiledLogLevel, event: &Level) -> bool {
    match threshold {
        CompiledLogLevel::Trace => true,
        CompiledLogLevel::Debug => *event != Level::TRACE,
        CompiledLogLevel::Info => matches!(*event, Level::ERROR | Level::WARN | Level::INFO),
        CompiledLogLevel::Warn => matches!(*event, Level::ERROR | Level::WARN),
        CompiledLogLevel::Error => *event == Level::ERROR,
    }
}

#[cfg(not(test))]
pub(crate) struct PolicyDecisionLogSink {
    level: CompiledDecisionLogLevel,
}

#[cfg(not(test))]
impl PolicyDecisionLogSink {
    pub(crate) const fn new(level: CompiledDecisionLogLevel) -> Self {
        Self { level }
    }
}

#[cfg(not(test))]
macro_rules! emit_policy_decision {
    ($level:ident, $record:ident) => {
        tracing::$level!(
            target: "acl_proxy::policy",
            request_id = %$record.request_id,
            allowed = $record.allowed,
            url = %$record.url,
            method = %$record.method,
            client_ip = %$record.client_ip,
            generation = %$record.generation,
            effective_policy = %$record.effective_policy,
            reason_category = $record.reason_category,
            reason_code = $record.reason_code,
            trace_id = %$record.trace_id,
            sensitive_header_presence = %$record.sensitive_header_presence,
            "policy decision"
        )
    };
}

#[cfg(not(test))]
impl ObservationSink for PolicyDecisionLogSink {
    fn record(&mut self, facts: &DecisionAuditFacts) {
        let record = PolicyDecisionLogRecord::from_facts(facts);
        match self.level {
            CompiledDecisionLogLevel::Info => emit_policy_decision!(info, record),
            CompiledDecisionLogLevel::Warn => emit_policy_decision!(warn, record),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PolicyDecisionLogRecord<'a> {
    request_id: &'a str,
    allowed: bool,
    url: &'a str,
    method: &'a str,
    client_ip: String,
    generation: String,
    effective_policy: String,
    reason_category: &'static str,
    reason_code: u16,
    trace_id: &'a str,
    sensitive_header_presence: String,
}

impl<'a> PolicyDecisionLogRecord<'a> {
    fn from_facts(facts: &'a DecisionAuditFacts) -> Self {
        let provenance = facts.provenance();
        let generation = provenance
            .map(|value| value.generation().get().to_string())
            .unwrap_or_default();
        let effective_policy = provenance
            .map(|value| match value.effective_policy() {
                EffectivePolicy::Default => "default".to_owned(),
                EffectivePolicy::Rule { id, ordinal } => {
                    format!("{}#{}", id.as_str(), ordinal)
                }
            })
            .unwrap_or_default();
        let reason = facts.reason();
        Self {
            request_id: facts.request_id().as_str(),
            allowed: matches!(
                facts.disposition(),
                http_access_types::DecisionDisposition::Allow
            ),
            url: facts
                .url()
                .map_or("", http_access_types::SinkSafeUrl::as_str),
            method: facts
                .method()
                .map_or("", http_access_types::HttpMethod::as_str),
            client_ip: facts
                .peer_ip()
                .map(|value| value.to_string())
                .unwrap_or_default(),
            generation,
            effective_policy,
            reason_category: decision_reason_category(reason.category()),
            reason_code: reason.code(),
            trace_id: provenance
                .and_then(http_access_types::DecisionProvenance::trace_id)
                .map_or("", http_access_types::StableId::as_str),
            sensitive_header_presence: facts
                .sensitive_header_presence()
                .iter()
                .map(http_access_types::HeaderName::as_str)
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

const fn decision_reason_category(category: DecisionReasonCategory) -> &'static str {
    match category {
        DecisionReasonCategory::Policy => "policy",
        DecisionReasonCategory::Provider => "provider",
        DecisionReasonCategory::ProviderFailure => "provider_failure",
        DecisionReasonCategory::Loop => "loop",
        DecisionReasonCategory::InvalidPlan => "invalid_plan",
        DecisionReasonCategory::Expired => "expired",
        DecisionReasonCategory::Audit => "audit",
        DecisionReasonCategory::Transport => "transport",
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
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

    #[error("global logging level control is already initialized")]
    ControlAlreadyInitialized,
}

#[derive(Debug, Clone)]
pub(crate) struct LoggingSettings {
    control: LoggingLevelControl,
    directory: Option<PathBuf>,
    max_bytes: u64,
    max_files: usize,
    console: bool,
}

pub(crate) struct LoggingGuards {
    _worker: Option<WorkerGuard>,
}

impl LoggingSettings {
    /// Builds the process-lifetime sink from strict compiled configuration.
    pub(crate) fn from_config(cfg: &StaticLoggingConfig, level: CompiledLogLevel) -> Self {
        Self {
            control: LoggingLevelControl::new(level),
            directory: cfg.directory.clone(),
            max_bytes: cfg.max_bytes,
            max_files: cfg.max_files,
            console: cfg.console,
        }
    }

    /// Configure a global tracing subscriber for the process-lifetime sinks.
    ///
    /// This is kept separate from the pure configuration parsing so that
    /// higher-level code can manage when the global subscriber is installed.
    pub(crate) fn init_tracing(&self) -> Result<LoggingGuards, LoggingError> {
        if let Some(directory) = &self.directory {
            create_private_dir_all(directory).map_err(|source| LoggingError::CreateDir {
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
            let control = self.control.clone();

            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(false)
                        .with_writer(writer_factory)
                        .with_filter(filter_fn(move |metadata| {
                            control.enabled(metadata.target(), metadata.level())
                        })),
                )
                .try_init()
                .map_err(|error| LoggingError::InitFailed(Box::new(error)))?;

            self.finish_initialization(Some(guard))
        } else if self.console {
            let control = self.control.clone();
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(false)
                        .with_writer(io::stdout)
                        .with_filter(filter_fn(move |metadata| {
                            control.enabled(metadata.target(), metadata.level())
                        })),
                )
                .try_init()
                .map_err(|error| LoggingError::InitFailed(Box::new(error)))?;

            self.finish_initialization(None)
        } else {
            let control = self.control.clone();
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(false)
                        .with_writer(io::sink)
                        .with_filter(filter_fn(move |metadata| {
                            control.enabled(metadata.target(), metadata.level())
                        })),
                )
                .try_init()
                .map_err(|error| LoggingError::InitFailed(Box::new(error)))?;

            self.finish_initialization(None)
        }
    }

    fn finish_initialization(
        &self,
        worker: Option<WorkerGuard>,
    ) -> Result<LoggingGuards, LoggingError> {
        PROCESS_LOGGING_LEVEL
            .set(self.control.clone())
            .map_err(|_| LoggingError::ControlAlreadyInitialized)?;
        Ok(LoggingGuards { _worker: worker })
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
        let file = open_private_file_for_append(&base_path)?;
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
        let mut rotation_error = None;
        let mut base_rotated = false;

        for index in (1..=self.max_files).rev() {
            let destination = self.rotated_path(index);
            let source = if index == 1 {
                self.base_path.clone()
            } else {
                self.rotated_path(index - 1)
            };

            if source.exists() {
                if destination.exists() {
                    if let Err(err) = fs::remove_file(&destination) {
                        rotation_error.get_or_insert(err);
                        continue;
                    }
                }
                if let Err(err) = fs::rename(source, destination) {
                    rotation_error.get_or_insert(err);
                } else if index == 1 {
                    base_rotated = true;
                }
            }
        }

        if base_rotated || !self.base_path.exists() {
            self.file = open_private_file_for_write(&self.base_path)?;
            self.size = 0;
        } else {
            self.file = open_private_file_for_append(&self.base_path)?;
            self.size = self
                .file
                .metadata()
                .map(|metadata| metadata.len())
                .unwrap_or(0);
        }

        if let Some(err) = rotation_error {
            eprintln!("log rotation completed with errors; continuing with active log file: {err}");
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn logging_settings_bind_the_initial_level_and_copy_static_sink_settings() {
        let cfg = StaticLoggingConfig {
            directory: Some(PathBuf::from("strict-logs")),
            max_bytes: 4096,
            max_files: 3,
            console: false,
        };

        let settings = LoggingSettings::from_config(&cfg, CompiledLogLevel::Warn);
        assert_eq!(settings.control.current(), CompiledLogLevel::Warn);
        assert_eq!(settings.directory, cfg.directory);
        assert_eq!(settings.max_bytes, 4096);
        assert_eq!(settings.max_files, 3);
        assert!(!settings.console);
    }

    #[test]
    fn staged_logging_level_changes_only_when_publication_commits() {
        let control = LoggingLevelControl::new(CompiledLogLevel::Info);
        let rejected = control.stage(CompiledLogLevel::Trace);

        let rejected_guard = rejected.publication_guard().unwrap();
        assert_eq!(control.current(), CompiledLogLevel::Info);
        drop(rejected_guard);
        drop(rejected.cleanup(CleanupReason::CandidateRejected));
        assert_eq!(control.current(), CompiledLogLevel::Info);

        let published = control.stage(CompiledLogLevel::Error);
        let mut published_guard = published.publication_guard().unwrap();
        published_guard.commit();
        assert_eq!(control.current(), CompiledLogLevel::Error);
    }

    #[test]
    fn dynamic_level_control_applies_the_general_tracing_threshold() {
        let control = LoggingLevelControl::new(CompiledLogLevel::Warn);
        assert!(control.enabled("acl_proxy", &Level::ERROR));
        assert!(control.enabled("acl_proxy", &Level::WARN));
        assert!(!control.enabled("acl_proxy", &Level::INFO));
        assert!(!control.enabled("acl_proxy", &Level::DEBUG));
        assert!(!control.enabled("acl_proxy", &Level::TRACE));

        control.publish(CompiledLogLevel::Debug);
        assert!(control.enabled("acl_proxy", &Level::DEBUG));
        assert!(!control.enabled("acl_proxy", &Level::TRACE));
    }

    #[test]
    fn reload_does_not_refilter_an_inflight_generation_decision() {
        let control = LoggingLevelControl::new(CompiledLogLevel::Info);
        assert!(control.enabled("acl_proxy::policy", &Level::INFO));

        control.publish(CompiledLogLevel::Error);

        assert!(!control.enabled("acl_proxy", &Level::INFO));
        assert!(control.enabled("acl_proxy::policy", &Level::INFO));
    }

    #[test]
    fn decision_record_has_the_exact_sanitized_product_fields() {
        use http_access_types::{
            DecisionAuditFactsInput, DecisionAuditSource, DecisionDisposition, DecisionProvenance,
            HeaderName, HttpMethod, PolicyGeneration, StableId,
        };

        let request_id = StableId::new("req-7").unwrap();
        let rule_id = StableId::new("allow-api").unwrap();
        let trace_id = StableId::new("trace-9").unwrap();
        let provenance = DecisionProvenance::new(
            PolicyGeneration::new(42).unwrap(),
            EffectivePolicy::Rule {
                id: rule_id,
                ordinal: 3,
            },
            http_access_types::DecisionReason::new(DecisionReasonCategory::Provider, 17),
            Some(trace_id),
        );
        let source = DecisionAuditSource::Policy(provenance);
        let method = HttpMethod::new("POST").unwrap();
        let url =
            http_access_url::canonicalize_http_url("https://example.test/private?token=secret")
                .unwrap();
        let presence = [
            HeaderName::new("authorization").unwrap(),
            HeaderName::new("x-provider-token").unwrap(),
        ];
        let facts = DecisionAuditFacts::new(DecisionAuditFactsInput {
            request_id: &request_id,
            disposition: DecisionDisposition::Allow,
            method: Some(&method),
            url: Some(&url),
            peer_ip: Some("192.0.2.8".parse().unwrap()),
            source: &source,
            sensitive_header_presence: &presence,
        })
        .unwrap();

        assert_eq!(
            PolicyDecisionLogRecord::from_facts(&facts),
            PolicyDecisionLogRecord {
                request_id: "req-7",
                allowed: true,
                url: "https://example.test/private?REDACTED",
                method: "POST",
                client_ip: "192.0.2.8".to_owned(),
                generation: "42".to_owned(),
                effective_policy: "allow-api#3".to_owned(),
                reason_category: "provider",
                reason_code: 17,
                trace_id: "trace-9",
                sensitive_header_presence: "authorization,x-provider-token".to_owned(),
            }
        );
    }

    struct RecordingSink {
        bytes: Arc<Mutex<Vec<u8>>>,
        flushed: Arc<AtomicBool>,
    }

    impl Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.lock().expect("lock recording sink").extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn non_blocking_guard_drains_accepted_lines_and_flushes() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let flushed = Arc::new(AtomicBool::new(false));
        let sink = RecordingSink {
            bytes: Arc::clone(&bytes),
            flushed: Arc::clone(&flushed),
        };
        let (mut writer, guard) = NonBlockingWriter::new(Box::new(sink));

        writer.write_all(b"first\n").expect("enqueue first line");
        writer.write_all(b"second\n").expect("enqueue second line");
        drop(guard);

        assert_eq!(
            bytes.lock().expect("lock recorded bytes").as_slice(),
            b"first\nsecond\n"
        );
        assert!(flushed.load(Ordering::SeqCst));
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

        #[cfg(unix)]
        {
            assert_eq!(mode(&base_path), 0o600);
            assert_eq!(mode(&rotated), 0o600);
        }
    }

    #[test]
    fn rotating_file_writer_recovers_when_archive_path_cannot_be_replaced() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let base_path = temp_dir.path().join("acl-proxy.log");
        let rotated = PathBuf::from(format!("{}.1", base_path.display()));
        let mut writer = RotatingFileWriter::new(base_path.clone(), 3, 1).expect("writer");

        writer.write_all(b"abc").expect("write initial line");
        std::fs::create_dir(&rotated).expect("create blocking rotated path");

        writer.write_all(b"d").expect("write through failed rotate");
        let current = std::fs::read_to_string(&base_path).expect("read current");
        assert_eq!(current, "abcd");

        writer.write_all(b"ef").expect("fill current log");
        writer
            .write_all(b"g")
            .expect("write through repeated failed rotate");
        let current = std::fs::read_to_string(&base_path).expect("read current after retry");
        assert_eq!(current, "abcdefg");
        assert!(rotated.is_dir(), "blocking rotated path should remain");
    }
}
