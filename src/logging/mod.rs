use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;

use tracing::Level;
use tracing_subscriber::fmt::SubscriberBuilder;

use crate::config::compiler::{CompiledLogLevel, StaticLoggingConfig};
use crate::filesystem::{
    create_private_dir_all, open_private_file_for_append, open_private_file_for_write,
};

const LOG_FILENAME: &str = "acl-proxy.log";
const LOG_QUEUE_CAPACITY: usize = 8192;

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
}

#[derive(Debug, Clone)]
pub(crate) struct LoggingSettings {
    level: Level,
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
    pub(crate) fn from_static_config(cfg: &StaticLoggingConfig) -> Self {
        Self {
            level: tracing_level(cfg.level),
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
        let builder: SubscriberBuilder = tracing_subscriber::fmt()
            .with_max_level(self.level)
            .with_target(true)
            .with_ansi(false);

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
}

fn tracing_level(level: CompiledLogLevel) -> Level {
    match level {
        CompiledLogLevel::Trace => Level::TRACE,
        CompiledLogLevel::Debug => Level::DEBUG,
        CompiledLogLevel::Info => Level::INFO,
        CompiledLogLevel::Warn => Level::WARN,
        CompiledLogLevel::Error => Level::ERROR,
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
    fn strict_static_logging_copies_process_lifetime_sink_settings() {
        let cfg = StaticLoggingConfig {
            level: CompiledLogLevel::Warn,
            directory: Some(PathBuf::from("strict-logs")),
            max_bytes: 4096,
            max_files: 3,
            console: false,
        };

        let settings = LoggingSettings::from_static_config(&cfg);
        assert_eq!(settings.level, Level::WARN);
        assert_eq!(settings.directory, cfg.directory);
        assert_eq!(settings.max_bytes, 4096);
        assert_eq!(settings.max_files, 3);
        assert!(!settings.console);
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
