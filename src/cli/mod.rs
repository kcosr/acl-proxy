use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use crate::activation::runner::ProductRuntime;
use crate::config::{
    load_and_compile_config, write_default_config_template, LoadedCompiledConfig, PolicyDump,
    StaticProductConfig,
};
use crate::logging::LoggingSettings;
use crate::runtime::{ReloadTriggerResult, Runtime};

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Config(String),

    #[error("failed to initialize async runtime: {0}")]
    Runtime(String),

    #[error(transparent)]
    Logging(#[from] crate::logging::LoggingError),

    #[error("{0}")]
    Product(String),

    #[error("failed to install {signal} signal handling: {source}")]
    Signal {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Process(String),
}

#[derive(Debug, Parser)]
#[command(
    name = "acl-proxy",
    version,
    about = "ACL-aware HTTP/HTTPS proxy (Rust)"
)]
pub struct Cli {
    /// Path to the strict TOML configuration file.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Run,

    /// Configuration related subcommands.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Policy inspection and debug commands.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate configuration file without starting the proxy.
    Validate,

    /// Initialize a new configuration file at the given path.
    Init {
        /// Path to write the new configuration TOML file.
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Dump the fully resolved policy rules for inspection.
    Dump {
        /// Output format: json (machine-readable) or table (human-friendly).
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
}

pub fn run() -> Result<ExitCode, CliError> {
    let cli = Cli::parse();
    let config_path = cli.config.as_deref();

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            let loaded = load_and_compile_config(config_path)
                .map_err(|error| CliError::Config(error.to_string()))?;
            let logging = LoggingSettings::from_config(
                &loaded.compiled.static_config.logging,
                loaded.compiled.reloadable_plan.observation.logging.level,
            );
            let _logging_guards = logging.init_tracing()?;
            log_startup(&loaded.compiled.static_config);

            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            runtime.block_on(run_product(loaded))?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Config { command } => match command {
            ConfigCommand::Validate => {
                load_and_compile_config(config_path)
                    .map_err(|error| CliError::Config(error.to_string()))?;
                println!("Configuration is valid");
                Ok(ExitCode::SUCCESS)
            }
            ConfigCommand::Init { path } => {
                if path.exists() {
                    eprintln!(
                        "Config file {} already exists; refusing to overwrite. Delete it or choose a new path.",
                        path.display()
                    );
                    return Ok(ExitCode::from(1));
                }

                write_default_config_template(&path)
                    .map_err(|error| CliError::Config(error.to_string()))?;
                println!("Wrote default config to {}", path.display());
                Ok(ExitCode::SUCCESS)
            }
        },
        Command::Policy { command } => match command {
            PolicyCommand::Dump { format } => {
                let compiled = load_and_compile_config(config_path)
                    .map_err(|error| CliError::Config(error.to_string()))?;
                let policy = PolicyDump::from_compiled(&compiled.compiled);

                let use_table = match format {
                    Some(OutputFormat::Table) => true,
                    Some(OutputFormat::Json) => false,
                    None => std::io::stdout().is_terminal(),
                };

                if use_table {
                    print_policy_table(&policy);
                } else if let Err(error) = serde_json::to_writer_pretty(std::io::stdout(), &policy)
                {
                    return Err(CliError::Process(format!(
                        "failed to serialize policy to JSON: {error}"
                    )));
                } else {
                    println!();
                }

                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

async fn run_product(loaded: LoadedCompiledConfig) -> Result<(), CliError> {
    let mut signals = ProcessSignals::install()?;
    let product = ProductRuntime::prepare(loaded)
        .await
        .map_err(|error| CliError::Product(error.to_string()))?;
    product
        .start_listeners()
        .await
        .map_err(|error| CliError::Product(error.to_string()))?;
    let generation = product
        .activate_initial()
        .await
        .map_err(|error| CliError::Product(error.to_string()))?;
    tracing::info!(
        target: "acl_proxy::startup",
        generation = generation.get(),
        "acl-proxy is ready"
    );

    supervise_process(&product, &mut signals).await
}

async fn supervise_process(
    product: &Arc<ProductRuntime>,
    signals: &mut ProcessSignals,
) -> Result<(), CliError> {
    let runtime = product.runtime().clone();
    let control_enabled = runtime.static_config().control.is_some();
    let mut reload_task: Option<ReloadTask> = None;
    let mut reload_again = false;

    let terminal = loop {
        tokio::select! {
            signal = signals.next() => {
                match signal? {
                    ProcessSignal::Interrupt => {
                        tracing::info!("received interrupt; initiating graceful shutdown");
                        break Ok(());
                    }
                    ProcessSignal::Terminate => {
                        tracing::info!("received SIGTERM; initiating graceful shutdown");
                        break Ok(());
                    }
                    ProcessSignal::Reload => {
                        if reload_task.is_some() {
                            reload_again = true;
                        } else {
                            reload_task = Some(spawn_reload(runtime.clone()));
                        }
                    }
                }
            }
            failure = product.wait_for_listener_failure() => {
                let message = failure.map_or_else(
                    || "proxy failure observer closed without a terminal result".to_string(),
                    |error| format!("proxy listener failed: {error}"),
                );
                break Err(CliError::Process(message));
            }
            failure = product.wait_for_control_failure(), if control_enabled => {
                let message = failure.map_or_else(
                    || "control failure observer closed without a terminal result".to_string(),
                    |error| format!("control supervisor failed: {error}"),
                );
                break Err(CliError::Process(message));
            }
            completed = wait_for_reload(&mut reload_task), if reload_task.is_some() => {
                reload_task = None;
                match completed {
                    Ok(result) => log_reload_result(result),
                    Err(error) => break Err(CliError::Process(format!(
                        "configuration reload coordinator failed: {error}"
                    ))),
                }
                if reload_again {
                    reload_again = false;
                    reload_task = Some(spawn_reload(runtime.clone()));
                }
            }
        }
    };

    product.shutdown().await;
    let shutdown_diagnostic = product.shutdown_diagnostic();
    if let Some(reload) = reload_task {
        match reload.await {
            Ok(Ok(_)) | Ok(Err(crate::runtime::RuntimeError::ShuttingDown)) => {}
            Ok(Err(error)) => tracing::debug!(%error, "reload ended during process shutdown"),
            Err(error) => {
                return Err(CliError::Process(format!(
                    "configuration reload coordinator did not join: {error}"
                )));
            }
        }
    }
    match (terminal, shutdown_diagnostic) {
        (Ok(()), None) => Ok(()),
        (Err(error), None) => Err(error),
        (Ok(()), Some(shutdown)) => Err(CliError::Process(shutdown)),
        (Err(error), Some(shutdown)) => Err(CliError::Process(format!(
            "{error}; additional shutdown failure: {shutdown}"
        ))),
    }
}

type ReloadTask =
    tokio::task::JoinHandle<Result<ReloadTriggerResult, crate::runtime::RuntimeError>>;

fn spawn_reload(runtime: Arc<Runtime>) -> ReloadTask {
    tokio::spawn(async move { runtime.trigger_reload().await })
}

async fn wait_for_reload(
    task: &mut Option<ReloadTask>,
) -> Result<Result<ReloadTriggerResult, crate::runtime::RuntimeError>, tokio::task::JoinError> {
    task.as_mut()
        .expect("reload completion is selected only while a task is owned")
        .await
}

fn log_reload_result(result: Result<ReloadTriggerResult, crate::runtime::RuntimeError>) {
    match result {
        Ok(ReloadTriggerResult::Coalesced) => {
            tracing::info!("configuration reload coalesced with the active attempt");
        }
        Ok(ReloadTriggerResult::Completed {
            attempts,
            generation,
        }) => {
            tracing::info!(
                attempts,
                generation = generation.get(),
                "configuration reload completed successfully"
            );
        }
        Err(error) => tracing::error!(%error, "configuration reload failed"),
    }
}

#[derive(Clone, Copy)]
enum ProcessSignal {
    Interrupt,
    Terminate,
    Reload,
}

#[cfg(unix)]
struct ProcessSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    reload: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ProcessSignals {
    fn install() -> Result<Self, CliError> {
        use tokio::signal::unix::{signal, SignalKind};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(|source| CliError::Signal {
                signal: "SIGINT",
                source,
            })?,
            terminate: signal(SignalKind::terminate()).map_err(|source| CliError::Signal {
                signal: "SIGTERM",
                source,
            })?,
            reload: signal(SignalKind::hangup()).map_err(|source| CliError::Signal {
                signal: "SIGHUP",
                source,
            })?,
        })
    }

    async fn next(&mut self) -> Result<ProcessSignal, CliError> {
        tokio::select! {
            signal = self.interrupt.recv() => signal
                .map(|()| ProcessSignal::Interrupt)
                .ok_or_else(|| CliError::Process("SIGINT signal stream closed".to_string())),
            signal = self.terminate.recv() => signal
                .map(|()| ProcessSignal::Terminate)
                .ok_or_else(|| CliError::Process("SIGTERM signal stream closed".to_string())),
            signal = self.reload.recv() => signal
                .map(|()| ProcessSignal::Reload)
                .ok_or_else(|| CliError::Process("SIGHUP signal stream closed".to_string())),
        }
    }
}

#[cfg(not(unix))]
struct ProcessSignals;

#[cfg(not(unix))]
impl ProcessSignals {
    fn install() -> Result<Self, CliError> {
        Ok(Self)
    }

    async fn next(&mut self) -> Result<ProcessSignal, CliError> {
        tokio::signal::ctrl_c()
            .await
            .map(|()| ProcessSignal::Interrupt)
            .map_err(|source| CliError::Signal {
                signal: "interrupt",
                source,
            })
    }
}

fn print_policy_table(policy: &PolicyDump) {
    println!("Default action: {}", policy.default.as_str());
    println!(
        "INDEX\tDECISION\tURLS\tMETHODS\tCLIENT_CIDRS\tHEADER_PREDICATES\tDESCRIPTION\tAUTHORIZATION_PROVIDER\tREDACTION_PROFILE\tMUTATIONS"
    );

    for row in policy.table_rows() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.index,
            row.decision,
            table_value(&row.urls),
            table_value(&row.methods),
            table_value(&row.client_cidrs),
            table_value(&row.header_predicates),
            table_value(&row.description),
            table_value(&row.authorization_provider),
            table_value(&row.redaction_profile),
            table_value(&row.mutations),
        );
    }
}

fn table_value(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

fn log_startup(config: &StaticProductConfig) {
    let listeners = &config.listeners;
    for (name, bind) in [
        (
            "explicit_http",
            listeners.explicit_http.as_ref().map(|value| value.bind),
        ),
        (
            "transparent_http",
            listeners.transparent_http.as_ref().map(|value| value.bind),
        ),
        (
            "explicit_https",
            listeners.explicit_https.as_ref().map(|value| value.bind),
        ),
        (
            "transparent_https",
            listeners.transparent_https.as_ref().map(|value| value.bind),
        ),
    ] {
        if let Some(bind) = bind {
            warn_on_unspecified_bind(name, bind);
        }
    }

    tracing::info!(
        target: "acl_proxy::startup",
        schema_version = config.schema_version,
        explicit_http_bind = ?listeners.explicit_http.as_ref().map(|value| value.bind),
        transparent_http_bind = ?listeners.transparent_http.as_ref().map(|value| value.bind),
        explicit_https_bind = ?listeners.explicit_https.as_ref().map(|value| value.bind),
        transparent_https_bind = ?listeners.transparent_https.as_ref().map(|value| value.bind),
        control_bind = ?config.control.as_ref().map(|value| value.bind),
        mitm_enabled = config.mitm.is_some(),
        "acl-proxy starting"
    );
}

fn warn_on_unspecified_bind(listener: &str, bind: SocketAddr) {
    if bind.ip().is_unspecified() {
        tracing::warn!(
            target: "acl_proxy::startup",
            listener,
            bind_address = %bind.ip(),
            port = bind.port(),
            "proxy listener is bound to all interfaces; restrict bind_address or firewall access when exposure is not intended"
        );
    }
}
