use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use crate::app::{AppState, SharedAppState};
use crate::config::{Config, ConfigError, ConfigPathKind};
use crate::proxy::http::HttpProxyError;
use crate::proxy::https_transparent::HttpsTransparentError;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    AppState(#[from] crate::app::AppStateError),

    #[error("failed to initialize async runtime: {0}")]
    Runtime(String),

    #[error(transparent)]
    Proxy(#[from] HttpProxyError),

    #[error(transparent)]
    HttpsTransparent(#[from] HttpsTransparentError),
}

#[derive(Debug, Parser)]
#[command(
    name = "acl-proxy",
    version,
    about = "ACL-aware HTTP/HTTPS proxy (Rust)"
)]
pub struct Cli {
    /// Path to configuration file (TOML or JSON).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy (not yet implemented).
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

fn load_config_for_cli(config_path: Option<&std::path::Path>) -> Result<Config, CliError> {
    let (path, kind) = Config::resolve_path(config_path);

    match Config::load_from_sources(config_path) {
        Ok(cfg) => Ok(cfg),
        Err(ConfigError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound
                && matches!(kind, ConfigPathKind::Default) =>
        {
            eprintln!(
                "No configuration file found.\n\
                 Searched default path: {path}\n\
                 Pass --config or set ACL_PROXY_CONFIG, or run:\n  acl-proxy config init {path}",
                path = path.display(),
            );
            Err(CliError::Config(ConfigError::Invalid(
                "configuration file not found".to_string(),
            )))
        }
        Err(e) => Err(CliError::Config(e)),
    }
}

pub fn run() -> Result<ExitCode, CliError> {
    let cli = Cli::parse();

    let config_path_owned = cli.config.clone();
    let config_path = config_path_owned.as_deref();

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            let config = load_config_for_cli(config_path)?;
            let shared_state = AppState::shared_from_config(config)?;

            if let Err(err) = shared_state.load().logging.init_tracing() {
                eprintln!("failed to initialize logging: {err}");
            } else {
                log_startup(shared_state.load().as_ref());
            }

            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Runtime(format!("failed to start tokio runtime: {e}")))?;

            let result: Result<(), CliError> = runtime.block_on(async move {
                run_proxy_with_signals(shared_state, config_path_owned.as_deref()).await
            });

            match result {
                Ok(()) => Ok(ExitCode::from(0)),
                Err(err) => {
                    eprintln!("proxy server exited with error: {err}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        Command::Config { command } => match command {
            ConfigCommand::Validate => {
                let _config = load_config_for_cli(config_path)?;
                println!("Configuration is valid");
                Ok(ExitCode::from(0))
            }
            ConfigCommand::Init { path } => {
                if path.exists() {
                    eprintln!(
                        "Config file {} already exists; refusing to overwrite. Delete it or choose a new path.",
                        path.display()
                    );
                    return Ok(ExitCode::from(1));
                }

                crate::config::write_default_config(&path)?;
                println!("Wrote default config to {}", path.display());
                Ok(ExitCode::from(0))
            }
        },
        Command::Policy { command } => match command {
            PolicyCommand::Dump { format } => {
                let config = load_config_for_cli(config_path)?;
                let effective = crate::policy::EffectivePolicy::from_config(&config.policy)
                    .map_err(|e| {
                        CliError::Config(crate::config::ConfigError::Invalid(e.to_string()))
                    })?;

                let use_table = match format {
                    Some(OutputFormat::Table) => true,
                    Some(OutputFormat::Json) => false,
                    None => std::io::stdout().is_terminal(),
                };

                if use_table {
                    print_policy_table(&effective);
                } else {
                    match serde_json::to_writer_pretty(std::io::stdout(), &effective) {
                        Ok(()) => {
                            println!();
                        }
                        Err(err) => {
                            eprintln!("failed to serialize policy to JSON: {err}");
                            return Ok(ExitCode::from(1));
                        }
                    }
                }

                Ok(ExitCode::from(0))
            }
        },
    }
}

fn print_policy_table(policy: &crate::policy::EffectivePolicy) {
    println!(
        "Default action: {}",
        match policy.default {
            crate::config::PolicyDefaultAction::Allow => "allow",
            crate::config::PolicyDefaultAction::Deny => "deny",
        }
    );
    println!("INDEX\tACTION\tPATTERN\tMETHODS\tSUBNETS\tDESCRIPTION");

    for rule in &policy.rules {
        let action = match rule.action {
            crate::config::PolicyDefaultAction::Allow => "allow",
            crate::config::PolicyDefaultAction::Deny => "deny",
        };

        let pattern = rule.pattern.as_deref().unwrap_or("-");
        let methods = if rule.methods.is_empty() {
            "-".to_string()
        } else {
            rule.methods.join(",")
        };
        let subnets = if rule.subnets.is_empty() {
            "-".to_string()
        } else {
            rule.subnets
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let description = rule.description.as_deref().unwrap_or("-");

        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            rule.index, action, pattern, methods, subnets, description
        );
    }
}

async fn run_proxy_with_signals(
    state: SharedAppState,
    config_path: Option<&Path>,
) -> Result<(), CliError> {
    use tokio::sync::Notify;

    let shutdown = Arc::new(Notify::new());
    let shutdown_http = shutdown.clone();
    let shutdown_https = shutdown.clone();

    let initial = state.load();
    let https_port = initial.config.proxy.https_port;

    // Spawn signal handlers: SIGHUP for reload (on Unix) and
    // Ctrl+C/SIGTERM for graceful shutdown.
    spawn_signal_handlers(state.clone(), config_path, shutdown.clone());

    let http_fut = crate::proxy::http::run_http_proxy(state.clone(), async move {
        shutdown_http.notified().await;
    });

    if https_port == 0 {
        http_fut.await.map_err(CliError::Proxy)?;
        tracing::info!("HTTP proxy listener shut down gracefully");
        Ok(())
    } else {
        let https_fut = crate::proxy::https_transparent::run_https_transparent_proxy(
            state.clone(),
            async move {
                shutdown_https.notified().await;
            },
        );

        tokio::select! {
            res = http_fut => {
                res.map_err(CliError::Proxy)?;
                tracing::info!("HTTP proxy listener shut down gracefully");
                Ok(())
            }
            res = https_fut => {
                res.map_err(CliError::HttpsTransparent)?;
                tracing::info!("HTTPS transparent listener shut down gracefully");
                Ok(())
            }
        }
    }
}

fn spawn_signal_handlers(
    state: SharedAppState,
    config_path: Option<&Path>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    // Graceful shutdown on Ctrl+C (cross-platform).
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("received interrupt (Ctrl+C); initiating graceful shutdown");
            shutdown_clone.notify_waiters();
        }
    });

    // Unix-specific signals: SIGHUP for reload, SIGTERM for shutdown.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let state_for_reload = state.clone();
        let config_path_for_reload = config_path.map(|p| p.to_path_buf());

        tokio::spawn(async move {
            let mut hup_stream = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!("failed to install SIGHUP handler: {err}");
                    return;
                }
            };

            while hup_stream.recv().await.is_some() {
                match reload_from_sources(&state_for_reload, config_path_for_reload.as_deref()) {
                    Ok(()) => {
                        tracing::info!("configuration reload completed successfully");
                    }
                    Err(err) => {
                        tracing::error!("configuration reload failed: {err}");
                    }
                }
            }
        });

        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            let mut term_stream = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!("failed to install SIGTERM handler: {err}");
                    return;
                }
            };

            if term_stream.recv().await.is_some() {
                tracing::info!("received SIGTERM; initiating graceful shutdown");
                shutdown_clone.notify_waiters();
            }
        });
    }
}

fn reload_from_sources(state: &SharedAppState, config_path: Option<&Path>) -> Result<(), String> {
    let config = Config::load_from_sources(config_path).map_err(|e| e.to_string())?;
    AppState::reload_shared_from_config(state, config).map_err(|e| e.to_string())
}

fn log_startup(state: &AppState) {
    let cfg = &state.config;

    let http_bind = format!("{}:{}", cfg.proxy.bind_address, cfg.proxy.http_port);
    let https_bind = if cfg.proxy.https_port == 0 {
        "disabled".to_string()
    } else {
        format!("{}:{}", cfg.proxy.https_bind_address, cfg.proxy.https_port)
    };

    let certs = &cfg.certificates;
    let has_explicit_ca = certs
        .ca_key_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some()
        && certs
            .ca_cert_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some();

    let loop_cfg = &cfg.loop_protection;
    let capture_cfg = &cfg.capture;

    tracing::info!(
        target: "acl_proxy::startup",
        http_bind = %http_bind,
        https_bind = %https_bind,
        loop_protection_enabled = loop_cfg.enabled,
        loop_protection_add_header = loop_cfg.add_header,
        loop_protection_header = %loop_cfg.header_name,
        capture_allowed_request = capture_cfg.allowed_request,
        capture_allowed_response = capture_cfg.allowed_response,
        capture_denied_request = capture_cfg.denied_request,
        capture_denied_response = capture_cfg.denied_response,
        capture_directory = %capture_cfg.directory,
        http2_inbound_enabled = true,
        ca_mode = %if has_explicit_ca { "configured" } else { "generated" },
        ca_certs_dir = %certs.certs_dir,
        "acl-proxy starting"
    );
}
