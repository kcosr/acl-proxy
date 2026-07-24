#[cfg(target_os = "linux")]
use std::{env, path::PathBuf, process::ExitCode, sync::Arc, time::Instant};

#[cfg(target_os = "linux")]
use access_async_contracts::{AccessCancellation, BoxAccessFuture};
#[cfg(target_os = "linux")]
use access_flow_relay::{
    AccessFlowRelay, AccessFlowRelayEvent, AccessFlowRelayObserver, AccessFlowRelayResourceBudget,
};
#[cfg(target_os = "linux")]
use access_flow_unix::UnixAccessFlowConnector;
#[cfg(target_os = "linux")]
use acl_proxy_access_flow_relay::config::{
    relay_descriptor_budget, relay_memory_budget, Config, ValidatedConfig,
};
#[cfg(target_os = "linux")]
use tokio::sync::watch;

#[cfg(target_os = "linux")]
fn config_path() -> Result<PathBuf, &'static str> {
    let mut args = env::args_os();
    let _program = args.next();
    match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => Ok(path.into()),
        _ => Err("usage: acl-proxy-access-flow-relay --config <path>"),
    }
}

#[cfg(target_os = "linux")]
struct ProcessCancellation {
    sender: watch::Sender<bool>,
}

#[cfg(target_os = "linux")]
impl ProcessCancellation {
    fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    fn cancel(&self) {
        self.sender.send_replace(true);
    }
}

#[cfg(target_os = "linux")]
impl AccessCancellation for ProcessCancellation {
    fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    fn cancelled(&self) -> BoxAccessFuture<'_, ()> {
        let mut receiver = self.sender.subscribe();
        Box::pin(async move {
            loop {
                if *receiver.borrow() {
                    return;
                }
                if receiver.changed().await.is_err() {
                    return;
                }
            }
        })
    }
}

#[cfg(target_os = "linux")]
struct JsonObserver;

#[cfg(target_os = "linux")]
impl AccessFlowRelayObserver for JsonObserver {
    fn observe(&self, event: AccessFlowRelayEvent) {
        tracing::info!(
            event = ?event.kind,
            route = event.route.as_ref().map(|route| route.as_str()),
            destination_address = event.destination.map(|destination| destination.address().to_string()),
            destination_port = event.destination.map(|destination| destination.port().get()),
            close_category = ?event.close_category,
            duration_ms = event.duration.map(|duration| duration.as_millis() as u64),
            bytes_to_channel = event.bytes_to_channel,
            bytes_to_source = event.bytes_to_source,
            active_flows = event.active_flows,
            "Access Flow relay event"
        );
    }
}

#[cfg(target_os = "linux")]
async fn shutdown_signal() -> Result<(), String> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| format!("failed to install interrupt signal: {error}"))?;
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| format!("failed to install termination signal: {error}"))?;
    tokio::select! {
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(target_os = "linux")]
async fn run(validated: ValidatedConfig) -> Result<(), String> {
    // Signal resources are initialized before relay preparation and are covered
    // by the fixed consumer descriptor reserve.
    let signal = shutdown_signal();
    tokio::pin!(signal);

    let budget = AccessFlowRelayResourceBudget {
        descriptors: relay_descriptor_budget().map_err(|error| error.to_string())?,
        memory_bytes: relay_memory_budget(),
    };
    let relay = AccessFlowRelay::new(
        validated.plan,
        UnixAccessFlowConnector::new(),
        Arc::new(JsonObserver),
        budget,
    )
    .map_err(|error| error.to_string())?;
    let projection = relay.resource_projection();
    tracing::info!(
        relay_descriptors = projection.total_descriptors,
        relay_memory_bytes = projection.total_memory_bytes,
        "Access Flow relay resources validated"
    );

    let cancellation = Arc::new(ProcessCancellation::new());
    let prepared = tokio::select! {
        biased;
        result = &mut signal => {
            cancellation.cancel();
            result?;
            return Ok(());
        }
        result = relay.prepare(cancellation.clone()) => result.map_err(|error| error.to_string())?,
    };
    let mut running = tokio::select! {
        biased;
        result = &mut signal => {
            cancellation.cancel();
            result?;
            return Ok(());
        }
        result = prepared.activate() => result.map_err(|error| error.to_string())?,
    };

    let failure = tokio::select! {
        biased;
        result = &mut signal => {
            result?;
            None
        }
        failure = running.wait_for_failure() => Some(failure),
    };
    let drain_deadline = Instant::now()
        .checked_add(validated.drain_timeout)
        .ok_or_else(|| "Access Flow relay drain deadline overflowed".to_string())?;
    let shutdown = running
        .shutdown(drain_deadline)
        .await
        .map_err(|error| error.to_string())?;
    tracing::info!(
        drained = shutdown.drained,
        forced_flows = shutdown.forced_flows,
        "Access Flow relay stopped"
    );
    match failure {
        Some(failure) => Err(failure.to_string()),
        None => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn suppress_process_dumps() -> Result<(), String> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the initialized limit for this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(format!(
            "failed to disable core dumps: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: PR_SET_DUMPABLE with scalar zero has no pointer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!(
            "failed to disable process dumpability: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    if let Err(error) = suppress_process_dumps() {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .init();

    let result = config_path().map_err(String::from).and_then(|path| {
        let validated = Config::load(&path)
            .map_err(|error| error.to_string())?
            .validate()
            .map_err(|error| error.to_string())?;
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("failed to initialize runtime: {error}"))?
            .block_on(run(validated))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(category = "startup", error = %error, "Access Flow relay stopped");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("acl-proxy-access-flow-relay is supported only on Linux");
    std::process::ExitCode::FAILURE
}
