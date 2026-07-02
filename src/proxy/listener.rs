use std::io::{Error, ErrorKind};
use std::time::Duration;

use tokio::task::{JoinError, JoinSet};

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

pub async fn handle_accept_error(listener: &str, err: Error) {
    match err.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock => {
            tracing::debug!(
                listener,
                error = %err,
                "recoverable listener accept error"
            );
            tokio::task::yield_now().await;
        }
        _ => {
            tracing::warn!(
                listener,
                error = %err,
                backoff_ms = ACCEPT_ERROR_BACKOFF.as_millis(),
                "listener accept error; backing off before retry"
            );
            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
        }
    }
}

pub fn connection_shutdown_channel() -> (
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
) {
    tokio::sync::watch::channel(false)
}

pub fn signal_connection_shutdown(shutdown: &tokio::sync::watch::Sender<bool>) {
    let _ = shutdown.send(true);
}

pub async fn wait_for_connection_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

pub fn log_connection_task_result(listener: &str, result: Result<(), JoinError>) {
    if let Err(err) = result {
        tracing::debug!(listener, "listener connection task failed: {err}");
    }
}

pub async fn drain_connections(
    listener: &str,
    connections: &mut JoinSet<()>,
    timeout: Option<Duration>,
) {
    let drain = async {
        while let Some(join_result) = connections.join_next().await {
            log_connection_task_result(listener, join_result);
        }
    };

    let Some(timeout) = timeout else {
        drain.await;
        return;
    };

    if tokio::time::timeout(timeout, drain).await.is_ok() {
        return;
    }

    let remaining = connections.len();
    tracing::warn!(
        listener,
        remaining_connections = remaining,
        timeout_ms = timeout.as_millis(),
        "timed out draining listener connections; aborting remaining tasks"
    );
    connections.abort_all();
    while let Some(join_result) = connections.join_next().await {
        log_connection_task_result(listener, join_result);
    }
}
