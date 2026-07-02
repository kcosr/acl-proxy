use std::io::{Error, ErrorKind};
use std::time::Duration;

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
