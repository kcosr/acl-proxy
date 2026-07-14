use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::authorization::webhook::runtime::WebhookAuthorizationRuntime;
use crate::config::compiler::StaticControlConfig;
use crate::http1::framing::BodyFraming;
use crate::http1::head::{parse_request_head, HeadParse, RequestHead};
use crate::runtime::ServiceReadiness;

use super::admission::ControlConnectionLease;
use super::callback::handle_callback_entity;
use super::response::ControlResponse;
use super::router::{ControlRoute, ControlRouter};
use super::wire::write_control_response;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlConnectionSignal {
    Running,
    CloseAfterRequest,
    Abort,
}

pub(crate) struct ControlConnectionContext<'a> {
    pub(crate) router: &'a ControlRouter,
    pub(crate) authorization: &'a WebhookAuthorizationRuntime,
    pub(crate) readiness: &'a ServiceReadiness,
    pub(crate) config: &'a StaticControlConfig,
    pub(crate) shutdown: &'a mut watch::Receiver<ControlConnectionSignal>,
}

/// Serves one admitted control connection without spawning work.
/// Dropping the consumed lease wipes and returns its parser store atomically
/// with the connection slot on every exit.
pub(crate) async fn serve_control_connection<S>(
    mut stream: S,
    mut lease: ControlConnectionLease,
    first_header_deadline: Instant,
    context: ControlConnectionContext<'_>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header_deadline = first_header_deadline;
    loop {
        let Some(head) =
            read_request_head(&mut stream, &mut lease, header_deadline, context.shutdown).await?
        else {
            return Ok(());
        };

        // The control protocol never emits an interim response. Closing here
        // avoids waiting on a caller that withheld its entity for 100 Continue.
        if head.expect_present {
            return Ok(());
        }

        let client_closes = head.connection_close;
        let body_deadline = Instant::now() + context.config.request_body_timeout;
        let outcome = match context.router.classify(&head) {
            ControlRoute::Callback => {
                let outcome = handle_callback_entity(
                    &mut stream,
                    lease.parser_store_mut(),
                    head.framing,
                    context.authorization,
                    context.config.max_request_body_bytes,
                    body_deadline,
                )
                .await;
                RequestOutcome {
                    response: outcome.response(),
                    reusable: outcome.connection_reusable(),
                }
            }
            ControlRoute::Readiness => RequestOutcome {
                response: Some(ControlResponse::readiness(context.readiness.is_ready())),
                reusable: matches!(
                    head.framing,
                    BodyFraming::None | BodyFraming::ContentLength(0)
                ),
            },
            ControlRoute::Respond(response) => RequestOutcome {
                response: Some(response),
                reusable: false,
            },
        };

        let reusable = prepare_parser_store_for_response(
            &mut lease,
            outcome.reusable,
            client_closes || connection_should_close(context.shutdown),
        );
        if let Some(response) = outcome.response {
            write_control_response(&mut stream, response, !reusable).await?;
        } else {
            return Ok(());
        }
        if !reusable {
            return Ok(());
        }
        header_deadline = Instant::now() + context.config.request_header_timeout;
    }
}

fn prepare_parser_store_for_response(
    lease: &mut ControlConnectionLease,
    application_reusable: bool,
    client_closes: bool,
) -> bool {
    let reusable =
        application_reusable && !client_closes && lease.parser_store().initialized_len() == 0;
    if reusable {
        return lease.prepare_for_next_request().is_ok();
    }

    // Immediate outcomes intentionally abandon unread framing, but no request
    // or pipeline bytes survive while their response is sent.
    lease.parser_store_mut().wipe();
    false
}

async fn read_request_head<S>(
    stream: &mut S,
    lease: &mut ControlConnectionLease,
    deadline: Instant,
    shutdown: &mut watch::Receiver<ControlConnectionSignal>,
) -> io::Result<Option<RequestHead>>
where
    S: AsyncRead + Unpin,
{
    loop {
        match parse_request_head(lease.parser_store_mut()) {
            Ok(HeadParse::Complete(head)) => return Ok(Some(head)),
            Ok(HeadParse::Incomplete) => {}
            Err(_) => return Ok(None),
        }

        let store = lease.parser_store_mut();
        if store.writable().is_empty() {
            return Ok(None);
        }
        let idle = store.initialized_len() == 0;
        let reading = tokio::time::timeout_at(deadline, stream.read(store.writable()));
        tokio::pin!(reading);
        let read = match if idle {
            tokio::select! {
                biased;
                result = &mut reading => result,
                _ = wait_for_connection_close(shutdown) => return Ok(None),
            }
        } else {
            reading.await
        } {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };
        if read == 0 {
            return Ok(None);
        }
        if store.commit_written(read).is_err() {
            return Ok(None);
        }
    }
}

fn connection_should_close(shutdown: &watch::Receiver<ControlConnectionSignal>) -> bool {
    *shutdown.borrow() != ControlConnectionSignal::Running
}

async fn wait_for_connection_close(shutdown: &mut watch::Receiver<ControlConnectionSignal>) {
    if connection_should_close(shutdown) {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if connection_should_close(shutdown) {
            return;
        }
    }
}

struct RequestOutcome {
    response: Option<ControlResponse>,
    reusable: bool,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::control::admission::ControlParserArena;

    fn config(header_timeout: Duration, body_timeout: Duration) -> StaticControlConfig {
        StaticControlConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8898),
            base_path: "/_acl-proxy".to_owned(),
            request_header_timeout: header_timeout,
            request_body_timeout: body_timeout,
            max_connections: 1,
            parser_arena_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            tls: None,
        }
    }

    fn start_server(
        server: DuplexStream,
        config: StaticControlConfig,
    ) -> tokio::task::JoinHandle<io::Result<()>> {
        let (shutdown, shutdown_rx) = watch::channel(ControlConnectionSignal::Running);
        tokio::spawn(async move {
            let _shutdown = shutdown;
            run_server(server, config, shutdown_rx).await
        })
    }

    fn start_server_with_shutdown(
        server: DuplexStream,
        config: StaticControlConfig,
    ) -> (
        tokio::task::JoinHandle<io::Result<()>>,
        watch::Sender<ControlConnectionSignal>,
    ) {
        let (shutdown, shutdown_rx) = watch::channel(ControlConnectionSignal::Running);
        (
            tokio::spawn(run_server(server, config, shutdown_rx)),
            shutdown,
        )
    }

    async fn run_server(
        server: DuplexStream,
        config: StaticControlConfig,
        mut shutdown: watch::Receiver<ControlConnectionSignal>,
    ) -> io::Result<()> {
        let arena = ControlParserArena::try_new(1).unwrap();
        let lease = arena.try_acquire().unwrap();
        let router = ControlRouter::try_new(&config.base_path).unwrap();
        let runtime = WebhookAuthorizationRuntime::for_test(None);
        let readiness = ServiceReadiness::new();
        let first_header_deadline = Instant::now() + config.request_header_timeout;
        serve_control_connection(
            server,
            lease,
            first_header_deadline,
            ControlConnectionContext {
                router: &router,
                authorization: &runtime,
                readiness: &readiness,
                config: &config,
                shutdown: &mut shutdown,
            },
        )
        .await
    }

    async fn read_response(client: &mut DuplexStream) -> Vec<u8> {
        let mut response = Vec::new();
        let head_end = loop {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break response.len();
            }
        };
        let head = std::str::from_utf8(&response[..head_end]).unwrap();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let current = response.len();
        response.resize(current + length, 0);
        client.read_exact(&mut response[current..]).await.unwrap();
        response
    }

    #[tokio::test]
    async fn readiness_keep_alive_reuses_only_after_a_clean_request() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = start_server(
            server,
            config(Duration::from_secs(1), Duration::from_secs(1)),
        );

        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let first = read_response(&mut client).await;
        assert_eq!(
            first,
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 22\r\nCache-Control: no-store\r\nContent-Type: application/json\r\n\r\n{\"status\":\"not_ready\"}"
        );

        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let second = read_response(&mut client).await;
        assert!(second
            .windows(b"Connection: close".len())
            .any(|window| window == b"Connection: close"));
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn graceful_close_ends_an_idle_keep_alive_without_another_request() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (task, shutdown) = start_server_with_shutdown(
            server,
            config(Duration::from_secs(30), Duration::from_secs(1)),
        );

        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;
        assert!(!response
            .windows(b"Connection: close".len())
            .any(|window| window == b"Connection: close"));

        shutdown
            .send(ControlConnectionSignal::CloseAfterRequest)
            .unwrap();
        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut trailing))
            .await
            .expect("an idle keep-alive must close promptly")
            .unwrap();
        assert!(trailing.is_empty());
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn graceful_close_serves_one_request_that_is_already_readable() {
        let (mut client, server) = tokio::io::duplex(4096);
        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let (shutdown, shutdown_rx) = watch::channel(ControlConnectionSignal::Running);
        shutdown
            .send(ControlConnectionSignal::CloseAfterRequest)
            .unwrap();
        let task = tokio::spawn(run_server(
            server,
            config(Duration::from_secs(1), Duration::from_secs(1)),
            shutdown_rx,
        ));

        let response = read_response(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(response
            .windows(b"Connection: close".len())
            .any(|window| window == b"Connection: close"));
        let mut trailing = Vec::new();
        client.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn buffered_pipeline_gets_one_response_and_closes() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = start_server(
            server,
            config(Duration::from_secs(1), Duration::from_secs(1)),
        );
        client
            .write_all(
                b"GET /_acl-proxy/ready HTTP/1.1\r\n\r\nGET /_acl-proxy/ready HTTP/1.1\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_response(&mut client).await;
        assert!(response
            .windows(b"Connection: close".len())
            .any(|window| window == b"Connection: close"));
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert!(task.await.unwrap().is_ok());
    }

    #[test]
    fn parser_store_is_fully_wiped_before_reusable_and_terminal_responses() {
        let arena = ControlParserArena::try_new(1).unwrap();
        let mut lease = arena.try_acquire().unwrap();
        lease.parser_store_mut().writable().fill(0xa5);
        assert!(prepare_parser_store_for_response(&mut lease, true, false));
        assert!(lease
            .parser_store()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));

        lease
            .parser_store_mut()
            .append(b"secret callback residue")
            .unwrap();
        assert!(!prepare_parser_store_for_response(&mut lease, false, false));
        assert_eq!(lease.parser_store().initialized_len(), 0);
        assert!(lease
            .parser_store()
            .complete_storage()
            .iter()
            .all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn header_deadline_is_absolute_across_partial_reads() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = start_server(
            server,
            config(Duration::from_millis(500), Duration::from_secs(1)),
        );
        client.write_all(b"GET /_acl").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        client
            .write_all(b"-proxy/ready HTTP/1.1\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_millis(300),
            client.read_to_end(&mut response),
        )
        .await
        .expect("absolute header deadline must not reset after a partial read")
        .unwrap();
        assert!(response.is_empty());
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn callback_body_deadline_starts_when_the_head_completes() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = start_server(
            server,
            config(Duration::from_secs(1), Duration::from_millis(500)),
        );
        client
            .write_all(b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 97\r\n\r\n{\"resumeToken\":\"")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        client.write_all(b"AAAAAAAAAA").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_millis(300),
            client.read_to_end(&mut response),
        )
        .await
        .expect("absolute body deadline must not reset after a partial read")
        .unwrap();
        assert!(response.is_empty());
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn callback_early_outcome_closes_unread_framing() {
        let cases: &[(&[u8], &[u8])] = &[
            (
                b"GET /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nignored",
                b"HTTP/1.1 405 Method Not Allowed",
            ),
            (
                b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nignored",
                b"HTTP/1.1 415 Unsupported Media Type",
            ),
            (
                b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\nignored",
                b"HTTP/1.1 413 Payload Too Large",
            ),
            (
                b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 97\r\n\r\n{\"resumeToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",",
                b"HTTP/1.1 404 Not Found",
            ),
        ];

        for (request, status) in cases {
            let (mut client, server) = tokio::io::duplex(4096);
            let task = start_server(
                server,
                config(Duration::from_secs(1), Duration::from_secs(1)),
            );
            client.write_all(request).await.unwrap();
            let response = read_response(&mut client).await;
            assert!(response.starts_with(status), "{response:?}");
            assert!(response
                .windows(b"Connection: close".len())
                .any(|window| window == b"Connection: close"));
            drop(client);
            assert!(task.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn malformed_head_and_expect_close_without_a_response() {
        for request in [
            b"GET /_acl-proxy/ready HTTP/1.0\r\n\r\n".as_slice(),
            b"GET /_acl-proxy/ready HTTP/1.1\r\nExpect: 100-continue\r\n\r\n".as_slice(),
        ] {
            let (mut client, server) = tokio::io::duplex(4096);
            let task = start_server(
                server,
                config(Duration::from_secs(1), Duration::from_secs(1)),
            );
            client.write_all(request).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
            assert!(task.await.unwrap().is_ok());
        }
    }
}
