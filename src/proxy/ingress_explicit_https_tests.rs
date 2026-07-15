use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use hyper::body::to_bytes;
use hyper::client::conn;
use hyper::{Body, Request, StatusCode, Version};
use rcgen::{CertificateParams, KeyPair};
use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use super::*;
use crate::activation::runner::ProductRuntime;
use crate::config::load_and_compile_exact_config;

fn prebound_listener() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    (address, listener)
}

async fn start_product(config: String, listener: StdTcpListener) -> (TempDir, Arc<ProductRuntime>) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let product = ProductRuntime::prepare_from_prebound(loaded, vec![listener])
        .await
        .unwrap();
    product.activate_initial().await.unwrap();
    let mut starter = ProductProxySupervisorStarter::new(
        product.runtime().clone(),
        product.observation_runtime().clone(),
        product.upgrade_runtime(),
    );
    product.start_proxy_supervisors(&mut starter).await.unwrap();
    (directory, product)
}

fn strict_config(
    listener: SocketAddr,
    listener_version: &str,
    origin: SocketAddr,
    identity: &TempDir,
) -> String {
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_https]
bind = "{listener}"
http_versions = ["{listener_version}"]

[listeners.explicit_https.connect]
{listener_version} = "deny"

[listeners.explicit_https.tls]
certificate_chain = "{}"
private_key = "{}"

[egress]
route = "direct"

[egress.origin_tls]
trust = "system"
http_versions = ["http1"]

[safety.loop_detection]
inject = true
header = "x-test-loop"

[policy]
default = "deny"

[[policy.rules]]
id = "explicit-https-ordinary-{listener_version}"
decision = "allow"
urls = ["http://{origin}/**"]
methods = ["GET"]
"#,
        identity.path().join("server.pem").display(),
        identity.path().join("server-key.pem").display(),
    )
}

fn test_tls_identity() -> (TempDir, Vec<u8>) {
    let directory = tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    fs::write(directory.path().join("server.pem"), certificate.pem()).unwrap();
    fs::write(directory.path().join("server-key.pem"), key.serialize_pem()).unwrap();
    (directory, certificate.der().to_vec())
}

fn test_tls_connector(certificate: Vec<u8>, alpn: &[u8]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(&Certificate(certificate)).unwrap();
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    TlsConnector::from(Arc::new(config))
}

async fn read_http_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut byte),
        )
        .await
        .expect("origin request head timed out")
        .expect("origin request head ended early");
        head.push(byte[0]);
        assert!(
            head.len() <= 32 * 1024,
            "origin request head exceeded bound"
        );
    }
    head
}

#[tokio::test]
async fn explicit_https_ordinary_forwarding_succeeds_over_http1_and_http2() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    for (listener_version, alpn, expected_version) in [
        ("http1", b"http/1.1".as_slice(), Version::HTTP_11),
        ("http2", b"h2".as_slice(), Version::HTTP_2),
    ] {
        let (proxy, listener) = prebound_listener();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let head = read_http_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\nConnection: close\r\n\r\nexplicit https accepted",
                )
                .await
                .unwrap();
            head
        });

        let (identity, certificate) = test_tls_identity();
        let config = strict_config(proxy, listener_version, origin, &identity);
        let (_directory, product) = start_product(config, listener).await;

        let connector = test_tls_connector(certificate, alpn);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(alpn),
            "{listener_version}"
        );
        let mut builder = conn::Builder::new();
        if expected_version == Version::HTTP_2 {
            builder.http2_only(true);
        }
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .method(http::Method::GET)
                    .version(expected_version)
                    .uri(format!(
                        "http://{origin}/ordinary?ingress={listener_version}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), expected_version, "{listener_version}");
        assert_eq!(response.status(), StatusCode::OK, "{listener_version}");
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "explicit https accepted",
            "{listener_version}"
        );

        let origin_head = String::from_utf8(origin_task.await.unwrap()).unwrap();
        let origin_head = origin_head.to_ascii_lowercase();
        assert!(
            origin_head.starts_with(&format!(
                "get /ordinary?ingress={listener_version} http/1.1\r\n"
            )),
            "unexpected {listener_version} origin request: {origin_head}"
        );
        assert!(
            origin_head.contains(&format!("\r\nhost: {origin}\r\n")),
            "missing canonical {listener_version} origin host: {origin_head}"
        );

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }
}
