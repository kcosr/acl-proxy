# Proxy modes

acl-proxy supports three request paths. All modes apply the same policy engine,
logging, capture, and header actions.

## HTTP explicit proxy (HTTP/1.1)

- Listener: `proxy.bind_address:proxy.http_port`.
- Clients send absolute-form requests (`GET http://host/path HTTP/1.1`).
- Non-absolute-form requests are rejected with `400 Bad Request`.

Example:

```bash
curl -x http://127.0.0.1:8881 http://example.com/
```

## HTTPS over CONNECT (MITM)

- CONNECT requests are accepted on the HTTP explicit listener.
- The proxy terminates TLS inside the tunnel using a per-host certificate
  signed by its CA.
- Decrypted requests inside the tunnel are processed as HTTP/1.1.
- Policy is evaluated on each decrypted request; the CONNECT request itself is
  only used to establish the tunnel.

Example:

```bash
curl -x http://127.0.0.1:8881 https://example.com/ \
  --proxy-cacert certs/ca-cert.pem
```

Notes:
- Clients must trust the proxy CA (`certs/ca-cert.pem` by default).
- Loop protection runs on both the CONNECT request and the inner requests.

## Transparent HTTPS listener (TLS terminating)

- Listener: `proxy.https_bind_address:proxy.https_port` (set `https_port = 0`
  to disable).
- The proxy terminates TLS directly and routes to upstream HTTPS destinations.
- URL construction is based on the Host header or the request URI authority.

Example (local testing):

```bash
curl https://upstream.internal/resource \
  --connect-to upstream.internal:443:127.0.0.1:8889 \
  --cacert certs/ca-cert.pem
```

Notes:
- Clients must trust the proxy CA.
- Inbound HTTP/2 is supported on the transparent listener (ALPN `h2`).
- If the Host header is missing or invalid, the proxy returns `400 Bad Request`.

## Upstream HTTP version

By default, acl-proxy uses HTTP/1.1 for upstream connections, even when
clients speak HTTP/2 to the proxy. To enable upstream HTTP/2, set:

```toml
[tls]
enable_http2_upstream = true
```

When enabled, ALPN is used per origin; the proxy will use HTTP/2 where
supported and fall back to HTTP/1.1 otherwise.
