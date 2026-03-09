# Proxy modes

acl-proxy supports four request paths. All modes apply the same policy engine,
logging, capture, and header actions.

When `[proxy.egress.default]` is configured, allowed proxied requests from all
supported modes use the configured egress destination as the outbound TCP dial
target. Policy matching, capture metadata, and the forwarded `Host` header stay
bound to the original request target.

## HTTP listener (HTTP/1.1 explicit proxy + transparent HTTP)

- Listener: `proxy.bind_address:proxy.http_port`.
- Explicit-proxy clients send absolute-form requests (`GET http://host/path HTTP/1.1`).
- Transparent HTTP interception uses origin-form requests with `Host`
  (`GET /path HTTP/1.1`) after network redirection (for example, iptables
  `REDIRECT`/DNAT from port `80`).
- In transparent HTTP mode, upstream target selection is based on the inbound
  `Host` header (`:80` when no port is present). Use restrictive policy rules
  for the destinations you intend to allow.

Example:

```bash
curl -x http://127.0.0.1:8881 http://example.com/
```

Transparent HTTP example (local testing):

```bash
curl http://example.com/path \
  --connect-to example.com:80:127.0.0.1:8881
```

## HTTPS over CONNECT (MITM)

- CONNECT requests are accepted on the HTTP listener.
- The proxy terminates TLS inside the tunnel using a per-host certificate
  signed by its CA.
- Decrypted requests inside the tunnel are processed as HTTP/1.1.
- Policy is evaluated on each decrypted request; the CONNECT request itself is
  only used to establish the tunnel.
- Request-header predicates such as `headers_absent` apply only to the
  decrypted inner requests, not to the outer CONNECT establishment request.

Example:

```bash
curl -x http://127.0.0.1:8881 https://example.com/ \
  --proxy-cacert certs/ca-cert.pem
```

Notes:
- Clients must trust the proxy CA (`certs/ca-cert.pem` by default).
- Loop protection runs on both the CONNECT request and the inner requests.
- The outer CONNECT handshake remains local to the first proxy hop. If egress
  forwarding is enabled, only the decrypted inner HTTPS requests use the egress
  destination.

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
- HTTP/1.1 upgrade requests (for example, WebSocket) are tunneled after a
  successful `101 Switching Protocols` handshake.

## Chained proxy deployments

- The egress forwarding leg stays cleartext TCP to the configured
  `proxy.egress.default` host:port.
- Forwarding is protocol-aware per request: HTTP/2 requests use h2c on the
  inner-to-outer hop, while HTTP/1.1 and upgrade/WebSocket flows stay
  HTTP/1.1.
- If an HTTP/2 chain hop cannot be established, the request fails; there is no
  implicit downgrade for that request.
- The recommended egress target for another `acl-proxy` instance is that
  instance's HTTP listener.
- For loop protection across multiple hops, either use different loop-header
  names per hop or disable `loop_protection.add_header` on the inner proxy.
- See `docs/operations.md` for deployment warnings and recovery guidance.

## Upstream HTTP version

By default, acl-proxy uses HTTP/1.1 for upstream connections, even when
clients speak HTTP/2 to the proxy. To enable upstream HTTP/2, set:

```toml
[tls]
enable_http2_upstream = true
```

When enabled, ALPN is used per origin; the proxy will use HTTP/2 where
supported and fall back to HTTP/1.1 otherwise.

## WebSocket and Upgrade Traffic

- HTTP/1.1 upgrade handshakes are proxied on all HTTP/1.1 request paths
  (HTTP listener requests, HTTPS CONNECT inner requests, and transparent HTTPS
  when the client negotiates HTTP/1.1).
- After a `101 Switching Protocols` response, acl-proxy switches to a
  bidirectional byte tunnel between client and upstream.
- HTTP/2 extended CONNECT / RFC 8441 is not currently implemented.
