# Getting started

This guide walks through a minimal setup for running acl-proxy locally. For
full details, see the configuration reference and proxy mode docs.

## 1. Build or run

Build a release binary:

```bash
cargo build --release
```

Or run directly with Cargo:

```bash
cargo run -- --config config/acl-proxy.toml
```

## 2. Create a configuration

Generate a minimal config:

```bash
acl-proxy config init config/acl-proxy.toml
```

Or copy the sample and edit it:

```bash
mkdir -p config
cp acl-proxy.sample.toml config/acl-proxy.toml
```

The generated minimal config defaults to deny-all and disables capture.

## 3. Validate the configuration

```bash
acl-proxy config validate --config config/acl-proxy.toml
```

## 4. Run the proxy

```bash
acl-proxy --config config/acl-proxy.toml
```

The proxy starts:
- The HTTP explicit proxy listener on `proxy.bind_address:proxy.http_port`.
- The transparent HTTPS listener on `proxy.https_bind_address:proxy.https_port` if
  `https_port` is non-zero.

## 5. Send traffic

### HTTP explicit proxy (HTTP/1.1)

```bash
curl -x http://127.0.0.1:8881 http://example.com/
```

### HTTPS over CONNECT (MITM)

```bash
curl -x http://127.0.0.1:8881 https://example.com/ \
  --proxy-cacert certs/ca-cert.pem
```

The proxy generates a CA in `certs/` by default. Clients must trust the CA
certificate when using CONNECT or transparent HTTPS.

### Transparent HTTPS listener

```bash
curl https://upstream.internal/resource \
  --connect-to upstream.internal:443:127.0.0.1:8889 \
  --cacert certs/ca-cert.pem
```

Transparent mode terminates TLS on the proxy and forwards to the upstream
HTTPS destination. In production, you typically route outbound HTTPS traffic
through the proxy using a network rule or service mesh.

## Next steps

- See `docs/proxy-modes.md` for detailed client configuration and mode behavior.
- See `docs/configuration.md` and `docs/config-reference.md` for full config details.
