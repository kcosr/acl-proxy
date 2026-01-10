# TLS and certificates

acl-proxy acts as a TLS man-in-the-middle for CONNECT and transparent HTTPS
modes. It issues per-host certificates signed by a local CA.

## CA behavior

- Default CA paths (when not explicitly configured):
  - `certs/ca-key.pem`
  - `certs/ca-cert.pem`
- If these files exist and are valid, they are reused.
- If they are missing or invalid, a new CA is generated and written.

If you set `certificates.ca_key_path` and `certificates.ca_cert_path`, both
must be present and valid. Explicit paths are treated as authoritative; missing
or invalid files cause startup and reload failures.

## Per-host certificates

Per-host certificates are generated on demand and cached in memory. The proxy
also writes PEM files to disk for transparency and debugging:

- `certs/dynamic/<host>.crt`
- `certs/dynamic/<host>.key`
- `certs/dynamic/<host>-chain.crt`

The on-disk files are not reloaded on startup. The proxy regenerates per-host
certificates from the CA as needed.

## Cache sizing

`certificates.max_cached_certs` controls the size of the in-memory LRU caches
used for per-host TLS configs and SNI resolution. The value must be at least 1.

## Client trust

Clients must trust the proxy CA to avoid TLS errors:

- CONNECT MITM: pass `--proxy-cacert certs/ca-cert.pem` or import the CA.
- Transparent HTTPS: pass `--cacert certs/ca-cert.pem` or import the CA.

Plain HTTP proxy traffic does not require CA trust.

## Upstream TLS verification

Outgoing TLS from the proxy to upstream servers is controlled by:

```toml
[tls]
verify_upstream = true
```

Set `verify_upstream = false` only in controlled test environments.
