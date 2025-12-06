# Code Review Findings

This document captures potential bugs, design issues, and opportunities for improvement identified during a detailed code review of the acl-proxy codebase.

---

## Potential Bugs

### 1. IPv6 Subnet Support Missing

**Location:** `src/policy/mod.rs`

The subnet matching only supports IPv4:
```rust
pub subnets: Vec<Ipv4Net>  // Only IPv4
```

And in `client_in_any_subnet()`:
```rust
let v4 = match parsed {
    IpAddr::V4(v4) => v4,
    IpAddr::V6(_) => return false,  // IPv6 clients never match subnet rules
};
```

**Impact:** IPv6 clients silently fail to match any subnet rule. A rule with `subnets = ["10.0.0.0/8"]` will correctly match IPv4 clients, but if the same logical network has IPv6 addresses, those clients will fall through to the default action.

**Suggested Fix:** Support `Ipv6Net` as well, or at minimum log a warning when an IPv6 client is evaluated against subnet rules.

---

### 2. Race Condition in External Auth Status Worker

**Location:** `src/external_auth.rs`

In `ensure_status_worker()`, there's a subtle race:
```rust
if self
    .workers_started
    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
    .is_err()
{
    return;  // Another thread won the race
}

let rx_opt = {
    let mut guard = self.status_rx.lock().unwrap();
    guard.take()  // Takes the receiver
};

if let Some(rx) = rx_opt {
    // Spawns worker
}
```

**Impact:** If `ensure_status_worker()` is called concurrently, one thread wins the CAS but another could theoretically enter the lock region before the winner takes the receiver. In practice this is likely fine due to the CAS, but the separation between the atomic flag and the mutex-protected receiver is fragile.

**Suggested Fix:** Combine the flag and receiver into a single mutex-protected state, or use `Once` / `OnceCell` for initialization.

---

### 3. Missing Content-Length Update After Header Actions

**Location:** `src/proxy/http.rs`

When `replace_substring` modifies header values, if the `content-length` header is modified (e.g., replacing a value that happens to appear in the content-length), the actual body length won't match the header.

**Impact:** Could cause HTTP framing issues with strict clients/servers.

**Suggested Fix:** Either disallow `replace_substring` on `content-length`, or recalculate it after modifications (though the latter is complex for streaming bodies).

---

## Design Issues

### 1. Certificate Cache Unbounded Growth

**Location:** `src/certs/mod.rs`

```rust
server_configs: Mutex<HashMap<String, Arc<ServerConfig>>>
```

This cache grows indefinitely. Each unique hostname gets a cached entry.

**Impact:** If the proxy handles requests to many unique hostnames (e.g., a CDN or API gateway scenario), memory usage will grow without bound.

**Suggested Fix:** Implement an LRU cache with a configurable maximum size. The `lru` or `moka` crates would work well here.

---

### 2. Blocking File I/O in Async Context

**Location:** `src/capture/mod.rs`, `src/certs/mod.rs`

In `write_capture_record()`:
```rust
pub fn write_capture_record(...) -> Result<PathBuf, CaptureError> {
    // ...
    fs::write(&path, format!("{json}\n"))  // Blocking!
}
```

This is called from async request handlers via `tokio::spawn`, but the spawned task still uses blocking I/O.

Similarly, certificate generation in `certs/mod.rs` writes files synchronously.

**Impact:** Under high capture volume or many TLS handshakes to new hosts, blocking I/O could starve the Tokio runtime's worker threads.

**Suggested Fix:** Use `tokio::fs::write()` or `tokio::task::spawn_blocking()` for file operations.

---

### 3. No Connection Pooling Limits

**Location:** `src/app.rs`

The HTTP client is built without connection pool limits:
```rust
Client::builder().build::<_, hyper::Body>(https)
```

**Impact:** Under high load to many backends, this could exhaust file descriptors or memory. Each unique (host, port) combination can accumulate idle connections.

**Suggested Fix:** Configure pool limits:
```rust
Client::builder()
    .pool_max_idle_per_host(10)
    .pool_idle_timeout(Duration::from_secs(30))
    .build(https)
```

---

### 4. Status Webhook Queue Silently Drops Events

**Location:** `src/external_auth.rs`

```rust
if let Err(err) = self.status_tx.try_send(event) {
    match err {
        mpsc::error::TrySendError::Full(_) => {
            tracing::debug!("...queue full; dropping event");  // Only debug level!
        }
```

**Impact:** Dropping terminal status webhooks means the external auth system won't know the final outcome of a request. This should be more visible.

**Suggested Fix:** Log at `warn` level, and consider adding a metric for dropped events.

---

### 5. Pattern Regex Recompilation per Rule

**Location:** `src/policy/mod.rs`

Each `CompiledRule` stores its own `Regex`. For policies with many rules, evaluation iterates through all rules until a match is found.

**Impact:** For large rule sets (hundreds of rules), this linear scan with individual regex matches may become a performance bottleneck.

**Suggested Fix:** Consider using `RegexSet` for an initial quick-reject pass, then only evaluate the full rule logic for potential matches.

---

## Opportunities for Improvement

### 1. HTTP/2 Downstream Support is Partial

**Location:** `src/proxy/https_transparent.rs`

The HTTPS transparent listener advertises `h2` via ALPN:
```rust
config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
```

But the request handling uses:
```rust
Http::new()
    .http1_keep_alive(true)
    .serve_connection(tls, service)
```

**Impact:** If a client negotiates HTTP/2, the behavior is unclear. Hyper may handle it, but this should be explicitly configured with `.http2_only(false)` or similar to be clear about intent.

**Suggested Fix:** Either remove `h2` from ALPN, or explicitly enable HTTP/2 handling with `Http::new().http1_only(false)`.

---

### 2. No Request Timeout

**Location:** `src/proxy/http.rs`

There's no global timeout for proxied requests.

**Impact:** A slow or unresponsive upstream could hold proxy connections indefinitely, eventually exhausting resources.

**Suggested Fix:** Add a configurable request timeout:
```rust
tokio::time::timeout(Duration::from_secs(30), client_http.request(req)).await
```

---

### 3. Capture Body Tee Allocation Overhead

**Location:** `src/proxy/http.rs`

The `tee_body()` function creates a channel-based stream:
```rust
let (tx, rx) = mpsc::channel::<Result<Bytes, hyper::Error>>(16);
```

**Impact:** This adds allocation and synchronization overhead when capture is enabled.

**Suggested Fix:** Since `Bytes` uses reference counting internally, a simpler approach might be to clone the `Bytes` directly without the channel indirection, using a `Vec<Bytes>` collector.

---

### 4. No Metrics/Observability

**Location:** Throughout codebase

There are no Prometheus metrics, OpenTelemetry traces, or similar observability features.

**Impact:** Operating the proxy in production without visibility into:
- Requests per second (by decision: allow/deny)
- Latency histograms (p50, p95, p99)
- Active connections
- Certificate cache size/hit rate
- External auth queue depth
- Policy evaluation time

**Suggested Fix:** Add a `/metrics` endpoint with Prometheus-format metrics using the `metrics` or `prometheus` crate.

---

### 5. Policy Hot Reload Compiles Regex Twice

**Location:** `src/config/mod.rs`, `src/app.rs`

On SIGHUP or config validation:
1. `validate_basic()` calls `PolicyEngine::from_config()` to validate
2. `AppState::from_config()` calls `PolicyEngine::from_config()` again

**Impact:** Regex compilation happens twice, which is wasteful for large policies.

**Suggested Fix:** Have validation return the built `PolicyEngine` so it can be reused, or use a two-phase approach where validation is cheap and compilation happens once.

---

### 6. No Graceful Drain on Shutdown

**Location:** `src/cli/mod.rs`

The shutdown logic stops accepting new connections but doesn't signal a drain period:
```rust
shutdown_clone.notify_waiters();
```

**Impact:** Load balancers in front of the proxy may continue sending traffic during shutdown. There's no way to signal "draining" status.

**Suggested Fix:** 
- Add a configurable drain period
- Optionally expose a `/health` endpoint that returns 503 during drain
- Consider supporting drain via a separate signal (e.g., SIGUSR1 to start drain, SIGTERM to hard stop)

---

### 7. External Auth Callback Endpoint Not Configurable

**Location:** `src/proxy/http.rs`

The callback path is hardcoded:
```rust
fn is_external_auth_callback_path(path: &str) -> bool {
    path == "/_acl-proxy/external-auth/callback"
}
```

**Impact:** If running behind a reverse proxy that uses that path prefix, or if the path conflicts with application routes, there's no way to change it.

**Suggested Fix:** Make the callback path configurable in `PolicyConfig` or a new `ExternalAuthConfig` section.

---

### 8. No Rate Limiting

**Location:** N/A (not implemented)

There's no built-in rate limiting capability.

**Impact:** The proxy cannot protect upstream services from request floods, even if policy allows the traffic.

**Suggested Fix:** Consider adding optional per-rule or global rate limiting using a token bucket or sliding window algorithm.

---

### 9. Capture Filename Collision Risk

**Location:** `src/capture/mod.rs`

Request IDs are generated with millisecond timestamps and a counter:
```rust
format!("req-{}-{}", ts, seq)
```

If the process restarts, the counter resets to 1, and if it happens within the same millisecond, filenames could collide.

**Impact:** Capture files could be overwritten on process restart.

**Suggested Fix:** Include a random component or process-unique identifier in the request ID.

---

## Summary

| Category | Count |
|----------|-------|
| Potential Bugs | 3 |
| Design Issues | 5 |
| Improvement Opportunities | 9 |

Priority recommendations:
1. **High:** Fix blocking I/O in async context (#2 Design Issue)
2. **High:** Add request timeout (#2 Improvement)
3. **Medium:** Add certificate cache eviction (#1 Design Issue)
4. **Medium:** Add IPv6 subnet support (#1 Bug)
5. **Medium:** Add basic metrics (#4 Improvement)
