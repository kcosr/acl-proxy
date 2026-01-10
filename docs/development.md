# Development and testing

This project is a Rust crate with integration tests that exercise proxy
behavior across HTTP and HTTPS modes.

## Build

```bash
cargo build
```

## Tests

```bash
cargo test
```

The test suite includes:
- Unit tests for config parsing, policy expansion, logging, capture, and certs.
- Integration tests for HTTP explicit, HTTPS CONNECT MITM, and transparent HTTPS
  (HTTP/1.1 and HTTP/2).
- Reload behavior and loop protection coverage.

## Formatting and linting

```bash
cargo fmt
cargo clippy
```

## Release tooling

See `scripts/release.mjs` and `scripts/bump-version.mjs` for release automation.
