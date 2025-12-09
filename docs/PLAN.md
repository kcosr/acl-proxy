goal_id: acl-proxy-mcp-suite-mvp-2025
lane: B
scope:
  - acl-proxy.sample.toml: add mcp-gateway preset and evidence logging example
  - src/config/mod.rs, src/logging/mod.rs: evidence logging config + JSONL writer
  - README.md: usage with mcp-gateway and evidence option
out_of_scope:
  - core proxy behavior changes (MITM/TLS/HTTP2)
  - non-MCP presets or rule rewrites
tests:
  - cargo fmt
  - cargo clippy --all-targets --all-features
  - cargo test
  - cargo build --release
