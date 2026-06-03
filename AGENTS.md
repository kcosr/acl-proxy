# Repository Conventions (acl-proxy)

## What This Repo Is

`acl-proxy` is a Rust-based ACL-aware HTTP/HTTPS proxy with a TOML configuration file and a flexible URL policy engine. It supports explicit HTTP proxying, transparent HTTP interception, HTTPS CONNECT MITM, and transparent HTTPS termination with HTTP/2.

## Fast Bootstrap

1. Build: `cargo build`
2. Format: `cargo fmt`
3. Lint: `cargo clippy`
4. Test: `cargo test`
5. Release build: `cargo build --release`
6. Run: `cargo run -- --config config/acl-proxy.toml`

## Source Map (Start Here)

- `src/main.rs` — Entry point, delegates to CLI.
- `src/cli/mod.rs` — CLI parsing, config validate/init, policy dump.
- `src/config/mod.rs` — Configuration structs, TOML loading, validation, env overrides.
- `src/policy/mod.rs` — Policy engine: rule compilation, pattern matching, macro/ruleset expansion.
- `src/app.rs` — `AppState` and shared state management (`ArcSwap`).
- `src/proxy/http.rs` — HTTP listener (explicit proxy + transparent HTTP interception).
- `src/proxy/https_connect.rs` — HTTPS CONNECT MITM handler.
- `src/proxy/https_transparent.rs` — Transparent HTTPS listener (HTTP/1.1 + HTTP/2).
- `src/external_auth.rs` — External auth webhooks, callbacks, approval lifecycle.
- `src/auth_plugin.rs` — Stdio plugin lifecycle management.
- `src/capture/mod.rs` — Request/response capture to JSON files.
- `src/certs/mod.rs` — CA and per-host certificate generation and caching.
- `src/logging/mod.rs` — Structured logging with file rotation.
- `src/loop_protection/mod.rs` — Loop detection and header injection.
- `src/bin/extract-capture-body.rs` — Helper CLI to decode captured bodies.

## Working Rules

1. Tests must be deterministic and offline — no network calls, no flaky timing.
2. For any new feature or behavior change, add or update tests and run `cargo test`.
3. For any new feature or behavior change, update `README.md` (the single source of user-facing docs).
4. Always run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release` before committing.
5. Keep `docs/design/` and `docs/implementation/` for internal design records only — user-facing docs live in `README.md`.

## Commands You'll Use Often

- Build: `cargo build`
- Test: `cargo test`
- Lint: `cargo clippy`
- Format: `cargo fmt`
- Validate config: `cargo run -- config validate --config config/acl-proxy.toml`
- Dump policy: `cargo run -- policy dump --config config/acl-proxy.toml`
- Release build: `cargo build --release`

## Changelog

Location: `CHANGELOG.md` (root)

### Format

Use these sections under `## [Unreleased]`:
- `### Breaking Changes` - API changes requiring migration
- `### Added` - New features
- `### Changed` - Changes to existing functionality
- `### Fixed` - Bug fixes
- `### Removed` - Removed features

### Rules

- New entries ALWAYS go under `## [Unreleased]`
- Append to existing subsections (e.g., `### Fixed`), do not create duplicates
- NEVER modify already-released version sections (e.g., `## [0.0.3]`)
- Use inline PR links: `([#123](https://github.com/kcosr/acl-proxy/pull/123))`

### Attribution

- Internal changes: `Fixed foo bar ([#123](https://github.com/kcosr/acl-proxy/pull/123))`
- External contributions: `Added feature X ([#456](https://github.com/kcosr/acl-proxy/pull/456) by [@user](https://github.com/user))`

## Releasing

### During Development

When preparing PRs for main, open the PR first to get the PR number, then update `CHANGELOG.md` under `## [Unreleased]` with that PR number and push a follow-up commit.

### When Ready to Release

1. Checkout and update main:
   ```bash
   git checkout main && git pull
   ```
2. Verify `## [Unreleased]` in CHANGELOG.md has all changes documented
3. Run the release script:
   ```bash
   node scripts/release.mjs current  # Release current Cargo.toml version
   node scripts/release.mjs patch    # Bug fixes (0.0.3 -> 0.0.4)
   node scripts/release.mjs minor    # New features (0.0.4 -> 0.1.0)
   node scripts/release.mjs major    # Breaking changes (0.1.0 -> 1.0.0)
   node scripts/release.mjs 0.1.0    # Explicit version
   ```

### What the Script Does

1. Verifies the current branch is `main`, the working tree is clean, required tools are available, GitHub CLI is authenticated, and the local/remote tag is free
2. Verifies the Rust project with `cargo check` and optionally bumps version in `Cargo.toml` (and `Cargo.lock`)
3. Updates CHANGELOG: `## [Unreleased]` -> `## [X.Y.Z] - YYYY-MM-DD`
4. Commits "Release vX.Y.Z" and creates git tag
5. Pushes commit and tag atomically to origin
6. Creates GitHub release with notes extracted from CHANGELOG
7. Adds new `## [Unreleased]` section with `_No unreleased changes._` placeholder
8. Commits "Prepare for next release" and pushes

If GitHub release creation fails after the commit and tag are pushed, create
the GitHub release manually for the existing tag instead of rerunning the
script. Then add a fresh `## [Unreleased]` section with the standard
`_No unreleased changes._` placeholder, commit it as
`Prepare for next release`, and push `main`.

Release archives are packaged separately after the GitHub release exists. Use
the README release section as the source of truth for archive names and
contents. The supported release platform is currently `linux-x86_64`, with
`bin/acl-proxy` and `bin/acl-proxy-extract-capture-body` in the archive.
