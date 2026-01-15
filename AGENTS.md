## Development guidelines

- For any new feature or behavior change, add or update tests and run `cargo test` before opening a PR (once the Rust project exists); tests must be deterministic and offline.
- For any new feature or behavior change, update documentation appropriately. See docs and README.md.
- If you are making code changes, acting as the implementor and not the reviewer, spawn a claude session and ask it to review after opening a PR.
- When updating Rust code in this project, always run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release` before committing and pushing.

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
   node scripts/release.mjs patch    # Bug fixes (0.0.3 -> 0.0.4)
   node scripts/release.mjs minor    # New features (0.0.4 -> 0.1.0)
   node scripts/release.mjs major    # Breaking changes (0.1.0 -> 1.0.0)
   ```

### What the Script Does

1. Verifies working directory is clean (no uncommitted changes)
2. Bumps version in `Cargo.toml` (and `Cargo.lock`)
3. Updates CHANGELOG: `## [Unreleased]` -> `## [X.Y.Z] - YYYY-MM-DD`
4. Commits "Release vX.Y.Z" and creates git tag
5. Pushes commit and tag to origin
6. Creates GitHub prerelease with notes extracted from CHANGELOG
7. Adds new `## [Unreleased]` section with `_No unreleased changes._` placeholder
8. Commits "Prepare for next release" and pushes
