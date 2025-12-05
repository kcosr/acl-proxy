## Development guidelines

- For any new feature or behavior change, add or update tests and run `cargo test` before opening a PR (once the Rust project exists); tests must be deterministic and offline.
- For any new feature or behavior change, update documentation appropriately. See docs and README.md.
- If you are making code changes, acting as the implementor and not the reviewer, spawn a claude session and ask it to review after opening a PR.
- When updating Rust code in this project, always run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release` before committing and pushing.
~                             
