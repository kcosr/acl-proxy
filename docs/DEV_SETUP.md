# Development setup (OpenSSL)

This project pulls in OpenSSL via `openssl-sys`. When system headers are unavailable (common in minimal WSL images), build a local OpenSSL and point cargo to it:

```bash
curl -LO https://www.openssl.org/source/openssl-3.3.2.tar.gz
tar xzf openssl-3.3.2.tar.gz
cd openssl-3.3.2
./config --prefix="$HOME/openssl-local/inst" --openssldir="$HOME/openssl-local/inst/ssl" no-shared
make -j4
make install_sw
```

Then set the following when running cargo commands:

```bash
export OPENSSL_DIR="$HOME/openssl-local/inst"
export OPENSSL_STATIC=1
export OPENSSL_NO_PKG_CONFIG=1
export PKG_CONFIG_PATH="$HOME/openssl-local/inst/lib64/pkgconfig"
```

Afterwards, run the usual checks from this repository’s AGENTS: `cargo fmt`, `cargo clippy --all-targets --all-features`, `cargo test`, and `cargo build --release`.
