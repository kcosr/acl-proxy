# Source Provenance

This file records the source lineage represented by the `acl-proxy` product
repository and its extracted shared-runtime dependency. Third-party dependency
licenses are recorded separately in `THIRD_PARTY_NOTICES` and the locked
candidate dependency, license, and SPDX reports.

## Product Source

- Source repository: `https://github.com/kcosr/acl-proxy`
- Initial source commit: `a829f43552c7118d1f206b9e4112b3c747eecd50`
- License: MIT
- Scope: product configuration, policy adapters, authorization-provider
  lifecycles, observation and capture, process activation, and command-line
  behavior that remain in this repository.

The product source was developed in this repository. It is not a vendored copy
of the shared runtime and does not carry a parallel forwarding, listener, MITM,
or WebSocket implementation.

## Shared Access Runtime

- Source repository: this `acl-proxy` repository
- Destination repository: `access-runtime`
- Accepted runtime commit:
  `c6af6ef8e2c5083f9f880fcd9022910a694cbfdb`
- Dependency version: `0.1.0`
- License: MIT
- Material changes: product-specific inputs were replaced by versionless,
  transport-neutral contracts; shared forwarding, listener, interception,
  upgrade, credential, URL, ACL, and redaction owners were deleted from the
  product as each extracted owner was adopted. P13 modernized the runtime's
  private HTTP transport family and retained the reviewed Hyper fork in the
  runtime repository.

The authoritative path-by-path moved-source record, including each immutable
`acl-proxy` source commit and material modification, is
`access-runtime/PROVENANCE.md` at the accepted commit above. This repository
consumes the shared crates through exact-version canonical sibling path
dependencies and does not vendor their source. Its root Cargo workspace applies
the required relative Hyper source redirect to the runtime-owned fork so all
transitive consumers resolve the same implementation and type family.

## Third-Party Source

`acl-proxy` does not vendor a third-party source tree. The reviewed Hyper 1.10.1
fork is owned and documented by `access-runtime`; this product only redirects
Cargo resolution to that sibling source. Cargo resolves all other exact
registry packages and checksums in `Cargo.lock`. In particular,
the `compu-brotli-sys` 1.2.0 Rust wrapper/package is distributed under
BSL-1.0, while the bundled Google Brotli C implementation it compiles is MIT.
The direct `brotli` crate also carries its Dropbox BSD-3-Clause notice, and
`zstd-sys` compiles bundled Zstandard source under BSD-3-Clause. Their exact
notices are retained in `THIRD_PARTY_NOTICES`.
