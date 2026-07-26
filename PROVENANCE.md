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
  `29ed484ec4b9b19a06031567b484d9678541ac2b`
- Dependency version: `0.1.0`
- License: MIT
- Material changes: product-specific inputs were replaced by versionless,
  transport-neutral contracts. Shared forwarding, listener, interception,
  upgrade, URL, and redaction owners were deleted from the product as each moved
  owner was adopted. Credential, ACL, identity, and Access Flow foundations were
  independently authored as product-neutral contracts, with product behavior
  oracles recorded where applicable. P13 modernized the runtime's private HTTP
  transport family and retained the reviewed Hyper fork in the runtime
  repository.

The authoritative complete origin record is `access-runtime/PROVENANCE.md` at
the accepted commit above. It identifies moved-source entries with immutable
`acl-proxy` source commits and material modifications, and independently
authored entries with implementation commits and behavior-oracle lineage where
applicable. Its `Shared Crate Origin Coverage` inventory is the exact per-crate
classification for the shared crates in this product's resolved dependency
graph. This repository consumes those crates through exact-version canonical
sibling path dependencies and does not vendor their source. Its root Cargo
workspace applies the required relative Hyper source redirect to the
runtime-owned fork so all transitive consumers resolve the same implementation
and type family.

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
