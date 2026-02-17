# Changelog

## [Unreleased]

_No unreleased changes._

## [0.0.8] - 2026-02-17

### Added
- Add repo-local build-service config for remote builds ([#38](https://github.com/kcosr/acl-proxy/pull/38)).
- Add HTTP/1.1 protocol upgrade tunneling (including WebSocket handshakes) for proxy traffic paths ([#39](https://github.com/kcosr/acl-proxy/pull/39)).

### Fixed
- Make transparent HTTPS H2 capture test select the request record deterministically ([#38](https://github.com/kcosr/acl-proxy/pull/38)).

## [0.0.7] - 2026-01-15

### Changed
- Use `Cargo.toml` as version source instead of separate `VERSION` file ([#37](https://github.com/kcosr/acl-proxy/pull/37))

## [0.0.6] - 2026-01-13

### Added
- Add stdio auth plugin support and URL allowlist demo ([#36](https://github.com/kcosr/acl-proxy/pull/36))

### Changed
- Restructure documentation and add an operator-focused docs layout ([#35](https://github.com/kcosr/acl-proxy/pull/35))

### Removed
- Remove internal code review findings documentation ([#35](https://github.com/kcosr/acl-proxy/pull/35))

## [0.0.5] - 2026-01-10

### Changed
- Restructure documentation and add an operator-focused docs layout ([#35](https://github.com/kcosr/acl-proxy/pull/35))

### Removed
- Remove internal code review findings documentation ([#35](https://github.com/kcosr/acl-proxy/pull/35))

## [0.0.4] - 2026-01-10

### Added
- Support IPv6 subnet matching in policy rules. ([#33](https://github.com/kcosr/acl-proxy/pull/33))
- Add `proxy.internal_base_path` for internal endpoints (including external auth callback paths). ([#34](https://github.com/kcosr/acl-proxy/pull/34))
- Add configurable upstream request timeouts (global and per-rule overrides). ([#34](https://github.com/kcosr/acl-proxy/pull/34))

### Fixed
- Avoid request ID collisions after process restarts by adding a per-process tag. ([#33](https://github.com/kcosr/acl-proxy/pull/33))
- Ensure the external auth status worker starts reliably under concurrent calls. ([#33](https://github.com/kcosr/acl-proxy/pull/33))
- Log dropped external auth status webhook events at warn level. ([#34](https://github.com/kcosr/acl-proxy/pull/34))

### Changed
- External auth demos honor `ACL_PROXY_INTERNAL_BASE_PATH` for internal endpoints. ([#34](https://github.com/kcosr/acl-proxy/pull/34))

## [0.0.3] - 2026-01-09

### Added
- External auth demo for TermStation integration ([#25](https://github.com/kcosr/acl-proxy/pull/25))
- Support approval macros for external auth header actions, including macro descriptors in pending webhooks and interpolation of approved values into per-rule header actions ([#19](https://github.com/kcosr/acl-proxy/pull/19))
- Update external auth demo webapp to support approval macros end-to-end ([#21](https://github.com/kcosr/acl-proxy/pull/21))
- Expose configurable external auth callbackUrl in webhooks and update demo webapp to consume it ([#22](https://github.com/kcosr/acl-proxy/pull/22))
- Add size-based rotating file logging with optional stdout tee ([#32](https://github.com/kcosr/acl-proxy/pull/32))
- Add release tooling scripts for versioning, changelog updates, tagging, and GitHub prereleases ([#32](https://github.com/kcosr/acl-proxy/pull/32))

### Changed
- Capture directory no longer falls back to logging.directory ([#32](https://github.com/kcosr/acl-proxy/pull/32))

## [0.0.2] - 2025-12-06

### Added
- Capture upstream failure paths (502 Bad Gateway) for allowed requests [#14]
- Add architecture and code review documentation [#12]
- Add LRU eviction for per-host certificate caches and `certificates.max_cached_certs` setting [#17]
- Implement external auth lifecycle status webhooks [#4]
- Add external auth webhook support for approval-required policy rules [#2]

### Changed
- Clean up external auth imports and apply fmt/clippy [#9]
- Refactor external auth gate handlers into shared helper [#7]

### Fixed
- Fix upstream HTTP/2: remove hardcoded HTTP/1.1 version hint so `tls.enable_http2_upstream` works correctly [#14]

## [0.0.1] - 2025-12-04

### Added

- Initial public release (pre-alpha).

[#14]: https://github.com/kcosr/acl-proxy/pull/14
[#12]: https://github.com/kcosr/acl-proxy/pull/12
[#17]: https://github.com/kcosr/acl-proxy/pull/17
[#9]: https://github.com/kcosr/acl-proxy/pull/9
[#7]: https://github.com/kcosr/acl-proxy/pull/7
[#4]: https://github.com/kcosr/acl-proxy/pull/4
[#2]: https://github.com/kcosr/acl-proxy/pull/2
