# Changelog

## [Unreleased]

### Added
- External auth demo for TermStation integration [#25]
- Support approval macros for external auth header actions, including macro descriptors in pending webhooks and interpolation of approved values into per-rule header actions [#19]
- Update external auth demo webapp to support approval macros end-to-end [#21]
- Expose configurable external auth callbackUrl in webhooks and update demo webapp to consume it [#22]

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
[#19]: https://github.com/kcosr/acl-proxy/pull/19
[#21]: https://github.com/kcosr/acl-proxy/pull/21
[#22]: https://github.com/kcosr/acl-proxy/pull/23
[#25]: https://github.com/kcosr/acl-proxy/pull/25
