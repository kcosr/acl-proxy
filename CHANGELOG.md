# Changelog

## [Unreleased]

- Fix upstream HTTP/2: remove hardcoded HTTP/1.1 version hint so `tls.enable_http2_upstream` works correctly [#14]
- Capture upstream failure paths (502 Bad Gateway) for allowed requests [#14]
- Add architecture and code review documentation [#12]
- Clean up external auth imports and apply fmt/clippy [#9]
- Refactor external auth gate handlers into shared helper [#7]
- Implement external auth lifecycle status webhooks [#4]
- Add external auth webhook support for approval-required policy rules [#2]

## [0.0.1] - 2025-12-04

### Added

- Initial public release (pre-alpha).

[#14]: https://github.com/kcosr/acl-proxy/pull/14
[#12]: https://github.com/kcosr/acl-proxy/pull/12
[#9]: https://github.com/kcosr/acl-proxy/pull/9
[#7]: https://github.com/kcosr/acl-proxy/pull/7
[#4]: https://github.com/kcosr/acl-proxy/pull/4
[#2]: https://github.com/kcosr/acl-proxy/pull/2

