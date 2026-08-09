# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-08-09

### Added

- Added kubeconfig-scoped kubectl bypasses for 10 minutes, 30 minutes, or 1 hour within the approved working-directory subtree.
- Added actionable `/infra-guard` controls for pausing, resuming, removing individual bypasses, and clearing active exceptions.
- Added shell token provenance so kubeconfig scopes preserve quoting, escaping, and expansion semantics across direct tools and Code Mode.

### Changed

- Made a temporary pause the explicit operator-controlled full policy off switch, while interactive TTY sessions remain blocked.
- Made ambiguous, dynamic, repeated, cwd-changing, or environment-uncertain kubeconfig commands ineligible for scoped bypasses.
- Revalidated pending authority immediately before creating a bypass and made duplicate bypasses refresh instead of accumulate.

### Fixed

- Prevented one bypass from authorizing another guarded operation in a compound command.
- Preserved the original blocked execution context when creating bypass rules.
- Prevented path-normalization mismatches involving `$HOME`, `~`, quotes, escapes, repeated separators, shell state changes, and wrapper options.
- Removed stale one-time grants when a scoped bypass is selected and disambiguated bypass-removal menu entries.

## [0.8.1] - 2026-08-09

### Fixed

- Switched Code Mode integration to the published `@howaboua/pi-codex-conversion` nested preflight API.

## [0.8.0] - 2026-08-08

### Added

- Added session-scoped guard pauses and cwd-scoped command-prefix bypasses with 10-minute, 30-minute, and 1-hour durations.

## [0.7.0] - 2026-08-07

### Fixed

- Integrated Code Mode through its nested preflight broker so dynamically assembled `exec_command` calls are guarded.

## [0.6.0] - 2026-07-26

### Added

- Added classified-dangerous-only mode for allowing classification uncertainty while preserving positively identified risks.

## [0.5.0] - 2026-07-25

### Added

- Added targeted Docker policy for destructive and host-control operations.
- Added destructive Git command policy.
- Added strict Vault policy for secret access and security-sensitive operations.

## [0.4.0] - 2026-07-23

### Added

- Added guards for destructive local file tools, `find -delete`, and deletion-enabled rsync operations.

## [0.3.2] - 2026-07-23

### Added

- Added per-command `allow` and `requireApproval` policy overrides.

## [0.3.1] - 2026-07-23

### Added

- Added per-CLI guard toggles with live configuration reloads.

## [0.3.0] - 2026-07-23

### Added

- Added policy coverage for AWS, Azure, and Google Cloud CLIs with classification corpora and benchmarks.

## [0.2.5] - 2026-07-22

### Changed

- Split the extension into focused policy, shell, approval, and attention modules.
- Added strict type checking, a unified policy entrypoint, typed evaluator registration, and deterministic adversarial shell tests.

### Fixed

- Isolated native notification data handling.

## [0.2.0] - 2026-07-22

### Added

- Added configurable approval notifications and sound attention mechanisms.

## [0.1.0] - 2026-07-22

### Added

- Initial infrastructure command guard with structured approval flow and CI packaging checks.

[Unreleased]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.2.0...v0.2.5
[0.2.0]: https://github.com/ramtinJ95/pi-infra-command-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ramtinJ95/pi-infra-command-guard/releases/tag/v0.1.0
