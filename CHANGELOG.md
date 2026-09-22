# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- **Breaking**: additional headers (and the body) are now joined with `headersDelimiter` when `schemeType` is enabled, and `headersDelimiter` now defaults to `.` when not explicitly configured. Existing configurations that use additional headers and do not set `headersDelimiter` will produce a different HMAC than before this change (previously the values were concatenated with no separator). If you rely on additional-header signing, set `headersDelimiter` to match the delimiter used by your signature generator before upgrading, or verify it against a value of `.`.

### Added

- Optional timestamp-based replay protection (`timestampValidity`): requires and validates a signed timestamp header, bounding how long a captured request remains replayable (`maxSignatureAge`, `clockSkew`).
