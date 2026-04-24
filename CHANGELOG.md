# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-04-24

### Added

- Injection mode: translates session cookies into Bearer tokens for upstream
  services. Enables OWASP Token Handler Pattern — browsers never hold access
  tokens. Select with `auth.mode = "injection"`.
- `auth.injection.*` configuration section: provider origin, client_id, scope,
  session cookie name, token cache settings, safety margin, timeout.
- Single-flight request coalescing: concurrent cache misses on the same
  session result in a single provider call.
- Configurable safety margin for token cache expiry
  (`auth.injection.tokenCache.safetyMarginSeconds`, default 5s).

### Changed

- Configuration restructured: `auth` now uses a discriminated union on
  `auth.mode`. Existing `auth.client.*` and `auth.introspect.*` paths move
  under `auth.validation.*`. Environment variables (`CLIENT_ID`,
  `INTROSPECT_URL`, etc.) are unchanged.
- `auth.mode` is now required — must be set explicitly to `"validation"`
  or `"injection"`. Omission or typos cause startup failure.
- `providerOrigin` (injection mode) validates as origin-only: no path,
  query, fragment, userinfo; http or https only.
