# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Validation mode rejects introspection responses that violate RFC 7662
  (#26). `active` must be a boolean: a `200` whose body is not JSON, not an
  object, or carries a non-boolean `active` is treated as a provider error
  (502 at the introspection boundary, answered to the caller as 500) instead
  of passing through a truthy check. Before, `{"active":"false"}` was read
  as active and the request was forwarded upstream.

### Changed

- Provider calls use Node's built-in `fetch` instead of axios (#26).
  Timeouts are `AbortSignal.timeout` with the existing
  `INTROSPECT_TIMEOUT_MS` / `INJECTION_TIMEOUT_MS`; network errors and
  timeouts surface as `provider_unavailable` (502) in injection mode and as
  500 in validation mode. Built-in `fetch` does not read `HTTP_PROXY` /
  `HTTPS_PROXY` / `NO_PROXY`, which axios honoured — a deployment that
  reached the provider through an egress proxy via those variables needs
  `NODE_USE_ENV_PROXY=1` (Node 24) or a direct route.
- A `200` with a malformed body is a provider error, not an auth decision:
  injection mode answers `provider_invalid_response` (502), validation mode
  answers 500. Before, a non-JSON `200` in validation mode was coerced into
  `401 Invalid Token`.
- Runtime dependencies: `@o3co/ts.hocon` 0.1 → 1.x, `@o3co/auth.utils`
  0.0.2 → 0.0.4, `cross-env` 7 → 10, `zod` 4.3 → 4.5.
- Build: `pnpm-lock.yaml` is committed and the `Dockerfile` installs with
  `--frozen-lockfile`, pinning pnpm through `corepack prepare`. The image
  build needs the lockfile in its context.

### Removed

- `axios` (runtime dependency).

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
