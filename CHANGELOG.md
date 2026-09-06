# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The `graceful shutdown: complete` line could say `reason: "drained"` next
  to a non-zero exit code.** When cleanup timed out or failed it set the exit
  code but not the reason, so the one line an operator alerts on contradicted
  itself. `reason` now names whatever decided the exit code
  (`cleanup-timeout` / `cleanup-failed`) and the drain outcome keeps its own
  `drain` key, so the shape stays stable and neither fact is lost. Shipped in
  0.5.0; found reviewing the same code in
  [auth.provider#511](https://github.com/o3co/auth.provider/pull/511).

- The `exit` option's doc said it defaults to `process.exit` after the default
  became `deferExit`.

## [0.5.0] — 2026-09-06

### Security

- Introspection cache entries and positive responses respect the token expiration, including expiration during the provider call. TTL zero bypasses caching.
- Validation rejects sender-constrained tokens on its Bearer-only path.
- Injection maps a rejected session grant (`400 invalid_grant`) to `401 session_required` instead of a proxy configuration error.

### Fixed

- **Graceful shutdown had no drain deadline, so SIGTERM could never complete on
  its own.** `gracefulShutdown` came from `@o3co/auth.utils@0.0.4`, which called
  `server.close()` with no timeout: one stuck in-flight request meant the
  process waited forever and the orchestrator's SIGKILL cut it down mid-flight —
  the opposite of a graceful shutdown, arriving precisely under the load that
  produces a stuck request. Shutdown now drains for `drainTimeoutMs` (default
  10s, size it below the orchestrator's kill grace period), then force-closes
  the remaining connections and exits non-zero so a truncated drain is
  distinguishable from a clean one. A `close` that reports a failure is no
  longer reported as a clean drain, and a cleanup failure is logged through the
  app logger rather than `console.error` — one bare line in a service whose
  every other line is NDJSON. `cleanup` is itself bounded by `cleanupTimeoutMs`
  (defaulting to `drainTimeoutMs`), so a dispose that never settles cannot
  replace the wedge it was meant to remove, and the process yields the loop
  once before exiting so a buffered log destination can flush the lines that
  say why. `auth.provider` reached the same conclusion for
  the same code in its issue #290.

- **The deployed proxy emitted console lines, not NDJSON.** `auth.utils` took
  `pino` as an *optional* peer and silently fell back to `console` when the
  import failed; this repo satisfied that peer from **devDependencies**, and the
  Dockerfile runs `pnpm prune --prod` before copying `node_modules` into the
  runtime stage. Every production log line was therefore a `[proxy] ...` console
  write that no aggregator parses — and no local run showed it, because dev
  installs kept pino present. `pino` is a direct runtime dependency now.

### Changed

- **`@o3co/auth.utils` is no longer a dependency.** Its five helpers
  (`createLogger`, `gracefulShutdown`, `createHealthcheckRouter`,
  `extractBearerToken`, `createRequestIdMiddleware`) now live in this
  repository, each with its own tests. This proxy was the package's only
  full-surface consumer: `auth.provider` had already moved its shutdown out
  (#290) and the verifier its logger (#107), both after finding defects that a
  shared pre-1.0 utility made hard to see from the code they deploy.

  The liveness path is the clearest case for the move. `auth.utils` defaulted to
  `/healthcheck` while this proxy, the provider and (since its 0.7.0) the
  verifier all answer on `/_healthcheck` — the shared default was itself the
  source of the divergence it was meant to prevent. Behaviour is otherwise
  unchanged: the Bearer grammar, the request-id reuse rule and the healthcheck
  path and body are the ones the proxy already shipped, now pinned by tests
  here.

## [0.4.0] — 2026-09-04

### Security

- Injection mode refuses session cookie values outside the RFC 6265 §4.1.1
  `cookie-value` grammar (#23). The extracted value is interpolated verbatim
  into the outbound `Cookie` header of the session grant call, and undici /
  `http.validateHeaderValue` reject only CR/LF/NUL, CTLs/DEL and code points
  above 0xFF — so a value carrying a comma, whitespace, DQUOTE, backslash or a
  latin-1 byte reached the provider unchanged and could malform the header or
  smuggle a second cookie-pair. A non-conforming value is now refused: the
  request is forwarded without `Authorization` and the provider is not called
  (the refusal is logged as `injection.cookie_rejected`, see Fixed below).

  A value wrapped in one DQUOTE pair is accepted and forwarded with the quotes
  preserved — user agents echo the provider's `Set-Cookie` bytes opaquely
  (§5.2), so the provider's own parser is the right place to interpret them. A
  DQUOTE anywhere else (interior or unbalanced) is refused, and an empty quoted
  value is refused like an empty bare value.
- `auth.injection.sessionCookieName` is validated at boot against the RFC 6265
  §4.1.1 `cookie-name` grammar (#75) — an RFC 9110 `token`, i.e. one or more
  of `` !#$%&'*+-.^_`|~ ``, digits and letters. The name is interpolated
  verbatim into the outbound `Cookie` header of the session grant call, and the
  schema accepted any non-empty string, so `"sid "` or `"a=b"` (a typo, or a
  copy-pasted `name=value`) malformed that header, or smuggled a second
  cookie-pair, on every request. Such a name is now a configuration error at
  startup whose message names the key.

### Fixed

- The session cookie value is no longer trimmed before the cookie-octet check
  (#23). `extractCookie` trimmed whitespace after `=`, normalising `sid= abc`
  and `sid=\tabc` into valid outbound values even though whitespace is outside
  `cookie-octet`. RFC 6265 §4.2.1 allows whitespace only as the SP after `;`
  (plus OWS at the header ends), so the cookie-pair token and the name are now
  trimmed of OWS only (SP / HTAB — `String.prototype.trim` would also strip a
  latin-1 NBSP) and the value is taken verbatim: `sid= abc` fails the grammar
  and is refused, while `a=1;  sid=abc ; b=2` still yields `abc`.
- A session cookie the proxy refuses to forward is logged as
  `injection.cookie_rejected` at warn instead of `injection.no_cookie` at debug
  (#73). Both cases forward the request without `Authorization` and skip the
  provider, but a header that never carried the cookie is an ordinary anonymous
  request, while one that carried it in a refused form points at a misbehaving
  client or a provider issuing cookies outside the grammar. The event carries
  the request id, a bounded `reason` class — `empty` (`sid=` / `sid=""`),
  `quoting` (a DQUOTE anywhere other than one surrounding pair) or `grammar` (a
  character outside `cookie-octet`) — an `action` (`forward`: the request went
  upstream anonymously; `fallback`: a later same-name pair was used, see #74)
  and the `metric: auth_proxy_injection_cookie_rejected` hint that
  `injection.authorization_override` already uses. The cookie bytes are never
  logged. Operators should treat a sustained rate of this event as a signal to
  look at the client or the provider's `Set-Cookie`; `injection.no_cookie`
  stays at debug for the absent case. The proxy has no metrics endpoint, so the
  log line is the deliverable.
- The first well-formed same-name pair wins (#74). A malformed pair aborted the
  scan, so `sid=bad,val; sid=good` was refused although a usable pair
  followed — and user agents may legitimately send two same-name pairs (RFC
  6265 §5.4 orders them by path, then creation time). The malformed pair is now
  skipped (and logged as above with `action: "fallback"`) and `good` is
  exchanged; `sid=good; sid=bad,val` still yields `good`; when every same-name
  pair is malformed the request is forwarded anonymously with the first pair's
  `reason`. Per-pair OWS trimming and the verbatim value semantics from #23 are
  unchanged.

### Changed

- The router cache-expiry test drives a faked clock instead of sleeping (#24).
  It slept a real 1.1 s with `ttlSeconds=1` / `safetyMarginSeconds=0`, adding
  wall-clock time to every run and leaving 100 ms of slack under CI load. Cache
  expiry is decided purely from `Date.now()`, so only `Date` is faked
  (`vi.useFakeTimers({ toFake: ["Date"] })`), leaving `setTimeout` & co. real so
  supertest's HTTP round trips are untouched. The case keeps the default TTL
  (55 s effective), asserts a hit at 30 s and a re-fetch at 60 s, and runs in
  about 3 ms.
- Release workflow: a tag with a semver pre-release suffix (`vX.Y.Z-rc.1`) is
  published as a GitHub pre-release (#76). `softprops/action-gh-release` ran
  without a `prerelease` input, so such a tag would have been marked the latest
  full release; a step now derives the flag from the tag name and nothing else
  in the workflow changes.

## [0.3.0] — 2026-09-03

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
