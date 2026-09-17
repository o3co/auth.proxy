# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-09-17

### Added

- **Injection mode can exchange an external credential for a first-party
  token (#90).** Opt-in with `auth.injection.exchange.enabled`
  (`INJECTION_EXCHANGE_ENABLED`, `"true"` / `"false"`, default `false`). A
  request that presents `Authorization: Bearer <JWT>` instead of a session
  cookie is submitted to the provider's `POST /oauth/token` as an RFC 7523
  jwt-bearer assertion, and the issued token replaces the header, so only a
  first-party token reaches the upstream. The original credential is never
  forwarded — not on success, refusal, outage or a malformed header — and no
  failure falls back to the session path. The proxy submits the assertion
  unchanged and does not decide trust: whatever auth.provider's
  `AssertionIssuerRegistry` admits for the issuer applies, which covers plain
  RFC 7523 assertions and the ID-JAG profile. It is not RFC 8693 token
  exchange, and it produces no `act` delegation.

  Disabled, injection mode behaves exactly as before, and a configuration
  without the `exchange` block parses as disabled, so upgrading needs no
  action. Turning it on needs:

  - `INJECTION_EXCHANGE_CLIENT_ID` and `INJECTION_EXCHANGE_CLIENT_SECRET`
    (`auth.injection.exchange.clientId` / `clientSecret`). The proxy
    authenticates with `client_secret_basic`, with the RFC 6749 §2.3.1 encoding
    validation mode already uses, and boot fails naming whichever key is
    missing. `INJECTION_EXCHANGE_SCOPE`, `INJECTION_EXCHANGE_AUDIENCE` and
    `INJECTION_EXCHANGE_RESOURCE` are sent only when set.
    `INJECTION_EXCHANGE_ALLOWED_ISSUERS` (whitespace-separated, like
    `INJECTION_SCOPE`; empty = off) is an optional prefilter that refuses an
    unlisted, unverified `iss` before any provider call; in HOCON a list entry
    that is empty or contains whitespace fails boot.
  - The proxy registered at the provider as a confidential client whose
    `allowedGrantTypes` names `urn:ietf:params:oauth:grant-type:jwt-bearer`,
    and listed in `allowedClients` of every issuer entry that names such a
    list. An ID-JAG must carry the proxy's client as its `client_id`.
  - For an issued token that never outlives its assertion, a provider that
    includes [auth.provider#588](https://github.com/o3co/auth.provider/pull/588),
    which caps a jwt-bearer token at the assertion's expiry. Without it the
    token can outlive the assertion at offline validators. The proxy's own
    cache is bounded by the assertion's `exp` either way.

  With the exchange enabled, an inbound `Authorization` is never passed
  through, so `stripInboundAuthorization` has nothing left to strip. The
  request shape decides the path, and neither refusal calls the provider:

  - A session cookie together with any `Authorization` is
    `400 credential_ambiguous`. The cookie counts as present whenever the
    header carries `auth.injection.sessionCookieName`, even in a form the
    cookie grammar check refuses.
  - An `Authorization` that is not `Bearer <JWS compact JWT>` — another
    scheme, an opaque token, a malformed JWT, an empty value — is
    `401 credential_unsupported`.

  A cookie alone, or no credential, takes the existing path. Exchange
  refusals use the session path's `{ error, error_description }` shape:
  `401 credential_rejected` (an `iss` outside `allowedIssuers`, or provider
  `invalid_grant`), `403 exchange_not_permitted` (`invalid_scope`,
  `invalid_target`, `unauthorized_client`), and `502` with
  `provider_config_error` (provider `401`, any other `400`, or a redirect),
  `provider_unavailable` (`5xx` / `429` with `Retry-After` passed through,
  network error, timeout) or `provider_invalid_response` (no `access_token`,
  or a `token_type` other than `Bearer`, such as `DPoP`). Each outcome is
  logged as an `injection.exchange_*` event; `exchange_credential_ambiguous`
  and `exchange_not_permitted` are at warn, and the ambiguous case carries
  `metric: auth_proxy_injection_exchange_credential_ambiguous`. The assertion,
  the issued token, the client secret and the unverified `iss` are never
  logged.

  A successful exchange is cached per instance in its own cache and
  single-flight, never shared with the session cache, but sized and timed by
  the same `auth.injection.tokenCache` settings and `timeoutMs`:
  `maxEntries` applies to each cache separately. An entry expires at
  `min(sent + ttlSeconds, sent + expires_in, assertion exp) - safetyMarginSeconds`,
  where `sent` is the instant the token request went out. An assertion
  without `exp` is not cached, and failures are never cached. The proxy keeps
  no rate-limit budget of its own: each token request the exchange sends — one
  per cache miss, after concurrent identical requests are coalesced — reaches
  the provider's `/oauth/token` and counts against the provider's `token`
  rate limit, as a session grant does, so size that budget for the proxy's
  traffic.

- **An ID-JAG is not replay-checked while its exchange is cached.** The
  provider accepts each ID-JAG `jti` once, when the assertion is submitted,
  and a cache hit submits nothing. Within the cache lifetime, whoever
  presents the same assertion is served the cached token. Treat the
  assertion as a bearer credential for that window, which
  `tokenCache.ttlSeconds` bounds. After the entry expires, or at another
  proxy instance, the same ID-JAG is a replay the provider refuses
  (`401 credential_rejected`), and the client must obtain a fresh one.
  Expiry bounds do not propagate revocation either: revoking the external
  credential, its issuer's registration or the proxy's client reaches
  neither a token already issued nor a result cached within that lifetime.

### Security

- **The exchange client does not follow redirects.** A token endpoint that
  answers with a redirect gets `502 provider_config_error`, so the
  assertion and the client secret are never re-sent to another location.

- **Provider-controlled error text is validated before it is logged or
  returned.** On the session path, a provider `400` other than
  `invalid_grant` had its `error_description` relayed verbatim as the
  `provider_config_error` description, in the response and in the log, so a
  provider that echoed the session cookie put it in both. The description is
  now used only when it is a well-formed RFC 6749 `error_description`: the
  RFC charset, at most 256 characters, nothing JWT-shaped, and not containing
  the session cookie value. Otherwise the existing generic
  `provider rejected proxy configuration (client_id or scope)` is returned. A
  client or alert that matched on a provider's own wording there may now see
  the generic one. The exchange logs the provider's `error` code only when
  it has that shape (no whitespace, at most 64 characters, nothing
  JWT-shaped, not echoing the assertion or client secret), records
  `invalid_error_code` otherwise, and never logs `error_description`.
  Provider error bodies are read up to 16 KiB on both paths; a longer body
  is abandoned and treated as having no diagnostic.

### Fixed

- **A slow provider could make a cached session token outlive the token
  itself.** The session cache lifetime,
  `min(ttlSeconds, expires_in) - safetyMarginSeconds`, was counted from when
  the grant response arrived. `expires_in` runs from issuance, so a slow
  response pushed the entry past the token's real expiry by the whole
  response time, and the proxy went on injecting an expired token. The
  lifetime is now counted from the instant the grant request was sent, and a
  grant whose response arrives after that point is not cached. Behaviour at
  normal latency is unchanged. The exchange cache uses the same anchor.

### Changed

- Runtime dependency: `zod` 4.5 → 4.6 (#87). Development-only, with no effect
  on the built proxy: `vitest` 4 → 5 (#88), `@biomejs/biome` 2.5.11 → 2.5.13
  and `@types/node` 26.4 → 26.5 (#86).

## [0.5.1] — 2026-09-06

### Fixed

- **The `graceful shutdown: complete` line could say `reason: "drained"` next
  to a non-zero exit code.** When cleanup timed out or failed it set the exit
  code but not the reason, so the one line an operator alerts on contradicted
  itself. `reason` now names whatever decided the exit code
  (`cleanup-timeout` / `cleanup-failed`) and the drain outcome keeps its own
  `drain` key, so the shape stays stable and neither fact is lost. Introduced in
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
