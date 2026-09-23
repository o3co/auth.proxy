# `src`

A source map: what each directory is, who owns lifecycle and state, and where the contracts are written down. Wire behaviour is in the [root README](../README.md); each directory that owns a contract has its own README. The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

| Path | Kind | Holds |
| --- | --- | --- |
| [`app.mts`](app.mts) | composition root | parses the config and assembles the server; executes at import |
| [`app-internal.mts`](app-internal.mts) | assembly | mode selection, split out of `app.mts` so it can be tested without listening |
| [`shutdown.mts`](shutdown.mts) | lifecycle contract + process | graceful shutdown |
| [`logger.mts`](logger.mts) | logging | the [`Logger`](logger.mts) interface and the singleton |
| [`router/`](router) | assembly | the healthcheck and the shared upstream proxy stage ([`createUpstreamProxy`](router/upstream.mts)); the mode routers are under `modes/` |
| [`modes/injection/`](modes/injection/README.md), [`modes/validation/`](modes/validation/README.md) | the two modes | each mode's decision, its provider client(s), its cache |
| [`express/`](express/README.md) | transport helpers | header reading, request id; no decisions |
| [`oauth/`](oauth/README.md) | contract | how the proxy authenticates itself to the provider |
| [`../config/`](../config/README.md) | contract | the configuration schema and the shipped conf |

## Public contract

The process: `node dist/src/app.mjs` (or `pnpm run debug`). Importing `app.mts` parses `../config/application.conf`, validates it and listens — there is no exported factory. Everything else is importable and assemblable by a test on its own.

## Inputs and outputs

`app.mts` mounts, in this order: the healthcheck, CORS, the mode router under `http.pathPrefix`; then `listen` and `installGracefulShutdown(server, { logger })`. The mode router is whichever [`resolveRouter`](app-internal.mts) picks from `auth.mode`, exhaustively; each ends with the shared upstream stage.

## Dependencies

Non-test edges: `app` → `config/application.schema`, `app-internal`, `logger`, `router/index`, `shutdown` · `app-internal` → `modes/injection/router`, `modes/validation/router` · `modes/validation/router` → `modes/validation/decision`, `modes/validation/introspect`, `modes/validation/introspection-cache`, `modes/validation/introspection-client`, `express/requestId`, `router/upstream`, `logger` · `modes/validation/decision` → `express/bearer`, `modes/validation/introspection-client` and the `Logger` type · `modes/validation/introspect` → `modes/validation/introspection-client`, and as types only `modes/validation/decision`, `modes/validation/introspection-cache` · `modes/validation/introspection-client` → `oauth/client-secret-basic` · `modes/injection/router` → `express/requestId`, `router/upstream`, `logger`, its siblings · `modes/injection/decision` → its siblings and the `Logger` type · `modes/injection/exchange` → `logger`, its siblings · `modes/injection/jwt-bearer-client` → `oauth/client-secret-basic`, `provider-error`, `token-endpoint` · `modes/injection/session-grant-client` → `provider-error`, `token-endpoint` · `router/upstream` → `express-http-proxy`. No cycles. Direction: `modes/*` depend on `express/`, `oauth/`, `router/upstream` and `logger`; nothing under `express/`, `oauth/`, `router/` or `config/` imports a mode.

## Invariants

- **Healthcheck before CORS, outside `pathPrefix` (F25).** `/_healthcheck` answers whatever the prefix is and without CORS headers, because it is mounted first and at the root (the `.use` chain in [`app.mts`](app.mts)) — that composition is documented, not tested: no test imports `app.mts`, which is why mode selection lives in `app-internal.mts`. The probe itself is liveness only — the process is up — and says nothing about the provider (the doc comment on the healthcheck [`createRouter`](router/Healthcheck.mts)); its path and GET-only method are pinned by [`Healthcheck.test.mts`](router/__tests__/Healthcheck.test.mts).
- **Shutdown drains, it does not wipe.** `app.mts` passes no `cleanup`, so the shutdown closes the listener, gives in-flight requests `drainTimeoutMs`, and exits; the token caches are left as they are and die with the process. The guarantees themselves — signals, idle sockets, the deadline, the non-zero exit, the bounded cleanup — are stated in the module doc comment of [`shutdown.mts`](shutdown.mts) and not repeated here; options are [`GracefulShutdownOptions`](shutdown.mts).
- **One logger.** Both mode routers use the singleton (the default export of [`logger.mts`](logger.mts)) as the default `deps.logger` and hand it to their decisions — [`decideInjection`](modes/injection/decision.mts), [`decideExchange`](modes/injection/exchange.mts), [`decideValidation`](modes/validation/decision.mts) — as a [`Logger`](logger.mts) (#95 F2, F3, F4), and `shutdown.mts` takes one as an option. Tests spy on the singleton, or inject a fake through `deps`. A replacement boundary on both paths (F22). Output is NDJSON on stdout, level from `LOG_LEVEL` read when the logger is created ([`createProxyLogger`](logger.mts)) — the only environment read outside the HOCON parse in `app.mts`.
- **`src/router/` holds the healthcheck and the upstream stage.** [`index.mts`](router/index.mts) re-exports only `Healthcheck`; [`upstream.mts`](router/upstream.mts) is imported by both mode routers directly (F18, #97), and its docstring states what the library forwards and why the decorator is a casing-only no-op. The routers that carry the modes are `modes/*/router.mts`.

## Failure and lifecycle

State held for the life of the process, and who owns it:

| State | Owner | Released |
| --- | --- | --- |
| parsed config | `config` in [`app.mts`](app.mts) | never; immutable after boot |
| session token cache and single-flight table, router-built (the default) | the [`createRouter`](modes/injection/router.mts) closure | at process exit |
| session token cache and single-flight table, supplied via `deps` (#95 F4) | the caller that supplied them — it may retain, clear or dispose them, and share them between routers whose grant context differs, since [`sessionCacheKey`](modes/injection/decision.mts) carries it (#95 F33) — what it must still match is the supplied `grantClient`, which cannot be hashed, and the cache policy, which decides how long an entry lives rather than which token comes back | the caller's responsibility; the router never clears what it did not build |
| exchange cache and single-flight table, router-built (the default) | the [`createRouter`](modes/injection/router.mts) closure | at process exit |
| exchange cache and single-flight table, supplied via `deps.exchange` (#95 F2) | the caller that supplied them — it may retain, clear or dispose them, and share them between routers whose exchange context differs, since [`exchangeCacheKey`](modes/injection/exchange.mts) carries it — what it must still match is `clientSecret` (not part of the context), the supplied `client` and the cache policy (#95 F33) | the caller's responsibility; the router never clears what it did not build |
| introspection cache, router-built (the default) | the [`createRouter`](modes/validation/router.mts) closure (#95 F5) | at process exit |
| introspection cache, reached through a supplied `deps.introspect` | the caller that built it | the caller's responsibility; the router never clears what it did not build |
| `shuttingDown` / `finished` | the [`installGracefulShutdown`](shutdown.mts) closure | n/a |
| the logger | the default export of [`logger.mts`](logger.mts) | n/a |

A config error stops the process before it listens; a provider failure is answered per mode and never stops it; SIGTERM / SIGINT start the drain described in `shutdown.mts`.

## Contract tests

| Test file | Pins |
| --- | --- |
| [`__tests__/config.test.mts`](__tests__/config.test.mts) | the schema against the shipped conf — see [`config/README.md`](../config/README.md) |
| [`__tests__/mode-selection.test.mts`](__tests__/mode-selection.test.mts) | `resolveRouter` dispatch and the exhaustive guard |
| [`__tests__/shutdown.test.mts`](__tests__/shutdown.test.mts) | every guarantee listed in `shutdown.mts` |
| [`__tests__/logger.test.mts`](__tests__/logger.test.mts) | level selection, NDJSON, the `name` field, structured fields |
| [`router/__tests__/Healthcheck.test.mts`](router/__tests__/Healthcheck.test.mts) | the `/_healthcheck` path and method |
| [`router/__tests__/upstream.test.mts`](router/__tests__/upstream.test.mts) | `createUpstreamProxy` targets `upstream.baseURL` with exactly `limit = http.bodyLimitSize` and the decorator; the decorator is a casing-only no-op on what the library already copied |

No test today for the `app.mts` composition itself: healthcheck before CORS, the `pathPrefix` mount, no `cleanup` passed (F25).
