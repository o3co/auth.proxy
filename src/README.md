# `src`

Last updated: 2026-09-24

A source map: what each directory is, who owns lifecycle and state, and where the contracts are written down. Wire behaviour is in the [root README](../README.md); each directory that owns a contract has its own README. The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** `src/` is the whole proxy process. Its root files are the composition root ([`app.mts`](app.mts)), the mode selection it calls, and the pieces both modes share — the logger, graceful shutdown, the coalescing primitive and the provider-body helpers. Its directories are the two modes (`modes/`), the route assembly both modes mount (`router/`), the header helpers (`express/`) and client authentication (`oauth/`). Configuration is [`../config/`](../config/README.md), outside `src/`.

**Owns:** assembling the server and the order it mounts things in; the process lifecycle (listen, drain, exit); the logger and what an error looks like in a log line; the modules both modes share, listed under [Where shared modules live](#where-shared-modules-live).

**Does not own:** any mode's decision, provider client or cache (`modes/*`, each with its own README); header grammar (`express/`); the client-authentication encoding (`oauth/`); configuration defaults and validation (`config/`).

**Why separate.** The root holds what is either assembly or shared by both modes; a mode imports the root's shared modules, never the other mode (the direction rule under [Dependencies](#dependencies)) — which is why a module both modes need moves here rather than staying in the mode that had it first (#95 F6, F39).

| Path | Kind | Holds |
| --- | --- | --- |
| [`app.mts`](app.mts) | assembly | the composition root: parses the config and assembles the server; executes at import |
| [`app-internal.mts`](app-internal.mts) | assembly | mode selection, split out of `app.mts` so it can be tested without listening |
| [`shutdown.mts`](shutdown.mts) | contract + process | graceful shutdown: the guarantees in its module doc comment and the process that keeps them |
| [`logger.mts`](logger.mts) | contract + external connection | the [`Logger`](logger.mts) interface; the singleton that writes NDJSON to stdout; the serialiser that decides which fields of an Error reach a log line (#95 F48) — see [Logging](#logging) |
| [`response-body.mts`](response-body.mts) | contract | what to do with a provider response body: read at most a bound of it as a JSON object ([`readBoundedJsonObject`](response-body.mts), the bound always the caller's), or release it unread ([`discardBody`](response-body.mts)) — which matters only beyond undici's 64 KiB read-ahead, where an unread body would hold its socket until collected. Both modes use it; it belongs to neither (#95 F28, F35, F37, F39). Its own contract is pinned by [`__tests__/response-body.test.mts`](__tests__/response-body.test.mts). |
| [`single-flight.mts`](single-flight.mts) | contract | [`SingleFlight`](single-flight.mts), with its in-memory default: one flight per key, the rejection shared with every waiter, the slot cleared in `finally`. Both modes coalesce with it; it belongs to neither. Its own contract is pinned by [`__tests__/single-flight.test.mts`](__tests__/single-flight.test.mts). |
| [`router/`](router) | assembly | the healthcheck and the shared upstream proxy stage — no README of its own; described [below](#srcrouter-and-srcmodes) |
| [`modes/`](modes) | process, external connection, contract, assembly — per file | the two modes, [`modes/injection/`](modes/injection/README.md) and [`modes/validation/`](modes/validation/README.md); the Kind of each file is in that mode's README. No README of its own; described [below](#srcrouter-and-srcmodes) |
| [`express/`](express/README.md) | contract | reading inbound headers (the `Bearer` grammar) and the request id; no decisions |
| [`oauth/`](oauth/README.md) | contract | how the proxy authenticates itself to the provider |
| [`../config/`](../config/README.md) | contract | the configuration schema and the shipped conf |

### `src/router` and `src/modes`

Neither directory has a README; this section is theirs.

**`src/router`** — *Role:* route assembly that is not a mode: the liveness probe ([`Healthcheck.mts`](router/Healthcheck.mts), mounted by `app.mts` through [`index.mts`](router/index.mts), which re-exports only `Healthcheck`) and the upstream proxy stage ([`createUpstreamProxy`](router/upstream.mts)), the last middleware of both mode routers, which import `upstream.mts` directly. *Owns:* the `/_healthcheck` path and its answer; building `express-http-proxy` from `upstream.baseURL` and `http.bodyLimitSize` ([`UpstreamStageConfig`](router/upstream.mts)). *Does not own:* what reaches upstream — that is decided on `req.headers` before the stage, by each mode; the mode routers themselves (`modes/*/router.mts`). *Why separate:* both files are assembly with no decision in them (the directory's row in #95's Directory table). The healthcheck has been in `src/router/` since the first commit (dcc8842), beside the original `Proxy.mts`, delegating to `@o3co/auth.utils`; 5811e97 only internalised its implementation. `upstream.mts` arrived later: the upstream stage was duplicated verbatim in both mode routers and moved here as one function (#95 F18). Why the two share a directory beyond both being assembly is not recorded.

**`src/modes`** — *Role:* the two alternative request paths; [`resolveRouter`](app-internal.mts) mounts exactly one, chosen by `auth.mode`. *Owns:* nothing at the directory level — every file is in [`modes/injection/`](modes/injection/README.md) or [`modes/validation/`](modes/validation/README.md), which state their own responsibility. *Does not own:* anything the two share; that sits at `src/` root or in `router/`, `express/`, `oauth/`. *Why separate:* each mode is a complete, alternative request path chosen once at boot, and neither imports the other; code both need lives outside `modes/`.

### Where shared modules live

There is no single placement rule; each shared module's location was decided with the change that made it shared. Current placement:

| Module | Where | Why there |
| --- | --- | --- |
| [`single-flight.mts`](single-flight.mts) | `src/` root | moved from `modes/injection/` when validation became its second user (#95 F6): validation importing it from another mode would break the direction rule. |
| [`response-body.mts`](response-body.mts) | `src/` root | created for body release across both modes' clients (#95 F37), "beside `single-flight.mts`"; `readBoundedJsonObject` joined it when validation became its third caller (#95 F39). |
| [`oauth/client-secret-basic.mts`](oauth/client-secret-basic.mts) | `src/oauth/` | extracted when the exchange became a second confidential-client path beside validation's introspection (#91); its README states it as the one place for how the proxy authenticates itself. |
| [`router/upstream.mts`](router/upstream.mts) | `src/router/` | assembly shared by both mode routers (#95 F18); see above. |
| [`modes/injection/token-endpoint.mts`](modes/injection/token-endpoint.mts) | `modes/injection/` | shared by the two injection clients only, not by validation; moved out of `session-grant-client.mts` so neither client imports the other (#95 F19). |
| [`express/bearer.mts`](express/bearer.mts) | `src/express/` | used by validation only; see [`src/express`](express/README.md#responsibility) for why it is there. |

## Public contract

The process: `node dist/src/app.mjs` (or `pnpm run debug`). Importing `app.mts` parses `../config/application.conf`, validates it and listens — there is no exported factory. Everything else is importable and assemblable by a test on its own.

## Inputs and outputs

`app.mts` mounts, in this order: the healthcheck, CORS, the mode router under `http.pathPrefix`; then `listen` and `installGracefulShutdown(server, { logger })`. The mode router is whichever [`resolveRouter`](app-internal.mts) picks from `auth.mode`, exhaustively; each ends with the shared upstream stage.

## Dependencies

Non-test edges: `app` → `config/application.schema`, `app-internal`, `logger`, `router/index`, `shutdown` · `app-internal` → `modes/injection/router`, `modes/validation/router` · `shutdown` → the `Logger` type · `modes/validation/router` → `modes/validation/decision`, `modes/validation/introspect`, `modes/validation/introspection-cache`, `modes/validation/introspection-client`, `express/requestId`, `router/upstream`, `logger`, `single-flight` · `modes/validation/decision` → `express/bearer`, `modes/validation/introspection-client` and the `Logger` type · `modes/validation/introspect` → `modes/validation/introspection-client`, and as types only `single-flight`, `modes/validation/decision`, `modes/validation/introspection-cache` · `modes/validation/introspection-client` → `oauth/client-secret-basic`, `response-body` · `modes/injection/router` → `express/requestId`, `router/upstream`, `logger`, `single-flight`, its siblings · `modes/injection/decision` → `single-flight` (as a type), its siblings and the `Logger` type · `modes/injection/exchange` → `single-flight` (as a type), its siblings and the `Logger` type · `modes/injection/jwt-bearer-client` → `oauth/client-secret-basic`, `response-body`, `provider-error`, `token-endpoint` · `modes/injection/session-grant-client` → `response-body`, `provider-error`, `token-endpoint` · `modes/injection/token-endpoint` → `response-body` · `router/upstream` → `express-http-proxy`. `config/application.schema` is also imported, as types only, by `app-internal`, both mode routers, `modes/injection/decision` and `modes/injection/exchange` ([`config/README.md`](../config/README.md#dependencies)). The only value imports of the logger singleton are `app` and the two mode routers. No cycles. Direction: `modes/*` depend on `express/`, `oauth/`, `router/upstream`, `logger`, `single-flight` and `response-body`; nothing under `express/`, `oauth/`, `router/` or `config/` imports a mode, and neither mode imports the other.

## Invariants

- **Healthcheck before CORS, outside `pathPrefix` (#95 F25).** `/_healthcheck` answers whatever the prefix is and without CORS headers, because it is mounted first and at the root (the `.use` chain in [`app.mts`](app.mts)) — that composition is documented, not tested: no test imports `app.mts`, which is why mode selection lives in `app-internal.mts`. The probe itself is liveness only — the process is up — and says nothing about the provider (the doc comment on the healthcheck [`createRouter`](router/Healthcheck.mts)); its path and GET-only method are pinned by [`Healthcheck.test.mts`](router/__tests__/Healthcheck.test.mts).
- **Shutdown drains, it does not wipe.** `app.mts` passes no `cleanup`, so the shutdown closes the listener, gives in-flight requests `drainTimeoutMs`, and exits; the token caches are left as they are and die with the process. The guarantees themselves — signals, idle sockets, the deadline, the non-zero exit, the bounded cleanup — are stated in the module doc comment of [`shutdown.mts`](shutdown.mts) and not repeated here; options are [`GracefulShutdownOptions`](shutdown.mts).
- **One logger.** Both mode routers use the singleton (the default export of [`logger.mts`](logger.mts)) as the default `deps.logger` and hand it to their decisions — [`decideInjection`](modes/injection/decision.mts), [`decideExchange`](modes/injection/exchange.mts), [`decideValidation`](modes/validation/decision.mts) — as a [`Logger`](logger.mts) (#95 F2, F3, F4), and `shutdown.mts` takes one as an option. Tests spy on the singleton, or inject a fake through `deps`. A replacement boundary on both paths (#95 F22). Output is NDJSON on stdout, level from `LOG_LEVEL` read when the logger is created ([`createProxyLogger`](logger.mts)) — the only environment read outside the HOCON parse in `app.mts`.
- **An Error reaches a log line through an allowlist (#95 F48).** The logger is built with `serializers: { error }`, so any value logged under the `error` key goes through [`serializeLoggedError`](logger.mts): an Error becomes its `type` (the class name), `message`, `stack`, and only the fields named in `LOGGED_ERROR_FIELDS` — `code`, `errno`, `syscall`, `status`, `refusedCredential` — with `cause` followed to at most `MAX_CAUSE_DEPTH` (5) levels, which also bounds a cyclic chain; every other property is dropped. The reason is security: some errors carry bytes nobody chose to log — undici's `HTTPParserError.data` is the unparsed rest of the provider's response, which may echo the token the proxy just sent. The message, the stack and the string fields pass through `redactUrlCredentials`, which rewrites `scheme://user:pass@host` to `scheme://***@host`, because undici puts the request URL in some messages and the configured introspection URL may carry userinfo. A non-Error under `error` (injection logs a string there) passes through unchanged. The serialiser covers the `error` key only: `shutdown.mts` logs a failed `server.close` and a failed cleanup under `err`, which pino's own default serialiser handles, not this allowlist. Neither error comes from a provider call — the first is the listener's own, and the second is unreachable in the shipped process because `app.mts` passes no `cleanup`.
- **`src/router/` holds the healthcheck and the upstream stage.** [`index.mts`](router/index.mts) re-exports only `Healthcheck`; [`upstream.mts`](router/upstream.mts) is imported by both mode routers directly (#95 F18). Its decorator does not choose what is forwarded: `express-http-proxy` has already copied every inbound header except `connection` and `host`, so the decorator's only effect on the wire is `Authorization` in canonical casing (it also re-sets `x-request-id` to the value already there). It is kept for header-name casing compatibility (#132): Node lower-cases inbound header names in `req.headers`, so without it an upstream would receive `authorization`; header names are case-insensitive (RFC 9110 §5.1), so a conforming upstream sees no difference, and the decorator serves one that matches the name case-sensitively. The reasoning is in the docstring on [`createUpstreamProxy`](router/upstream.mts); what the decorator does is pinned by [`upstream.test.mts`](router/__tests__/upstream.test.mts), and the casing on the wire by [`upstream-wire.test.mts`](router/__tests__/upstream-wire.test.mts). The routers that carry the modes are `modes/*/router.mts`.

## Logging

The logger's contract is the [`Logger`](logger.mts) interface and the `error` serialiser above. The field names are the callers', and today they differ by mode:

| Line | Request id field | Other fields |
| --- | --- | --- |
| each mode router's `incoming request` line (injection and validation alike) | `"x-request-id"` | `method`, `path` |
| injection decisions ([`decideInjection`](modes/injection/decision.mts), [`decideExchange`](modes/injection/exchange.mts)) | `requestId` | `event` (an `injection.*` name), and on a failure `error` as a **string** (the error's message, or `String(err)`) |
| validation decision ([`decideValidation`](modes/validation/decision.mts)) | `"x-request-id"` | `error` as the **Error** itself, serialised by the allowlist; no `event` field |
| shutdown ([`shutdown.mts`](shutdown.mts)) | none | `drainTimeoutMs`, `reason`, `drain`, `exitCode`, `cleanupTimeoutMs`, `err` |

Levels differ too: a provider 401 about the caller's credential is logged at `info` on the session path (`injection.session_unauthorized`) and at `error` on the validation path (the `introspect failed` line, which every introspection failure that is not a client-credential refusal or a redirect shares).

Known issue (#134): the two modes name the request id and the error differently (`requestId` / `event` / string `error` against `"x-request-id"` / Error `error`), and grade a caller-caused provider 401 at different levels, so one log query does not cover both modes.

## Failure and lifecycle

State held for the life of the process, and who owns it:

| State | Owner | Released |
| --- | --- | --- |
| parsed config | `config` in [`app.mts`](app.mts) | never; immutable after boot |
| session token cache and single-flight table, router-built (the default) | the [`createRouter`](modes/injection/router.mts) closure | at process exit |
| session token cache and single-flight table, supplied via `deps` (#95 F4) | the caller that supplied them — it may retain, clear or dispose them, and share them between routers whose grant context differs, since [`sessionCacheKey`](modes/injection/decision.mts) carries it (#95 F33) — what it must still match is the supplied `grantClient`, which cannot be hashed, and the cache policy, which decides how long an entry lives rather than which token comes back | the caller's responsibility; the router never clears what it did not build |
| exchange cache and single-flight table, router-built (the default) | the [`createRouter`](modes/injection/router.mts) closure | at process exit |
| exchange cache and single-flight table, supplied via `deps.exchange` (#95 F2) | the caller that supplied them — it may retain, clear or dispose them, and share them between routers whose exchange context differs, since [`exchangeCacheKey`](modes/injection/exchange.mts) carries it — what it must still match is `clientSecret` (not part of the context), the supplied `client` and the cache policy (#95 F33) | the caller's responsibility; the router never clears what it did not build |
| introspection cache and single-flight table, router-built (the default) | the [`createRouter`](modes/validation/router.mts) closure (#95 F5, F6) | at process exit |
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
| [`__tests__/logger.test.mts`](__tests__/logger.test.mts) | level selection, NDJSON, the `name` field, structured fields; and the `error` serialiser (#95 F48): an Error with its message, stack and cause chain (`serialises an Error under \`error\` with its message, stack and cause chain`), a string kept as it is (`keeps a string \`error\` as it is, which is how injection logs`), the allowlist dropping `data` and `headers` (`logs only the allowlisted fields of an error in the chain`), URL credentials redacted (`redacts URL credentials from messages and stacks`), a cyclic cause chain (`stops at a cycle in the cause chain`), a non-Error passed through (`passes a non-Error through, message-shaped or not`) |
| [`router/__tests__/Healthcheck.test.mts`](router/__tests__/Healthcheck.test.mts) | the `/_healthcheck` path and method |
| [`router/__tests__/upstream.test.mts`](router/__tests__/upstream.test.mts) | `createUpstreamProxy` targets `upstream.baseURL` with exactly `limit = http.bodyLimitSize` and the decorator; the decorator is a casing-only no-op on what the library already copied |
| [`router/__tests__/upstream-wire.test.mts`](router/__tests__/upstream-wire.test.mts) | through the real `express-http-proxy`, an upstream receives `Authorization` once, in canonical casing, though it arrived in lower case, and none when none arrived (#132) |

No test today for the `app.mts` composition itself: healthcheck before CORS, the `pathPrefix` mount, no `cleanup` passed (#95 F25). No test pins a shared log shape across modes; each mode's decision tests pin its own field names (validation's `{ "x-request-id": …, error }`, injection's `requestId`, `event` and `action`), so the divergence is pinned too; the routers' `incoming request` line is asserted by message only.
