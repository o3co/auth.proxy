# `src`

Last updated: 2026-09-24

The whole proxy process. Wire behaviour is in the [root README](../README.md); each directory that owns a contract has its own README. The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** The root holds the composition root ([`app.mts`](app.mts), the process entry point), the mode selection it calls, and the pieces both modes share: the logger, graceful shutdown, request coalescing and the provider-body helpers. The directories are the two modes (`modes/`), the route assembly both modes mount (`router/`), the inbound-header helpers ([`express/`](express/README.md)) and client authentication ([`oauth/`](oauth/README.md)). Configuration is [`../config/`](../config/README.md), outside `src/`.

**Owns:** assembling the server and the order it mounts things in; the process lifecycle (listen, drain, exit); the logger and what an error looks like in a log line; the modules both modes share.

**Does not own:** any mode's decision, provider client or cache (`modes/*`, each with its own README); header grammar (`express/`); the client-authentication encoding (`oauth/`); configuration defaults and validation (`config/`).

**Why separate.** The root holds only what is assembly or shared by both modes. A mode may import the root's shared modules but never the other mode, so a module both modes need lives here rather than in either mode (#95 F6, F39).

### `src/router`

No README of its own; this is its description.

- **Role:** route assembly that is not a mode — the liveness probe, which `app.mts` mounts, and the upstream proxy stage, the last middleware of both mode routers.
- **Owns:** the `/_healthcheck` path and its answer; building the upstream proxy from `upstream.baseURL` and `http.bodyLimitSize`.
- **Does not own:** what reaches upstream — each mode decides that on `req.headers` before the stage; the mode routers themselves (`modes/*/router.mts`).
- **Why separate:** both are assembly with no decision in them (#95 F18).

### `src/modes`

No README of its own; this is its description.

- **Role:** the two alternative request paths. [`resolveRouter`](app-internal.mts) mounts exactly one, chosen by `auth.mode` at boot.
- **Owns:** nothing at the directory level; [`modes/injection/`](modes/injection/README.md) and [`modes/validation/`](modes/validation/README.md) state their own responsibility.
- **Does not own:** anything the two share; that sits at the `src/` root or in `router/`, `express/` or `oauth/`.
- **Why separate:** each mode is a complete, alternative request path chosen once at boot, and neither imports the other.

### Where shared modules live

Code both modes need sits outside `modes/`, because neither mode may import the other: at the `src/` root (the logger, coalescing, provider-body handling), in `oauth/` (how the proxy authenticates itself to the provider), in `router/` (route assembly) or in `express/` (inbound-header parsing).

## Dependencies

- `modes/*` may import the `src/` root's shared modules, `express/`, `oauth/`, `router/upstream.mts` and `config/`. Neither mode imports the other.
- Nothing under `express/`, `oauth/`, `router/` or `config/` imports a mode, and the root's shared modules import no mode. In production code, only `app-internal.mts` imports a mode, to select its router.
- `express/` and `oauth/` import nothing else in `src/`.

## Invariants

- **The healthcheck is outside `pathPrefix` and CORS (#95 F25).** It is mounted first and at the root, so `/_healthcheck` answers whatever the prefix is and without CORS headers. It is liveness only — the process is up — and says nothing about the provider. The composition in `app.mts` is not tested (no test imports it); the probe's path and method are pinned by [`router/__tests__/Healthcheck.test.mts`](router/__tests__/Healthcheck.test.mts).
- **Shutdown drains; it does not wipe.** The process passes no cleanup to the shutdown, so the token caches die with the process. The shutdown guarantees are stated in the header of [`shutdown.mts`](shutdown.mts).
- **State belongs to whoever built it.** Parsed configuration is immutable after boot and passed down as an argument; caches and coalescing tables live in the closure that built them, and a router never clears state it was handed rather than built.
- **One logger.** Every module logs through the [`Logger`](logger.mts) interface; the mode routers default to the singleton and hand it to their decisions, and tests inject a fake through `deps`. Configuration comes from the HOCON parse in `app.mts`; the one environment read outside it is `LOG_LEVEL`, in `logger.mts`.
- **An Error reaches a log line only through an allowlist (#95 F48).** Some errors carry bytes nobody chose to log — undici's `HTTPParserError.data` is the unparsed rest of the provider's response, which may echo the token the proxy just sent — so an `Error` logged under the `error` key keeps only named fields, with URL credentials redacted; everything else on it is dropped. A value under `error` that is not an `Error` passes through unchanged: injection logs `String(err)` there for a throw it could not classify, whatever that message holds. The allowlist covers the `error` key only; `shutdown.mts` logs its own failures, which are not provider errors, under `err`. The mechanics are in the header of [`logger.mts`](logger.mts), pinned by [`__tests__/logger.test.mts`](__tests__/logger.test.mts).
- **One log vocabulary for both modes (#134).** Every line about a request — each router's `incoming request` and every decision line — carries the request id as `requestId` and an `event` named after its mode (`injection.*`, `validation.*`), so a query on `requestId` covers both modes; the event names are per mode. The level of a provider failure says whose it was: the provider refusing the caller's credential is `info` (a refusal of what the credential may do, injection's `exchange_not_permitted`, is `warn`); the proxy's own failures — its client refused, a redirect, a provider `5xx`, a timeout, an invalid response, an unexpected throw — are `error`. Pinned by each mode's `decision.test.mts` and `router.test.mts`.
- **A provider failure never stops the process.** A configuration error stops it before it listens; a provider failure is answered per mode; SIGTERM / SIGINT start the drain.
