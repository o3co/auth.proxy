# `src/modes/validation`

Validation mode: an inbound `Authorization: Bearer <token>` is checked against the provider's RFC 7662 introspection endpoint and the request is forwarded or refused. The wire behaviour and the credential choice are in the root README under [Validation mode](../../../README.md#validation-mode-authmode--validation) and [Introspection client identity](../../../README.md#introspection-client-identity); revocation under [Revocation and the access-token lifetime](../../../README.md#revocation-and-the-access-token-lifetime). This file states who owns what and which test pins it. The boundary review behind it is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

| File | Kind | Owns |
| --- | --- | --- |
| [`introspect.mts`](introspect.mts) | external connection + response validation + cache policy + cache storage, fused in one function ([`introspect`](introspect.mts), seven positional parameters) | the module-level `cache`; the error contract [`IntrospectHttpError`](introspect.mts); the credential choice [`buildAuthHeader`](introspect.mts) |
| [`router.mts`](router.mts) | process (the enforcement handler, the last middleware before the upstream stage) + assembly ([`createRouter`](router.mts), which mounts the shared upstream stage [`createUpstreamProxy`](../../router/upstream.mts)) | the resolved client credentials (`credentials` in `createRouter`) |

`introspect.mts` is client and cache in one module. Its state is a module singleton, shared by every router created in the process and reset only by [`clearCache`](introspect.mts), which exists as the test seam (the `beforeEach` in [`introspect.test.mts`](__tests__/introspect.test.mts) and in [`router.test.mts`](__tests__/router.test.mts)). There is no client interface and no cache interface here — injection has both — and the router calls the concrete function directly (the `introspect(...)` call in [`createRouter`](router.mts)). #95 tracks separating the client from the cache without changing behaviour (F5).

## Public contract

`createRouter({ config })` returns an Express router and throws unless `auth.mode` is `"validation"` (the guard at the top of [`createRouter`](router.mts)). Refusals are `{ "code", "message" }` — a different shape from injection's — with no `WWW-Authenticate`.

| Inbound | Answer | Where | Pinned by ([`router.test.mts`](__tests__/router.test.mts)) |
| --- | --- | --- | --- |
| no `Authorization` | forwarded unchanged | the first check in the handler | `passes a request without Authorization through to upstream without consulting the provider` |
| not `Bearer <token>` (scheme case-sensitive) | `400 Invalid Token Type` | `extractBearerToken` returning `null` | `answers 400 Invalid Token Type to a non-Bearer scheme without consulting the provider` |
| `active: false` — including a `cnf`, a non-Bearer `token_type`, or expiry during the call | `401 Invalid Token` | the `!result.active` check | `refuses bound token %j before forwarding`; `forwards a live token, then refuses it when its warm cache reaches exp` |
| provider `401` | `401 Invalid Token` | `IntrospectHttpError` with status 401 in the `catch` | `answers 401 Invalid Token when the provider answers 401` |
| any other failure: non-2xx, invalid body, timeout, network | `500 Internal Server Error` | the `catch` fallthrough | `answers 500 Internal Server Error when $failure` (a provider 503, a 200 with a non-JSON body, a rejected `fetch`) |
| `active: true` | forwarded; upstream receives the inbound `Authorization` bytes | `next()` into the shared stage ([`createUpstreamProxy`](../../router/upstream.mts)) | `forwards a live token, then refuses it when its warm cache reaches exp` |

**What a provider 401 means (F7).** Without client credentials the inbound token *is* the introspection credential (`Bearer <token>`, [`buildAuthHeader`](introspect.mts)), so a provider 401 is about that token and `401 Invalid Token` is right. With `CLIENT_ID` / `CLIENT_SECRET` the credential is the proxy's own `client_secret_basic`, and a provider 401 means the proxy's client authentication was refused (RFC 7662 §2.3) — a configuration error, answered today as the same `401 Invalid Token`, indistinguishable on the wire. Injection mode tells the two apart (`provider_config_error` 502). #95 flags this as a separate decision; nothing has changed yet.

## Inputs and outputs

- In: `Authorization`, read by [`extractBearerToken`](../../express/bearer.mts) — case-sensitive `Bearer`, then the first SP-delimited word; `x-request-id` as normalised by [`express/requestId.mts`](../../express/README.md).
- Out, provider: `POST auth.validation.introspect.url`, form body `token=<token>`, `Authorization` either Basic (both client credentials set) or `Bearer <token>`, `x-request-id`, `AbortSignal.timeout(timeoutMs)` (the `fetch` call in [`introspect`](introspect.mts)).
- Out, upstream: the inbound request with every inbound header — `express-http-proxy` copies `req.headers` wholesale except `connection` and `host`, cookies included (`reqHeaders` in its `lib/requestOptions.js`); this handler modifies nothing, and the shared stage's decorator only re-sets casing ([`createUpstreamProxy`](../../router/upstream.mts)). **The forwarded header is the inbound bytes unchanged, while the introspected token is the first SP-delimited word** (F14): `Bearer abc123 extra` introspects `abc123` and forwards `Bearer abc123 extra`. The extraction half is pinned by [`keeps only the first token when the header carries trailing content`](../../express/__tests__/bearer.test.mts); the forwarding half is documented, not tested. The upstream must verify the token it is handed regardless ([Inbound Authorization headers](../../../README.md#inbound-authorization-headers)).

## Dependencies

`router` → [`express/bearer`](../../express/bearer.mts), [`express/requestId`](../../express/requestId.mts), [`router/upstream`](../../router/upstream.mts), the [`logger`](../../logger.mts) singleton, `introspect`, the config types · `introspect` → [`oauth/client-secret-basic`](../../oauth/client-secret-basic.mts). No cycles. The upstream proxy stage is [`createUpstreamProxy`](../../router/upstream.mts) (`src/router/upstream.mts`), shared with injection (F18, #97).

## Invariants

1. **Parsed once.** `Authorization` is parsed once, by [`extractBearerToken`](../../express/bearer.mts) at the top of the handler, and every decision reads `bearer.token`. What is forwarded is decided by `req.headers`, which this handler never modifies: the library copies every inbound header and the shared stage's decorator only re-sets casing — see the docstring on [`createUpstreamProxy`](../../router/upstream.mts), which also notes that dropping the decorator is tracked with F14 / F15 on #95. `BearerToken.raw` is unused anywhere today (F15).
2. **Cache key and bound.** Key = SHA-256 of the token ([`getCacheKey`](introspect.mts)). An entry expires at `min(now + cacheTtlSec, exp)` with `now` captured before the fetch, so entries are capped at `exp` and anchored at the request. Pinned by [`returns cached result on second call within TTL`](__tests__/introspect.test.mts), [`stops accepting a warm cache entry at the token's exp`](__tests__/introspect.test.mts) and, through the router, [`forwards a live token, then refuses it when its warm cache reaches exp`](__tests__/router.test.mts). `cacheTtlSec` ≤ 0 disables the read — pinned by [`does not reuse a cached result when caching is disabled`](__tests__/introspect.test.mts) — and the write, which is documented, not tested.
3. **What is never cached:** a response carrying `cnf` or a non-Bearer `token_type` (answered `active: false`), a token that expired during the call, an entry already past its bound on arrival, and every error — each throw precedes the single `cache.set` in [`introspect`](introspect.mts). Pinned by [`refuses a positive response that expires during the provider call`](__tests__/introspect.test.mts), [`refuses unsupported possession evidence on the Bearer path: %j`](__tests__/introspect.test.mts), [`refuses bound token %j before forwarding`](__tests__/router.test.mts); the error case is documented, not tested.
4. **What is cached:** the validated response as returned, whether `active` is `true` or `false` (the `cache.set` in [`introspect`](introspect.mts)) — a negative answer is held for the same bound. Documented, not tested.
5. **Only a boolean `active` is trusted** (the RFC 7662 §2.2 check in [`introspect`](introspect.mts)); `{"active":"false"}` is a 502, not a bypass. Pinned by [`throws IntrospectHttpError(502) when active is not a boolean`](__tests__/introspect.test.mts), [`throws IntrospectHttpError(502) when 200 body is valid JSON but not a plain object`](__tests__/introspect.test.mts).
6. **Eviction:** expired entries are swept, then the oldest insertion is dropped at `cacheMaxEntries` (the sweep just before the `cache.set` in [`introspect`](introspect.mts)). Pinned by [`evicts oldest entry when cache exceeds maxCacheEntries`](__tests__/introspect.test.mts).
7. **No single-flight (F6).** There is no pending table, so concurrent misses on one token each call the provider — unlike the session and exchange paths, which coalesce. Adding it is a behaviour change and a separate decision. Documented, not tested.

## Failure and lifecycle

- [`IntrospectHttpError`](introspect.mts) carries the provider's status for a non-2xx and `502` for a 200 whose body is not a valid RFC 7662 response. A rejected `fetch` — timeout or network — propagates unwrapped ([`propagates fetch rejection (network error / AbortError)`](__tests__/introspect.test.mts)); the router logs `introspect failed` with the error and answers 500 ([`answers 500 Internal Server Error when $failure`](__tests__/router.test.mts)).
- **Cancellation is the timeout only:** `introspect` accepts no signal; a caller's disconnect does not abort the provider call. Documented, not tested (F10).
- **Lifetime (F21):** the cache is created at module load (the module-level `cache` in [`introspect.mts`](introspect.mts)) and lives until process exit; [`app.mts`](../../app.mts) passes no `cleanup`, so a drain does not wipe it. Nothing needs releasing.
- `cacheMaxEntries` and `timeoutMs` defaults are declared a third time as parameter defaults of [`introspect`](introspect.mts); the schema is authoritative — see [`config/README.md`](../../../config/README.md). #95 tracks removing the copy.

## Contract tests

| Test file | Pins |
| --- | --- |
| [`__tests__/introspect.test.mts`](__tests__/introspect.test.mts) | request shape and credential header (`sends form-urlencoded body with correct Content-Type`, `uses Basic auth header when client credentials are configured`), timeout (`passes custom timeoutMs as AbortSignal.timeout`), the cache bound, TTL 0 on the read, malformed `exp` (`refuses malformed exp $exp`), bound tokens, non-boolean `active`, non-object and non-JSON bodies (`throws IntrospectHttpError(502) on 200 with non-JSON body`), status passthrough (`throws IntrospectHttpError with matching status on non-2xx response`), rejection propagation, eviction. |
| [`__tests__/router.test.mts`](__tests__/router.test.mts) | through the router: a warm entry refused at `exp` (`forwards a live token, then refuses it when its warm cache reaches exp`); a bound token refused before the upstream (`refuses bound token %j before forwarding`); the router's own mappings (F27, #96): `passes a request without Authorization through to upstream without consulting the provider`, `answers 400 Invalid Token Type to a non-Bearer scheme without consulting the provider`, `answers 401 Invalid Token when the provider answers 401`, `answers 500 Internal Server Error when $failure` — the 401 and 500 cases also assert `fetch` was called exactly once. |

Untested today: concurrent misses (invariant 7), caller cancellation, negative-result caching (invariant 4), TTL 0 disabling the write (invariant 2), and the forwarded `Authorization` equalling the inbound bytes (F14).
