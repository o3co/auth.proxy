# `src/modes/injection`

Last updated: 2026-09-24

Injection mode turns a session cookie into the outbound `Authorization: Bearer` header. With the exchange enabled, it does the same for an external JWT. The root README describes the wire behaviour under [Injection mode](../../../README.md#injection-mode-authmode--injection), [Cache behavior](../../../README.md#cache-behavior), [Scope boundary](../../../README.md#scope-boundary), [CSRF responsibility boundary](../../../README.md#csrf-responsibility-boundary), [Cookie forwarding](../../../README.md#cookie-forwarding) and [External credential exchange](../../../README.md#external-credential-exchange-authinjectionexchange). The boundary review behind this directory is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** This directory is the proxy's whole request path when `auth.mode` is `"injection"`: [`resolveRouter`](../../app-internal.mts) mounts its [`createRouter`](router.mts). Outside tests, `app-internal.mts` is the only file that imports this directory. It talks to the provider's token endpoint through its own two clients, one for the session grant and one for the RFC 7523 jwt-bearer exchange.

**Owns:**
- turning a session cookie, or with the exchange enabled an inbound assertion, into the outbound `Authorization`;
- the two token clients and their error codes;
- the token caches, with their keys and expiry;
- what is logged about each request on this path.

**Does not own:**
- the upstream proxy stage ([`src/router`](../../router/upstream.mts)) and the request id ([`src/express`](../../express/README.md));
- the coalescing primitive ([`single-flight.mts`](../../single-flight.mts)) and the bounded body read ([`response-body.mts`](../../response-body.mts)), which sit at `src/` root because both modes use them;
- configuration defaults ([`config/`](../../../config/README.md));
- verifying the inbound assertion, which is the provider's job. This side reads the assertion unverified, and uses its claims only to refuse early or to shorten a cache entry.

**Why a separate module.** Each mode is a complete, alternative request path, chosen once by `auth.mode`, and the two modes share only what sits outside `src/modes/`. Within this directory, the decisions ([`decideInjection`](decision.mts), [`decideExchange`](exchange.mts)) never see Express. That keeps them testable on their own and lets their dependencies be injected (#95 F1, F2, F4). The router only reads headers and applies the outcome.

**Contracts live beside their default implementation.** A client contract and its error class are declared in the same file as the bundled client ([`session-grant-client.mts`](session-grant-client.mts), [`jwt-bearer-client.mts`](jwt-bearer-client.mts)), and the cache contract beside its default ([`token-cache.mts`](token-cache.mts)). The decisions classify a failure with `instanceof SessionGrantError` or `instanceof JwtBearerError`, so a client supplied through `deps` must throw those classes.

## Invariants

1. **Each credential is parsed once.** The `Cookie` header is parsed once per request, by [`extractCookie`](cookie-extractor.mts), at the top of `decideInjection`. On the exchange path, `Authorization` is parsed once, by [`parseBearerAssertion`](bearer-assertion.mts), at the top of `decideExchange`. The session path never parses `Authorization`: it checks only whether the header is present, and an empty value counts as present. The parsers are tested on their own ([`cookie-extractor.test.mts`](__tests__/cookie-extractor.test.mts), [`bearer-assertion.test.mts`](__tests__/bearer-assertion.test.mts)). That each runs once per request is not tested.
2. **What reaches upstream is decided on `req.headers`, before the shared stage.** The other inbound headers pass through as the shared stage forwards them. `Authorization` is exactly one of three things:
   - the minted token (`inject`);
   - removed (`forward_stripped`), when `stripInboundAuthorization` is on and the header is present;
   - left as received (`forward`).

   With the exchange enabled, an inbound `Authorization` is never forwarded as received: it is exchanged, or the request is refused. Pinned by [`router.test.mts`](__tests__/router.test.mts) and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts).
3. **Credential bytes are not logged.** Log lines carry the request id and bounded classes, never a cookie value, an assertion, an issued token or the client secret. A provider's `error` and `error_description` are logged or relayed only after the sanitisers in [`provider-error.mts`](provider-error.mts) have run. The sanitisers refuse text containing any credential the request sent, whatever its length, because the proxy does not choose how long a session cookie value is. The unverified `iss` is not logged. The one exception is an unclassified throw, which is logged as `String(err)`. Pinned by [`provider-error.test.mts`](__tests__/provider-error.test.mts), [`cookie-extractor.test.mts`](__tests__/cookie-extractor.test.mts), [`session-grant-client.test.mts`](__tests__/session-grant-client.test.mts), [`jwt-bearer-client.test.mts`](__tests__/jwt-bearer-client.test.mts), [`exchange-decision.test.mts`](__tests__/exchange-decision.test.mts), [`router.test.mts`](__tests__/router.test.mts) and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts).
4. **Success from the provider is a `200` with a token, and nothing else.** Both clients read only a `200` as success (RFC 6749 §5.1). It must carry a non-empty `access_token`, and on the exchange a Bearer `token_type`. Any other `2xx` is `provider_unavailable`. Every provider body is read against a bound, or released unread when the status alone decides the answer:
   - a token response is read up to `MAX_TOKEN_BODY_BYTES` ([`token-endpoint.mts`](token-endpoint.mts));
   - an error body is read up to `MAX_ERROR_BODY_BYTES` ([`provider-error.mts`](provider-error.mts)).

   Pinned by [`session-grant-client.test.mts`](__tests__/session-grant-client.test.mts), [`jwt-bearer-client.test.mts`](__tests__/jwt-bearer-client.test.mts) and [`token-endpoint.test.mts`](__tests__/token-endpoint.test.mts).
5. **Redirects are refused. There is no retry and no fallback.** Both token clients set `redirect: "manual"` and answer a `3xx` as `502 provider_config_error` (#95 F8). This is because a followed redirect would either replay the credential to a path nothing configured, or strip it and misreport the result. Each call submits once. The exchange never falls back to the session grant, nor the reverse: a request carrying both credentials is refused `400 credential_ambiguous`. Pinned by the two client tests and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts). [`session-grant-client-wire.test.mts`](__tests__/session-grant-client-wire.test.mts) and [`jwt-bearer-client-wire.test.mts`](__tests__/jwt-bearer-client-wire.test.mts) pin this and the bounds in invariant 4 through the real `fetch`, against a fake provider on a real socket: a redirect sends nothing further, and a body past its bound or never finished closes its connection.
6. **The cache is written only on success, and its lifetime is anchored at the request.** The only writes sit inside the flight, after the client has returned, so a failure is never cached. An entry expires at `min(requestedAt + ttl, requestedAt + expires_in, exp) − safetyMargin`:
   - `requestedAt` is captured before the call goes out;
   - `exp`, the assertion's own expiry, applies on the exchange path only, and an assertion without an `exp` is not cached;
   - an entry whose expiry has already passed is not written.

   Pinned by [`cache-expiry.test.mts`](__tests__/cache-expiry.test.mts), [`decision.test.mts`](__tests__/decision.test.mts), [`exchange-decision.test.mts`](__tests__/exchange-decision.test.mts), [`router.test.mts`](__tests__/router.test.mts) and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts).
7. **Cache keys and bounds.** Each key is a SHA-256 over a JSON array of the grant context and the credential ([`sessionCacheKey`](decision.mts), [`exchangeCacheKey`](exchange.mts)), so the credential never appears in the key. The session and exchange paths each have their own cache and flight table. Each cache is bounded at `tokenCache.maxEntries`: writes sweep expired entries and then drop the oldest insertion. Because the key carries the grant context, a supplied cache or flight table may be shared between routers. Those routers must still match what the key cannot carry:
   - the supplied client;
   - the exchange's `clientSecret`;
   - the cache policy.

   Pinned by [`token-cache.test.mts`](__tests__/token-cache.test.mts), [`decision.test.mts`](__tests__/decision.test.mts), [`exchange.test.mts`](__tests__/exchange.test.mts) and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts).
8. **Single-flight, and cancellation is the timeout only.** Concurrent misses on one key share one provider call ([`SingleFlight`](../../single-flight.mts)). The rejection is shared with every waiter, and the slot is cleared either way. Neither client accepts a signal: the only abort is `AbortSignal.timeout(timeoutMs)`. A caller that disconnects therefore does not abort a flight that other waiters share (#95 F10). Pinned by [`single-flight.test.mts`](../../__tests__/single-flight.test.mts), [`decision.test.mts`](__tests__/decision.test.mts), [`router.test.mts`](__tests__/router.test.mts) (which covers the disconnect on a real socket) and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts). The exchange path has no disconnect test of its own.
9. **How failures map to statuses.** Every refusal is a JSON body `{ "error", "error_description" }`, with the provider's `Retry-After` passed through. No refusal carries a `WWW-Authenticate` header: the caller holds a session cookie, not an RFC 6750 credential to challenge for.
   - **Provider refusals.** The `error` is the client's code ([`SessionGrantErrorCode`](session-grant-client.mts), [`JwtBearerErrorCode`](jwt-bearer-client.mts)), except that `session_unauthorized` is answered as `session_required`.
   - **Refusals before any provider call** are made by the exchange ([`decideExchange`](exchange.mts)):
     - `credential_ambiguous` (400);
     - `credential_unsupported` (401);
     - `credential_rejected` (401), for an issuer outside `allowedIssuers`.
   - **A provider `401`** on the session path is `401 session_required`, unless its `error` is `invalid_client`: that means the proxy's own `clientId` was refused, and it is answered `502 provider_config_error` (#95 F47). On the exchange, a provider `401` is always `502 provider_config_error`.
   - **Everything else.** A timeout or a network error before the response arrives, or an unclassified throw, is `502 provider_unavailable`. A failure while reading a `200`'s body — a timeout or a dropped connection mid-body — is `502 provider_invalid_response`.

   Each code maps to exactly one log event and level, and a code the union does not declare is logged rather than dropped. Pinned by [`decision.test.mts`](__tests__/decision.test.mts), [`exchange-decision.test.mts`](__tests__/exchange-decision.test.mts), [`router.test.mts`](__tests__/router.test.mts), [`exchange-router.test.mts`](__tests__/exchange-router.test.mts) and the two client tests.
10. **The router owns only what it builds.** `createRouter({ config, deps })` refuses any mode other than `"injection"`. For each dependency, it takes what the caller supplied under `deps` or `deps.exchange`, and builds the rest. `deps.exchange` is refused while the exchange is disabled. Anything the router built lives in its closure until process exit, and nothing clears it; anything the caller supplied remains the caller's. Pinned by [`router.test.mts`](__tests__/router.test.mts) and [`exchange-router.test.mts`](__tests__/exchange-router.test.mts). That shutdown leaves the caches untouched is not tested.

## Dependencies

- **Within `src/`:** [`router/upstream.mts`](../../router/upstream.mts), `express/requestId.mts`, [`oauth/client-secret-basic.mts`](../../oauth/client-secret-basic.mts) (the exchange's client authentication), and the root modules `single-flight.mts`, `response-body.mts` and `logger.mts`. Only the router takes the logger singleton; the decisions see just the `Logger` type.
- **Outside `src/`:** `config/application.schema.mts`, as types only.
- **Packages:** `express` and `node:crypto`.
- **Never imported:** `src/modes/validation`, which in turn never imports this directory. This mode does not use `express/bearer.mts`, because the exchange parses `Authorization` with its own grammar.
- **Inside the directory:** no import cycles, and neither token client imports the other. What they share lives in `token-endpoint.mts` and `provider-error.mts` (#95 F19).
