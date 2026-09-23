# `src/modes/validation`

Last updated: 2026-09-24

In validation mode, an inbound `Authorization: Bearer <token>` is checked against the provider's RFC 7662 introspection endpoint, and the request is then forwarded or refused. The root README covers the wire behaviour and the credential choice under [Validation mode](../../../README.md#validation-mode-authmode--validation) and [Introspection client identity](../../../README.md#introspection-client-identity). It covers revocation under [Revocation and the access-token lifetime](../../../README.md#revocation-and-the-access-token-lifetime). The boundary review behind this directory is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** This directory is the proxy's whole request path when `auth.mode` is `"validation"`. [`resolveRouter`](../../app-internal.mts) mounts its [`createRouter`](router.mts), and outside tests `app-internal.mts` is the only file that imports this directory. It reaches the provider's introspection endpoint through its own client.

**Owns:**
- whether an inbound Bearer token is forwarded or refused;
- a refusal's status, body and `WWW-Authenticate` challenge;
- the introspection client and its error contract ([`IntrospectHttpError`](introspection-client.mts));
- which responses are accepted and cached;
- the cache, its key and its bound;
- the coalescing of concurrent misses.

**Does not own:**
- the upstream proxy stage ([`src/router`](../../router/upstream.mts));
- the request id and the Bearer grammar ([`src/express`](../../express/README.md));
- the coalescing primitive ([`single-flight.mts`](../../single-flight.mts)) and the bounded body read ([`response-body.mts`](../../response-body.mts)), both of which sit at `src/` root because both modes use them;
- configuration defaults ([`config/`](../../../config/README.md));
- verifying the forwarded token for the upstream. The upstream receives the inbound bytes and must verify the token itself ([Inbound Authorization headers](../../../README.md#inbound-authorization-headers)).

**Why a separate module.** Each mode is a complete request path, the two are alternatives, and `auth.mode` picks one of them once. The two modes share only what sits outside `src/modes/`. Within this directory, the decision ([`decideValidation`](decision.mts)) never sees Express, so it can be tested without Express and its dependencies can be injected (#95 F3). The provider's endpoint, the cache, and the reading of a response between them are separate, each behind its own interface (#95 F5).

**Contracts sit beside their default implementation.** The client contract and its error class are declared in the same file as the bundled client ([`introspection-client.mts`](introspection-client.mts)), and the cache contract sits beside its default ([`introspection-cache.mts`](introspection-cache.mts)). The decision classifies a failure with `instanceof IntrospectHttpError`. A supplied introspector must therefore throw that class if it wants a provider failure answered `401` or `502` rather than `500`.

## Invariants

1. **`Authorization` is parsed once and never rewritten.** It is parsed once, by [`extractBearerToken`](../../express/bearer.mts) at the top of `decideValidation`, and every later step reads the token that call returned. The middleware never modifies `req.headers` on this path. What is introspected is the first SP-delimited word, while what goes upstream is the inbound header unchanged (#95 F14): `Bearer abc123 extra` introspects `abc123` and forwards `Bearer abc123 extra`. [`decision.test.mts`](__tests__/decision.test.mts), [`router.test.mts`](__tests__/router.test.mts) and [`bearer.test.mts`](../../express/__tests__/bearer.test.mts) pin this. That the parse happens once per request is not tested.
2. **Only `active: true` forwards.** The client accepts only a boolean `active` (RFC 7662 §2.2), and anything else is a `502`, never a bypass. The decision forwards on `=== true` alone, so a non-boolean from a supplied introspector is a `401`. [`introspection-client.test.mts`](__tests__/introspection-client.test.mts) and [`decision.test.mts`](__tests__/decision.test.mts) pin this.
3. **This path refuses more than the provider does.** Four cases, handled in [`introspect.mts`](introspect.mts):
   - a response carrying `cnf` (possession evidence this path cannot check) is answered `active: false`;
   - so is one with a non-Bearer `token_type`;
   - so is a token that expired while the call was in flight;
   - a malformed `exp` is a `502`.

   [`introspect.test.mts`](__tests__/introspect.test.mts) and [`router.test.mts`](__tests__/router.test.mts) pin this.
4. **What is cached, and for how long.**
   - **Key.** The key is the SHA-256 of the token, never the token itself.
   - **Lifetime.** An entry expires at `min(now + cacheTtlSec, exp)`, where `now` is captured before the call goes out.
   - **Cached.** The provider's validated answer is cached, and that includes a plain `active: false`.
   - **Never cached.** The refusals this path makes itself, an entry already past its bound when it arrives, and any error.
   - **Disabled.** `cacheTtlSec` ≤ 0 turns off both reading and writing.
   - **Bound.** The cache holds at most `cacheMaxEntries`. Each write sweeps expired entries, then drops the oldest insertion. Re-writing a key already held evicts nothing. This cache is its own implementation, not injection's `TokenCache`; how the two differ is recorded in the doc comment on [`IntrospectionCache`](introspection-cache.mts).

   [`introspect.test.mts`](__tests__/introspect.test.mts), [`introspection-cache.test.mts`](__tests__/introspection-cache.test.mts) and [`router.test.mts`](__tests__/router.test.mts) pin this. The error case is not tested.
5. **One flight per token (#95 F6).** Concurrent misses on one token share one provider call. The flight table is [`SingleFlight`](../../single-flight.mts), keyed by the same digest as the cache.
   - The leader's answer, and the leader's rejection, go to every waiter, and only the leader writes the cache.
   - The slot clears either way.
   - The flight does not depend on `cacheTtlSec`: with the cache off, requests still coalesce.
   - When requests coalesce, the provider sees only the leader's `x-request-id`, and a shared rejection is logged once per waiter.
   - The table is not bounded by `cacheMaxEntries`; what bounds it is stated on `IntrospectorConfig.singleFlight` in [`introspect.mts`](introspect.mts).

   [`introspect.test.mts`](__tests__/introspect.test.mts) and [`build-introspector.test.mts`](__tests__/build-introspector.test.mts) pin this. The table's high-water mark is not tested.
6. **Redirects are refused, and provider bodies are bounded.** The client sets `redirect: "manual"`, and a `3xx` becomes `502 Provider Configuration Error` (#95 F43). A `200` body is read up to [`MAX_INTROSPECTION_BODY_BYTES`](introspection-client.mts) as a JSON object. A non-2xx body is released unread. [`introspection-client.test.mts`](__tests__/introspection-client.test.mts), [`decision.test.mts`](__tests__/decision.test.mts) and [`router.test.mts`](__tests__/router.test.mts) pin this.
7. **The timeout is the only cancellation (#95 F10).** Neither the client nor the `Introspector` accepts a signal, and the only abort is `AbortSignal.timeout(timeoutMs)`. A caller that disconnects does not abort a flight that others wait on. The flight completes, and its answer is cached when it is cacheable. [`router.test.mts`](__tests__/router.test.mts) pins this on a real socket.
8. **How failures map to statuses.** A refusal's body is `{ "code", "message" }`. A refusal about the caller's credential is a `400` or a `401`, and it carries the RFC 6750 §3 challenge:
   - on a `401`: `error="invalid_token"`;
   - on a `Bearer` credential that is malformed: `error="invalid_request"`;
   - on another auth method: the realm alone, or no header at all when no realm is configured;
   - whenever `auth.validation.realm` is set, the realm comes first in the challenge (#95 F29, F45).

   A provider's `401` is about the caller only when the inbound token was itself the introspection credential. When the proxy authenticated with its own client credentials, a `401` means the provider refused the proxy (#95 F7). Provider failures are `502` and carry no challenge:
   - `Provider Configuration Error` when the deployment's own configuration was refused, or the endpoint redirected;
   - `Bad Gateway` for everything else, which includes a timeout (#95 F42).

   Anything the proxy did not expect is a `500`. A caller should therefore retry a `502`, which is the provider failing and can recover, and not a `500`, which is the proxy's own. No `Retry-After` is passed through, so a caller that retries backs off on its own. The full table is the doc comment on [`decideValidation`](decision.mts). [`decision.test.mts`](__tests__/decision.test.mts) and [`router.test.mts`](__tests__/router.test.mts) pin this.
9. **Failures are logged without the token.** The failure lines carry the request id and the error. The logger serialises the error through its allowlist ([`logger.mts`](../../logger.mts)), which drops fields that may echo the token, such as an undici parser error's `data`. [`decision.test.mts`](__tests__/decision.test.mts) and [`logger.test.mts`](../../__tests__/logger.test.mts) pin this.
10. **One seam, and the router owns what it builds.** `createRouter({ config, deps })` refuses any mode other than `"validation"`. `deps` can supply only the introspector and the logger. A supplied introspector replaces the client, the cache and the flight table together. It then owns what the bundled one guarantees and the decision does not: the boolean `active` check, the refusals in invariant 3, its own timeout and its own coalescing. Each router builds its own cache and its own flight table, and they live in its closure until the process exits. [`build-introspector.test.mts`](__tests__/build-introspector.test.mts) and [`router.test.mts`](__tests__/router.test.mts) pin this. That shutdown leaves the cache untouched is not tested.

## Dependencies

- **Within `src/`:**
  - [`express/bearer.mts`](../../express/bearer.mts) and `express/requestId.mts`;
  - [`router/upstream.mts`](../../router/upstream.mts);
  - [`oauth/client-secret-basic.mts`](../../oauth/client-secret-basic.mts), used when client credentials are configured;
  - the root modules `single-flight.mts`, `response-body.mts` and `logger.mts`. Only the router takes the logger singleton; the decision sees just the `Logger` type.
- **Outside `src/`:** `config/application.schema.mts`, for types only.
- **Packages:** `express` and `node:crypto`.
- **Never imported:** `src/modes/injection`. The dependency runs neither way: injection does not import this directory either.
- **Inside the directory:** there are no import cycles.

## Known issues

- [#134](https://github.com/o3co/auth.proxy/issues/134): the two modes use different log field names and levels.
