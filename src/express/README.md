# `src/express`

Last updated: 2026-09-23

Helpers for reading inbound request headers at the Express layer. They read and normalise; they decide nothing. Neither module reads configuration, calls the provider, or logs. The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** Contract modules for the inbound side of a request, used by the mode code: the request-id middleware is mounted first by both mode routers; the `Bearer` grammar is applied by the validation decision ([`decideValidation`](../modes/validation/decision.mts)). They use nothing else in `src/`.

**Owns:** the `Authorization: Bearer` grammar validation applies, and whether a refused header still named the `Bearer` scheme; the request id — reuse, generation, normalisation into `req.headers`, and the echo on the response.

**Does not own:** what a refused header is answered with (status, challenge, realm) — that is [`decideValidation`](../modes/validation/decision.mts)'s; the injection path's `Authorization` grammar ([`parseBearerAssertion`](../modes/injection/bearer-assertion.mts), in `modes/injection`); where the middleware is mounted (each mode router); forwarding the id to the provider or upstream (the clients and [`createUpstreamProxy`](../router/upstream.mts)).

**Why separate.** Both files are parsing of untrusted inbound headers with no decision, configuration or I/O, kept apart from the modes that act on the result. They sit in `express/`, mirroring the `@o3co/auth.utils/express` subpath they were internalised from (5811e97); no reason for the placement is recorded. Both moved unchanged when the proxy stopped depending on `@o3co/auth.utils`. `bearer.mts` has no Express dependency and one caller, the validation decision; no reason for keeping it in `express/` rather than beside that caller is recorded.

| File | Kind | Owns |
| --- | --- | --- |
| [`bearer.mts`](bearer.mts) | contract | reading an `Authorization: Bearer <token>` header: [`extractBearerToken`](bearer.mts), answering the token itself or `null`; and [`namesBearerScheme`](bearer.mts), whether a header `extractBearerToken` refused still named the `Bearer` scheme by the same rule (#95 F45). No state. |
| [`requestId.mts`](requestId.mts) | contract | correlating a request across the proxy's logs, its provider call and its upstream call: [`createRequestIdMiddleware`](requestId.mts), options [`RequestIdOptions`](requestId.mts). No state beyond `req` / `res`. |

## Public contract

- `extractBearerToken(header) → string | null`: the credential with the scheme stripped, or `null` for an absent header, another scheme, or no token.
- `namesBearerScheme(header) → boolean`: `true` when the header's first SP-delimited word is exactly `Bearer` — a malformed Bearer credential (`Bearer`, `Bearer  t`) rather than another method. Meaningful only for a header `extractBearerToken` refused; a lowercase `bearer` is another method here, since `extractBearerToken` does not admit it either.
- `createRequestIdMiddleware(options?) → RequestHandler`: reuses an inbound id, generates one otherwise, writes it back into `req.headers` and echoes it on the response.

## Inputs and outputs

- `bearer.mts` — in: the header string; out: the token, or `null`; and, for a refused header, whether it named `Bearer`. Validation is its only caller; what that path forwards is `req.headers`, which it does not touch, so the header as received was never worth carrying alongside the token (#95 F15), and once it was gone, neither was the one-field record around the token (#95 F36).
- `requestId.mts` — in: `req.headers[<header>]` (`string | string[]`); out: the same key normalised to one non-empty string, and the response header. Default header `x-request-id`, compared lowercased as Node stores it (`headerKey` in [`createRequestIdMiddleware`](requestId.mts)).

## Dependencies

`node:crypto` and Express types only; nothing else in `src/`. Imported by both mode routers (`requestId`) and by the validation decision, [`modes/validation/decision.mts`](../modes/validation/decision.mts) (`bearer`: both functions).

## Invariants

**Two `Authorization` grammars (#95 F16).** This directory holds one; [`injection/bearer-assertion.mts`](../modes/injection/bearer-assertion.mts) holds the other. Each path parses once and applies exactly one of them:

| | [`extractBearerToken`](bearer.mts) | [`parseBearerAssertion`](../modes/injection/bearer-assertion.mts) |
| --- | --- | --- |
| Scheme | `Bearer`, case-sensitive (the `type !== "Bearer"` check) | case-insensitive, RFC 9110 (the `toLowerCase()` comparison) |
| Separator | exactly one SP — `split(" ")`; a double space leaves an empty token and is refused ([`rejects a double space, which leaves an empty token`](__tests__/bearer.test.mts)) | `1*SP` per RFC 6750 (the `/^ +(\S+)$/` match; [`accepts multiple spaces between the scheme and the token (RFC 6750 1*SP)`](../modes/injection/__tests__/bearer-assertion.test.mts)) |
| Token | the first SP-delimited word; trailing content is ignored ([`keeps only the first token when the header carries trailing content`](__tests__/bearer.test.mts)) | the whole remainder, which must be a JWS compact serialization with JSON-object header and payload ([`JWS_COMPACT_RE`](../modes/injection/bearer-assertion.mts), [`decodeJsonObject`](../modes/injection/bearer-assertion.mts)) |
| Applied by | the validation decision ([`decideValidation`](../modes/validation/decision.mts)) | the exchange ([`decideExchange`](../modes/injection/exchange.mts)) |
| On mismatch | `null` → `400 Invalid Token Type`, whose challenge [`namesBearerScheme`](bearer.mts) picks: `error="invalid_request"` when the header named `Bearer`, the realm alone (or no challenge without a realm) for another method (#95 F45) | `{ kind: "unsupported", reason }` → `401 credential_unsupported` |

Why they differ: the case-sensitive scheme is what this proxy shipped with, and loosening it would admit requests the upstream has never seen — a widening decided as a side effect, so it stays until decided on its own (the doc comment on [`extractBearerToken`](bearer.mts)). The assertion parser is newer, follows RFC 6750 / 9110, and narrows to a JWS compact JWT so an opaque token or a JWE is refused before it costs a provider call (the grammar note on [`parseBearerAssertion`](../modes/injection/bearer-assertion.mts)). The session path parses no `Authorization` at all — presence checks only (see [`src/modes/injection`](../modes/injection/README.md)).

**Request-id ordering (#95 F17).** The middleware writes the normalised id back into `req.headers`, and every later reader takes it from there: the two request-logging middlewares as-is, both mode middlewares as `string | undefined` with `?? ""` ([`injectionMiddleware`](../modes/injection/router.mts), [`validationMiddleware`](../modes/validation/router.mts)); the clients receive it as a parameter and send it to the provider as `X-Request-Id` ([`createSessionGrantClient`](../modes/injection/session-grant-client.mts), [`createJwtBearerClient`](../modes/injection/jwt-bearer-client.mts)) or lowercase `x-request-id` ([`createIntrospectionClient`](../modes/validation/introspection-client.mts)); and `express-http-proxy` copies it upstream with the rest of `req.headers` in the shared stage ([`createUpstreamProxy`](../router/upstream.mts)). That is correct only because the middleware is mounted **first** in each mode router (the first `.use` in [injection `createRouter`](../modes/injection/router.mts) and [validation `createRouter`](../modes/validation/router.mts)). Mount nothing that reads the id in front of it. Documented, not tested — no test pins the order. The healthcheck is mounted before either router (in [`app.mts`](../app.mts)) and carries no id.

**Reuse over replace.** An inbound id is kept rather than replaced; a duplicated header yields its first value; an empty value counts as absent. Pinned by [`reuses an inbound id rather than replacing it`](__tests__/requestId.test.mts), [`takes the first value when the header arrives duplicated (#81 review)`](__tests__/requestId.test.mts), [`generates an id when the inbound header is present but empty`](__tests__/requestId.test.mts).

## Failure and lifecycle

Nothing to fail and nothing to release: no I/O, no timers, no state. The `header` and `generator` options ([`RequestIdOptions`](requestId.mts)) are the two seams — `header` for a deployment that correlates on another name, pinned by [`honours a custom header name, lowercased to match Node's header keys`](__tests__/requestId.test.mts); `generator` for tests and deployments that mint their own ids.

## Contract tests

| Test file | Pins |
| --- | --- |
| [`__tests__/bearer.test.mts`](__tests__/bearer.test.mts) | `extractBearerToken`: well-formed extraction, absent and empty headers, case-sensitive scheme (``is case-sensitive on the scheme (RFC 6750 spells it `Bearer`)``), other schemes, no token, double space, trailing content. `namesBearerScheme` (#95 F45): true for the malformed Bearer `Bearer`, `Bearer `, `Bearer  t`; false for `Basic …`, `bearer t`, `BEARER t`, `Bearerx t`. |
| [`__tests__/requestId.test.mts`](__tests__/requestId.test.mts) | generation, reuse, echo on the response, custom header name, single `next`, id shape, duplicated header, empty header, uniqueness. |

Not tested: the mount order (#95 F17). That the forwarded `Authorization` equals the inbound bytes (#95 F14) is pinned on the validation path since #101; on the injection path what goes upstream is whatever the outcome left in `req.headers` — the minted token, nothing, or the inbound bytes — which [`src/modes/injection`](../modes/injection/README.md) documents as the three-way it is.
