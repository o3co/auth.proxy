# `src/express`

Transport helpers for the Express layer. They read and normalise inbound headers; they decide nothing. Neither module reads configuration, calls the provider, or logs. The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

| File | Owns |
| --- | --- |
| [`bearer.mts`](bearer.mts) | reading an `Authorization: Bearer <token>` header: [`extractBearerToken`](bearer.mts), result [`BearerToken`](bearer.mts). No state. |
| [`requestId.mts`](requestId.mts) | correlating a request across the proxy's logs, its provider call and its upstream call: [`createRequestIdMiddleware`](requestId.mts), options [`RequestIdOptions`](requestId.mts). No state beyond `req` / `res`. |

## Public contract

- `extractBearerToken(header) → BearerToken | null`: `null` for an absent header, another scheme, or no token.
- `createRequestIdMiddleware(options?) → RequestHandler`: reuses an inbound id, generates one otherwise, writes it back into `req.headers` and echoes it on the response.

## Inputs and outputs

- `bearer.mts` — in: the header string; out: `{ token, raw }`. `raw` ("for forwarding it on unchanged") is not read anywhere in `src/` outside tests (F15; #95 tracks using it or dropping it).
- `requestId.mts` — in: `req.headers[<header>]` (`string | string[]`); out: the same key normalised to one non-empty string, and the response header. Default header `x-request-id`, compared lowercased as Node stores it (`headerKey` in [`createRequestIdMiddleware`](requestId.mts)).

## Dependencies

`node:crypto` and Express types only; nothing else in `src/`. Imported by both mode routers (`requestId`) and by the validation router (`bearer`).

## Invariants

**Two `Authorization` grammars (F16).** This directory holds one; [`injection/bearer-assertion.mts`](../modes/injection/bearer-assertion.mts) holds the other. Each path parses once and applies exactly one of them:

| | [`extractBearerToken`](bearer.mts) | [`parseBearerAssertion`](../modes/injection/bearer-assertion.mts) |
| --- | --- | --- |
| Scheme | `Bearer`, case-sensitive (the `type !== "Bearer"` check) | case-insensitive, RFC 9110 (the `toLowerCase()` comparison) |
| Separator | exactly one SP — `split(" ")`; a double space leaves an empty token and is refused ([`rejects a double space, which leaves an empty token`](__tests__/bearer.test.mts)) | `1*SP` per RFC 6750 (the `/^ +(\S+)$/` match; [`accepts multiple spaces between the scheme and the token (RFC 6750 1*SP)`](../modes/injection/__tests__/bearer-assertion.test.mts)) |
| Token | the first SP-delimited word; trailing content is ignored ([`keeps only the first token when the header carries trailing content`](__tests__/bearer.test.mts)) | the whole remainder, which must be a JWS compact serialization with JSON-object header and payload ([`JWS_COMPACT_RE`](../modes/injection/bearer-assertion.mts), [`decodeJsonObject`](../modes/injection/bearer-assertion.mts)) |
| Applied by | the validation decision ([`decideValidation`](../modes/validation/decision.mts)) | the exchange ([`decideExchange`](../modes/injection/exchange.mts)) |
| On mismatch | `null` → `400 Invalid Token Type` | `{ kind: "unsupported", reason }` → `401 credential_unsupported` |

Why they differ: the case-sensitive scheme is what this proxy shipped with, and loosening it would admit requests the upstream has never seen — a widening decided as a side effect, so it stays until decided on its own (the doc comment on [`extractBearerToken`](bearer.mts)). The assertion parser is newer, follows RFC 6750 / 9110, and narrows to a JWS compact JWT so an opaque token or a JWE is refused before it costs a provider call (the grammar note on [`parseBearerAssertion`](../modes/injection/bearer-assertion.mts)). The session path parses no `Authorization` at all — presence checks only (see [`src/modes/injection`](../modes/injection/README.md)).

**Request-id ordering (F17).** The middleware writes the normalised id back into `req.headers`, and every later reader takes it from there: the two request-logging middlewares as-is, injection's handler as `string | undefined` with `?? ""` ([`injectionMiddleware`](../modes/injection/router.mts)), validation's handler with a bare `as string` (the handler in [`validation/router.mts`](../modes/validation/router.mts)); the clients receive it as a parameter and send it to the provider as `X-Request-Id` ([`createSessionGrantClient`](../modes/injection/session-grant-client.mts), [`createJwtBearerClient`](../modes/injection/jwt-bearer-client.mts)) or lowercase `x-request-id` ([`introspect`](../modes/validation/introspect.mts)); and `express-http-proxy` copies it upstream with the rest of `req.headers` in the shared stage ([`createUpstreamProxy`](../router/upstream.mts)). That is correct only because the middleware is mounted **first** in each mode router (the first `.use` in [injection `createRouter`](../modes/injection/router.mts) and [validation `createRouter`](../modes/validation/router.mts)). Mount nothing that reads the id in front of it. Documented, not tested — no test pins the order. The healthcheck is mounted before either router (in [`app.mts`](../app.mts)) and carries no id.

**Reuse over replace.** An inbound id is kept rather than replaced; a duplicated header yields its first value; an empty value counts as absent. Pinned by [`reuses an inbound id rather than replacing it`](__tests__/requestId.test.mts), [`takes the first value when the header arrives duplicated (#81 review)`](__tests__/requestId.test.mts), [`generates an id when the inbound header is present but empty`](__tests__/requestId.test.mts).

## Failure and lifecycle

Nothing to fail and nothing to release: no I/O, no timers, no state. The `header` and `generator` options ([`RequestIdOptions`](requestId.mts)) are the two seams — `header` for a deployment that correlates on another name, pinned by [`honours a custom header name, lowercased to match Node's header keys`](__tests__/requestId.test.mts); `generator` for tests and deployments that mint their own ids.

## Contract tests

| Test file | Pins |
| --- | --- |
| [`__tests__/bearer.test.mts`](__tests__/bearer.test.mts) | well-formed extraction, absent and empty headers, case-sensitive scheme (``is case-sensitive on the scheme (RFC 6750 spells it `Bearer`)``), other schemes, no token, double space, trailing content. |
| [`__tests__/requestId.test.mts`](__tests__/requestId.test.mts) | generation, reuse, echo on the response, custom header name, single `next`, id shape, duplicated header, empty header, uniqueness. |

Not tested: the mount order (F17); `BearerToken.raw` is unused (F15); that the forwarded `Authorization` equals the inbound bytes (F14) is documented, not tested.
