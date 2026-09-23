# `src/express`

Last updated: 2026-09-24

Helpers for reading inbound request headers at the Express layer. They read and normalise; they decide nothing. The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** Contract modules for the inbound side of a request, used by the mode code: the request-id middleware, which both mode routers mount, and the `Authorization: Bearer` grammar, which the validation path applies.

**Owns:** the `Bearer` grammar validation applies, and whether a refused header still named the `Bearer` scheme; the request id — reuse, generation, normalisation into `req.headers`, and the echo on the response.

**Does not own:** what a refused header is answered with (status, challenge, realm) — that is the validation decision's; the injection path's `Authorization` grammar (in `modes/injection`); where the middleware is mounted (each mode router); forwarding the id to the provider or upstream (the clients and the upstream stage in `router/`).

**Why separate.** Both are parsing of untrusted inbound headers, with no decision, configuration or I/O, kept apart from the modes that act on the result. Why they sit in `express/` rather than beside their callers is not recorded.

## Dependencies

`node:crypto` and Express types only; nothing else in `src/`. Imported only by `modes/*`.

## Invariants

- **No decision, configuration, provider call, logging or state.** Nothing here can fail or needs releasing.
- **Two `Authorization` grammars, one per path (#95 F16).** This directory holds the one validation applies ([`bearer.mts`](bearer.mts): a case-sensitive `Bearer`, exactly one SP, the first word as the token); [`modes/injection`](../modes/injection/README.md) holds the exchange's, which follows RFC 6750 / 9110 and narrows to a JWS compact JWT. Each path parses once and applies exactly one of them; the session path parses no `Authorization` at all. Why this grammar is stricter than RFC 7235 is in the doc comment on [`extractBearerToken`](bearer.mts). Pinned by [`__tests__/bearer.test.mts`](__tests__/bearer.test.mts).
- **The request id is mounted first (#95 F17).** The middleware writes the normalised id back into `req.headers`, and every later reader — the request logs, the mode middlewares, the provider clients, the upstream stage — takes it from there. That is correct only because each mode router mounts it before anything else; mount nothing that reads the id in front of it. Not tested — no test pins the order.
- **Reuse over replace.** An inbound id is kept rather than replaced; a duplicated header yields its first value; an empty value counts as absent. Pinned by [`__tests__/requestId.test.mts`](__tests__/requestId.test.mts).
