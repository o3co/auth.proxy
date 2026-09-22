# `config`

The proxy's configuration contract: [`application.conf`](application.conf) is the shipped HOCON with an environment override per key, and [`application.schema.mts`](application.schema.mts) is the Zod schema that validates the parsed file and produces the [`AppConfig`](application.schema.mts) the code reads. The environment variables themselves are listed in the root README under [Configuration](../README.md#configuration). The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

Contract only; no runtime state. The file is parsed and validated exactly once, at boot, at the top of [`app.mts`](../src/app.mts) (`parseFile` from `@o3co/ts.hocon`, then `validate(…, AppConfigSchema)`); a validation failure stops the process before it listens. The schema itself never reads the environment — the `${?NAME}` substitution happens in that HOCON parse — and no module re-reads it afterwards; the one read outside the HOCON parse is `LOG_LEVEL` in [`createProxyLogger`](../src/logger.mts).

## Public contract

[`AppConfigSchema`](application.schema.mts), the inferred [`AppConfig`](application.schema.mts), and the hand-written [`ExchangeConfig`](application.schema.mts) the exchange transform produces. Modules narrow `AppConfig["auth"]` to their own mode (`InjectionConfig` in [`injection/router.mts`](../src/modes/injection/router.mts), `ValidationConfig` in [`validation/router.mts`](../src/modes/validation/router.mts)).

## Inputs and outputs

In: `application.conf` plus the process environment — every `${?NAME}` substitutes the variable *as a string*. Out: `AppConfig`, the schema's output type, which is the only shape the code sees.

**The schema is authoritative (F23).** Defaults are declared twice — as a literal in the conf and as a Zod `.default()` — and the two must agree, because the conf literal is what reaches the code when the environment is silent and the schema default is what applies when the key is absent altogether:

| Key | In [`application.conf`](application.conf) | In [`application.schema.mts`](application.schema.mts) |
| --- | --- | --- |
| `http.hostname`, `port`, `pathPrefix`, `bodyLimitSize` | the `http` block | `.default()` on each field of the `http` object |
| `http.cors.origin.pattern` | `http.cors.origin` | `.nullable().default(null)` |
| `auth.validation.client.*` | `auth.validation.client` | `.nullable().default(null)` with `""` → `null` |
| `auth.validation.introspect.cacheTtlSec`, `cacheMaxEntries`, `timeoutMs` | `auth.validation.introspect` | `.default()` on each of those three fields (`url` has none) |
| `auth.injection.stripInboundAuthorization` | `auth.injection` | `strictBoolean` |
| `auth.injection.tokenCache.*` | `auth.injection.tokenCache` | `.default()` on each field of the `tokenCache` object |
| `auth.injection.timeoutMs` | `auth.injection` | `.default()` |
| `auth.injection.exchange.*` | `auth.injection.exchange` | `strictBoolean`, `optionalString`, `whitespaceSeparatedList`; an absent block is `{}` via `.prefault` on [`exchangeSchema`](application.schema.mts) |

A third copy of `cacheMaxEntries` / `timeoutMs` exists as parameter defaults of [`introspect`](../src/modes/validation/introspect.mts); #95 tracks removing it. Keys whose default lives **only** in the conf (the schema validates but has no `.default()`): `auth.validation.introspect.url`, `auth.injection.providerOrigin`, `auth.injection.sessionCookieName`, `upstream.baseURL`. Keys the conf sets to a placeholder the schema refuses, so they are effectively required: `auth.mode` (`null` in the conf; the `discriminatedUnion` has no default), `auth.injection.clientId` (`""` in the conf; `.min(1)`), `auth.injection.scope` (`""` in the conf; `.min(1)`).

## Dependencies

`zod` only. Its importers are five: [`src/app.mts`](../src/app.mts) (the one value import: parse and validate), [`src/app-internal.mts`](../src/app-internal.mts), both mode routers ([injection](../src/modes/injection/router.mts), [validation](../src/modes/validation/router.mts)) and [`src/modes/injection/exchange.mts`](../src/modes/injection/exchange.mts) (type-only, and for `ExchangeConfig` rather than `AppConfig`). Nothing under `src/express`, `src/oauth` or `src/router`, and none of the clients, parsers or caches, imports it.

## Invariants

**Environment round trip.** Because an override arrives as a string: numbers use `z.coerce.number()`; booleans use [`strictBoolean`](application.schema.mts), which accepts a boolean or exactly `"true"` / `"false"` and refuses anything else naming the key — `z.coerce.boolean()` would read `"false"` as `true`; lists use [`whitespaceSeparatedList`](application.schema.mts), a HOCON list or one whitespace-split string, whose entries must be non-empty and whitespace-free so every list is expressible from the environment; optional strings treat `""` as unset ([`optionalString`](application.schema.mts), and the `auth.validation.client` fields).

**Cross-field invariants** live only in the schema; the conf cannot express them:

- `auth.mode` selects the branch; the other mode's section is not validated (the `discriminatedUnion` on `mode`), which is why the shipped conf boots in validation mode with `injection.clientId = ""`.
- `auth.validation.client.clientId` and `clientSecret` are both set or both unset (the `.refine` on `auth.validation.client`).
- `auth.injection.providerOrigin` is an http(s) origin only — no userinfo, path, query or fragment (the `.refine` on `providerOrigin`).
- `auth.injection.sessionCookieName` is an RFC 6265 `cookie-name` ([`COOKIE_NAME_RE`](application.schema.mts)) — it is interpolated into the outbound `Cookie` header.
- `auth.injection.exchange.enabled` requires `clientId` and `clientSecret` (the `.transform` in [`exchangeSchema`](application.schema.mts)); disabled parses to `{ enabled: false }` — every `exchange.*` field is still parsed and validated first (an invalid `allowedIssuers` entry fails the configuration even when disabled), and the transform then drops them.
- `auth.injection.tokenCache.safetyMarginSeconds < ttlSeconds` (the `.refine` on `tokenCache`).

## Failure and lifecycle

A violation is a `validate` error at boot; the process does not start. The offending key is in the message for the hand-written checks (every `ctx.addIssue` and `.refine` message in [`application.schema.mts`](application.schema.mts)) and in the issue `path` for the built-in ones (`.min(1)` on `clientId` / `scope`, `.url()`, `.int().positive()`). There is no reload — a change needs a restart. The parsed object is held by `app.mts` for the process lifetime and passed to the routers as an argument; nothing re-reads it from a global.

## Who reads which section

| Section | Reader |
| --- | --- |
| `http.hostname`, `http.port` | the `listen` call in [`app.mts`](../src/app.mts) |
| `http.cors.origin.pattern` | `corsOrigin` in [`app.mts`](../src/app.mts) |
| `http.pathPrefix` | the mode-router mount in [`app.mts`](../src/app.mts) |
| `http.bodyLimitSize`, `upstream.baseURL` | [`createUpstreamProxy`](../src/router/upstream.mts) via `UpstreamStageConfig`, which both mode routers mount |
| `auth.mode` | [`resolveRouter`](../src/app-internal.mts), and the guard at the top of each mode router |
| `auth.validation.*` | [validation `createRouter`](../src/modes/validation/router.mts) |
| `auth.injection.*` | [injection `createRouter`](../src/modes/injection/router.mts), which hands the whole object to `createSessionGrantClient` (reads the five fields of [`SessionGrantClientConfig`](../src/modes/injection/session-grant-client.mts)) and, with the exchange on, builds the exchange's deps from it ([`buildExchangeDeps`](../src/modes/injection/router.mts): the jwt-bearer client from `providerOrigin`, `timeoutMs` and the `exchange` block, the key's context by [`exchangeContext`](../src/modes/injection/exchange.mts), the cache policy from `tokenCache`) |
| `auth.injection.exchange` | [`buildExchangeDeps`](../src/modes/injection/router.mts), which builds the jwt-bearer client from it and hands `allowedIssuers` to [`decideExchange`](../src/modes/injection/exchange.mts) |

## Contract tests

[`src/__tests__/config.test.mts`](../src/__tests__/config.test.mts) parses the **shipped** `application.conf` (`confPath`) with environment overrides, so a conf literal that drifts from what a test asserts is caught there: validation defaults and the credential pair (`proxy config — validation mode`), injection required fields and `providerOrigin` (`proxy config — injection mode`), the cookie-name grammar (`sessionCookieName must be an RFC 6265 cookie-name (#75)`), `strictBoolean` (`stripInboundAuthorization`), the exchange block and `whitespaceSeparatedList` (`exchange (#90)`), the safety margin (`rejects tokenCache where safetyMarginSeconds >= ttlSeconds (equal)`), mode selection (`proxy config — mode selection`). The general rule that every conf literal equals its schema default is checked only for the keys those tests assert — documented, not tested as a whole.
