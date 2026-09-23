# `src/oauth`

One place for how this proxy authenticates *itself* to the provider: `client_secret_basic`. The provider-side requirements — which client to register, what audience to pin, what the alternative trades away — are in the root README under [Introspection client identity](../../README.md#introspection-client-identity) and, for the exchange, under [External credential exchange](../../README.md#external-credential-exchange-authinjectionexchange) ("Client authentication"). The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

[`client-secret-basic.mts`](client-secret-basic.mts): a pure function from a credential pair to an `Authorization` header value. [`clientSecretBasic`](client-secret-basic.mts), input type [`ClientCredentials`](client-secret-basic.mts). No I/O, no configuration, no logging, no state.

## Public contract

`clientSecretBasic({ clientId, clientSecret }) → "Basic <base64>"`. The output goes on the wire unchanged as the provider call's `Authorization` header.

## Inputs and outputs

In: the raw `client_id` and `client_secret` as configured — set the raw values in the environment; do not pre-encode them. Out: the header value. Nothing else is produced, and the secret appears in no other outbound place.

## Dependencies

None. Its two callers are the two paths on which the proxy is a confidential client:

- validation — [`buildAuthHeader`](../modes/validation/introspection-client.mts), only when both `auth.validation.client` credentials are set; otherwise the inbound token itself is the introspection credential;
- the exchange — [`createJwtBearerClient`](../modes/injection/jwt-bearer-client.mts), always.

The session grant is **not** a caller: there the proxy is a public client and sends `client_id` in the form body with no `Authorization` ([`createSessionGrantClient`](../modes/injection/session-grant-client.mts)).

## Invariants

**Encoding (RFC 6749 §2.3.1).** Each half is `application/x-www-form-urlencoded`-encoded *before* the two are joined with `:` and base64'd (the doc comment on [`clientSecretBasic`](client-secret-basic.mts)). Without that, a `:` inside either half re-splits the credential and the provider reads a different pair than the one configured. `encodeURIComponent` escapes `:` and every character the form-urlencoded decoder would read as a separator or escape (`&`, `=`, `+`, `%`, and the space it writes as `%20`), leaving only `-_.!~*'()` and alphanumerics bare, and the provider decodes with the matching form-urlencoded decoder, so a credential containing reserved characters round-trips byte for byte.

**Not logged, within a bound.** Neither caller rebuilds the configured header per request: [`createJwtBearerClient`](../modes/injection/jwt-bearer-client.mts) holds it in its closure, and so does [`createIntrospectionClient`](../modes/validation/introspection-client.mts) since #95 F5 — the Basic form is a function of configuration alone. Validation's other path has nothing to hold: without client credentials the credential *is* the request's own token, so that header is built per call ([`buildAuthHeader`](../modes/validation/introspection-client.mts)). The jwt-bearer client checks the provider's `error` values against the secret before recording them (its [`sanitizeErrorCode`](../modes/injection/provider-error.mts) calls); validation's decision logs the thrown error, never the request it sent (the `catch` in [`decideValidation`](../modes/validation/decision.mts)). The check is a substring match for a secret of eight characters or more and an exact match below that (`MIN_CONTAINED_CREDENTIAL_LENGTH` in [`provider-error.mts`](../modes/injection/provider-error.mts)), so a client secret shorter than eight characters can reach a log inside a provider's error text — documented, tracked as F30 on #95.

## Failure and lifecycle

A pure function has neither. A wrong or unregistered credential surfaces as a provider `401`, and both callers now read it the same way: the exchange as `502 provider_config_error`, validation as `502 Provider Configuration Error` (#95 F7). Validation answers `401 Invalid Token` for a provider `401` only when it sent no Basic header at all — without client credentials the inbound token is the introspection credential, so that `401` is about the caller rather than about this module's output. See [`src/modes/validation`](../modes/validation/README.md).

## Contract tests

| Test file | Pins |
| --- | --- |
| [`__tests__/client-secret-basic.test.mts`](__tests__/client-secret-basic.test.mts) | the header shape (`builds a Basic header from client_id and client_secret`), encoding before joining (`percent-encodes both halves before joining them`), the round trip through a form-urlencoded decoder (`round-trips reserved characters through a form-urlencoded decoder`). |
| [`validation/__tests__/introspection-client.test.mts`](../modes/validation/__tests__/introspection-client.test.mts) | `buildAuthHeader` choosing Basic vs. Bearer (`returns Basic auth when client credentials are provided`, `returns Bearer with the request token when no client credentials`); a `:` in either half (`percent-encodes a ':' in either half so the credential cannot re-split`); the round trip (`round-trips reserved characters through the provider's form-urlencoded decoder`). |
| [`injection/__tests__/jwt-bearer-client.test.mts`](../modes/injection/__tests__/jwt-bearer-client.test.mts) | the header on the wire (`authenticates with client_secret_basic and sends only isolated headers`), reserved characters (`percent-encodes reserved characters in the client credentials (RFC 6749 section 2.3.1)`), the secret never in an error message (`never puts the assertion or the client secret into an error message`). |
