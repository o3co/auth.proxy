# `src/oauth`

Last updated: 2026-09-24

One place for how this proxy authenticates *itself* to the provider: `client_secret_basic`. The provider-side requirements — which client to register, what audience to pin, what the alternative trades away — are in the root README under [Introspection client identity](../../README.md#introspection-client-identity) and, for the exchange, under [External credential exchange](../../README.md#external-credential-exchange-authinjectionexchange) ("Client authentication"). The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** A contract module the two paths on which the proxy is a confidential client call to build their `Authorization` header to the provider: validation's introspection client (only when client credentials are configured) and the exchange's jwt-bearer client. The session grant is not a caller — there the proxy is a public client.

**Owns:** the encoding from a configured credential pair to the header value, [`clientSecretBasic`](client-secret-basic.mts) (RFC 6749 §2.3.1).

**Does not own:** whether client credentials are configured and which header a call sends without them (validation's introspection client); holding the built header (each client's closure); keeping the secret out of logs (the callers); what a provider `401` means (each mode's decision).

**Why separate.** Both modes need the same encoding, and neither may import the other, so it is written once here (#91).

## Dependencies

None. Imported only by `modes/*`.

## Invariants

- **Pure.** No I/O, configuration, logging or state; nothing to fail or release. A wrong or unregistered credential surfaces as a provider `401`, which each caller interprets.
- **Encode each half before joining (RFC 6749 §2.3.1).** Each half is form-urlencoded before the two are joined with `:` and base64'd, so a reserved character in either half round-trips byte for byte through the provider's decoder. The encoding is spelled out in the doc comment on [`clientSecretBasic`](client-secret-basic.mts) and pinned by [`__tests__/client-secret-basic.test.mts`](__tests__/client-secret-basic.test.mts).
- **The secret goes only into this header.** It takes the raw `client_id` and `client_secret` as configured (do not pre-encode them), and the output goes on the wire unchanged as the provider call's `Authorization`; the secret appears in no other outbound place.
