# `src/oauth`

Last updated: 2026-09-30

One place for how this proxy authenticates *itself* to the provider: `client_secret_basic` or `private_key_jwt`. The provider-side requirements — which client to register, what audience to pin, what the alternatives trade away — are in the root README under [Introspection client identity](../../README.md#introspection-client-identity), [Client authentication with a private key](../../README.md#client-authentication-with-a-private-key-private_key_jwt) and, for the exchange, under [External credential exchange](../../README.md#external-credential-exchange-authinjectionexchange) ("Client authentication").

## Responsibility

**Role.** A contract module the provider clients call to authenticate the proxy's client on one call: validation's introspection client (when client credentials are configured), the exchange's jwt-bearer client, and the session grant client when it holds a key (without one, the proxy is a public client there and this module is not asked).

**Owns:**

- what one call carries to authenticate the client, [`authenticateClient`](client-authentication.mts): the Basic header for a secret, or a client assertion and the `client_id` in the body for a key;
- the `client_secret_basic` encoding, [`clientSecretBasic`](client-secret-basic.mts) (RFC 6749 §2.3.1);
- reading a client key from a private JWK, [`parseClientKey`](private-key-jwt.mts), and signing a client assertion with it, [`signClientAssertion`](private-key-jwt.mts) (RFC 7523 §2.2).

**Does not own:** whether client credentials are configured and which header a call sends without them (validation's introspection client); where the provider's issuer comes from (`config/`); keeping provider text that echoes a credential out of what is relayed or logged (the callers, given the credential as sent); what a provider `401` means (each mode's decision).

**Why separate.** Both modes need the same client authentication, and neither may import the other, so it is written once here. The configuration schema reads a client key through `parseClientKey`, so a key the proxy cannot sign with stops the process at boot.

## Dependencies

`jose` (signing) and `node:crypto` (reading the key). Imported by `modes/*` and by `config/application.schema.mts` (`parseClientKey` only).

## Invariants

- **No I/O, configuration, logging or state.** A wrong or unregistered credential surfaces as a provider `401`, which each caller interprets.
- **Encode each half before joining (RFC 6749 §2.3.1).** Each half is form-urlencoded before the two are joined with `:` and base64'd, so a reserved character in either half round-trips byte for byte through the provider's decoder. Spelled out on [`clientSecretBasic`](client-secret-basic.mts) and pinned by [`__tests__/client-secret-basic.test.mts`](__tests__/client-secret-basic.test.mts). It takes the raw `client_id` and `client_secret` as configured (do not pre-encode them).
- **One method per call.** A secret is sent only as the `Authorization` header; a key only as `client_assertion_type` / `client_assertion` with the `client_id` in the body, and no `Authorization` header — the provider refuses a request that authenticates two ways. Pinned by [`__tests__/client-authentication.test.mts`](__tests__/client-authentication.test.mts).
- **A new assertion per call.** `iss` and `sub` are the client id, the only `aud` is the provider's issuer identifier, the `jti` is random, and `exp` is `iat` + 60 s. The provider accepts each `jti` once, so nothing caches or reuses an assertion. Pinned by [`__tests__/private-key-jwt.test.mts`](__tests__/private-key-jwt.test.mts), which verifies each assertion with `jose` as the provider does.
- **The key never leaves the process, and is never quoted.** Only signatures go on the wire. `parseClientKey` accepts an Ed25519, EC P-256/P-384/P-521 or RSA (2048 bits or more) private JWK whose `alg`, if any, fits it, and refuses anything else with a `ClientKeyError` whose message names what is wrong without quoting the key. `authenticateClient` returns the credential as sent — the secret, or the assertion — so a caller can keep provider text that echoes it out of what it relays.
