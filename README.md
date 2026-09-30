# auth.proxy

Last updated: 2026-10-01

[![CI](https://github.com/o3co/auth.proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.proxy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/o3co/auth.proxy/graph/badge.svg)](https://codecov.io/gh/o3co/auth.proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> This repository is an optional perimeter gate that sits outside the three-layer separation of concerns ([authentication & token issuance](https://github.com/o3co/auth.provider) / [authorization decision](https://github.com/o3co/auth.policy-verifier) / [authorization enforcement](https://github.com/o3co/protobuf.interceptors)) of the [auth](https://github.com/o3co/auth) stack.

Reverse proxy that sits between clients and downstream services. Operates in one of two mutually exclusive modes selected at deploy time via `auth.mode`.

## Responsibility

**Role.** auth.proxy is an *optional* gate at the perimeter of the auth stack, not one of its three layers: [auth.provider](https://github.com/o3co/auth.provider) authenticates and issues tokens, [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) makes authorization decisions, and the downstream service — or [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) inside it — enforces them. Besides the upstream it forwards to, auth.provider is the only service the proxy calls.

One deployment runs one of two modes:

- **[Validation](#validation-mode-authmode--validation)** — in front of a resource server. It checks an inbound `Authorization: Bearer` token against auth.provider's introspection endpoint, caches the answer, and forwards or refuses the request.
- **[Injection](#injection-mode-authmode--injection)** — in front of a browser-facing (BFF) service. It exchanges the browser's session cookie at auth.provider's token endpoint for an access token and injects it as `Authorization: Bearer`, so the browser never holds the token; opt-in, it also [exchanges an external JWT](#external-credential-exchange-authinjectionexchange) for a first-party token.

**Owns:**

- the per-request decision — forward, refuse, or inject — and the wire shape of its refusals (including the RFC 6750 `WWW-Authenticate` challenge in validation mode);
- its calls to the provider: `POST /oauth/introspect`, and `POST /oauth/token` for the session grant and the jwt-bearer exchange, with its own client authentication — [`client_secret_basic`](#introspection-client-identity) or [`private_key_jwt`](#client-authentication-with-a-private-key-private_key_jwt);
- per-instance, in-memory caches of provider answers, and the single-flight that coalesces concurrent misses;
- its configuration schema, logging and graceful shutdown.

**Does not own:**

- issuing tokens, login and sessions, issuer trust, identity mapping, and what introspection calls `active` — [auth.provider](https://github.com/o3co/auth.provider);
- authorization decisions — [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — and their enforcement, which stays in the downstream service;
- verifying the token the upstream is handed: the upstream must still verify it (see [Inbound Authorization headers](#inbound-authorization-headers));
- CSRF protection (see [CSRF responsibility boundary](#csrf-responsibility-boundary));
- propagating a revocation to tokens already issued or cached (see [Revocation and the access-token lifetime](#revocation-and-the-access-token-lifetime));
- the provider's rate-limit budget (see [Provider rate limiting](#provider-rate-limiting)).

**Why a separate service.** The stack's [architecture](https://github.com/o3co/auth/blob/develop/docs/architecture.md#migration-path) runs each component as a standalone HTTP service that talks to the others only through endpoint URLs in configuration: the proxy needs only the provider's endpoint, and can be replaced by any token-validating reverse proxy (e.g. Envoy with ext_authz) with no application code change. Being in front of the service is what lets downstream services receive pre-validated requests without implementing auth logic themselves, and lets injection mode keep access tokens out of the browser (the OWASP Token Handler Pattern). Being optional, a deployment can leave it out.

**Source map.** Each source directory's README states its responsibility, role and invariants; what a single file does is in that file's header comment. Start at [`src/README.md`](src/README.md) (the source tree), [`config/README.md`](config/README.md) (the configuration schema), and the module READMEs — [`src/express`](src/express/README.md), [`src/oauth`](src/oauth/README.md), [`src/modes/injection`](src/modes/injection/README.md), [`src/modes/validation`](src/modes/validation/README.md).

## Operating modes

`auth.mode` is required — must be set explicitly to `"validation"` or `"injection"`. Omission or a typo causes the proxy to fail to start. Set it via HOCON (`auth.mode = "validation"`) or the `AUTH_MODE` environment variable.

### Validation mode (`auth.mode = "validation"`)

Validates inbound `Authorization: Bearer <token>` headers against the provider's introspection endpoint. A request with no `Authorization` header, or an empty one, is forwarded unchanged (public endpoints remain reachable). A request whose `Authorization` is anything other than `Bearer <token>` — another scheme, a lowercase `bearer`, a `Bearer` with no usable token — is refused `400 Invalid Token Type` (see the challenge table below).

Flow:

1. Detects `Authorization: Bearer <token>` header (passes through if there is no `Authorization` header, or an empty one; any other `Authorization` is `400`).
2. Checks in-memory cache keyed by SHA-256 of the token.
3. On cache miss, calls provider's `POST /oauth/introspect`. A redirect from it is not followed — the endpoint is configuration — and is answered `502 Provider Configuration Error`. Concurrent misses on the same token coalesce into a single provider call (single-flight), as they do in injection mode.
4. Returns `401` if `active: false`; forwards the request if `active: true`. Only a `200` is read as an answer: another `2xx`, even one carrying `active: true`, is a provider failure (see the logging table below).

Challenges, without and with `VALIDATION_REALM` (here `api`):

| Refusal | No realm | Realm set |
| --- | --- | --- |
| `401`: an access token the proxy would not accept (RFC 6750 §3) | `Bearer error="invalid_token"` | `Bearer realm="api", error="invalid_token"` |
| `400`: a `Bearer` credential too malformed to read (`Bearer`, `Bearer  t`) | `Bearer error="invalid_request"` | `Bearer realm="api", error="invalid_request"` |
| `400`: another method (`Basic …`, or a lowercase `bearer`, which this proxy does not admit) — no error code, as §3.1 says | none | `Bearer realm="api"` |

A `500` or `502` carries none, because it is the proxy's or the provider's failure rather than a statement about the caller's credential. Injection mode answers no challenge on any path, deliberately: its caller holds a session cookie, not a Bearer token.

Two limits worth knowing. A browser cannot read the header cross-origin — `WWW-Authenticate` is not CORS-safelisted and this proxy sets no `Access-Control-Expose-Headers` — so a SPA on another origin sees the status and the body only. And `invalid_token` invites a client to fetch a new token and retry (§3.1), which cannot help in the audience case described below: a token the provider calls `active: false` because its `aud` names neither this proxy's client nor an audience registered in that client's `allowedAudiences` is refused the same way however fresh it is.

**Logging.** A provider failure is logged once for each request it answers — requests that share one provider call (single-flight) each log it — with the request id as `requestId`, the error under `error` and one of these events:

| Event | Level | When |
| --- | --- | --- |
| `validation.token_unauthorized` | info | The provider answered `401` about the caller's token (`401 Invalid Token`). |
| `validation.provider_config_error` | error | The provider refused the proxy's own client credentials, or the endpoint redirected (`502 Provider Configuration Error`). |
| `validation.provider_error` | error | Any other provider failure — `5xx`, `429`, another `4xx`, a `2xx` other than `200`, a response that is not an introspection response, a timeout or a network error (`502 Bad Gateway`). |
| `validation.unexpected_error` | error | Anything else thrown (`500 Internal Server Error`). |

A token the provider refuses is the caller's problem, not the proxy's, so it is logged at the level `injection.session_unauthorized` has and an alert on error-level lines does not fire for it. An `active: false` answer is not logged.

Benefits over JWT-only local validation:

- Detects a revoked token — within the introspection cache TTL, and the only validation mode that can (see [Revocation and the access-token lifetime](#revocation-and-the-access-token-lifetime)).
- Introspection results are cached (default 30s TTL), reducing provider load.
- Downstream services receive pre-validated requests without implementing auth logic.

Validation supports unbound Bearer tokens. A response carrying any `cnf` or a
non-Bearer `token_type` is refused with 401; introspection alone does not verify
possession of a DPoP key or client certificate for the incoming request.
Cache entries never outlive a supplied numeric `exp`, and a token that expires
during introspection is refused immediately. An absent `exp` uses the configured
TTL; a malformed `exp` is treated as a provider response error. TTL zero disables caching.

#### Introspection client identity

`CLIENT_ID` with `CLIENT_SECRET` or `CLIENT_KEY` is optional, and the choice between setting them and leaving them unset changes which tokens the provider will call `active`.

**With client authentication (`CLIENT_ID`, and `CLIENT_SECRET` or `CLIENT_KEY`).** The proxy authenticates to `POST /oauth/introspect` as its own client — with HTTP Basic, or with a client assertion when it holds a key (see [Client authentication with a private key](#client-authentication-with-a-private-key-private_key_jwt)) — and the provider then pins the introspected token's audience to **what the calling client may address** — its own `client_id` and its `allowedAudiences` (auth.provider v0.12.0 and later; earlier releases pinned it to the `client_id` alone): a token whose `aud` names neither comes back `active: false`. There is no error and no diagnostic — on the wire an audience mismatch is indistinguishable from a forged or expired token, so the proxy answers `401` for tokens that are in fact perfectly valid.

The client the proxy authenticates as must therefore be associated with the audience of the tokens it validates. Either:

- register that audience in the client's `allowedAudiences`, or
- give the client the resource URI as its own `client_id`.

A proxy fronting `https://api.example.com/orders` that authenticates as a `client_id` which is neither that URI nor lists it in `allowedAudiences` answers `401` to every request whose token was minted with an RFC 8707 `resource` audience — which, wherever resource indicators are in use, is every request it sees.

**What a provider `401` means.** RFC 7662 §2.1 has the introspection request authenticated, and §2.3 answers an invalid credential with `401`, so the provider's `401` answers whichever credential it carried. Without client credentials the inbound token *is* that credential and the `401` is about the caller: `401 Invalid Token`. With them the credential is the proxy's own — its Basic header or its client assertion — the `401` refused the *proxy*, and the caller's token was never examined — that is `502 Provider Configuration Error`, logged at error as `validation.provider_config_error` (`introspect refused the proxy's client credentials`) rather than at info as the caller's `validation.token_unauthorized`, because it is the operator's to fix. The injection path reports the same situation as `provider_config_error` 502 — the exchange always has, and the session grant since #95 F47. A misconfigured deployment therefore answers a status that clients and gateways retry more readily than `401`, which spends the same per-instance introspection budget described under [Provider rate limiting](#provider-rate-limiting); the fix is the credential, not the retry policy.

**Without client authentication (all unset).** The proxy presents the inbound token itself as the introspection credential — `buildAuthHeader` emits `Authorization: Bearer <token>` with the same token in the body, which the provider requires to match. On that path the calling client is never identified, so **the audience pin does not apply** and a token for any audience is introspected on its own merits.

What that trades away:

- **The provider stops checking `aud` for you.** It records the gap and returns the claims. The proxy does not check `aud` either, so a token minted for a *different* resource server validates here. Unless the upstream service checks `aud` itself, that is a confused-deputy gap — set client authentication and register the audience, or check `aud` upstream.
- **No client identity in the provider's audit trail** for these calls.
- Signature, issuer, token type, expiry and the revocation denylist are still checked, so a revoked or forged token is still `active: false`.

Rate limiting is unaffected by the choice — it is keyed on the proxy's IP either way (see [Provider rate limiting](#provider-rate-limiting)).

**Credentials containing reserved characters.** RFC 6749 §2.3.1 requires both halves to be `application/x-www-form-urlencoded`-encoded *before* they are joined with `:` and base64'd into the Basic header; otherwise a `:` inside either half re-splits the credential in the wrong place and the provider reads a different pair than the one configured. `clientSecretBasic` (`src/oauth/client-secret-basic.mts`) does this, and the provider decodes with the matching form-urlencoded decoder, so a credential containing reserved characters round-trips byte for byte. Set the raw value in the environment variable — do not pre-encode it yourself.

### Injection mode (`auth.mode = "injection"`)

Translates an inbound session cookie into an outbound `Authorization: Bearer` token. Realizes the OWASP OAuth 2.0 BCP Token Handler Pattern — browsers never hold access tokens.

Flow:

1. Extracts the session cookie named in `auth.injection.sessionCookieName`.
2. If absent, forwards the request unchanged (the service layer decides whether authentication is required). A cookie that is present but refused (see [Cookie forwarding](#cookie-forwarding)) is forwarded the same way, but logged.
3. On cache hit, injects the cached Bearer and forwards.
4. On cache miss, exchanges the cookie for an access token via the provider's `POST /oauth/token` with `grant_type=session`. Concurrent misses on the same cookie coalesce into a single provider call (single-flight).
5. Injects `Authorization: Bearer <token>` and forwards upstream.

Opt-in, injection mode can also exchange an external credential presented as `Authorization: Bearer <JWT>` for a first-party token — see [External credential exchange](#external-credential-exchange-authinjectionexchange).

#### Cache behavior

- In-memory, per-instance. Restart and horizontal scale-out produce cold caches. Peak provider load during rollout ≈ `instance count × active sessions`.
- TTL: `min(auth.injection.tokenCache.ttlSeconds, provider.expires_in) - safetyMarginSeconds`, counted from the instant the grant request was sent — not from the response, so a slow provider cannot push an entry past the token's expiry. Default 60s minus 5s safety margin. A grant whose response arrives after that point is not cached.
- Every cache miss spends from a rate-limit bucket the whole instance shares — see [Provider rate limiting](#provider-rate-limiting) before lowering the TTL.

#### Revocation and the access-token lifetime

For a downstream service that validates JWTs offline, the **access token's own lifetime** bounds replay exposure after logout at the provider. A downstream service that introspects tokens can observe tracked-session invalidation sooner.

With UserSession tracking configured, the provider's `session` grant requires a live tracked session whose subject matches the browser user, and stamps its `sid` on the access token. It issues no refresh token and therefore no refresh-token `family_id`. `POST /session/logout` invalidates the tracked UserSession and associated federation state before destroying the browser session. Successful tracked-session invalidation makes introspection return `active: false` and userinfo refuse the token; store failures are logged as described in the provider's operator runbook.

`tokenCache.ttlSeconds` bounds how long this proxy keeps re-injecting a token it already holds without asking the provider again. Lowering it makes a *new* request on a logged-out session reach the provider sooner. An unauthenticated browser session returns `401`; a retained browser session with a missing, revoked or inconsistent tracked record returns `400 invalid_grant`. The injection proxy maps either rejection to its existing `401 session_required` response. A shorter cache TTL does not recall tokens already forwarded, and it multiplies the calls this proxy makes to `/oauth/token` (see [Provider rate limiting](#provider-rate-limiting)).

So, for an operator:

- **Keep the provider's access-token lifetime short in a BFF topology.** `oauth.accessToken.defaultExpiresIn` (`expiresIn` in older providers, which newer ones keep as a deprecated alias) bounds replay exposure at offline validators. The proxy owns the cookie-to-token exchange, so a short lifetime costs a grant call while the browser session remains valid.
- **A downstream service that validates the JWT offline cannot learn about a logout at all.** Signature, `iss`, `aud` and `exp` are everything an offline validator checks, and none of them changes when a session ends. For such a service the revocation window *is* the token lifetime, with nothing available to shorten it.
- **Introspection-based validation is the only mode that can observe a revocation.** A resource server — or an `auth.mode = "validation"` proxy in front of one — calling `POST /oauth/introspect` asks the provider on every cache miss, so a token the provider has stopped vouching for comes back `active: false` within that introspection cache TTL.

The validation proxy also caps each introspection cache entry at the token's `exp`. A zero introspection TTL bypasses the cache, so each request that is not concurrent with another for the same token asks the provider about the tracked session. Concurrent requests for one token still share a single call — the single-flight is independent of the TTL — so a burst sees the answer the provider gave to the first of them. This setting belongs to validation mode; it does not change the injection proxy's token cache or an offline validator's behavior.

#### Scope boundary

One proxy instance serves one OAuth scope domain. `auth.injection.clientId` and `auth.injection.scope` are fixed at deploy time, as are the exchange's `clientId`, `scope`, `audience` and `resource`. Serve multiple scope domains with multiple proxy instances.

A provider response of `400 invalid_grant` is mapped to `401 session_required`,
so a revoked session prompts authentication rather than appearing as a proxy
configuration failure. Other provider 400 responses retain their configuration-error mapping.
Conversely, a provider `401` is `session_required` unless its `error` is `invalid_client`,
which means the proxy's own client was refused — its `auth.injection.clientId`, or with a key its
client assertion — a configuration failure that signing in again cannot fix, answered
`502 provider_config_error` rather than a login prompt.

Only a `200` is a successful token response on either injection path (RFC 6749 §5.1). Any other
`2xx` — even one carrying a token — is `502 provider_unavailable`, "unexpected provider response", with
the status in the message.

A redirect from the token endpoint is not followed on either injection path: it is
`502 provider_config_error`, with the status in the message. The endpoint is configuration, and a
followed redirect cannot be reported honestly. A `307` or `308` to the same origin replays the whole
POST — session cookie and form body — to a path nothing configured, and mints a token there. The same
statuses cross-origin have the cookie stripped, so the provider answers `401` and the caller is told
to authenticate again over an endpoint that is merely misconfigured. A `301`, `302` or `303` turns the
grant into a `GET` with no body, which a token endpoint answers `405`.

#### CSRF responsibility boundary

The proxy is a transparent augmentation layer. It injects the Bearer but does NOT enforce CSRF. Combine with `SameSite=Lax` cookies, same-origin deployment, and CSRF protection in the upstream service. Being transparent cuts the other way too — see [Inbound Authorization headers](#inbound-authorization-headers).

#### Inbound Authorization headers

The proxy overrides an inbound `Authorization` header only on the requests where a session cookie actually produced a token (logged as `injection.authorization_override`, an inbound `Authorization:` with an empty value included). On the two paths where it minted nothing — no session cookie at all, or a cookie the grammar check refused — the request is forwarded as-is, **inbound `Authorization` header included**.

**The upstream service must verify the token it is handed.** It must not read "a Bearer header arrived on the connection from the proxy" as "the proxy minted this": a client that sends its own `Authorization` and no session cookie reaches the upstream with that header intact. Verify signature, `iss`, `aud` and `exp` against the provider's keys, or introspect — exactly as for a request that never went through a proxy. Header provenance is not an authentication signal.

`auth.injection.stripInboundAuthorization` (`INJECTION_STRIP_INBOUND_AUTHORIZATION`) removes the ambiguity at the proxy. When `true`, an inbound `Authorization` on a request the proxy did not mint a token for is dropped before the request is forwarded, and logged as `injection.inbound_authorization_stripped` at **warn** with the request id and a `reason` of `no_cookie` or `cookie_rejected`. The header value is never logged. Upstream then sees a Bearer header only when the proxy put it there.

It defaults to `false` — the pass-through behaviour every deployment before the flag ran on — because that behaviour is load-bearing wherever a non-browser client (a service account, a mobile app) deliberately presents its own token through the same proxy. Turn it on when this proxy fronts browser sessions only, and especially when the upstream's authorization has any dependence on where the header came from. It is defence in depth, not a substitute for the paragraph above: nothing stops a client reaching the upstream by another route.

With `auth.injection.exchange.enabled` the pass-through is gone altogether: an inbound `Authorization` header is either exchanged for a first-party token or the request is refused, so `stripInboundAuthorization` has nothing left to strip — see [External credential exchange](#external-credential-exchange-authinjectionexchange).

#### Cookie forwarding

Only the cookie named in `auth.injection.sessionCookieName` is forwarded to the provider on the session grant call. Other cookies (analytics, CSRF tokens, third-party) do not reach the provider.

The forwarded value must conform to the RFC 6265 section 4.1.1 `cookie-value` grammar: a run of `cookie-octet`s (printable US-ASCII excluding whitespace, DQUOTE, comma, semicolon, and backslash), optionally wrapped in exactly one surrounding DQUOTE pair. A surrounding DQUOTE pair is accepted and forwarded verbatim (quotes preserved) so the provider's own cookie parser decides how to read it. Anything else is refused — a `,`, whitespace, `\`, a control character, or a non-ASCII byte anywhere in the value, or a DQUOTE anywhere other than as that surrounding pair (interior or unbalanced), or an empty value: the request is forwarded without a minted `Authorization` and the provider is not called. With the exchange disabled, a client's own `Authorization` header still reaches the upstream unless `stripInboundAuthorization` is on; with the exchange enabled, an inbound `Authorization` is handed to the exchange before the cookie is considered, so it is exchanged or refused rather than passed through (see [Inbound Authorization headers](#inbound-authorization-headers)). Whitespace immediately after `=` is part of the value and is refused; SP / HTAB next to the `;` separator or at the ends of the header is separator slack and is ignored. `;` is the cookie-pair delimiter and never becomes part of a value. Default session stores (express-session `connect.sid`, hex / base64url / JWT session ids) always conform.

A refused cookie is not silent. A header that does not carry the cookie at all is an ordinary anonymous request and logs `injection.no_cookie` at debug; a header that carries it in a refused form logs `injection.cookie_rejected` at **warn** with the request id and a bounded `reason` — `empty` (`sid=` / `sid=""`), `quoting` (a DQUOTE anywhere other than one surrounding pair) or `grammar` (a character outside `cookie-octet`). The cookie bytes are never logged. A sustained rate of this event points at a misbehaving client or a provider issuing session cookies outside the grammar.

When the header carries the same name more than once (RFC 6265 section 5.4 lets a user agent send two same-name pairs, ordered by path and then creation time), the first well-formed pair is used. A malformed pair before it is skipped and logged as `injection.cookie_rejected` with `action: "fallback"`; only when every same-name pair is malformed is the request forwarded without a minted `Authorization`, logged with `action: "forward"` — or `action: "forward_stripped"` when `stripInboundAuthorization` is on and there was an inbound header to remove. `action` is the outcome's own name on both this line and `injection.no_cookie`, so a query keyed on `"forward"` alone does not see the stripped requests. `sid=bad,val; sid=good` and `sid=good; sid=bad,val` both exchange `good`.

The cookie name itself is checked at startup: `auth.injection.sessionCookieName` must be an RFC 6265 `cookie-name` (an RFC 9110 `token`: one or more of `` !#$%&'*+-.^_`|~ ``, digits and letters). A name containing whitespace, `=` or another separator is a configuration error naming the key, because the name is interpolated into the same outbound `Cookie` header.

#### External credential exchange (`auth.injection.exchange`)

Opt-in. With `auth.injection.exchange.enabled = true`, a request that presents `Authorization: Bearer <JWT>` instead of a session cookie is exchanged at the provider for a first-party access token, and only that token reaches the upstream. Session-based clients and clients holding a supported external credential then meet the same backend token validation and authorization. Disabled (the default), nothing in this section applies and injection mode behaves exactly as described above.

**Responsibility boundary.** The proxy is a token-endpoint client. It extracts the credential, submits it to its configured provider, caches a successful result within its validity bounds, and replaces the inbound `Authorization` header with the issued token. Token validation, issuer trust, identity mapping, exchange authorization and token issuance belong to [auth.provider](https://github.com/o3co/auth.provider). Its `AssertionIssuerRegistry` is the source of truth for which external issuers are trusted and on what terms — per-issuer keys, algorithms and `allowedSubjects` / `allowedScopes` / `allowedAudiences` / `allowedClients`. Adding a tenant's IdP is a provider registration; the proxy does not duplicate that trust configuration and imposes no single-issuer restriction. The unverified `iss` never selects a token endpoint, a key URL or a client: the proxy always calls its configured `providerOrigin`.

**Grant: RFC 7523, not RFC 8693.** The exchange is the [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) JWT-bearer authorization grant:

```http
POST /oauth/token
Authorization: Basic <client_secret_basic credentials>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWT>[&scope=…][&audience=…][&resource=…]
```

With a client key instead of a secret, there is no `Authorization` header, and the body also carries `client_id`, `client_assertion_type` and `client_assertion`.

It is not [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) token exchange (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with `subject_token` / `subject_token_type`), and the two are not interchangeable. The provider accepts only assertions that satisfy the registered issuer's profile, including an audience naming the provider itself: a JWT access token an external IdP issued for some unrelated API is not a valid assertion merely because its issuer is registered. Exchanging general external access tokens needs a separately defined provider validation and exchange contract (RFC 8693) and is not what this path does. Delegation is out of scope as well: the jwt-bearer grant issues no `act` claim, and no forwarding header stands in for one.

**Supported profiles.** Whatever the provider's registry admits for the assertion's issuer — plain RFC 7523 assertions, and the Identity Assertion JWT Authorization Grant (ID-JAG) profile. The proxy submits the `assertion` unchanged; the registry entry decides which profile applies. For ID-JAG the provider enforces two rules the proxy's behaviour is built around:

- **Client binding.** The ID-JAG's `client_id` claim must equal the client that authenticated at the token endpoint — the proxy's `auth.injection.exchange.clientId`. The IdP must mint ID-JAGs for that client; one minted for any other client is refused (`401 credential_rejected`).
- **One-time use.** Each `jti` is accepted once. The proxy never resubmits an assertion on its own: it does not retry, it does not cache failures, and concurrent identical requests share one submission. A successful result is reused from the cache until the cache entry expires. After that — or at another proxy instance, whose cache is its own — the same ID-JAG is a replay the provider refuses (`401 credential_rejected`), and the client must obtain a fresh assertion.
- **The cache window is not replay-checked.** The provider's one-time check runs when an assertion is submitted, and a cache hit submits nothing. Within the cache lifetime, whoever presents the same assertion — the client, or anyone who obtained it — is served the cached token. Treat the assertion as a bearer credential for that window; `tokenCache.ttlSeconds` bounds it.

**Client authentication.** When the exchange is enabled, `clientId` and exactly one of `clientSecret` and `clientKey` are required, and boot fails otherwise: a `client_id` alone is not client authentication. With a secret the proxy authenticates with `client_secret_basic`, using the RFC 6749 §2.3.1 encoding described under [Introspection client identity](#introspection-client-identity); with a key, with `private_key_jwt` (see [Client authentication with a private key](#client-authentication-with-a-private-key-private_key_jwt)). Register it at the provider as a confidential client whose `allowedGrantTypes` names `urn:ietf:params:oauth:grant-type:jwt-bearer`, and list it in `allowedClients` of every issuer entry that names such a list. The requested `scope`, `audience` and `resource` are fixed by deployment configuration and sent only when set; the provider enforces what they may be, and decides which of them it reads (auth.provider's jwt-bearer grant reads `scope`, and `resource` under `oauth.resourceIndicator.enabled`).

**Request shape.** With the exchange enabled:

| Session cookie | `Authorization` | Result |
| --- | --- | --- |
| absent | absent | Forwarded without `Authorization`, as without the exchange. |
| present | absent | Session grant, as without the exchange. |
| absent | `Bearer <JWT>` | Exchanged; the issued token replaces the header. |
| absent | anything else — another scheme, an opaque token, a malformed JWT, an empty value | `401 credential_unsupported`. No provider call, nothing forwarded. |
| present | any | `400 credential_ambiguous`. No provider call, nothing forwarded. |

"Present" means the `Cookie` header carries `auth.injection.sessionCookieName`, whether or not the value passes the [cookie grammar check](#cookie-forwarding); other cookies do not count. The proxy never chooses between two credentials and never switches to the other one after one fails. The `Bearer` scheme is matched case-insensitively, and the token must be a JWS compact JWT whose header and payload decode to JSON objects.

**Errors.** The session path's shape — `{ "error", "error_description" }`, no `WWW-Authenticate`. None of these forwards the original credential or falls back to a session.

| Status | `error` | When |
| --- | --- | --- |
| 400 | `credential_ambiguous` | Session cookie and `Authorization` on the same request. |
| 401 | `credential_unsupported` | `Authorization` is not `Bearer <JWT>`. |
| 401 | `credential_rejected` | The `iss` is not in `allowedIssuers` (no provider call), or the provider answered `invalid_grant`: bad signature, expired, wrong audience, unregistered issuer, client not admitted by the issuer, replayed ID-JAG, unresolvable subject. |
| 403 | `exchange_not_permitted` | The provider answered `invalid_scope`, `invalid_target` or `unauthorized_client`. |
| 502 | `provider_config_error` | The provider answered `401` (the proxy's own client authentication), any other `400`, or a redirect (redirects are not followed). |
| 502 | `provider_unavailable` | Provider `5xx` or `429`, a network error or timeout before the response arrives, or an unexpected status. The provider's `Retry-After` is passed through. |
| 502 | `provider_invalid_response` | A `200` whose body is not a JSON object (empty, not JSON, or an array), exceeds the 64 KiB bound, or could not be read — a timeout or a dropped connection while reading it; one without an `access_token`; or one with a `token_type` other than `Bearer` (e.g. `DPoP`). |

Each outcome is logged as an `injection.exchange_*` event (`exchange_fetch`, `exchange_success`, `exchange_cache_hit`, `exchange_credential_ambiguous` at warn, `exchange_credential_unsupported` with a `reason` of `scheme` or `format`, `exchange_issuer_refused`, `exchange_rejected`, `exchange_not_permitted` at warn, `exchange_provider_config_error` / `exchange_provider_unavailable` / `exchange_provider_invalid_response` at error, with the provider's `error` code where there is one). The assertion, the issued token, the client secret or key, the client assertion signed with the key, and the unverified `iss` are never logged. The provider's `error` is logged only when it is shaped like an RFC 6749 error code — no whitespace, at most 64 characters, nothing JWT-shaped, not echoing the assertion or secret — and as `invalid_error_code` otherwise; its `error_description` is not logged.

**Issuer prefilter.** `allowedIssuers` (default empty = off) refuses an assertion whose unverified `iss` is not listed, before any provider call — a way to shed traffic from issuers the deployment never expects. It is not required for the security of the exchange and never replaces provider validation: a listed issuer is still verified by the provider in full, and an unlisted one gets the same `credential_rejected` a provider refusal does. From the environment the list is whitespace-separated, like `INJECTION_SCOPE`.

**Cache.** A successful exchange is cached in memory, per instance, in a cache separate from the session cache but sized and timed by the same `auth.injection.tokenCache` settings. Its key is SHA-256 over the grant type, the token endpoint, the client, `scope`, `audience`, `resource` and the assertion, so a result is never reused for a different assertion or exchange context. An entry expires at

`min(sent + tokenCache.ttlSeconds, sent + provider expires_in, assertion exp) − tokenCache.safetyMarginSeconds`

where `sent` is the instant the token request went out. `ttlSeconds` and `expires_in` are counted from the request, not from the response, so a slow provider cannot push an entry past the issued token's expiry. An assertion without `exp`, or an entry that would already have expired by the time the response arrives, is not cached. The assertion's `exp` is read unverified, which is safe because it can only shorten the lifetime. A provider that includes [auth.provider#588](https://github.com/o3co/auth.provider/pull/588) also caps a jwt-bearer token's lifetime at the assertion's remaining validity; the proxy's cache bound holds independently of that.

**Revocation delay.** Expiry bounds do not propagate revocation. Revoking the external credential, its issuer's registration or the proxy's client does not reach a token already issued, which stays valid at offline validators until its own `exp` (see [Revocation and the access-token lifetime](#revocation-and-the-access-token-lifetime)), nor a cached result, which this proxy keeps injecting for up to the cache lifetime above without asking the provider again. A deployment that needs immediate revocation needs an explicit mechanism — short issued-token lifetimes and introspection-based validation upstream.

**Backends and CSRF.** The upstream still verifies every token it is handed — signature, `iss`, `aud` and `exp` against the provider's keys, or introspection — and enforces authorization; a header arriving from this proxy proves nothing on its own. Which internal issuer and audience the issued token carries follows from the provider's configuration, not from the proxy. The session path still needs CSRF protection exactly as described under [CSRF responsibility boundary](#csrf-responsibility-boundary). Every exchange cache miss spends from the same per-instance `/oauth/token` rate-limit bucket as the session grant (see [Provider rate limiting](#provider-rate-limiting)).

#### Threat model — process memory

Active access tokens reside in process memory, and so does a configured client secret or private key, which also sits in the process environment. An attacker with read access to proxy process memory can extract all cached tokens and the proxy's own client credentials. Standard host-security practices apply (container isolation, minimal image, no unnecessary `ptrace` capabilities).

Graceful shutdown does not clear the caches: the drain closes the listener and lets in-flight requests finish within `drainTimeoutMs`, after which the remaining connections are force-closed, and the cached tokens stay in memory until the process exits (#95 F21).

### Provider rate limiting

The provider rate-limits its OAuth endpoints on the **caller's IP address** — the bucket key is `<endpoint>:ip:<ip>`. Every call this proxy makes shares one bucket per proxy instance: `POST /oauth/token` in injection mode (session grants and exchanges alike), `POST /oauth/introspect` in validation mode. Not per user, not per session, not per token.

With the provider's default budget of 60 requests per 60s, one proxy instance is capped at roughly **60 cache-missing requests a minute**, however many end users sit behind it. Cache hits are free; every miss spends from the shared bucket. Concurrent misses on one credential spend once: both modes coalesce them into a single provider call, so a burst of parallel requests carrying the same token or cookie costs one.

The overflow is not graceful. The provider answers `429`, and the proxy turns that into a 5xx:

- Injection mode — an unexpected provider 4xx becomes `502 provider_unavailable` (the provider's `Retry-After` is passed through).
- Validation mode — the provider's `429` becomes `502 Bad Gateway`, as every provider failure there does other than a `401` (the token's `401 Invalid Token`, or `502 Provider Configuration Error` for the proxy's own client) and a redirect (`502 Provider Configuration Error`).

So the symptom is a burst of proxy 5xx under load, with nothing in it that says "rate limit". Check the provider's rate-limit events before treating it as a provider outage.

Raise the budget on the provider side rather than working around it here:

- `memoryRateLimiter.limits { token { limit, windowSeconds } }` and `{ introspect { … } }` for the single-process memory adapter.
- `redisRateLimiter.limits { … }` (and `redisRateLimiter.defaultLimit`) when `rateLimiter.adapter = "redis"` — which a multi-replica deployment needs anyway, since the memory adapter's counters fork per replica.

Two things that make it worse:

- **Lowering `tokenCache.ttlSeconds` / `INTROSPECT_CACHE_TTL_SEC` multiplies the misses.** The shorter the TTL, the more of the same 60/60s bucket the same traffic spends. Their effects on revocation differ between injection and validation — see [Revocation and the access-token lifetime](#revocation-and-the-access-token-lifetime).
- **Scaling out gives each instance its own bucket and its own cold cache.** A rollout therefore costs `instance count × active sessions` provider calls at exactly the moment the buckets are being spent fastest. If several instances sit behind one NAT or egress gateway they present a single source IP and share one bucket instead.

### Request body limit

`HTTP_BODY_LIMIT_SIZE` (default `10mb`) bounds the request body in both modes. It is a number, optionally signed `+` and followed by `b`, `kb`, `mb`, `gb`, `tb` or `pb` in any case, with 1kb = 1024 bytes and any fraction of a byte dropped; any other value fails at boot.

A request whose `Content-Length` is over the limit is refused before the mode does anything: its token is not introspected and no token is minted for it, so it spends none of the provider's budget. A request that declares no length — a chunked body — can only be measured by reading it. That happens when the request goes upstream, after the mode has checked or minted its token, and nothing reaches the upstream. Both are answered `413`, in the mode's refusal shape: `{ "code": 413, "message": "Payload Too Large" }` in validation mode, `{ "error": "body_too_large", "error_description": "request body over the limit" }` in injection mode. The rest of the body is read and discarded, so a keep-alive connection goes on to its next request.

A body within the limit is read whole before it goes upstream, and is sent with a `Content-Length` whether it arrived with one or chunked; the inbound `Transfer-Encoding`, and a `Trailer` announcing fields of it, are not sent on. A request with a transfer coding other than `chunked` is refused `501`, since its body would reach the upstream still coded.

Whatever else reaches the end of a mode's router unanswered is refused in the same shape: `{ "code", "message" }` with the status's reason phrase in validation mode, `{ "error": "request_failed", "error_description" }` in injection mode. That includes a body that ended early, an upstream that refused the connection, and anything a mode's middleware threw. The status is the error's own `4xx` or `5xx`, and `500` otherwise, so an unreachable upstream is a `500`. A failure after the upstream's answer has started cannot change its status; it is logged, and the connection closed. Each is logged with the request id as `requestId`:

| Event | Level | When |
| --- | --- | --- |
| `validation.body_too_large`, `injection.body_too_large` | info | A body over the limit (`413`). The line carries `limitBytes`, and `contentLength` when the request declared one. |
| `validation.request_failed`, `injection.request_failed` | info for a `4xx`, error otherwise | Anything else no stage answered, with the error under `error`: the `Error` itself in validation mode, its message in injection mode, as each mode logs its other failures. |

### Client authentication with a private key (`private_key_jwt`)

Wherever the proxy authenticates to the provider as a client, it can hold a private key instead of a shared secret ([RFC 7523 §2.2](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2)): introspection in validation mode, the exchange, and the session grant.

| Call | Key | Secret, the alternative | Neither |
| --- | --- | --- | --- |
| Introspection | `CLIENT_KEY` | `CLIENT_SECRET` | the inbound token is the credential |
| Session grant | `INJECTION_CLIENT_KEY` | — | a public client: `client_id` alone |
| Exchange | `INJECTION_EXCHANGE_CLIENT_KEY` | `INJECTION_EXCHANGE_CLIENT_SECRET` | refused at boot |

A key and a secret for the same client are refused at boot. With a key, every call signs a new client assertion and sends it in the form body with the `client_id`, and no `Authorization` header — the provider refuses a request that authenticates two ways:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=…&client_id=<client id>&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<JWT>
```

The assertion's `iss` and `sub` are the client id, its only `aud` is the provider's issuer identifier, and it carries a random `jti` and an `exp` 60 seconds after its `iat`. Its header names `typ: client-authentication+jwt`, so it cannot be taken for another kind of JWT signed with the same key. The provider accepts each `jti` once, and the proxy never reuses one.

**The provider's issuer.** `VALIDATION_PROVIDER_ISSUER` or `INJECTION_PROVIDER_ISSUER` is required with a key, and refused without one (an issuer no key uses is a key that did not arrive). Copy it from the `issuer` of the provider's discovery document (`/.well-known/openid-configuration`), character for character: `https` (`http` only on a loopback host), a path allowed, printable ASCII (if the provider's issuer has a Unicode host, configure the provider with its `xn--` form), no query, fragment, userinfo or whitespace. Unsetting the issuer is part of turning off the last key, including disabling an exchange that holds one. It is not derived from `INTROSPECT_URL` or `INJECTION_PROVIDER_ORIGIN`, since the URL the proxy reaches the provider at can differ from the issuer the provider names itself by. The issuer alone is the audience, as recommended for `private_key_jwt`, rather than the token endpoint URL RFC 7523 also allows.

**The key.** A private JWK, as JSON text in the environment variable: an Ed25519 key (`EdDSA`), an EC P-256, P-384 or P-521 key (`ES256`, `ES384`, `ES512`), or an RSA key of 2048 bits or more (`RS256` unless the JWK's `alg` names `RS384`, `RS512` or a `PS*`). An `alg`, if the JWK has one, must be the JWS name above — `EdDSA`, not RFC 9864's `Ed25519` — since the provider matches a registered key's `alg` to the header's exactly. A `use` other than `sig`, or `key_ops` without `sign`, is refused, and so is a JWK whose public members are not its private key's. Its `kid`, when present, goes in every assertion's header, so the provider picks the matching public key. Anything else — a public key, a symmetric key, an algorithm that does not fit the key — stops the process at boot, naming the key and never printing it. The proxy logs neither the key nor an assertion. Supply the key from the environment (or a secret store that sets it), not by writing it into `application.conf`: the image build copies `config/`, so a key written there ends up in an image layer.

For example, an Ed25519 key generated with Node and the public half to register:

```sh
node -e 'const { generateKeyPairSync } = require("node:crypto");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const kid = "proxy-2026-09";
console.log("CLIENT_KEY=" + JSON.stringify({ ...privateKey.export({ format: "jwk" }), kid }));
console.log("public JWK: " + JSON.stringify({ ...publicKey.export({ format: "jwk" }), kid }));'
```

**At the provider** (auth.provider: the oauth package's README, "Client authentication: `private_key_jwt`"), register the client with `tokenEndpointAuthMethod: "private_key_jwt"`, no `clientSecret`, and its public key — inline as `jwks`, or at a `jwksUri` the provider fetches. The public JWK is the private one without its private members (`d`, and an RSA key's `p`, `q`, `dp`, `dq`, `qi`), keeping its `kid`; its `alg`, if any, `EdDSA`/`ES*`/`RS*`/`PS*` as signed, and its `key_ops`, if any, `["verify"]`. The provider records each `jti` in its replay seen-set, which a composition must wire for `private_key_jwt` to be accepted at all: without one, the provider answers a client assertion `500 server_error`, which the proxy reports as a provider failure (`502 Bad Gateway` in validation, `502 provider_unavailable` in injection), not as a configuration error. A session-grant client that authenticates with a key is a confidential client: register it as one.

**Switching an existing client to a key.** The provider allows one authentication method per client (`tokenEndpointAuthMethod`), so changing an existing client from a secret, or from a public client, to `private_key_jwt` in place is a hard cutover: every instance still sending the old credential is refused from that moment. Instead, register a new client id with `private_key_jwt` and the same scopes, grant types and `allowedAudiences`, roll the proxy to the new client id and key, then retire the old client. What depends on the client id, and so needs carrying over:

- validation's audience pin is the calling client's id and its `allowedAudiences` — if tokens name the old client id as `aud`, list it in the new client's `allowedAudiences`;
- a token from the session grant or the exchange (absent a `resource`) has `aud` = the client's first `allowedAudiences` entry, else its client id — if the old client had none, give the new one the old client id as its **first** entry;
- a token's `azp` — from the session grant or the exchange — is the client id, and an exchanged token also carries it as `client_id`, so an upstream that pins either must accept the new one, and a provider grant policy that names the client must name the new one;
- an issuer entry at the provider that names `allowedClients` must list the new exchange client, or every exchange is refused.

**Rotating the key.** The proxy signs with one key at a time; rotation happens where keys are verified. Publish the new public key beside the old one in the client's `jwks` or `jwksUri`, switch the proxy's key (with a new `kid`), and remove the old public key once no instance signs with it. Instances mid-rollout keep working, since the provider picks the key by `kid` — so give every key a `kid`: with two public keys of the same type published, an assertion without one matches both and is refused, which makes rotating away from a key without a `kid` a cutover.

**Clocks.** An assertion is valid from its `iat` for 60 seconds, and the provider allows its clock tolerance (30 seconds by default) on top. A proxy whose clock runs far enough behind or ahead has its assertions refused: validation answers `502 Provider Configuration Error`, and injection `502 provider_config_error`, as for any refused client authentication.

## Setup

```bash
pnpm install
pnpm run build
pnpm run start
```

## Development

```bash
pnpm run debug    # tsx watch mode
```

## Docker

```bash
make docker       # Build runtime image
```

## Configuration

Shared environment variables:

| Environment Variable | Description |
| --- | --- |
| `AUTH_MODE` | **Required.** `"validation"` or `"injection"`. |
| `HTTP_PORT` | HTTP listen port (default: 80). |
| `HTTP_HOSTNAME` | HTTP listen hostname (default: 0.0.0.0). |
| `HTTP_PATH_PREFIX` | Path prefix for proxy routes (default: /). |
| `HTTP_BODY_LIMIT_SIZE` | Request body size limit (default: 10mb). A number, optionally signed `+`, with an optional unit — `b`, `kb`, `mb`, `gb`, `tb`, `pb`; 1kb = 1024 bytes — or the proxy does not start. See [Request body limit](#request-body-limit). |
| `UPSTREAM_BASEURL` | Upstream service base URL. |
| `CORS_ORIGIN_PATTERN` | CORS origin regex pattern (optional). |
| `LOG_LEVEL` | pino log level — `trace`, `debug`, `info`, `warn`, `error`, `fatal` or `silent` (default: `info`). Read directly from the environment when the logger is created, not through the HOCON config. Output is NDJSON on stdout. In both modes, every line about a request — `incoming request` and each decision — carries the request id as `requestId` and an `event` named `injection.*` or `validation.*`. |

Validation mode:

| Environment Variable | Description |
| --- | --- |
| `CLIENT_ID` | Client ID for introspection auth (optional; set with exactly one of `CLIENT_SECRET` and `CLIENT_KEY`). |
| `CLIENT_SECRET` | Client secret for introspection auth (`client_secret_basic`; optional, with `CLIENT_ID`). |
| `CLIENT_KEY` | Private JWK for introspection auth (`private_key_jwt`; optional, with `CLIENT_ID` and `VALIDATION_PROVIDER_ISSUER`). See [Client authentication with a private key](#client-authentication-with-a-private-key-private_key_jwt). |
| `VALIDATION_PROVIDER_ISSUER` | The provider's issuer identifier, the client assertion's audience. **Required** with `CLIENT_KEY`, and refused without it. |
| `INTROSPECT_URL` | Introspection endpoint URL: absolute `http(s)`, without userinfo. Anything else is refused at boot, naming the key — the proxy authenticates with its client credentials, never with the URL. |
| `VALIDATION_REALM` | RFC 6750 `realm` for `WWW-Authenticate` (optional; at most 256 printable ASCII characters, without `"`, `\` or surrounding spaces). Unset, a request using another auth scheme gets no challenge. |
| `INTROSPECT_CACHE_TTL_SEC` | Cache TTL in seconds (default: 30). |
| `INTROSPECT_CACHE_MAX_ENTRIES` | Cache max entries (default: 10000). |
| `INTROSPECT_TIMEOUT_MS` | Introspection HTTP timeout (default: 5000). |

Injection mode:

| Environment Variable | Description |
| --- | --- |
| `INJECTION_PROVIDER_ORIGIN` | Provider origin — `scheme://host[:port]`, no path/query/fragment, no userinfo, http or https only (default: `http://localhost:3000`). |
| `INJECTION_CLIENT_ID` | **Required.** OAuth `client_id`. |
| `INJECTION_CLIENT_KEY` | Private JWK for the session grant (`private_key_jwt`; optional). Unset, the session grant is a public client. |
| `INJECTION_PROVIDER_ISSUER` | The provider's issuer identifier, the client assertion's audience. **Required** with `INJECTION_CLIENT_KEY` or an enabled exchange's `INJECTION_EXCHANGE_CLIENT_KEY`, and refused without either. |
| `INJECTION_SCOPE` | **Required.** OAuth `scope` string (space-separated). |
| `INJECTION_SESSION_COOKIE_NAME` | Session cookie name (default: `connect.sid`). Must be an RFC 6265 `cookie-name` (RFC 9110 token) — whitespace, `=` or other separators fail at startup. |
| `INJECTION_STRIP_INBOUND_AUTHORIZATION` | `"true"` / `"false"` (default: `false`). Drop an inbound `Authorization` header on a request the proxy did not mint a token for. Any other value fails at startup. See [Inbound Authorization headers](#inbound-authorization-headers). |
| `INJECTION_TOKEN_CACHE_TTL_SEC` | Token cache TTL in seconds (default: 60). Applies to the session and exchange caches alike. |
| `INJECTION_TOKEN_CACHE_MAX_ENTRIES` | Token cache max entries (default: 10000), for each of the session and exchange caches. |
| `INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC` | Clock-drift safety margin in seconds (default: 5). Applies to both caches. |
| `INJECTION_TIMEOUT_MS` | Provider HTTP timeout (default: 5000), for session grants and exchanges. |
| `INJECTION_EXCHANGE_ENABLED` | `"true"` / `"false"` (default: `false`). Exchange an inbound `Authorization: Bearer <JWT>` at the provider (RFC 7523 jwt-bearer). Any other value fails at startup. See [External credential exchange](#external-credential-exchange-authinjectionexchange). |
| `INJECTION_EXCHANGE_CLIENT_ID` | `client_id` the proxy authenticates as for the exchange. **Required** when the exchange is enabled. |
| `INJECTION_EXCHANGE_CLIENT_SECRET` | Its client secret (`client_secret_basic`). When the exchange is enabled, exactly one of this and `INJECTION_EXCHANGE_CLIENT_KEY` is **required**. |
| `INJECTION_EXCHANGE_CLIENT_KEY` | Its private JWK (`private_key_jwt`), instead of the secret; needs `INJECTION_PROVIDER_ISSUER`. |
| `INJECTION_EXCHANGE_SCOPE` | `scope` sent with the exchange (space-separated; optional). |
| `INJECTION_EXCHANGE_AUDIENCE` | `audience` sent with the exchange (optional). |
| `INJECTION_EXCHANGE_RESOURCE` | RFC 8707 `resource` sent with the exchange (optional). |
| `INJECTION_EXCHANGE_ALLOWED_ISSUERS` | Optional prefilter on the unverified `iss`: a whitespace-separated list (default: empty = off). |

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 token issuance.
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — No-DSL ABAC policy verifier.
- [auth](https://github.com/o3co/auth) — Architecture docs and cross-component E2E tests.
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — protobuf-option-driven authorization interceptors for gRPC / ConnectRPC.

## License

Apache License 2.0
