# auth.proxy

[![CI](https://github.com/o3co/auth.proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.proxy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/o3co/auth.proxy/graph/badge.svg)](https://codecov.io/gh/o3co/auth.proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> This repository is an optional perimeter gate that sits outside the three-layer separation of concerns ([authentication & token issuance](https://github.com/o3co/auth.provider) / [authorization decision](https://github.com/o3co/auth.policy-verifier) / [authorization enforcement](https://github.com/o3co/protobuf.interceptors)) of the [auth](https://github.com/o3co/auth) stack.

Reverse proxy that sits between clients and downstream services. Operates in one of two mutually exclusive modes selected at deploy time via `auth.mode`.

## Operating modes

`auth.mode` is required — must be set explicitly to `"validation"` or `"injection"`. Omission or a typo causes the proxy to fail to start. Set it via HOCON (`auth.mode = "validation"`) or the `AUTH_MODE` environment variable.

### Validation mode (`auth.mode = "validation"`)

Validates inbound `Authorization: Bearer <token>` headers against the provider's introspection endpoint. Requests without a Bearer header are forwarded unchanged (public endpoints remain reachable).

Flow:

1. Detects `Authorization: Bearer <token>` header (passes through if absent).
2. Checks in-memory cache keyed by SHA-256 of the token.
3. On cache miss, calls provider's `POST /oauth/introspect`.
4. Returns `401` if `active: false`; forwards the request if `active: true`.

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

`CLIENT_ID` / `CLIENT_SECRET` are optional, and the choice between setting them and leaving them unset changes which tokens the provider will call `active`.

**With client authentication (both set).** The proxy authenticates to `POST /oauth/introspect` with HTTP Basic, and the provider then pins the introspected token's audience to the **calling client's own identity**: a token whose `aud` does not name this client comes back `active: false`. There is no error and no diagnostic — on the wire an audience mismatch is indistinguishable from a forged or expired token, so the proxy answers `401` for tokens that are in fact perfectly valid.

The client the proxy authenticates as must therefore be associated with the audience of the tokens it validates. Either:

- register that audience in the client's `allowedAudiences`, or
- give the client the resource URI as its own `client_id`.

A proxy fronting `https://api.example.com/orders` that authenticates as some unrelated `client_id` answers `401` to every request whose token was minted with an RFC 8707 `resource` audience — which, wherever resource indicators are in use, is every request it sees.

> A companion change in `auth.provider` widens this pin to `allowedAudiences ∪ {clientId}`, the ceiling its other grants already use. Until it lands, only a token whose `aud` is exactly the caller's `client_id` introspects as active under client authentication.

**Without client authentication (both unset).** The proxy presents the inbound token itself as the introspection credential — `buildAuthHeader` emits `Authorization: Bearer <token>` with the same token in the body, which the provider requires to match. On that path the calling client is never identified, so **the audience pin does not apply** and a token for any audience is introspected on its own merits.

What that trades away:

- **The provider stops checking `aud` for you.** It records the gap and returns the claims. The proxy does not check `aud` either, so a token minted for a *different* resource server validates here. Unless the upstream service checks `aud` itself, that is a confused-deputy gap — set `CLIENT_ID` / `CLIENT_SECRET` and register the audience, or check `aud` upstream.
- **No client identity in the provider's audit trail** for these calls.
- Signature, issuer, token type, expiry and the revocation denylist are still checked, so a revoked or forged token is still `active: false`.

Rate limiting is unaffected by the choice — it is keyed on the proxy's IP either way (see [Provider rate limiting](#provider-rate-limiting)).

**Credentials containing reserved characters.** RFC 6749 §2.3.1 requires both halves to be `application/x-www-form-urlencoded`-encoded *before* they are joined with `:` and base64'd into the Basic header; otherwise a `:` inside either half re-splits the credential in the wrong place and the provider reads a different pair than the one configured. `buildAuthHeader` does this (`pctEncode`, `src/modes/validation/introspect.mts`), and the provider decodes with the matching form-urlencoded decoder, so a credential containing reserved characters round-trips byte for byte. Set the raw value in the environment variable — do not pre-encode it yourself.

### Injection mode (`auth.mode = "injection"`)

Translates an inbound session cookie into an outbound `Authorization: Bearer` token. Realizes the OWASP OAuth 2.0 BCP Token Handler Pattern — browsers never hold access tokens.

Flow:

1. Extracts the session cookie named in `auth.injection.sessionCookieName`.
2. If absent, forwards the request unchanged (the service layer decides whether authentication is required). A cookie that is present but refused (see [Cookie forwarding](#cookie-forwarding)) is forwarded the same way, but logged.
3. On cache hit, injects the cached Bearer and forwards.
4. On cache miss, exchanges the cookie for an access token via the provider's `POST /oauth/token` with `grant_type=session`. Concurrent misses on the same cookie coalesce into a single provider call (single-flight).
5. Injects `Authorization: Bearer <token>` and forwards upstream.

#### Cache behavior

- In-memory, per-instance. Restart and horizontal scale-out produce cold caches. Peak provider load during rollout ≈ `instance count × active sessions`.
- TTL: `min(auth.injection.tokenCache.ttlSeconds, provider.expires_in) - safetyMarginSeconds`. Default 60s minus 5s safety margin.
- Every cache miss spends from a rate-limit bucket the whole instance shares — see [Provider rate limiting](#provider-rate-limiting) before lowering the TTL.

#### Revocation and the access-token lifetime

For a downstream service that validates JWTs offline, the **access token's own lifetime** bounds replay exposure after logout at the provider. A downstream service that introspects tokens can observe tracked-session invalidation sooner.

With UserSession tracking configured, the provider's `session` grant requires a live tracked session whose subject matches the browser user, and stamps its `sid` on the access token. It issues no refresh token and therefore no refresh-token `family_id`. `POST /session/logout` invalidates the tracked UserSession and associated federation state before destroying the browser session. Successful tracked-session invalidation makes introspection return `active: false` and userinfo refuse the token; store failures are logged as described in the provider's operator runbook.

`tokenCache.ttlSeconds` bounds how long this proxy keeps re-injecting a token it already holds without asking the provider again. Lowering it makes a *new* request on a logged-out session reach the provider sooner. An unauthenticated browser session returns `401`; a retained browser session with a missing, revoked or inconsistent tracked record returns `400 invalid_grant`. The injection proxy maps either rejection to its existing `401 session_required` response. A shorter cache TTL does not recall tokens already forwarded, and it multiplies the calls this proxy makes to `/oauth/token` (see [Provider rate limiting](#provider-rate-limiting)).

So, for an operator:

- **Keep the provider's access-token lifetime short in a BFF topology.** `oauth.accessToken.expiresIn` bounds replay exposure at offline validators. The proxy owns the cookie-to-token exchange, so a short lifetime costs a grant call while the browser session remains valid.
- **A downstream service that validates the JWT offline cannot learn about a logout at all.** Signature, `iss`, `aud` and `exp` are everything an offline validator checks, and none of them changes when a session ends. For such a service the revocation window *is* the token lifetime, with nothing available to shorten it.
- **Introspection-based validation is the only mode that can observe a revocation.** A resource server — or an `auth.mode = "validation"` proxy in front of one — calling `POST /oauth/introspect` asks the provider on every cache miss, so a token the provider has stopped vouching for comes back `active: false` within that introspection cache TTL.

The validation proxy also caps each introspection cache entry at the token's `exp`. A zero introspection TTL bypasses the cache so each request asks the provider about the tracked session. This setting belongs to validation mode; it does not change the injection proxy's token cache or an offline validator's behavior.

#### Scope boundary

One proxy instance serves one OAuth scope domain. `auth.injection.clientId` and `auth.injection.scope` are fixed at deploy time. Serve multiple scope domains with multiple proxy instances.

A provider response of `400 invalid_grant` is mapped to `401 session_required`,
so a revoked session prompts authentication rather than appearing as a proxy
configuration failure. Other provider 400 responses retain their configuration-error mapping.

#### CSRF responsibility boundary

The proxy is a transparent augmentation layer. It injects the Bearer but does NOT enforce CSRF. Combine with `SameSite=Lax` cookies, same-origin deployment, and CSRF protection in the upstream service. Being transparent cuts the other way too — see [Inbound Authorization headers](#inbound-authorization-headers).

#### Inbound Authorization headers

The proxy overrides an inbound `Authorization` header only on the requests where a session cookie actually produced a token (logged as `injection.authorization_override`). On the two paths where it minted nothing — no session cookie at all, or a cookie the grammar check refused — the request is forwarded as-is, **inbound `Authorization` header included**.

**The upstream service must verify the token it is handed.** It must not read "a Bearer header arrived on the connection from the proxy" as "the proxy minted this": a client that sends its own `Authorization` and no session cookie reaches the upstream with that header intact. Verify signature, `iss`, `aud` and `exp` against the provider's keys, or introspect — exactly as for a request that never went through a proxy. Header provenance is not an authentication signal.

`auth.injection.stripInboundAuthorization` (`INJECTION_STRIP_INBOUND_AUTHORIZATION`) removes the ambiguity at the proxy. When `true`, an inbound `Authorization` on a request the proxy did not mint a token for is dropped before the request is forwarded, and logged as `injection.inbound_authorization_stripped` at **warn** with the request id and a `reason` of `no_cookie` or `cookie_rejected`. The header value is never logged. Upstream then sees a Bearer header only when the proxy put it there.

It defaults to `false` — the pass-through behaviour every deployment before the flag ran on — because that behaviour is load-bearing wherever a non-browser client (a service account, a mobile app) deliberately presents its own token through the same proxy. Turn it on when this proxy fronts browser sessions only, and especially when the upstream's authorization has any dependence on where the header came from. It is defence in depth, not a substitute for the paragraph above: nothing stops a client reaching the upstream by another route.

#### Cookie forwarding

Only the cookie named in `auth.injection.sessionCookieName` is forwarded to the provider on the session grant call. Other cookies (analytics, CSRF tokens, third-party) do not reach the provider.

The forwarded value must conform to the RFC 6265 section 4.1.1 `cookie-value` grammar: a run of `cookie-octet`s (printable US-ASCII excluding whitespace, DQUOTE, comma, semicolon, and backslash), optionally wrapped in exactly one surrounding DQUOTE pair. A surrounding DQUOTE pair is accepted and forwarded verbatim (quotes preserved) so the provider's own cookie parser decides how to read it. Anything else is refused — a `,`, whitespace, `\`, a control character, or a non-ASCII byte anywhere in the value, or a DQUOTE anywhere other than as that surrounding pair (interior or unbalanced), or an empty value: the request is forwarded without `Authorization` and the provider is not called. Whitespace immediately after `=` is part of the value and is refused; SP / HTAB next to the `;` separator or at the ends of the header is separator slack and is ignored. `;` is the cookie-pair delimiter and never becomes part of a value. Default session stores (express-session `connect.sid`, hex / base64url / JWT session ids) always conform.

A refused cookie is not silent. A header that does not carry the cookie at all is an ordinary anonymous request and logs `injection.no_cookie` at debug; a header that carries it in a refused form logs `injection.cookie_rejected` at **warn** with the request id and a bounded `reason` — `empty` (`sid=` / `sid=""`), `quoting` (a DQUOTE anywhere other than one surrounding pair) or `grammar` (a character outside `cookie-octet`). The cookie bytes are never logged. A sustained rate of this event points at a misbehaving client or a provider issuing session cookies outside the grammar.

When the header carries the same name more than once (RFC 6265 section 5.4 lets a user agent send two same-name pairs, ordered by path and then creation time), the first well-formed pair is used. A malformed pair before it is skipped and logged as `injection.cookie_rejected` with `action: "fallback"`; only when every same-name pair is malformed is the request forwarded anonymously, logged with `action: "forward"`. `sid=bad,val; sid=good` and `sid=good; sid=bad,val` both exchange `good`.

The cookie name itself is checked at startup: `auth.injection.sessionCookieName` must be an RFC 6265 `cookie-name` (an RFC 9110 `token`: one or more of `` !#$%&'*+-.^_`|~ ``, digits and letters). A name containing whitespace, `=` or another separator is a configuration error naming the key, because the name is interpolated into the same outbound `Cookie` header.

#### Threat model — process memory

Active access tokens reside in process memory. An attacker with read access to proxy process memory can extract all cached tokens. Standard host-security practices apply (container isolation, minimal image, no unnecessary `ptrace` capabilities).

### Provider rate limiting

The provider rate-limits its OAuth endpoints on the **caller's IP address** — the bucket key is `<endpoint>:ip:<ip>`. Every call this proxy makes shares one bucket per proxy instance: `POST /oauth/token` in injection mode, `POST /oauth/introspect` in validation mode. Not per user, not per session, not per token.

With the provider's default budget of 60 requests per 60s, one proxy instance is capped at roughly **60 cache-missing requests a minute**, however many end users sit behind it. Cache hits are free; every miss spends from the shared bucket.

The overflow is not graceful. The provider answers `429`, and the proxy turns that into a 5xx:

- Injection mode — an unexpected provider 4xx becomes `502 provider_unavailable` (the provider's `Retry-After` is passed through).
- Validation mode — a non-401 introspection failure becomes `500 Internal Server Error`.

So the symptom is a burst of proxy 5xx under load, with nothing in it that says "rate limit". Check the provider's rate-limit events before treating it as a provider outage.

Raise the budget on the provider side rather than working around it here:

- `memoryRateLimiter.limits { token { limit, windowSeconds } }` and `{ introspect { … } }` for the single-process memory adapter.
- `redisRateLimiter.limits { … }` (and `redisRateLimiter.defaultLimit`) when `rateLimiter.adapter = "redis"` — which a multi-replica deployment needs anyway, since the memory adapter's counters fork per replica.

Two things that make it worse:

- **Lowering `tokenCache.ttlSeconds` / `INTROSPECT_CACHE_TTL_SEC` multiplies the misses.** The shorter the TTL, the more of the same 60/60s bucket the same traffic spends. Their effects on revocation differ between injection and validation — see [Revocation and the access-token lifetime](#revocation-and-the-access-token-lifetime).
- **Scaling out gives each instance its own bucket and its own cold cache.** A rollout therefore costs `instance count × active sessions` provider calls at exactly the moment the buckets are being spent fastest. If several instances sit behind one NAT or egress gateway they present a single source IP and share one bucket instead.

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
| `HTTP_BODY_LIMIT_SIZE` | Request body size limit (default: 10mb). |
| `UPSTREAM_BASEURL` | Upstream service base URL. |
| `CORS_ORIGIN_PATTERN` | CORS origin regex pattern (optional). |

Validation mode:

| Environment Variable | Description |
| --- | --- |
| `CLIENT_ID` | Client ID for introspection auth (optional; must be set together with `CLIENT_SECRET`). |
| `CLIENT_SECRET` | Client secret for introspection auth (optional; must be set together with `CLIENT_ID`). |
| `INTROSPECT_URL` | Introspection endpoint URL. |
| `INTROSPECT_CACHE_TTL_SEC` | Cache TTL in seconds (default: 30). |
| `INTROSPECT_CACHE_MAX_ENTRIES` | Cache max entries (default: 10000). |
| `INTROSPECT_TIMEOUT_MS` | Introspection HTTP timeout (default: 5000). |

Injection mode:

| Environment Variable | Description |
| --- | --- |
| `INJECTION_PROVIDER_ORIGIN` | Provider origin — `scheme://host[:port]`, no path/query/fragment, no userinfo, http or https only (default: `http://localhost:3000`). |
| `INJECTION_CLIENT_ID` | **Required.** OAuth `client_id`. |
| `INJECTION_SCOPE` | **Required.** OAuth `scope` string (space-separated). |
| `INJECTION_SESSION_COOKIE_NAME` | Session cookie name (default: `connect.sid`). Must be an RFC 6265 `cookie-name` (RFC 9110 token) — whitespace, `=` or other separators fail at startup. |
| `INJECTION_STRIP_INBOUND_AUTHORIZATION` | `"true"` / `"false"` (default: `false`). Drop an inbound `Authorization` header on a request the proxy did not mint a token for. Any other value fails at startup. See [Inbound Authorization headers](#inbound-authorization-headers). |
| `INJECTION_TOKEN_CACHE_TTL_SEC` | Token cache TTL in seconds (default: 60). |
| `INJECTION_TOKEN_CACHE_MAX_ENTRIES` | Token cache max entries (default: 10000). |
| `INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC` | Clock-drift safety margin in seconds (default: 5). |
| `INJECTION_TIMEOUT_MS` | Provider HTTP timeout (default: 5000). |

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 token issuance.
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — No-DSL ABAC policy verifier.
- [auth](https://github.com/o3co/auth) — Architecture docs and cross-component E2E tests.
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — protobuf-option-driven authorization interceptors for gRPC / ConnectRPC.

## License

Apache License 2.0
