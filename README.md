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

- Detects revoked tokens immediately.
- Introspection results are cached (default 30s TTL), reducing provider load.
- Downstream services receive pre-validated requests without implementing auth logic.

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

#### Session revocation latency

After logout at the provider, the proxy may continue returning cached tokens for up to `tokenCache.ttlSeconds` (minus the safety margin). To reduce revocation latency, lower `ttlSeconds` (e.g., `10`). Tradeoff: higher provider load.

#### Scope boundary

One proxy instance serves one OAuth scope domain. `auth.injection.clientId` and `auth.injection.scope` are fixed at deploy time. Serve multiple scope domains with multiple proxy instances.

#### CSRF responsibility boundary

The proxy is a transparent augmentation layer. It injects the Bearer but does NOT enforce CSRF. Combine with `SameSite=Lax` cookies, same-origin deployment, and CSRF protection in the upstream service.

#### Cookie forwarding

Only the cookie named in `auth.injection.sessionCookieName` is forwarded to the provider on the session grant call. Other cookies (analytics, CSRF tokens, third-party) do not reach the provider.

The forwarded value must conform to the RFC 6265 section 4.1.1 `cookie-value` grammar: a run of `cookie-octet`s (printable US-ASCII excluding whitespace, DQUOTE, comma, semicolon, and backslash), optionally wrapped in exactly one surrounding DQUOTE pair. A surrounding DQUOTE pair is accepted and forwarded verbatim (quotes preserved) so the provider's own cookie parser decides how to read it. Anything else is refused — a `,`, whitespace, `\`, a control character, or a non-ASCII byte anywhere in the value, or a DQUOTE anywhere other than as that surrounding pair (interior or unbalanced), or an empty value: the request is forwarded without `Authorization` and the provider is not called. Whitespace immediately after `=` is part of the value and is refused; SP / HTAB next to the `;` separator or at the ends of the header is separator slack and is ignored. `;` is the cookie-pair delimiter and never becomes part of a value. Default session stores (express-session `connect.sid`, hex / base64url / JWT session ids) always conform.

A refused cookie is not silent. A header that does not carry the cookie at all is an ordinary anonymous request and logs `injection.no_cookie` at debug; a header that carries it in a refused form logs `injection.cookie_rejected` at **warn** with the request id and a bounded `reason` — `empty` (`sid=` / `sid=""`), `quoting` (a DQUOTE anywhere other than one surrounding pair) or `grammar` (a character outside `cookie-octet`). The cookie bytes are never logged. A sustained rate of this event points at a misbehaving client or a provider issuing session cookies outside the grammar.

When the header carries the same name more than once (RFC 6265 section 5.4 lets a user agent send two same-name pairs, ordered by path and then creation time), the first well-formed pair is used. A malformed pair before it is skipped and logged as `injection.cookie_rejected` with `action: "fallback"`; only when every same-name pair is malformed is the request forwarded anonymously, logged with `action: "forward"`. `sid=bad,val; sid=good` and `sid=good; sid=bad,val` both exchange `good`.

The cookie name itself is checked at startup: `auth.injection.sessionCookieName` must be an RFC 6265 `cookie-name` (an RFC 9110 `token`: one or more of `` !#$%&'*+-.^_`|~ ``, digits and letters). A name containing whitespace, `=` or another separator is a configuration error naming the key, because the name is interpolated into the same outbound `Cookie` header.

#### Threat model — process memory

Active access tokens reside in process memory. An attacker with read access to proxy process memory can extract all cached tokens. Standard host-security practices apply (container isolation, minimal image, no unnecessary `ptrace` capabilities).

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
