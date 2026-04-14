# auth.proxy

Token validation reverse proxy with introspection result caching. Sits between client and downstream service.

This component is optional. auth.policy-verifier and grpc.authz validate JWT directly, so the system works without auth.proxy. Benefits of adding it:

- **Introspection-based validation** — detects revoked tokens immediately, unlike JWT-only local validation which relies on token expiry
- **Caching** — introspection results are cached (default 30s TTL), reducing load on auth.provider
- **Centralized validation** — downstream services receive pre-validated requests without implementing auth logic

## Behavior

1. Detects `Authorization: Bearer <token>` header (passes through if absent — allows public APIs)
2. Checks in-memory cache using SHA-256 hash of token
3. On cache miss, calls provider's `POST /oauth/introspect`
4. Returns `401` if `active: false`, forwards request to downstream if `active: true`

## Features

- Introspection result caching (default 30s TTL) to reduce provider load
- Transparent request forwarding via `express-http-proxy`
- Authorization header forwarded to downstream service
- HOCON configuration with Zod validation

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

| Environment Variable | Description |
| --- | --- |
| `HTTP_PORT` | HTTP listen port (default: 80) |
| `HTTP_HOSTNAME` | HTTP listen hostname (default: 0.0.0.0) |
| `HTTP_PATH_PREFIX` | Path prefix for proxy routes (default: /) |
| `HTTP_BODY_LIMIT_SIZE` | Request body size limit (default: 10mb) |
| `CLIENT_ID` | Client ID for introspection auth (optional; must be set together with `CLIENT_SECRET`) |
| `CLIENT_SECRET` | Client secret for introspection auth (optional; must be set together with `CLIENT_ID`) |
| `INTROSPECT_URL` | Introspection endpoint URL |
| `INTROSPECT_CACHE_TTL_SEC` | Cache TTL in seconds (default: 30) |
| `UPSTREAM_BASEURL` | Upstream service base URL |
| `CORS_ORIGIN_PATTERN` | CORS origin regex pattern (optional) |

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 token issuance
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — No-DSL ABAC policy verifier
- [auth](https://github.com/o3co/auth) — Architecture docs and cross-component E2E tests
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC authorization middleware

## License

Apache License 2.0
