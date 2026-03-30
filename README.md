# auth.proxy

Auth proxy — token validation and caching reverse proxy.

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
| `INTROSPECT_URL` | Introspection endpoint URL |
| `INTROSPECT_CACHE_TTL_SEC` | Cache TTL in seconds |
| `ENDPOINT_BASEURL` | Downstream service base URL |

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 token issuance
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — No-DSL ABAC policy verifier
- [auth](https://github.com/o3co/auth) — Architecture docs and cross-component E2E tests
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC authorization middleware

## License

Apache License 2.0
