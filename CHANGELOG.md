# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-09-24

### Changed

Ten of the changes below are breaking, marked **BREAKING**. Each says what an
operator sees on the wire and in the logs, and what to do.

- **BREAKING: with client credentials configured, a provider `401` to
  introspection is `502 Provider Configuration Error`, not `401 Invalid Token`
  (#95 F7, #111).** RFC 7662 §2.3 has the introspection request authenticated,
  so the provider's `401` refuses whichever credential the request carried.
  With both `CLIENT_ID` and `CLIENT_SECRET` set, that credential is the proxy's
  own Basic header: the caller's token was never examined, and the old answer
  told the caller their token was bad when the deployment was misconfigured.
  The answer is now `502 {"code":502,"message":"Provider Configuration Error"}`
  with no `WWW-Authenticate`, logged at error as
  `introspect refused the proxy's client credentials` under the event
  `validation.provider_config_error`, where 0.6.0 logged `introspect failed`.
  Without client credentials the caller's token is the credential, and the
  status and body do not change; `active: false` is still `401 Invalid Token`
  either way.
  Clients and gateways retry a `502` more readily than a `401`, and every
  retry spends the same per-instance introspection rate-limit budget.
  **Action:** an alert keyed on `introspect failed` stops firing for this
  case, so alert on the new event; fix the credential, not the retry policy.

- **BREAKING: validation answers a provider failure `502 Bad Gateway`, and
  keeps `500` for the proxy's own (#95 F42, #126).** A provider `5xx` or `429`,
  a `4xx` other than `401`, a `2xx` whose body is not an introspection
  response, a malformed `exp`, a timeout and a network error were all
  `500 Internal Server Error` in 0.6.0. They are now
  `502 {"code":502,"message":"Bad Gateway"}`, logged at error as
  `introspect failed` under `validation.provider_error`, which is what
  injection mode has always answered for the same failures. `500` is kept for
  a thrown value that is not an introspection error — a bug in the proxy, or a
  supplied introspector's own error — logged under
  `validation.unexpected_error`. **Action:** review alerts keyed on
  validation's `500` and retry policies that retry a `502` but not a `500`:
  they now retry against a failing provider, and validation passes no
  `Retry-After` through.

- **BREAKING: validation refuses a redirect from the introspection endpoint
  instead of following it (#95 F43, #123).** A `3xx` from
  `POST /oauth/introspect` is `502 Provider Configuration Error`, logged at
  error as `introspect endpoint redirected` under
  `validation.provider_config_error`, with no challenge. It is not cached, so
  a corrected URL takes effect on the next request. An endpoint that
  redirected on the same origin used to work whenever the target answered
  introspection — typically a trailing-slash rewrite; a cross-origin one, such
  as `http` → `https`, never did — and now fails every request that needs
  introspection. **Action:** set
  `INTROSPECT_URL` to the final URL. Why following was unsafe is under
  Security.

- **BREAKING: validation's `401` carries
  `WWW-Authenticate: Bearer error="invalid_token"` (#95 F29, #114).** RFC 6750
  §3 makes the challenge a MUST on this refusal. It is sent for
  `active: false` and for a provider `401` about the caller's token; the
  status and the body are unchanged, and with `VALIDATION_REALM` set the
  challenge also carries `realm` (see Added). A browser does not prompt on a
  Bearer challenge — only Basic and Digest do — so a client that ignores the
  header sees no difference. Two limits: a browser cannot read the header
  cross-origin, because it is not CORS-safelisted and the proxy sets no
  `Access-Control-Expose-Headers`; and `invalid_token` invites a retry with a
  fresh token, which cannot help when the provider answers `active: false`
  because the token's `aud` does not name the proxy's client. Injection mode
  still sends no challenge. **Action:** none for a client that ignores the
  header; expose it at your edge if a cross-origin browser client must read
  it.

- **BREAKING: neither injection token client follows a redirect (#95 F8,
  #112).** The session grant now refuses a `3xx` from `POST /oauth/token`, as
  the exchange always has:
  `502 {"error":"provider_config_error","error_description":"provider token endpoint redirected (<status>)"}`,
  logged as `injection.provider_config_error` at error, with the provider's
  `Retry-After` passed through. What that replaces depends on the status. A
  same-origin `307` / `308` used to succeed, minting a token at the redirect
  target; that deployment stops working. A cross-origin `307` / `308` was
  `401 session_required`. A `301` / `302` / `303` was usually already a
  `502` — it depended on what the target answered the resulting `GET` — but as
  `provider_unavailable` with `unexpected provider response: 405` (or whatever
  the redirect target answered to a `GET`) — the code and the description
  change, which is what alerts key on, and it is what most affected
  deployments will see. **Action:** set `INJECTION_PROVIDER_ORIGIN`
  (`auth.injection.providerOrigin`) to the origin that answers `/oauth/token`
  itself. If the redirect stays on the same origin — `/oauth/token` to
  `/oauth/token/`, or under a path prefix — the provider or its ingress must
  answer `POST /oauth/token` directly, because `providerOrigin` cannot carry a
  path. Re-key alerts on the code. Why following was unsafe is under
  Security.

- **BREAKING: a session grant succeeds only on a `200` (#95 F38, #124).** Any
  other `2xx` from the token endpoint is
  `502 provider_unavailable`, `unexpected provider response: <status>`, as the
  exchange client already answered. 0.6.0 accepted a `201` that carried a
  token, and refused a `204` as `provider_invalid_response` with a description
  naming a `200` the provider never sent. **Action:** none for a provider that
  answers `200`, as RFC 6749 §5.1 describes.

- **BREAKING: a session grant's `401 invalid_client` is
  `502 provider_config_error`, not `401 session_required` (#95 F47, #120).**
  RFC 6749 §5.2 answers `invalid_client` when the client fails authentication,
  which here means `auth.injection.clientId` is wrong or unregistered; 0.6.0
  told every browser to sign in again, forever, over something signing in
  cannot fix. The `401` body is now read, bounded at 16 KiB, and
  `error: "invalid_client"` is answered
  `502 {"error":"provider_config_error", …}` — the provider's
  `error_description` relayed only when it passes the same check as the
  `400` branch, otherwise `provider rejected the proxy's client (client_id)` —
  with `Retry-After` passed through, and logged as
  `injection.provider_config_error` at error instead of
  `injection.session_unauthorized` at info. Any other `401` — another code, no
  code, a body over the bound or one that cannot be read — is still
  `401 session_required`; auth.provider answers an unauthenticated browser
  session `401 unauthorized`, which stays there. Reading the body has one
  cost: a provider that trickles its `401` body holds the request, and every
  request coalesced onto it, until `INJECTION_TIMEOUT_MS` ends the read, and
  that timeout then lands as `session_required`, logged
  `injection.session_unauthorized` at info — the one provider timeout not
  logged at error. **Action:** correct the client registration if this starts
  appearing; re-key alerts and dashboards on either event.

- **BREAKING: a credential inside provider error text is refused at any
  length, not only from eight characters up (#95 F30, #115).** A deployment
  whose session cookie values are shorter than eight characters sees the
  proxy's own wording where the session path used to relay and log the
  provider's `error_description`; one whose exchange client secret is shorter
  than eight characters sees `invalid_error_code` where the exchange's log
  lines carried the provider's `error`. The status, the `error` code, the
  event and the level are unchanged on every path; only the provider's
  diagnostic is lost. A short cookie costs that caller's own requests; a short
  client secret costs every exchange refusal. **Action:** rotate an
  `INJECTION_EXCHANGE_CLIENT_SECRET` shorter than eight characters. What this
  closes is under Security.

- **BREAKING: log lines carry `requestId` instead of `"x-request-id"`, every
  request, decision and failure line carries an `event`, and a caller-caused
  provider `401` is logged at info (#134, #139).** Both modes'
  `incoming request` lines are `injection.incoming_request` /
  `validation.incoming_request`. Validation's failure lines keep their
  messages and are now:

  | Event | Level | When |
  | --- | --- | --- |
  | `validation.token_unauthorized` | info (was error) | The provider answered `401` about the caller's token. |
  | `validation.provider_config_error` | error | The proxy's own client credentials were refused, or the endpoint redirected. |
  | `validation.provider_error` | error | Any other provider failure (`502 Bad Gateway`). |
  | `validation.unexpected_error` | error | Anything else thrown (`500`). |

  An `x-request-id` header sent to the provider or the upstream is unchanged.
  A query on `*.provider_config_error` or `*.unexpected_error` now matches
  both modes. **Action:** move log queries and alerts from `"x-request-id"`
  to `requestId`. An alert on validation's error-level lines no longer fires
  when the provider refuses a caller's token with a `401`; that line still
  says `introspect failed`, now at info, so an alert on the message alone
  still fires — re-key it on `event`.

- **BREAKING: `auth.validation.introspect.url` must be an absolute `http(s)`
  URL without userinfo, checked at boot (#140).** An `INTROSPECT_URL` that
  carries userinfo, is not a URL, or has any other scheme stops the process
  at boot, with a message that names the key and does not quote the value.
  Such a deployment used to boot and then served only requests carrying no
  Bearer token — `fetch` refuses a URL with credentials on every call, and
  fails to parse a non-URL — answering every request with one `500`; with a `data:`
  URL it admitted every token (see Security). **Action:** set
  `INTROSPECT_URL` to the endpoint's `http(s)` URL with no credential in it,
  and set `CLIENT_ID` / `CLIENT_SECRET` if the introspection request should
  authenticate as the proxy.

- **Validation's failure lines carry the error (#95 F48, #128).** In 0.6.0
  their `error` field was `{}` for a plain `Error` — so a timeout and a
  refused connection wrote the same line — and `{status, name}` for an
  introspection error, with no message. `error` is now an object with `type`, `message`, `stack`,
  `code`, `errno`, `syscall`, `status`, `refusedCredential` and `cause`,
  followed up to five levels, so a network failure shows undici's error and
  the socket's `ECONNREFUSED` beneath it. It is an allowlist; see Security.
  Injection's lines still log a string under `error`, so a query on
  `error.message` matches validation lines only. A supplied `deps.logger` is
  unaffected.

- **With `stripInboundAuthorization` on, an empty inbound `Authorization` is
  stripped like any other (#95 F40, #122).** With the exchange disabled, a
  header that was present but empty (`Authorization:`, or whitespace only,
  which Node trims to empty) reached the upstream. It is now deleted, logged
  as `injection.inbound_authorization_stripped` at warn, and the `action`
  on `injection.no_cookie` / `injection.cookie_rejected` is
  `forward_stripped`. With stripping off it still passes through.

- **An empty inbound `Authorization` that an injected token overwrites is
  logged as an override (#133, #135).** With the exchange disabled it now logs
  `injection.authorization_override` at warn with its `metric`, like any other
  override. The upstream receives the minted token, as before.

- **An empty `Authorization` that reaches the upstream is sent as
  `Authorization`, not `authorization` (#132, #136).** Casing only; the value
  is still empty. The upstream stage re-sets a present `Authorization` in
  canonical casing for upstreams that match header names case-sensitively,
  and it used to skip an empty one. This is the case for validation mode,
  which passes an empty header through, and for injection mode when nothing
  strips or replaces it.

- **`action` on `injection.no_cookie` and `injection.cookie_rejected` names
  what happened: `forward_stripped` when the inbound `Authorization` was
  stripped (#95 F31, #108).** 0.6.0 logged `action: "forward"` while the
  header was being removed, so a dashboard keyed on `action: "forward"` now
  under-counts; add `"forward_stripped"`. Only deployments with
  `stripInboundAuthorization` on are affected. Separately,
  `injection.cookie_rejected`'s message changes on every non-`fallback`
  occurrence, with stripping on or off, from
  `session cookie rejected, forwarding without Authorization` to
  `session cookie rejected, forwarding without a minted Authorization` — a
  client's own header still reaches the upstream unless it is stripped.

- **Provider response bodies are read at a bound (#95 F34, F35, F39; #106,
  #107, #119).** A `200` from the token endpoint is read up to 64 KiB on both
  injection paths; a longer one is `502 provider_invalid_response` instead of
  being buffered. The `error_description` for a `200` that is not a JSON
  object changes from `provider returned 200 with a non-JSON or non-object
  JSON body` to `provider returned 200 with a body that is not a JSON object,
  or is over the size bound`; on the session path a `200` carrying a JSON array
  answered `provider returned 200 without an access_token` and now answers
  the same. Validation reads its `200` up to 64 KiB too; a longer body, or one
  that is not a JSON object, is `502 Bad Gateway`, logged as
  `introspect failed` with `introspect returned 200 with a body that is not a
  JSON object, or is over the size bound` in `error.message`. A leading byte-order mark is accepted on every path,
  including error bodies, whose diagnostic it used to cost. No provider sends
  a legitimate body near the bound.

- Runtime dependency: `zod` 4.6.2 → 4.6.5 (#94).

### Added

- **`VALIDATION_REALM` (`auth.validation.realm`), and a `400` challenge shaped
  by what was sent (#95 F45, #127).** Optional; unset (`null`, or `""` from the
  environment) means no realm. A value must be at most 256 printable ASCII
  characters without `"` or `\` and without surrounding spaces, or boot fails
  naming the key. Set, every challenge carries `realm="…"`. The
  `400 Invalid Token Type` now answers by what was sent: a `Bearer` with no
  usable token (`Bearer`, `Bearer  t`) gets `Bearer error="invalid_request"`,
  and another method (`Basic …`, or a lowercase `bearer`, which the proxy does
  not admit) gets `Bearer realm="…"` when a realm is set and no header
  otherwise, since RFC 6750 §3.1 says a request using an unsupported method
  SHOULD NOT carry an error code. Statuses and bodies are unchanged, and a
  `500` or `502` carries no challenge. For a deployment that sets no realm the
  one change is that a malformed `Bearer` now gets
  `WWW-Authenticate: Bearer error="invalid_request"` on its `400` — the `400`
  counterpart of the BREAKING `401` challenge under Changed; its commit
  carries no breaking marker. **Action:** none; set a realm if your
  clients expect one on every challenge.

- **Validation coalesces concurrent misses on one token into one provider
  call (#95 F6, #116).** Injection mode already did. The first request asks;
  the others are answered by its response or its failure and do not write the
  cache. The coalescing is independent of `INTROSPECT_CACHE_TTL_SEC`: with a
  zero TTL, requests for the same token that overlap still share one call, so
  a burst sees the provider's answer to the first of them. The provider sees
  only the first request's `x-request-id`, and a shared failure is logged once
  for each request it answers. A burst of parallel requests carrying one token
  now spends one call from the per-instance introspection rate limit.

- **Both routers take injectable dependencies — a library seam, not
  operator configuration (#95 F1–F5; #99, #100, #101, #102).**
  `createRouter({ config, deps })` accepts, for injection, `tokenCache`,
  `singleFlight`, `grantClient`, `logger` and — only while the exchange is
  enabled, and refused at construction otherwise —
  `exchange: { client, tokenCache, singleFlight }`; for validation,
  `introspect` and `logger`. Each decision is a function of plain values
  (`decideInjection`, `decideExchange`, `decideValidation`). The introspection
  cache now belongs to the router, so two routers in one process no longer
  share one, and the module-level `clearCache` is gone. A caller that supplies
  a dependency owns its lifecycle and whatever the bundled one guaranteed. The
  session cache key covers the grant context — grant type, token endpoint,
  client, scope and cookie name as well as the cookie value (#95 F33, #113) —
  so one supplied cache can serve routers whose contexts differ; it must still
  be matched on the supplied client, the exchange's client secret and the
  cache policy, none of which is in the key. A supplied grant or exchange
  client's failures are logged by their error code rather than their status,
  and a code outside the declared set is logged as
  `injection.provider_unavailable` / `injection.exchange_provider_unavailable`
  at error (#95 F32, F41; #109, #121).
  The package is private and ships as the Docker image: a deployment
  configures none of this, and the image wires what 0.6.0 did.

- **The cancellation contract is stated and tested (#95 F10, #117).** A
  caller that disconnects does not cancel the provider call:
  `INTROSPECT_TIMEOUT_MS` and `INJECTION_TIMEOUT_MS` are the only
  cancellation, because the request that leaves may be the one others are
  coalesced onto. The call completes, and its result is cached when it is
  cacheable. No behaviour changes; the contract is now on the client
  interfaces and pinned by tests on a real socket.

### Security

- **The introspection URL is checked at boot, and a `data:` URL no longer
  admits every token (#140).** `fetch` answers a `POST` to a `data:` URL with
  the body the URL encodes, so in 0.6.0
  `INTROSPECT_URL=data:application/json,{"active":true}` made validation
  forward every Bearer token without asking anyone. The schema accepted any
  string; it now accepts only an absolute `http(s)` URL without userinfo. See
  the BREAKING entry under Changed for what a refused deployment sets instead.

- **No provider call follows a redirect (#95 F8, F43; #112, #123).** 0.6.0's
  session-grant and introspection clients followed redirects (the exchange
  never did). On the same origin, any redirect carried the session cookie, or
  the introspection request's `Authorization` (the proxy's Basic header, or
  the caller's token), to the path in `Location`, and a `307` / `308` re-sent
  the body too. Across origins `fetch` drops `Authorization` and `Cookie`, but
  a `307` / `308` still re-sends the body — and for introspection the body is
  `token=<the caller's token>`, which reached the other origin. A `301` / `302` / `303`
  on the introspection path became a `GET` of `Location` whose answer was
  read as the introspection response, so a target answering
  `{"active":true}` admitted the token. Both clients now answer a `3xx` as a
  configuration error without sending a second request; see the BREAKING
  entries under Changed.

- **Provider error text is checked for a credential at any length (#95 F30,
  #115).** 0.6.0 refused a credential inside provider-controlled text only
  from eight characters up, and a shorter one only when the whole text was
  that credential; before 0.6.0 there was no check at all. A provider that echoed a short session cookie value inside
  its `error_description` had it relayed in the response and written to the
  log, and a short exchange client secret inside the provider's `error`
  reached the log. Any occurrence is refused now; the cost and the action are
  in the BREAKING entry under Changed.

- **Logged errors pass through an allowlist, and URL userinfo in them is
  redacted however it is written (#95 F48, #128; #140).** Validation's failure
  lines carry the error's text from 0.7.0 on (see Changed). What reaches a
  line is the class, `message`, `stack`, `code`, `errno`, `syscall`,
  `status`, `refusedCredential` and the `cause` chain to five levels; every
  other property is dropped. That is deliberately not pino's
  `errWithCause`, which copies every enumerable property down the chain and
  would have written undici's `HTTPParserError.data` — the provider's
  unparsed response, which can echo the token the proxy just sent. The same
  allowlist now serialises the `err` key the shutdown lines use, where pino's
  own serialiser copied every enumerable property; the shutdown lines the
  proxy writes come out as before. `scheme://user:pass@` in a message or a
  stack is redacted up to the last `@` before the next `/` or the end of the
  line, because `fetch` quotes a URL as it was given: a password containing a
  space, an `@`, a `?` or a `#` is redacted whole. A `/` inside a raw password
  still ends the match early; the boot check above keeps any
  credential-bearing introspection URL out of the process. 0.5.0 and 0.6.0
  logged these errors without their message, so neither wrote such a
  password.

### Fixed

- **Provider bodies the clients answer without reading are released (#95 F28,
  F37; #105, #118).** The introspection client's non-`2xx`, and the session
  grant's `3xx`, `5xx`, unexpected `4xx` and non-`200` `2xx` and the
  exchange's `3xx`, now cancel the body instead of leaving it unread. Within
  undici's 64 KiB read-ahead — every realistic refusal — nothing changes;
  past it an unread body held its socket until garbage collection (thirty
  200 KiB refusals left 27 sockets open on Node 26). Nothing on the wire
  changes.

- **A single-flight whose fetcher throws synchronously is cleared, not pinned
  (#141).** The rejection stayed under its key, so every later call for that
  key got the old error until the process restarted.
  Unreachable from the proxy's own callers, which all pass `async` fetchers;
  reachable by code that uses the single-flight directly.

### Removed

- **`jsonwebtoken` (runtime dependency) and `@types/jsonwebtoken` (#95 F24,
  #104).** Nothing imported them. The proxy verifies no JWT: validation asks
  the provider over RFC 7662, and the exchange submits the assertion to the
  provider, reading only its unverified `iss` and `exp`.

## [0.6.0] — 2026-09-17

### Added

- **Injection mode can exchange an external credential for a first-party
  token (#90).** Opt-in with `auth.injection.exchange.enabled`
  (`INJECTION_EXCHANGE_ENABLED`, `"true"` / `"false"`, default `false`). A
  request that presents `Authorization: Bearer <JWT>` instead of a session
  cookie is submitted to the provider's `POST /oauth/token` as an RFC 7523
  jwt-bearer assertion, and the issued token replaces the header, so only a
  first-party token reaches the upstream. The original credential is never
  forwarded — not on success, refusal, outage or a malformed header — and no
  failure falls back to the session path. The proxy submits the assertion
  unchanged and does not decide trust: whatever auth.provider's
  `AssertionIssuerRegistry` admits for the issuer applies, which covers plain
  RFC 7523 assertions and the ID-JAG profile. It is not RFC 8693 token
  exchange, and it produces no `act` delegation.

  Disabled, injection mode behaves exactly as before, and a configuration
  without the `exchange` block parses as disabled, so upgrading needs no
  action. Turning it on needs:

  - `INJECTION_EXCHANGE_CLIENT_ID` and `INJECTION_EXCHANGE_CLIENT_SECRET`
    (`auth.injection.exchange.clientId` / `clientSecret`). The proxy
    authenticates with `client_secret_basic`, with the RFC 6749 §2.3.1 encoding
    validation mode already uses, and boot fails naming whichever key is
    missing. `INJECTION_EXCHANGE_SCOPE`, `INJECTION_EXCHANGE_AUDIENCE` and
    `INJECTION_EXCHANGE_RESOURCE` are sent only when set.
    `INJECTION_EXCHANGE_ALLOWED_ISSUERS` (whitespace-separated, like
    `INJECTION_SCOPE`; empty = off) is an optional prefilter that refuses an
    unlisted, unverified `iss` before any provider call; in HOCON a list entry
    that is empty or contains whitespace fails boot.
  - The proxy registered at the provider as a confidential client whose
    `allowedGrantTypes` names `urn:ietf:params:oauth:grant-type:jwt-bearer`,
    and listed in `allowedClients` of every issuer entry that names such a
    list. An ID-JAG must carry the proxy's client as its `client_id`.
  - For an issued token that never outlives its assertion, a provider that
    includes [auth.provider#588](https://github.com/o3co/auth.provider/pull/588),
    which caps a jwt-bearer token at the assertion's expiry. Without it the
    token can outlive the assertion at offline validators. The proxy's own
    cache is bounded by the assertion's `exp` either way.

  With the exchange enabled, an inbound `Authorization` is never passed
  through, so `stripInboundAuthorization` has nothing left to strip. The
  request shape decides the path, and neither refusal calls the provider:

  - A session cookie together with any `Authorization` is
    `400 credential_ambiguous`. The cookie counts as present whenever the
    header carries `auth.injection.sessionCookieName`, even in a form the
    cookie grammar check refuses.
  - An `Authorization` that is not `Bearer <JWS compact JWT>` — another
    scheme, an opaque token, a malformed JWT, an empty value — is
    `401 credential_unsupported`.

  A cookie alone, or no credential, takes the existing path. Exchange
  refusals use the session path's `{ error, error_description }` shape:
  `401 credential_rejected` (an `iss` outside `allowedIssuers`, or provider
  `invalid_grant`), `403 exchange_not_permitted` (`invalid_scope`,
  `invalid_target`, `unauthorized_client`), and `502` with
  `provider_config_error` (provider `401`, any other `400`, or a redirect),
  `provider_unavailable` (`5xx` / `429` with `Retry-After` passed through,
  network error, timeout) or `provider_invalid_response` (no `access_token`,
  or a `token_type` other than `Bearer`, such as `DPoP`). Each outcome is
  logged as an `injection.exchange_*` event; `exchange_credential_ambiguous`
  and `exchange_not_permitted` are at warn, and the ambiguous case carries
  `metric: auth_proxy_injection_exchange_credential_ambiguous`. The assertion,
  the issued token, the client secret and the unverified `iss` are never
  logged.

  A successful exchange is cached per instance in its own cache and
  single-flight, never shared with the session cache, but sized and timed by
  the same `auth.injection.tokenCache` settings and `timeoutMs`:
  `maxEntries` applies to each cache separately. An entry expires at
  `min(sent + ttlSeconds, sent + expires_in, assertion exp) - safetyMarginSeconds`,
  where `sent` is the instant the token request went out. An assertion
  without `exp` is not cached, and failures are never cached. The proxy keeps
  no rate-limit budget of its own: each token request the exchange sends — one
  per cache miss, after concurrent identical requests are coalesced — reaches
  the provider's `/oauth/token` and counts against the provider's `token`
  rate limit, as a session grant does, so size that budget for the proxy's
  traffic.

- **An ID-JAG is not replay-checked while its exchange is cached.** The
  provider accepts each ID-JAG `jti` once, when the assertion is submitted,
  and a cache hit submits nothing. Within the cache lifetime, whoever
  presents the same assertion is served the cached token. Treat the
  assertion as a bearer credential for that window, which
  `tokenCache.ttlSeconds` bounds. After the entry expires, or at another
  proxy instance, the same ID-JAG is a replay the provider refuses
  (`401 credential_rejected`), and the client must obtain a fresh one.
  Expiry bounds do not propagate revocation either: revoking the external
  credential, its issuer's registration or the proxy's client reaches
  neither a token already issued nor a result cached within that lifetime.

### Security

- **The exchange client does not follow redirects.** A token endpoint that
  answers with a redirect gets `502 provider_config_error`, so the
  assertion and the client secret are never re-sent to another location.

- **Provider-controlled error text is validated before it is logged or
  returned.** On the session path, a provider `400` other than
  `invalid_grant` had its `error_description` relayed verbatim as the
  `provider_config_error` description, in the response and in the log, so a
  provider that echoed the session cookie put it in both. The description is
  now used only when it is a well-formed RFC 6749 `error_description`: the
  RFC charset, at most 256 characters, nothing JWT-shaped, and not containing
  the session cookie value. Otherwise the existing generic
  `provider rejected proxy configuration (client_id or scope)` is returned. A
  client or alert that matched on a provider's own wording there may now see
  the generic one. The exchange logs the provider's `error` code only when
  it has that shape (no whitespace, at most 64 characters, nothing
  JWT-shaped, not echoing the assertion or client secret), records
  `invalid_error_code` otherwise, and never logs `error_description`.
  Provider error bodies are read up to 16 KiB on both paths; a longer body
  is abandoned and treated as having no diagnostic.

### Fixed

- **A slow provider could make a cached session token outlive the token
  itself.** The session cache lifetime,
  `min(ttlSeconds, expires_in) - safetyMarginSeconds`, was counted from when
  the grant response arrived. `expires_in` runs from issuance, so a slow
  response pushed the entry past the token's real expiry by the whole
  response time, and the proxy went on injecting an expired token. The
  lifetime is now counted from the instant the grant request was sent, and a
  grant whose response arrives after that point is not cached. Behaviour at
  normal latency is unchanged. The exchange cache uses the same anchor.

### Changed

- Runtime dependency: `zod` 4.5 → 4.6 (#87). Development-only, with no effect
  on the built proxy: `vitest` 4 → 5 (#88), `@biomejs/biome` 2.5.11 → 2.5.13
  and `@types/node` 26.4 → 26.5 (#86).

## [0.5.1] — 2026-09-06

### Fixed

- **The `graceful shutdown: complete` line could say `reason: "drained"` next
  to a non-zero exit code.** When cleanup timed out or failed it set the exit
  code but not the reason, so the one line an operator alerts on contradicted
  itself. `reason` now names whatever decided the exit code
  (`cleanup-timeout` / `cleanup-failed`) and the drain outcome keeps its own
  `drain` key, so the shape stays stable and neither fact is lost. Introduced in
  0.5.0; found reviewing the same code in
  [auth.provider#511](https://github.com/o3co/auth.provider/pull/511).

- The `exit` option's doc said it defaults to `process.exit` after the default
  became `deferExit`.

## [0.5.0] — 2026-09-06

### Security

- Introspection cache entries and positive responses respect the token expiration, including expiration during the provider call. TTL zero bypasses caching.
- Validation rejects sender-constrained tokens on its Bearer-only path.
- Injection maps a rejected session grant (`400 invalid_grant`) to `401 session_required` instead of a proxy configuration error.

### Fixed

- **Graceful shutdown had no drain deadline, so SIGTERM could never complete on
  its own.** `gracefulShutdown` came from `@o3co/auth.utils@0.0.4`, which called
  `server.close()` with no timeout: one stuck in-flight request meant the
  process waited forever and the orchestrator's SIGKILL cut it down mid-flight —
  the opposite of a graceful shutdown, arriving precisely under the load that
  produces a stuck request. Shutdown now drains for `drainTimeoutMs` (default
  10s, size it below the orchestrator's kill grace period), then force-closes
  the remaining connections and exits non-zero so a truncated drain is
  distinguishable from a clean one. A `close` that reports a failure is no
  longer reported as a clean drain, and a cleanup failure is logged through the
  app logger rather than `console.error` — one bare line in a service whose
  every other line is NDJSON. `cleanup` is itself bounded by `cleanupTimeoutMs`
  (defaulting to `drainTimeoutMs`), so a dispose that never settles cannot
  replace the wedge it was meant to remove, and the process yields the loop
  once before exiting so a buffered log destination can flush the lines that
  say why. `auth.provider` reached the same conclusion for
  the same code in its issue #290.

- **The deployed proxy emitted console lines, not NDJSON.** `auth.utils` took
  `pino` as an *optional* peer and silently fell back to `console` when the
  import failed; this repo satisfied that peer from **devDependencies**, and the
  Dockerfile runs `pnpm prune --prod` before copying `node_modules` into the
  runtime stage. Every production log line was therefore a `[proxy] ...` console
  write that no aggregator parses — and no local run showed it, because dev
  installs kept pino present. `pino` is a direct runtime dependency now.

### Changed

- **`@o3co/auth.utils` is no longer a dependency.** Its five helpers
  (`createLogger`, `gracefulShutdown`, `createHealthcheckRouter`,
  `extractBearerToken`, `createRequestIdMiddleware`) now live in this
  repository, each with its own tests. This proxy was the package's only
  full-surface consumer: `auth.provider` had already moved its shutdown out
  (#290) and the verifier its logger (#107), both after finding defects that a
  shared pre-1.0 utility made hard to see from the code they deploy.

  The liveness path is the clearest case for the move. `auth.utils` defaulted to
  `/healthcheck` while this proxy, the provider and (since its 0.7.0) the
  verifier all answer on `/_healthcheck` — the shared default was itself the
  source of the divergence it was meant to prevent. Behaviour is otherwise
  unchanged: the Bearer grammar, the request-id reuse rule and the healthcheck
  path and body are the ones the proxy already shipped, now pinned by tests
  here.

## [0.4.0] — 2026-09-04

### Security

- Injection mode refuses session cookie values outside the RFC 6265 §4.1.1
  `cookie-value` grammar (#23). The extracted value is interpolated verbatim
  into the outbound `Cookie` header of the session grant call, and undici /
  `http.validateHeaderValue` reject only CR/LF/NUL, CTLs/DEL and code points
  above 0xFF — so a value carrying a comma, whitespace, DQUOTE, backslash or a
  latin-1 byte reached the provider unchanged and could malform the header or
  smuggle a second cookie-pair. A non-conforming value is now refused: the
  request is forwarded without `Authorization` and the provider is not called
  (the refusal is logged as `injection.cookie_rejected`, see Fixed below).

  A value wrapped in one DQUOTE pair is accepted and forwarded with the quotes
  preserved — user agents echo the provider's `Set-Cookie` bytes opaquely
  (§5.2), so the provider's own parser is the right place to interpret them. A
  DQUOTE anywhere else (interior or unbalanced) is refused, and an empty quoted
  value is refused like an empty bare value.
- `auth.injection.sessionCookieName` is validated at boot against the RFC 6265
  §4.1.1 `cookie-name` grammar (#75) — an RFC 9110 `token`, i.e. one or more
  of `` !#$%&'*+-.^_`|~ ``, digits and letters. The name is interpolated
  verbatim into the outbound `Cookie` header of the session grant call, and the
  schema accepted any non-empty string, so `"sid "` or `"a=b"` (a typo, or a
  copy-pasted `name=value`) malformed that header, or smuggled a second
  cookie-pair, on every request. Such a name is now a configuration error at
  startup whose message names the key.

### Fixed

- The session cookie value is no longer trimmed before the cookie-octet check
  (#23). `extractCookie` trimmed whitespace after `=`, normalising `sid= abc`
  and `sid=\tabc` into valid outbound values even though whitespace is outside
  `cookie-octet`. RFC 6265 §4.2.1 allows whitespace only as the SP after `;`
  (plus OWS at the header ends), so the cookie-pair token and the name are now
  trimmed of OWS only (SP / HTAB — `String.prototype.trim` would also strip a
  latin-1 NBSP) and the value is taken verbatim: `sid= abc` fails the grammar
  and is refused, while `a=1;  sid=abc ; b=2` still yields `abc`.
- A session cookie the proxy refuses to forward is logged as
  `injection.cookie_rejected` at warn instead of `injection.no_cookie` at debug
  (#73). Both cases forward the request without `Authorization` and skip the
  provider, but a header that never carried the cookie is an ordinary anonymous
  request, while one that carried it in a refused form points at a misbehaving
  client or a provider issuing cookies outside the grammar. The event carries
  the request id, a bounded `reason` class — `empty` (`sid=` / `sid=""`),
  `quoting` (a DQUOTE anywhere other than one surrounding pair) or `grammar` (a
  character outside `cookie-octet`) — an `action` (`forward`: the request went
  upstream anonymously; `fallback`: a later same-name pair was used, see #74)
  and the `metric: auth_proxy_injection_cookie_rejected` hint that
  `injection.authorization_override` already uses. The cookie bytes are never
  logged. Operators should treat a sustained rate of this event as a signal to
  look at the client or the provider's `Set-Cookie`; `injection.no_cookie`
  stays at debug for the absent case. The proxy has no metrics endpoint, so the
  log line is the deliverable.
- The first well-formed same-name pair wins (#74). A malformed pair aborted the
  scan, so `sid=bad,val; sid=good` was refused although a usable pair
  followed — and user agents may legitimately send two same-name pairs (RFC
  6265 §5.4 orders them by path, then creation time). The malformed pair is now
  skipped (and logged as above with `action: "fallback"`) and `good` is
  exchanged; `sid=good; sid=bad,val` still yields `good`; when every same-name
  pair is malformed the request is forwarded anonymously with the first pair's
  `reason`. Per-pair OWS trimming and the verbatim value semantics from #23 are
  unchanged.

### Changed

- The router cache-expiry test drives a faked clock instead of sleeping (#24).
  It slept a real 1.1 s with `ttlSeconds=1` / `safetyMarginSeconds=0`, adding
  wall-clock time to every run and leaving 100 ms of slack under CI load. Cache
  expiry is decided purely from `Date.now()`, so only `Date` is faked
  (`vi.useFakeTimers({ toFake: ["Date"] })`), leaving `setTimeout` & co. real so
  supertest's HTTP round trips are untouched. The case keeps the default TTL
  (55 s effective), asserts a hit at 30 s and a re-fetch at 60 s, and runs in
  about 3 ms.
- Release workflow: a tag with a semver pre-release suffix (`vX.Y.Z-rc.1`) is
  published as a GitHub pre-release (#76). `softprops/action-gh-release` ran
  without a `prerelease` input, so such a tag would have been marked the latest
  full release; a step now derives the flag from the tag name and nothing else
  in the workflow changes.

## [0.3.0] — 2026-09-03

### Security

- Validation mode rejects introspection responses that violate RFC 7662
  (#26). `active` must be a boolean: a `200` whose body is not JSON, not an
  object, or carries a non-boolean `active` is treated as a provider error
  (502 at the introspection boundary, answered to the caller as 500) instead
  of passing through a truthy check. Before, `{"active":"false"}` was read
  as active and the request was forwarded upstream.

### Changed

- Provider calls use Node's built-in `fetch` instead of axios (#26).
  Timeouts are `AbortSignal.timeout` with the existing
  `INTROSPECT_TIMEOUT_MS` / `INJECTION_TIMEOUT_MS`; network errors and
  timeouts surface as `provider_unavailable` (502) in injection mode and as
  500 in validation mode. Built-in `fetch` does not read `HTTP_PROXY` /
  `HTTPS_PROXY` / `NO_PROXY`, which axios honoured — a deployment that
  reached the provider through an egress proxy via those variables needs
  `NODE_USE_ENV_PROXY=1` (Node 24) or a direct route.
- A `200` with a malformed body is a provider error, not an auth decision:
  injection mode answers `provider_invalid_response` (502), validation mode
  answers 500. Before, a non-JSON `200` in validation mode was coerced into
  `401 Invalid Token`.
- Runtime dependencies: `@o3co/ts.hocon` 0.1 → 1.x, `@o3co/auth.utils`
  0.0.2 → 0.0.4, `cross-env` 7 → 10, `zod` 4.3 → 4.5.
- Build: `pnpm-lock.yaml` is committed and the `Dockerfile` installs with
  `--frozen-lockfile`, pinning pnpm through `corepack prepare`. The image
  build needs the lockfile in its context.

### Removed

- `axios` (runtime dependency).

## [0.2.0] — 2026-04-24

### Added

- Injection mode: translates session cookies into Bearer tokens for upstream
  services. Enables OWASP Token Handler Pattern — browsers never hold access
  tokens. Select with `auth.mode = "injection"`.
- `auth.injection.*` configuration section: provider origin, client_id, scope,
  session cookie name, token cache settings, safety margin, timeout.
- Single-flight request coalescing: concurrent cache misses on the same
  session result in a single provider call.
- Configurable safety margin for token cache expiry
  (`auth.injection.tokenCache.safetyMarginSeconds`, default 5s).

### Changed

- Configuration restructured: `auth` now uses a discriminated union on
  `auth.mode`. Existing `auth.client.*` and `auth.introspect.*` paths move
  under `auth.validation.*`. Environment variables (`CLIENT_ID`,
  `INTROSPECT_URL`, etc.) are unchanged.
- `auth.mode` is now required — must be set explicitly to `"validation"`
  or `"injection"`. Omission or typos cause startup failure.
- `providerOrigin` (injection mode) validates as origin-only: no path,
  query, fragment, userinfo; http or https only.
