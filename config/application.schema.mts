/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { z } from "zod";

/**
 * RFC 6265 section 4.1.1 `cookie-name = token`, with RFC 9110 section 5.6.2
 *
 *   token = 1*tchar
 *   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 *
 * The configured name is interpolated verbatim into the outbound `Cookie` header
 * of the session grant call (session-grant-client.mts). A separator or
 * whitespace in it (`"sid "`, `"a=b"`) would malform that header, or smuggle a
 * second cookie-pair, on every request, so it is refused at boot (#75).
 */
const COOKIE_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * A boolean knob that has to survive the HOCON -> environment round trip.
 * `parseFile` substitutes an environment override as a *string*, so both the
 * literal `false` from application.conf and the string `"false"` from
 * `INJECTION_STRIP_INBOUND_AUTHORIZATION` reach the schema and both must mean
 * false.
 *
 * `z.coerce.boolean()` is not usable for this: it is `Boolean(v)`, under which
 * the non-empty string `"false"` is `true`. The one way an operator would turn
 * a flag off from the environment would silently leave it on, which for a
 * traffic-altering switch is the worst possible failure mode. Anything that is
 * neither `true` nor `false` is a configuration error naming the key, in the
 * shape the other auth.injection validations use.
 */
const strictBoolean = (key: string) =>
	z
		.union([z.boolean(), z.string()])
		.default(false)
		.transform((value, ctx): boolean => {
			if (typeof value === "boolean") {
				return value;
			}
			if (value === "true") {
				return true;
			}
			if (value === "false") {
				return false;
			}
			ctx.addIssue({
				code: "custom",
				message: `${key} must be true or false (got ${JSON.stringify(value)})`,
			});
			return z.NEVER;
		});

/** An optional string where the environment's empty value means unset. */
const optionalString = () =>
	z
		.string()
		.nullable()
		.default(null)
		.transform((v) => (v === "" ? null : v));

/**
 * A list that has to survive the HOCON -> environment round trip, like
 * `strictBoolean`. In application.conf it is a HOCON list; an environment
 * override arrives as one string, which is split on whitespace — the encoding
 * `INJECTION_SCOPE` already uses for its space-separated scope list. An empty
 * string is the empty list. Because whitespace is the separator, a HOCON entry
 * that is empty or contains whitespace could never be expressed from the
 * environment, and is refused at boot naming the key.
 */
const whitespaceSeparatedList = (key: string) =>
	z
		.union([z.array(z.string()), z.string()])
		.default([])
		.transform((value, ctx): string[] => {
			if (typeof value === "string") {
				return value.split(/\s+/).filter((entry) => entry.length > 0);
			}
			const invalid = value.find((entry) => entry.length === 0 || /\s/.test(entry));
			if (invalid !== undefined) {
				ctx.addIssue({
					code: "custom",
					message: `${key} entries must be non-empty and contain no whitespace (got ${JSON.stringify(invalid)})`,
				});
				return z.NEVER;
			}
			return value;
		});

const EXCHANGE_KEY = "auth.injection.exchange";

export type ExchangeConfig =
	| { enabled: false }
	| {
			enabled: true;
			clientId: string;
			clientSecret: string;
			scope: string | null;
			audience: string | null;
			resource: string | null;
			allowedIssuers: string[];
	  };

/**
 * The external credential exchange (#90): an inbound `Authorization: Bearer
 * <JWT>` is submitted to the provider's token endpoint as an RFC 7523
 * `jwt-bearer` assertion and the issued token replaces it.
 *
 * Disabled (the default) parses to `{ enabled: false }` and nothing else is
 * used, so injection mode behaves exactly as it does without the block. Enabled,
 * the proxy authenticates to the token endpoint with `client_secret_basic`: a
 * `client_id` alone is not client authentication, so both credentials are
 * required and a missing one fails at boot naming the key.
 *
 * `scope`, `audience` and `resource` are sent only when set. `allowedIssuers`
 * is an optional prefilter on the unverified `iss` — empty means off; trust in
 * an issuer is the provider's decision, never the proxy's.
 */
const exchangeSchema = z
	.object({
		enabled: strictBoolean(`${EXCHANGE_KEY}.enabled`),
		clientId: optionalString(),
		clientSecret: optionalString(),
		scope: optionalString(),
		audience: optionalString(),
		resource: optionalString(),
		allowedIssuers: whitespaceSeparatedList(`${EXCHANGE_KEY}.allowedIssuers`),
	})
	.transform((exchange, ctx): ExchangeConfig => {
		if (!exchange.enabled) {
			return { enabled: false as const };
		}
		const { clientId, clientSecret } = exchange;
		if (clientId === null || clientSecret === null) {
			for (const [name, value] of [
				["clientId", clientId],
				["clientSecret", clientSecret],
			] as const) {
				if (value === null) {
					ctx.addIssue({
						code: "custom",
						message: `${EXCHANGE_KEY}.${name} is required when ${EXCHANGE_KEY}.enabled is true (the proxy authenticates to the token endpoint with client_secret_basic)`,
					});
				}
			}
			return z.NEVER;
		}
		return {
			enabled: true as const,
			clientId,
			clientSecret,
			scope: exchange.scope,
			audience: exchange.audience,
			resource: exchange.resource,
			allowedIssuers: exchange.allowedIssuers,
		};
	})
	.prefault({});

export const AppConfigSchema = z.object({
	http: z.object({
		hostname: z.string().default("0.0.0.0"),
		port: z.coerce.number().default(80),
		pathPrefix: z.string().default("/"),
		bodyLimitSize: z.string().default("10mb"),
		cors: z.object({
			origin: z.object({
				pattern: z.string().nullable().default(null),
			}),
		}),
	}),
	auth: z.discriminatedUnion("mode", [
		z.object({
			mode: z.literal("validation"),
			validation: z.object({
				client: z
					.object({
						clientId: z
							.string()
							.nullable()
							.default(null)
							.transform((v) => (v === "" ? null : v)),
						clientSecret: z
							.string()
							.nullable()
							.default(null)
							.transform((v) => (v === "" ? null : v)),
					})
					.refine(
						(c) => (c.clientId === null) === (c.clientSecret === null),
						{
							message:
								"auth.validation.client.clientId and auth.validation.client.clientSecret must both be set or both be unset",
						},
					),
				// RFC 6750 §3's `realm`, for `WWW-Authenticate` (#95 F45). Unset, the
				// challenges carry none. It is sent inside a quoted-string, so only
				// printable ASCII that needs no escaping is accepted — no `"`, no
				// `\`, no control character — and the header cannot be split by it.
				// No surrounding space (an environment value is not trimmed), and at
				// most 256 characters: it goes out on every challenge, and a front
				// proxy's header buffer is finite.
				realm: optionalString().refine(
					(v) =>
						v === null ||
						(/^[\x21\x23-\x5B\x5D-\x7E]([\x20\x21\x23-\x5B\x5D-\x7E]*[\x21\x23-\x5B\x5D-\x7E])?$/.test(v) &&
							v.length <= 256),
					{
						message:
							'auth.validation.realm must be at most 256 printable ASCII characters, without `"` or `\\` and without surrounding spaces (it is sent as an RFC 6750 quoted-string)',
					},
				),
				introspect: z.object({
					url: z.string(),
					cacheTtlSec: z.coerce.number().default(30),
					cacheMaxEntries: z.coerce.number().int().positive().default(10000),
					timeoutMs: z.coerce.number().int().positive().default(5000),
				}),
			}),
		}),
		z.object({
			mode: z.literal("injection"),
			injection: z.object({
				providerOrigin: z
					.string()
					.url()
					.refine(
						(u) => {
							const parsed = new URL(u);
							return (
								(parsed.protocol === "http:" || parsed.protocol === "https:") &&
								parsed.username === "" &&
								parsed.password === "" &&
								(parsed.pathname === "" || parsed.pathname === "/") &&
								!parsed.search &&
								!parsed.hash
							);
						},
						{
							message:
								"providerOrigin must be an http(s) origin only (scheme://host[:port]), no userinfo/path/query/fragment",
						},
					),
				clientId: z.string().min(1),
				scope: z.string().min(1),
				sessionCookieName: z.string().regex(COOKIE_NAME_RE, {
					message:
						"auth.injection.sessionCookieName must be an RFC 6265 cookie-name (RFC 9110 token: one or more of !#$%&'*+-.^_`|~ DIGIT ALPHA; no whitespace, '=' or other separators)",
				}),
				/**
				 * Opt-in: drop an inbound `Authorization` header on a request the
				 * proxy did NOT mint a token for (no session cookie, or a cookie
				 * the grammar check refused). Without it those requests reach
				 * upstream carrying whatever `Authorization` the client sent, so an
				 * upstream service that reads "a Bearer header arrived from the
				 * proxy" as "the proxy minted this" is bypassable by a client that
				 * simply sends its own.
				 *
				 * Default `false` — the pass-through behaviour every existing
				 * deployment already runs on, including the ones that deliberately
				 * let a service account present its own token through this proxy.
				 * Turning it on is defence in depth, not a replacement for the
				 * upstream verifying the token it was handed.
				 */
				stripInboundAuthorization: strictBoolean(
					"auth.injection.stripInboundAuthorization",
				),
				tokenCache: z
					.object({
						ttlSeconds: z.coerce.number().int().positive().default(60),
						maxEntries: z.coerce.number().int().positive().default(10000),
						safetyMarginSeconds: z.coerce.number().int().nonnegative().default(5),
					})
					.refine(
						(tc) => tc.safetyMarginSeconds < tc.ttlSeconds,
						{
							message:
								"auth.injection.tokenCache.safetyMarginSeconds must be less than auth.injection.tokenCache.ttlSeconds",
						},
					),
				timeoutMs: z.coerce.number().int().positive().default(5000),
				exchange: exchangeSchema,
			}),
		}),
	]),
	upstream: z.object({
		baseURL: z.string(),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
