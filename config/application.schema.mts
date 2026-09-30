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

/**
 * The configuration schema: validates the parsed `application.conf` and
 * produces the `AppConfig` the code reads. It never reads the environment:
 * `${?NAME}` is substituted as a string by the HOCON parse in `src/app.mts`,
 * so numbers are coerced and booleans and lists have their own parsers below.
 *
 * Defaults are declared twice, as a `.default()` here and as a literal in
 * `application.conf`, and the two must agree. Keys whose default lives only in
 * the conf (validated here, no `.default()`): `auth.validation.introspect.url`,
 * `auth.injection.providerOrigin`, `auth.injection.sessionCookieName`,
 * `upstream.baseURL`. Keys the conf sets to a placeholder this schema refuses,
 * so they are effectively required: `auth.mode` (`null`; the union has no
 * default), `auth.injection.clientId` and `auth.injection.scope` (`""`;
 * `.min(1)`).
 *
 * `auth` is a discriminated union on `mode`: the other mode's section is not
 * validated, so the shipped conf passes in validation mode although
 * `auth.injection.clientId` is `""`.
 */

import { z } from "zod";
import { type ClientKey, ClientKeyError, parseClientKey } from "../src/oauth/private-key-jwt.mjs";

/**
 * An RFC 6265 section 4.1.1 `cookie-name`: an RFC 9110 section 5.6.2 `token`,
 * one or more `tchar`. The name is interpolated verbatim into the outbound
 * `Cookie` header of the session grant call (session-grant-client.mts); a
 * separator or whitespace in it (`"sid "`, `"a=b"`) would malform that header,
 * or smuggle a second cookie-pair, on every request, so it is refused at boot.
 */
const COOKIE_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * The introspection endpoint the validation proxy POSTs every cache miss to:
 * an absolute http(s) URL with no userinfo. The URL carries no credential: the
 * introspection client authenticates with `auth.validation.client`, or
 * presents the inbound token when that is unset.
 *
 * Anything else stops the process at boot. `fetch` would refuse a URL with
 * userinfo, or a string that is not a URL, on every call, and its error
 * quotes the value as configured; the logger's URL redaction does not cover
 * every raw form (a `/` in a password, or `https:/` with one slash), so the
 * schema, not the logger, keeps the configured credential out of the log. A
 * non-http(s) scheme is refused too: `fetch` answers a POST to a `data:` URL
 * with the body it encodes, so `data:application/json,{"active":true}` would
 * admit every token.
 *
 * A refine rather than `.url()`, so the message is this one and never quotes
 * the value it refused.
 */
const isIntrospectionUrl = (value: string): boolean => {
	if (!URL.canParse(value)) return false;
	const parsed = new URL(value);
	return (
		(parsed.protocol === "http:" || parsed.protocol === "https:") &&
		parsed.username === "" &&
		parsed.password === ""
	);
};

/**
 * A boolean that survives the HOCON -> environment round trip: `parseFile`
 * substitutes an environment override as a string, so both the literal
 * `false` and the string `"false"` must mean false. Anything that is neither
 * `true` nor `false` is a configuration error naming the key.
 *
 * Not `z.coerce.boolean()`: that is `Boolean(v)`, under which `"false"` is
 * `true`, so turning a flag off from the environment would leave it on.
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

/**
 * A client key for `private_key_jwt`: unset (`null`, or the environment's
 * empty value), or a private JWK — JSON text, the form an environment variable
 * carries, or a HOCON object — read by `parseClientKey`. A key the proxy
 * cannot sign with stops the process at boot naming the key; the message
 * never quotes it.
 */
const clientKey = (key: string) =>
	z
		.union([z.string(), z.record(z.string(), z.unknown())])
		.nullable()
		.default(null)
		.transform((value, ctx): ClientKey | null => {
			if (value === null || value === "") return null;
			try {
				return parseClientKey(value);
			} catch (err) {
				ctx.addIssue({
					code: "custom",
					message: `${key}: ${err instanceof ClientKeyError ? err.message : "the client key cannot be read"}`,
				});
				return z.NEVER;
			}
		});

/**
 * The provider's issuer identifier, the only audience of a client assertion
 * (RFC 7523 section 3). RFC 8414 section 2 makes it an https URL with no query
 * or fragment; http is accepted too, for a provider on a development host. It
 * is used exactly as written, since the provider compares it as a string, and
 * it may differ from the URL the proxy reaches the provider at.
 */
const providerIssuer = (key: string) =>
	optionalString().refine(
		(value) => {
			if (value === null) return true;
			if (!URL.canParse(value)) return false;
			const parsed = new URL(value);
			return (
				(parsed.protocol === "https:" || parsed.protocol === "http:") &&
				parsed.search === "" &&
				parsed.hash === "" &&
				!value.includes("?") &&
				!value.includes("#")
			);
		},
		{ message: `${key} must be the provider's issuer identifier: an http(s) URL with no query or fragment` },
	);

const EXCHANGE_KEY = "auth.injection.exchange";

export type ExchangeConfig =
	| { enabled: false }
	| {
			enabled: true;
			clientId: string;
			/** Exactly one of `clientSecret` and `clientKey` is set. */
			clientSecret: string | null;
			clientKey: ClientKey | null;
			scope: string | null;
			audience: string | null;
			resource: string | null;
			allowedIssuers: string[];
	  };

/**
 * The external credential exchange (README, External credential exchange): an
 * inbound `Authorization: Bearer <JWT>` is submitted to the provider's token
 * endpoint as an RFC 7523 `jwt-bearer` assertion and the issued token
 * replaces it.
 *
 * Disabled (the default) parses to `{ enabled: false }` and nothing else is
 * used. Enabled, the proxy authenticates to the token endpoint as a
 * confidential client, with `client_secret_basic` or `private_key_jwt`: a
 * `client_id` alone is not client authentication, so the id and exactly one
 * of `clientSecret` and `clientKey` are required, and anything else fails at
 * boot naming the keys. A key also needs `auth.injection.providerIssuer`,
 * checked where both are in view. `allowedIssuers` is an optional prefilter
 * on the unverified `iss`, empty meaning off; trust in an issuer is the
 * provider's decision.
 *
 * Every field is parsed and validated before the transform, so an invalid
 * entry (in `allowedIssuers`, say) fails the configuration even when the
 * exchange is disabled.
 */
const exchangeSchema = z
	.object({
		enabled: strictBoolean(`${EXCHANGE_KEY}.enabled`),
		clientId: optionalString(),
		clientSecret: optionalString(),
		clientKey: clientKey(`${EXCHANGE_KEY}.clientKey`),
		scope: optionalString(),
		audience: optionalString(),
		resource: optionalString(),
		allowedIssuers: whitespaceSeparatedList(`${EXCHANGE_KEY}.allowedIssuers`),
	})
	.transform((exchange, ctx): ExchangeConfig => {
		if (!exchange.enabled) {
			return { enabled: false as const };
		}
		const { clientId, clientSecret, clientKey } = exchange;
		const enabledNote = `when ${EXCHANGE_KEY}.enabled is true (the proxy authenticates to the token endpoint as a confidential client)`;
		if (clientId === null) {
			ctx.addIssue({ code: "custom", message: `${EXCHANGE_KEY}.clientId is required ${enabledNote}` });
		}
		if (clientSecret === null && clientKey === null) {
			ctx.addIssue({
				code: "custom",
				message: `${EXCHANGE_KEY}.clientSecret or ${EXCHANGE_KEY}.clientKey is required ${enabledNote}`,
			});
		}
		if (clientSecret !== null && clientKey !== null) {
			ctx.addIssue({
				code: "custom",
				message: `${EXCHANGE_KEY}.clientSecret and ${EXCHANGE_KEY}.clientKey are alternatives; set one`,
			});
		}
		if (clientId === null || (clientSecret === null) === (clientKey === null)) {
			return z.NEVER;
		}
		return {
			enabled: true as const,
			clientId,
			clientSecret,
			clientKey,
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
				// How the proxy authenticates to introspection: not at all (all
				// unset, and the inbound token is the credential), or as a client
				// with exactly one of a secret and a key.
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
						clientKey: clientKey("auth.validation.client.clientKey"),
					})
					.superRefine((c, ctx) => {
						const k = "auth.validation.client";
						if (c.clientSecret !== null && c.clientKey !== null) {
							ctx.addIssue({
								code: "custom",
								message: `${k}.clientSecret and ${k}.clientKey are alternatives; set one`,
							});
						} else if (c.clientId === null && (c.clientSecret !== null || c.clientKey !== null)) {
							ctx.addIssue({
								code: "custom",
								message: `${k}.clientId is required with ${k}.clientSecret or ${k}.clientKey`,
							});
						} else if (c.clientId !== null && c.clientSecret === null && c.clientKey === null) {
							ctx.addIssue({
								code: "custom",
								message: `${k}.clientId needs ${k}.clientSecret or ${k}.clientKey (client_secret_basic or private_key_jwt); unset all three to introspect with the inbound token`,
							});
						}
					}),
				providerIssuer: providerIssuer("auth.validation.providerIssuer"),
				// RFC 6750 §3's `realm`, for `WWW-Authenticate`. Unset, the challenges
				// carry none. It is sent inside a quoted-string, so only printable
				// ASCII that needs no escaping is accepted — no `"`, no `\`, no
				// control character — and the header cannot be split by it. No
				// surrounding space (an environment value is not trimmed), and at
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
					url: z.string().refine(isIntrospectionUrl, {
						message:
							"auth.validation.introspect.url must be an absolute http(s) URL without userinfo; the URL carries no credential (configure auth.validation.client)",
					}),
					cacheTtlSec: z.coerce.number().default(30),
					cacheMaxEntries: z.coerce.number().int().positive().default(10000),
					timeoutMs: z.coerce.number().int().positive().default(5000),
				}),
			}).superRefine((validation, ctx) => {
				if (validation.client.clientKey !== null && validation.providerIssuer === null) {
					ctx.addIssue({
						code: "custom",
						path: ["providerIssuer"],
						message:
							"auth.validation.providerIssuer is required with auth.validation.client.clientKey: it is the client assertion's audience",
					});
				}
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
				/**
				 * Unset, the proxy is a public client for the session grant, sending
				 * its `client_id` alone. Set, it is a confidential client that
				 * authenticates with `private_key_jwt`.
				 */
				clientKey: clientKey("auth.injection.clientKey"),
				/** The client assertion's audience, for this key and the exchange's. */
				providerIssuer: providerIssuer("auth.injection.providerIssuer"),
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
				 * upstream that reads "a Bearer header arrived from the proxy" as
				 * "the proxy minted this" is bypassable by a client that sends its
				 * own.
				 *
				 * Default `false`: pass-through is what lets a service account
				 * present its own token through this proxy. Turning it on is
				 * defence in depth, not a replacement for the upstream verifying
				 * the token it was handed.
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
			}).superRefine((injection, ctx) => {
				const keyed =
					injection.clientKey !== null ||
					(injection.exchange.enabled && injection.exchange.clientKey !== null);
				if (keyed && injection.providerIssuer === null) {
					ctx.addIssue({
						code: "custom",
						path: ["providerIssuer"],
						message:
							"auth.injection.providerIssuer is required with auth.injection.clientKey or auth.injection.exchange.clientKey: it is the client assertion's audience",
					});
				}
			}),
		}),
	]),
	upstream: z.object({
		baseURL: z.string(),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
