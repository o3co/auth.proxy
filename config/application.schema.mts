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
 * so integers, booleans and lists have their own parsers below.
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
import { parseAddressRange } from "../src/address-range.mjs";
import { parseByteSize } from "../src/byte-size.mjs";
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
 * An http(s) origin and nothing else: `scheme://host[:port]`, optionally with
 * a bare trailing slash, and no userinfo, path, query or fragment. Port `0`
 * is no port anything can be reached at.
 */
const isHttpOrigin = (value: string): boolean => {
	if (!URL.canParse(value)) return false;
	const parsed = new URL(value);
	return (
		(parsed.protocol === "http:" || parsed.protocol === "https:") &&
		parsed.username === "" &&
		parsed.password === "" &&
		parsed.port !== "0" &&
		(parsed.pathname === "" || parsed.pathname === "/") &&
		!parsed.search &&
		!parsed.hash
	);
};

/**
 * An http(s) origin as written: `scheme://host[:port]` and at most one trailing
 * `/`, nothing else. Read before the URL parser, which would turn
 * `https://h/a/..`, `https://h?`, `https://h#` or `https://@h` into the bare
 * origin. The host is a bracketed IPv6 address or a run of characters that end
 * no authority; the parser then has the last word on whether it is a host.
 */
const ORIGIN_AS_WRITTEN = /^https?:\/\/(?:\[[0-9a-f:.]+\]|[^\s\p{Cc}/?#@\\:[\]]+)(?::[0-9]{1,5})?\/?$/iu;

const isHttpOriginAsWritten = (value: string): boolean =>
	ORIGIN_AS_WRITTEN.test(value) && isHttpOrigin(value);

/** A segment of `http.pathPrefix`: RFC 3986 unreserved characters only. */
const PATH_PREFIX_SEGMENT = /^[A-Za-z0-9._~-]+$/;

/**
 * A path prefix express mounts where it reads: `/`, or `/`-separated segments
 * of RFC 3986 unreserved characters, optionally with one trailing `/`, which
 * express mounts the same as none. Express mounts a prefix without its leading
 * `/` nowhere, reads `:`, `*`, `(`, `?` and the like as route syntax, and
 * matches the request's percent-encoded path, so any other character would
 * mount the router somewhere else or nowhere; `.` and `..` are segments a
 * client resolves away before it sends the request.
 */
const isPathPrefix = (value: string): boolean => {
	if (value === "/") return true;
	if (!value.startsWith("/")) return false;
	return value
		.slice(1)
		.replace(/\/$/, "")
		.split("/")
		.every((segment) => PATH_PREFIX_SEGMENT.test(segment) && segment !== "." && segment !== "..");
};

/** The longest delay a Node timer holds; a longer one fires after 1 ms. */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * An integer from `min` to `max` that survives the HOCON -> environment round
 * trip: a HOCON number, or an override of decimal digits, whitespace around
 * them allowed. Anything else is a configuration error naming the key.
 *
 * Not `z.coerce.number()`: under it an empty override is `0` — a random
 * listen port, or a cache turned off — and `1e3` and `0x50` are numbers too.
 */
const integer = (
	key: string,
	{ min, max = Number.MAX_SAFE_INTEGER, note = "" }: { min: number; max?: number; note?: string },
	fallback: number,
) =>
	z
		.union([z.number(), z.string()])
		.default(fallback)
		.transform((value, ctx): number => {
			const parsed = typeof value === "number" ? value : /^\s*[0-9]+\s*$/.test(value) ? Number(value) : Number.NaN;
			if (Number.isSafeInteger(parsed) && parsed >= min && parsed <= max) return parsed;
			const range = max === Number.MAX_SAFE_INTEGER ? `of at least ${min}` : `from ${min} to ${max}`;
			ctx.addIssue({
				code: "custom",
				message: `${key} must be an integer ${range}${note} (got ${JSON.stringify(value)})`,
			});
			return z.NEVER;
		});

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

/** Hosts on which the provider accepts an `http:` issuer. */
const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Whether `value` is an issuer identifier the provider can have: what
 * auth.provider's `checkCanonicalIssuer` accepts — an absolute `https:` URL (a
 * path allowed), or `http:` on a loopback host, with no query, fragment or
 * userinfo — written in printable ASCII with no backslash. The value is sent as
 * written, since the provider compares it as a string, so a form the URL
 * parser would clean up (surrounding space, a tab, a backslash, a fullwidth
 * letter) could never equal the provider's.
 */
const isIssuerIdentifier = (value: string): boolean => {
	if (!/^[\x21-\x7E]+$/.test(value) || value.includes("\\")) return false;
	if (!URL.canParse(value)) return false;
	const parsed = new URL(value);
	return (
		parsed.hostname !== "" &&
		(parsed.protocol === "https:" ||
			(parsed.protocol === "http:" && LOOPBACK_HOSTNAMES.has(parsed.hostname))) &&
		parsed.username === "" &&
		parsed.password === "" &&
		parsed.search === "" &&
		parsed.hash === "" &&
		!value.includes("?") &&
		!value.includes("#")
	);
};

/**
 * The provider's issuer identifier, the only audience of a client assertion
 * (RFC 7523 section 3), as the provider's discovery document names it. It may
 * differ from the URL the proxy reaches the provider at.
 */
const providerIssuer = (key: string) =>
	optionalString().refine((value) => value === null || isIssuerIdentifier(value), {
		message: `${key} must be the provider's issuer identifier as its discovery document names it: https (http only on a loopback host), printable ASCII (configure a Unicode host at the provider in its xn-- form), with no query, fragment, userinfo or whitespace`,
	});

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
		hostname: z
			.string()
			.regex(/^\S+$/, {
				message: "http.hostname must be a host name or an IP address to listen on, not empty and without whitespace",
			})
			.default("0.0.0.0"),
		port: integer("http.port", { min: 1, max: 65535 }, 80),
		pathPrefix: z
			.string()
			.refine(isPathPrefix, {
				message:
					"http.pathPrefix must be / or /-separated segments of letters, digits, -, ., _ and ~ (/api, /api/v1), starting with /",
			})
			.default("/"),
		// Read once more by the router, which enforces it; a value the body
		// reader would misread is refused here rather than at the first request.
		bodyLimitSize: z
			.string()
			.refine((value) => parseByteSize(value) !== null, {
				message:
					"http.bodyLimitSize must be a byte size: a number, optionally followed by b, kb, mb, gb, tb or pb (1kb = 1024 bytes)",
			})
			.default("10mb"),
		cors: z.object({
			origin: z.object({
				// Compiled here, so a pattern that does not compile stops the
				// process naming the key rather than when CORS is built.
				pattern: optionalString().superRefine((value, ctx) => {
					if (value === null) return;
					try {
						new RegExp(value);
					} catch (err) {
						ctx.addIssue({
							code: "custom",
							message: `http.cors.origin.pattern must be a regular expression that compiles (${err instanceof Error ? err.message : "it does not"})`,
						});
					}
				}),
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
					cacheTtlSec: integer(
						"auth.validation.introspect.cacheTtlSec",
						{ min: 0, note: " (0 turns the cache off)" },
						30,
					),
					cacheMaxEntries: integer("auth.validation.introspect.cacheMaxEntries", { min: 1 }, 10000),
					timeoutMs: integer("auth.validation.introspect.timeoutMs", { min: 1, max: MAX_TIMER_MS }, 5000),
				}),
			}).superRefine((validation, ctx) => {
				const keyed = validation.client.clientKey !== null;
				if (keyed && validation.providerIssuer === null) {
					ctx.addIssue({
						code: "custom",
						path: ["providerIssuer"],
						message:
							"auth.validation.providerIssuer is required with auth.validation.client.clientKey: it is the client assertion's audience",
					});
				}
				// An issuer no key uses is a key that did not arrive.
				if (!keyed && validation.providerIssuer !== null) {
					ctx.addIssue({
						code: "custom",
						path: ["providerIssuer"],
						message:
							"auth.validation.providerIssuer is set but no client key uses it: set auth.validation.client.clientKey, or unset the issuer",
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
					.refine(isHttpOrigin, {
						message:
							"auth.injection.providerOrigin must be an http(s) origin only (scheme://host[:port]), no userinfo/path/query/fragment",
					}),
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
				/**
				 * The origin browsers reach this proxy at. A request whose `Origin`
				 * equals it may be answered from the session cache
				 * (`modes/injection/origin-gate.mts`). Written as
				 * `scheme://host[:port]`, optionally with one trailing `/`, and
				 * held as a browser serialises `Origin` — scheme and host
				 * lower-cased, no default port, no trailing slash — so the gate
				 * compares strings.
				 */
				publicOrigin: optionalString().transform((value, ctx): string | null => {
					if (value === null) return null;
					if (!isHttpOriginAsWritten(value)) {
						ctx.addIssue({
							code: "custom",
							message:
								"auth.injection.publicOrigin must be an http(s) origin written as scheme://host[:port], optionally with one trailing /, and nothing else",
						});
						return z.NEVER;
					}
					return new URL(value).origin;
				}),
				/**
				 * The proxies in front of this one whose `X-Forwarded-For` and
				 * `X-Forwarded-Proto` it believes when it tells the provider where a
				 * browser request came from (`modes/injection/request-source.mts`).
				 * Each entry is an IP address or an address/prefix range; empty
				 * believes none.
				 */
				trustedProxies: whitespaceSeparatedList("auth.injection.trustedProxies").refine(
					(entries) => entries.every((entry) => parseAddressRange(entry) !== null),
					{
						message:
							"auth.injection.trustedProxies entries must be IP addresses or address/prefix ranges (10.0.0.0/8, 192.0.2.1, fd00::/8), with no port, zone ID or host name",
					},
				),
				tokenCache: z
					.object({
						ttlSeconds: integer("auth.injection.tokenCache.ttlSeconds", { min: 1 }, 60),
						maxEntries: integer("auth.injection.tokenCache.maxEntries", { min: 1 }, 10000),
						safetyMarginSeconds: integer("auth.injection.tokenCache.safetyMarginSeconds", { min: 0 }, 5),
					})
					.refine(
						(tc) => tc.safetyMarginSeconds < tc.ttlSeconds,
						{
							message:
								"auth.injection.tokenCache.safetyMarginSeconds must be less than auth.injection.tokenCache.ttlSeconds",
						},
					),
				timeoutMs: integer("auth.injection.timeoutMs", { min: 1, max: MAX_TIMER_MS }, 5000),
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
				// An issuer no key uses is a key that did not arrive: the session
				// grant would stay a public client without a word.
				if (!keyed && injection.providerIssuer !== null) {
					ctx.addIssue({
						code: "custom",
						path: ["providerIssuer"],
						message:
							"auth.injection.providerIssuer is set but no client key uses it: set auth.injection.clientKey, or enable the exchange with auth.injection.exchange.clientKey, or unset the issuer",
					});
				}
			}),
		}),
	]),
	upstream: z.object({
		/**
		 * The upstream every proxied request goes to, held as its origin. The
		 * upstream proxy (express-http-proxy) keeps only the host and port of
		 * its target, so a path would be dropped without a word; only an
		 * origin is accepted, and the message never quotes the value, which
		 * may carry userinfo.
		 */
		baseURL: z.string().transform((value, ctx): string => {
			if (!isHttpOriginAsWritten(value)) {
				ctx.addIssue({
					code: "custom",
					message:
						"upstream.baseURL must be an http(s) origin written as scheme://host[:port], optionally with one trailing /, and nothing else: the proxy forwards to its host and port only, so a path, query, fragment or userinfo would be dropped",
				});
				return z.NEVER;
			}
			return new URL(value).origin;
		}),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
