import { readFileSync } from "node:fs";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "../../config/application.schema.mjs";

const confPath = new URL("../../config/application.conf", import.meta.url).pathname;

describe("proxy config — validation mode", () => {
	it("parses validation mode with defaults", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "validation" },
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.auth.mode).toBe("validation");
		if (config.auth.mode !== "validation") throw new Error("narrow");
		expect(config.auth.validation.introspect.cacheTtlSec).toBe(30);
		expect(config.auth.validation.introspect.cacheMaxEntries).toBe(10000);
		expect(config.auth.validation.introspect.timeoutMs).toBe(5000);
		expect(config.auth.validation.client.clientId).toBeNull();
		expect(config.auth.validation.client.clientSecret).toBeNull();
	});

	it("accepts env overrides for validation introspect", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "validation",
				HTTP_PORT: "8080",
				INTROSPECT_URL: "http://auth:3000/oauth/introspect",
				UPSTREAM_BASEURL: "http://backend:4000",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(8080);
		if (config.auth.mode !== "validation") throw new Error("narrow");
		expect(config.auth.validation.introspect.url).toBe("http://auth:3000/oauth/introspect");
		expect(config.upstream.baseURL).toBe("http://backend:4000");
	});

	it("accepts both clientId and clientSecret set", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "validation", CLIENT_ID: "my-proxy", CLIENT_SECRET: "s3cret" },
		});
		const config = validate(raw, AppConfigSchema);

		if (config.auth.mode !== "validation") throw new Error("narrow");
		expect(config.auth.validation.client.clientId).toBe("my-proxy");
		expect(config.auth.validation.client.clientSecret).toBe("s3cret");
	});

	it("treats empty strings as null for client credentials", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "validation", CLIENT_ID: "", CLIENT_SECRET: "" },
		});
		const config = validate(raw, AppConfigSchema);

		if (config.auth.mode !== "validation") throw new Error("narrow");
		expect(config.auth.validation.client.clientId).toBeNull();
		expect(config.auth.validation.client.clientSecret).toBeNull();
	});

	// #95 F45: the RFC 6750 realm, optional. It goes into a quoted-string in
	// `WWW-Authenticate`, so only what needs no escaping is accepted.
	describe("auth.validation.realm", () => {
		const realmOf = (env: Record<string, string>) => {
			const config = validate(
				parseFile(confPath, { env: { AUTH_MODE: "validation", ...env } }),
				AppConfigSchema,
			);
			if (config.auth.mode !== "validation") throw new Error("narrow");
			return config.auth.validation.realm;
		};

		it("is unset by default", () => {
			expect(realmOf({})).toBeNull();
		});

		it("is read from VALIDATION_REALM", () => {
			expect(realmOf({ VALIDATION_REALM: "orders api" })).toBe("orders api");
		});

		it("treats an empty VALIDATION_REALM as unset", () => {
			expect(realmOf({ VALIDATION_REALM: "" })).toBeNull();
		});

		it.each(['a"b', "a\\b", "a\u0001b", "a\u00e9b", "a\nb"])(
			"refuses %j, which a quoted-string would need to escape or cannot carry",
			(realm) => {
				expect(() => realmOf({ VALIDATION_REALM: realm })).toThrow(/auth\.validation\.realm/);
			},
		);
	});

	it("rejects when only clientId is set", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "validation", CLIENT_ID: "my-proxy" },
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects when only clientSecret is set", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "validation", CLIENT_SECRET: "s3cret" },
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});
});

describe("proxy config — injection mode", () => {
	it("parses injection mode with required fields", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api.read api.write",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.auth.mode).toBe("injection");
		if (config.auth.mode !== "injection") throw new Error("narrow");
		expect(config.auth.injection.providerOrigin).toBe("http://localhost:3000");
		expect(config.auth.injection.clientId).toBe("my-spa");
		expect(config.auth.injection.scope).toBe("api.read api.write");
		expect(config.auth.injection.sessionCookieName).toBe("connect.sid");
		expect(config.auth.injection.tokenCache.ttlSeconds).toBe(60);
		expect(config.auth.injection.tokenCache.maxEntries).toBe(10000);
		expect(config.auth.injection.tokenCache.safetyMarginSeconds).toBe(5);
		expect(config.auth.injection.timeoutMs).toBe(5000);
	});

	it("rejects injection mode with empty clientId", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "injection", INJECTION_CLIENT_ID: "", INJECTION_SCOPE: "api" },
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects injection mode with empty scope", () => {
		const raw = parseFile(confPath, {
			env: { AUTH_MODE: "injection", INJECTION_CLIENT_ID: "my-spa", INJECTION_SCOPE: "" },
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects providerOrigin with a path component", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_PROVIDER_ORIGIN: "https://provider.example/api",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects providerOrigin with a query component", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_PROVIDER_ORIGIN: "https://provider.example/?x=1",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("accepts providerOrigin with bare trailing slash", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_PROVIDER_ORIGIN: "https://provider.example/",
			},
		});
		const config = validate(raw, AppConfigSchema);
		if (config.auth.mode !== "injection") throw new Error("narrow");
		expect(config.auth.injection.providerOrigin).toBe("https://provider.example/");
	});

	it("accepts providerOrigin without trailing slash", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_PROVIDER_ORIGIN: "https://provider.example",
			},
		});
		const config = validate(raw, AppConfigSchema);
		if (config.auth.mode !== "injection") throw new Error("narrow");
		expect(config.auth.injection.providerOrigin).toBe("https://provider.example");
	});

	it("rejects providerOrigin with non-HTTP scheme", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_PROVIDER_ORIGIN: "ftp://provider.example",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects providerOrigin with embedded userinfo", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_PROVIDER_ORIGIN: "https://user:pass@provider.example",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	// RFC 6265 section 4.1.1 `cookie-name = token` (RFC 9110 token: 1*tchar). The
	// configured name is interpolated verbatim into the outbound `Cookie` header
	// of the session grant call, so a separator or whitespace in it would malform
	// that header at every request; it must fail at boot instead (#75).
	describe("sessionCookieName must be an RFC 6265 cookie-name (#75)", () => {
		const injectionEnv = (sessionCookieName: string) => ({
			AUTH_MODE: "injection",
			INJECTION_CLIENT_ID: "my-spa",
			INJECTION_SCOPE: "api",
			INJECTION_SESSION_COOKIE_NAME: sessionCookieName,
		});

		it("accepts the default connect.sid and common prefixed names", () => {
			for (const name of ["connect.sid", "__Host-sid", "__Secure-session_id", "SID"]) {
				const raw = parseFile(confPath, { env: injectionEnv(name) });
				const config = validate(raw, AppConfigSchema);
				if (config.auth.mode !== "injection") throw new Error("narrow");
				expect(config.auth.injection.sessionCookieName, name).toBe(name);
			}
		});

		it("accepts every tchar (!#$%&'*+-.^_`|~ DIGIT ALPHA)", () => {
			const tchars =
				"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			const raw = parseFile(confPath, { env: injectionEnv(tchars) });
			const config = validate(raw, AppConfigSchema);
			if (config.auth.mode !== "injection") throw new Error("narrow");
			expect(config.auth.injection.sessionCookieName).toBe(tchars);
		});

		it("rejects a name with whitespace, naming the key in the error", () => {
			const raw = parseFile(confPath, { env: injectionEnv("sid ") });
			expect(() => validate(raw, AppConfigSchema)).toThrow(
				/auth\.injection\.sessionCookieName/,
			);
		});

		it("rejects a name containing '=' — it would smuggle a value into the outbound Cookie header", () => {
			const raw = parseFile(confPath, { env: injectionEnv("a=b") });
			expect(() => validate(raw, AppConfigSchema)).toThrow(
				/auth\.injection\.sessionCookieName/,
			);
		});

		it("rejects every RFC 9110 separator and non-ASCII", () => {
			const separators = ['"', "(", ")", ",", "/", ":", ";", "<", ">", "?", "@", "[", "\\", "]", "{", "}"];
			for (const sep of [...separators, "\t", "\u00a0", "é"]) {
				const raw = parseFile(confPath, { env: injectionEnv(`sid${sep}x`) });
				expect(() => validate(raw, AppConfigSchema), JSON.stringify(sep)).toThrow(
					/auth\.injection\.sessionCookieName/,
				);
			}
		});

		it("still rejects an empty name", () => {
			const raw = parseFile(confPath, { env: injectionEnv("") });
			expect(() => validate(raw, AppConfigSchema)).toThrow();
		});
	});

	// An opt-in hardening switch, so it has to default to the pass-through
	// behaviour and it has to be validated at boot like every other
	// auth.injection key. `z.coerce.boolean()` would be wrong here: it is
	// `Boolean(v)`, under which the string "false" an operator sets in the
	// environment is `true` — the flag would silently refuse to turn off.
	describe("stripInboundAuthorization", () => {
		const injectionEnv = (extra: Record<string, string> = {}) => ({
			AUTH_MODE: "injection",
			INJECTION_CLIENT_ID: "my-spa",
			INJECTION_SCOPE: "api",
			...extra,
		});

		it("defaults to false — today's forward-untouched behaviour", () => {
			const raw = parseFile(confPath, { env: injectionEnv() });
			const config = validate(raw, AppConfigSchema);

			if (config.auth.mode !== "injection") throw new Error("narrow");
			expect(config.auth.injection.stripInboundAuthorization).toBe(false);
		});

		it('reads "true" from the environment as true', () => {
			const raw = parseFile(confPath, {
				env: injectionEnv({ INJECTION_STRIP_INBOUND_AUTHORIZATION: "true" }),
			});
			const config = validate(raw, AppConfigSchema);

			if (config.auth.mode !== "injection") throw new Error("narrow");
			expect(config.auth.injection.stripInboundAuthorization).toBe(true);
		});

		it('reads "false" from the environment as false, not as a truthy string', () => {
			const raw = parseFile(confPath, {
				env: injectionEnv({ INJECTION_STRIP_INBOUND_AUTHORIZATION: "false" }),
			});
			const config = validate(raw, AppConfigSchema);

			if (config.auth.mode !== "injection") throw new Error("narrow");
			expect(config.auth.injection.stripInboundAuthorization).toBe(false);
		});

		it("rejects a value that is neither true nor false, naming the key", () => {
			for (const value of ["yes", "1", "TRUE", ""]) {
				const raw = parseFile(confPath, {
					env: injectionEnv({ INJECTION_STRIP_INBOUND_AUTHORIZATION: value }),
				});
				expect(() => validate(raw, AppConfigSchema), value).toThrow(
					/auth\.injection\.stripInboundAuthorization/,
				);
			}
		});
	});

	// The external credential exchange (#90) is opt-in inside injection mode.
	// Disabled, nothing about it is read; enabled, the proxy authenticates to
	// the token endpoint as a confidential client, so a client_id alone is a
	// boot failure rather than an unauthenticated exchange.
	describe("exchange (#90)", () => {
		const injectionEnv = (extra: Record<string, string> = {}) => ({
			AUTH_MODE: "injection",
			INJECTION_CLIENT_ID: "my-spa",
			INJECTION_SCOPE: "api",
			...extra,
		});
		const enabledEnv = (extra: Record<string, string> = {}) =>
			injectionEnv({
				INJECTION_EXCHANGE_ENABLED: "true",
				INJECTION_EXCHANGE_CLIENT_ID: "proxy-exchange",
				INJECTION_EXCHANGE_CLIENT_SECRET: "s3cret",
				...extra,
			});
		const load = (env: Record<string, string>) => {
			const config = validate(parseFile(confPath, { env }), AppConfigSchema);
			if (config.auth.mode !== "injection") throw new Error("narrow");
			return config.auth.injection.exchange;
		};

		it("defaults to disabled, carrying nothing else", () => {
			expect(load(injectionEnv())).toEqual({ enabled: false });
		});

		it("ignores exchange credentials while disabled", () => {
			expect(
				load(injectionEnv({ INJECTION_EXCHANGE_CLIENT_ID: "proxy-exchange" })),
			).toEqual({ enabled: false });
		});

		it("parses an enabled exchange with credentials and unset optional parameters", () => {
			expect(load(enabledEnv())).toEqual({
				enabled: true,
				clientId: "proxy-exchange",
				clientSecret: "s3cret",
				scope: null,
				audience: null,
				resource: null,
				allowedIssuers: [],
			});
		});

		it("reads scope, audience, resource and a whitespace-separated issuer list from the environment", () => {
			expect(
				load(
					enabledEnv({
						INJECTION_EXCHANGE_SCOPE: "orders.read orders.write",
						INJECTION_EXCHANGE_AUDIENCE: "https://api.example.com",
						INJECTION_EXCHANGE_RESOURCE: "https://api.example.com/orders",
						INJECTION_EXCHANGE_ALLOWED_ISSUERS:
							"https://idp-a.example  https://idp-b.example\turn:issuer:c",
					}),
				),
			).toEqual({
				enabled: true,
				clientId: "proxy-exchange",
				clientSecret: "s3cret",
				scope: "orders.read orders.write",
				audience: "https://api.example.com",
				resource: "https://api.example.com/orders",
				allowedIssuers: ["https://idp-a.example", "https://idp-b.example", "urn:issuer:c"],
			});
		});

		it("treats empty optional parameters as unset", () => {
			const exchange = load(
				enabledEnv({
					INJECTION_EXCHANGE_SCOPE: "",
					INJECTION_EXCHANGE_AUDIENCE: "",
					INJECTION_EXCHANGE_RESOURCE: "",
					INJECTION_EXCHANGE_ALLOWED_ISSUERS: "",
				}),
			);
			expect(exchange).toMatchObject({
				scope: null,
				audience: null,
				resource: null,
				allowedIssuers: [],
			});
		});

		it("reads allowedIssuers as a HOCON list", () => {
			const text = `${readFileSync(confPath, "utf8")}
auth.injection.exchange.allowedIssuers = ["https://idp-a.example", "urn:issuer:b"]
`;
			const config = validate(parseString(text, { env: enabledEnv() }), AppConfigSchema);
			if (config.auth.mode !== "injection") throw new Error("narrow");
			expect(config.auth.injection.exchange).toMatchObject({
				allowedIssuers: ["https://idp-a.example", "urn:issuer:b"],
			});
		});

		it("rejects a HOCON list entry that is empty or contains whitespace, naming the key", () => {
			for (const entry of ['""', '"https://idp.example other"']) {
				const text = `${readFileSync(confPath, "utf8")}
auth.injection.exchange.allowedIssuers = [${entry}]
`;
				expect(
					() => validate(parseString(text, { env: enabledEnv() }), AppConfigSchema),
					entry,
				).toThrow(/auth\.injection\.exchange\.allowedIssuers/);
			}
		});

		it("rejects enabled without clientId, naming the key", () => {
			expect(() => load(enabledEnv({ INJECTION_EXCHANGE_CLIENT_ID: "" }))).toThrow(
				/auth\.injection\.exchange\.clientId/,
			);
		});

		it("rejects enabled without clientSecret — a client_id alone is not client authentication", () => {
			expect(() => load(enabledEnv({ INJECTION_EXCHANGE_CLIENT_SECRET: "" }))).toThrow(
				/auth\.injection\.exchange\.clientSecret/,
			);
		});

		it('reads "false" from the environment as disabled', () => {
			expect(load(enabledEnv({ INJECTION_EXCHANGE_ENABLED: "false" }))).toEqual({
				enabled: false,
			});
		});

		it("rejects an enabled value that is neither true nor false, naming the key", () => {
			for (const value of ["yes", "1", "TRUE", ""]) {
				expect(() => load(injectionEnv({ INJECTION_EXCHANGE_ENABLED: value })), value).toThrow(
					/auth\.injection\.exchange\.enabled/,
				);
			}
		});

		it("defaults to disabled when the exchange block is absent altogether", () => {
			const config = AppConfigSchema.parse({
				http: { cors: { origin: { pattern: null } } },
				auth: {
					mode: "injection",
					injection: {
						providerOrigin: "http://provider.example",
						clientId: "my-spa",
						scope: "api",
						sessionCookieName: "sid",
						tokenCache: {},
					},
				},
				upstream: { baseURL: "http://u" },
			});
			if (config.auth.mode !== "injection") throw new Error("narrow");
			expect(config.auth.injection.exchange).toEqual({ enabled: false });
		});
	});

	it("rejects tokenCache where safetyMarginSeconds >= ttlSeconds (equal)", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_TOKEN_CACHE_TTL_SEC: "5",
				INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC: "5",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects tokenCache where safetyMarginSeconds > ttlSeconds", () => {
		const raw = parseFile(confPath, {
			env: {
				AUTH_MODE: "injection",
				INJECTION_CLIENT_ID: "my-spa",
				INJECTION_SCOPE: "api",
				INJECTION_TOKEN_CACHE_TTL_SEC: "5",
				INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC: "10",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});
});

describe("proxy config — mode selection", () => {
	it("rejects when auth.mode is omitted (null)", () => {
		const raw = parseFile(confPath);
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects when auth.mode is a typo", () => {
		const raw = parseFile(confPath, { env: { AUTH_MODE: "validaton" } });
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects when auth.mode=\"validation\" but validation section is empty/missing", () => {
		// Use an env-injected mode with no validation block present.
		// Since application.conf always has a validation block, craft a raw
		// object directly using the Zod schema's parse method (validate() from
		// ts.hocon/zod requires a HOCON Config object, not a plain object).
		expect(() =>
			AppConfigSchema.parse({
				http: { cors: { origin: { pattern: null } } },
				auth: { mode: "validation" },
				upstream: { baseURL: "http://u" },
			}),
		).toThrow();
	});
});
