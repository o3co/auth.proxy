import { parseFile } from "@o3co/ts.hocon";
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
