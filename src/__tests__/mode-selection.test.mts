import { describe, expect, it } from "vitest";
import type { AppConfig } from "../../config/application.schema.mjs";
import { resolveRouter } from "../app-internal.mjs";

const validationConfig: AppConfig = {
	http: {
		hostname: "0.0.0.0",
		port: 80,
		pathPrefix: "/",
		bodyLimitSize: "10mb",
		cors: { origin: { pattern: null } },
	},
	auth: {
		mode: "validation" as const,
		validation: {
			client: { clientId: null, clientSecret: null },
			introspect: {
				url: "http://auth/introspect",
				cacheTtlSec: 30,
				cacheMaxEntries: 100,
				timeoutMs: 5000,
			},
		},
	},
	upstream: { baseURL: "http://upstream" },
};

const injectionConfig: AppConfig = {
	http: {
		hostname: "0.0.0.0",
		port: 80,
		pathPrefix: "/",
		bodyLimitSize: "10mb",
		cors: { origin: { pattern: null } },
	},
	auth: {
		mode: "injection" as const,
		injection: {
			providerOrigin: "http://provider",
			clientId: "my-spa",
			scope: "api",
			sessionCookieName: "sid",
			tokenCache: { ttlSeconds: 60, maxEntries: 100, safetyMarginSeconds: 5 },
			timeoutMs: 5000,
		},
	},
	upstream: { baseURL: "http://upstream" },
};

describe("resolveRouter", () => {
	it("returns a router for validation mode", () => {
		const router = resolveRouter(validationConfig);
		expect(typeof router).toBe("function");
	});

	it("returns a router for injection mode", () => {
		const router = resolveRouter(injectionConfig);
		expect(typeof router).toBe("function");
	});
});
