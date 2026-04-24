import { describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../config/application.schema.mjs";

// Mock both factories so we can verify dispatch routes to the correct one.
vi.mock("../modes/validation/router.mjs", () => ({
	createRouter: vi.fn(() => "VALIDATION_ROUTER"),
}));
vi.mock("../modes/injection/router.mjs", () => ({
	createRouter: vi.fn(() => "INJECTION_ROUTER"),
}));

// Dynamic import after mocks so the mocked factories are in effect.
const { resolveRouter } = await import("../app-internal.mjs");
const { createRouter: createValidationRouter } = await import(
	"../modes/validation/router.mjs"
);
const { createRouter: createInjectionRouter } = await import(
	"../modes/injection/router.mjs"
);

const baseHttp = {
	hostname: "0.0.0.0",
	port: 80,
	pathPrefix: "/",
	bodyLimitSize: "10mb",
	cors: { origin: { pattern: null } },
};
const baseUpstream = { baseURL: "http://upstream" };

const validationConfig: AppConfig = {
	http: baseHttp,
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
	upstream: baseUpstream,
};

const injectionConfig: AppConfig = {
	http: baseHttp,
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
	upstream: baseUpstream,
};

describe("resolveRouter", () => {
	it("dispatches to validation router when mode=validation", () => {
		const result = resolveRouter(validationConfig) as unknown as string;
		expect(result).toBe("VALIDATION_ROUTER");
		expect(createValidationRouter).toHaveBeenCalledWith({ config: validationConfig });
		expect(createInjectionRouter).not.toHaveBeenCalled();
	});

	it("dispatches to injection router when mode=injection", () => {
		vi.mocked(createValidationRouter).mockClear();
		vi.mocked(createInjectionRouter).mockClear();

		const result = resolveRouter(injectionConfig) as unknown as string;
		expect(result).toBe("INJECTION_ROUTER");
		expect(createInjectionRouter).toHaveBeenCalledWith({ config: injectionConfig });
		expect(createValidationRouter).not.toHaveBeenCalled();
	});

	it("throws on unknown auth.mode (exhaustive guard)", () => {
		const bogus = { ...validationConfig, auth: { mode: "unknown" } } as unknown as AppConfig;
		expect(() => resolveRouter(bogus)).toThrow(/Unsupported auth\.mode/);
	});
});
