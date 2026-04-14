import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "../../config/application.schema.mjs";

describe("proxy config", () => {
	it("loads and validates application.conf with defaults", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
		);
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(80);
		expect(config.http.bodyLimitSize).toBe("10mb");
		expect(config.http.cors.origin.pattern).toBeNull();
		expect(config.auth.introspect.cacheTtlSec).toBe(30);
		expect(config.auth.introspect.cacheMaxEntries).toBe(10000);
		expect(config.auth.introspect.timeoutMs).toBe(5000);
		expect(config.auth.client.clientId).toBeNull();
		expect(config.upstream.baseURL).toBe("http://localhost:3000");
	});

	it("overrides with env vars", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { HTTP_PORT: "8080", INTROSPECT_URL: "http://auth:3000/oauth/introspect", UPSTREAM_BASEURL: "http://backend:4000" } },
		);
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(8080);
		expect(config.auth.introspect.url).toBe("http://auth:3000/oauth/introspect");
		expect(config.upstream.baseURL).toBe("http://backend:4000");
	});

	it("loads config with client credentials (both set)", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { CLIENT_ID: "my-proxy", CLIENT_SECRET: "s3cret" } },
		);
		const config = validate(raw, AppConfigSchema);

		expect(config.auth.client.clientId).toBe("my-proxy");
		expect(config.auth.client.clientSecret).toBe("s3cret");
	});

	it("loads config with self-introspect mode (neither set)", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
		);
		const config = validate(raw, AppConfigSchema);

		expect(config.auth.client.clientId).toBeNull();
		expect(config.auth.client.clientSecret).toBeNull();
	});

	it("rejects config when only clientId is set", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { CLIENT_ID: "my-proxy" } },
		);
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("rejects config when only clientSecret is set", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { CLIENT_SECRET: "s3cret" } },
		);
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("treats empty clientId as unset (null)", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { CLIENT_ID: "", CLIENT_SECRET: "" } },
		);
		const config = validate(raw, AppConfigSchema);

		expect(config.auth.client.clientId).toBeNull();
		expect(config.auth.client.clientSecret).toBeNull();
	});

	it("rejects config when only clientId is empty and clientSecret is set", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { CLIENT_ID: "", CLIENT_SECRET: "s3cret" } },
		);
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});
});
