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
		expect(config.introspect.cacheTtlSec).toBe(30);
		expect(config.endpoint.baseURL).toBe("http://localhost:3000");
	});

	it("overrides with env vars", () => {
		const raw = parseFile(
			new URL("../../config/application.conf", import.meta.url).pathname,
			{ env: { HTTP_PORT: "8080", INTROSPECT_URL: "http://auth:3000/oauth/introspect" } },
		);
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(8080);
		expect(config.introspect.url).toBe("http://auth:3000/oauth/introspect");
	});
});
