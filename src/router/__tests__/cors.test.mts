// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * CORS (`cors.mts`) in front of a stand-in for the mode router, which
 * answers `200 reached` with the method it saw. Where it is mounted, under
 * the prefix, is pinned by `__tests__/app-entry.test.mts`.
 */
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger.mjs";
import { createCors } from "../cors.mjs";

/** A logger that records what it is given and writes nothing. */
const recordingLogger = () => {
	const warn = vi.fn<Logger["warn"]>();
	const logger: Logger = { info: vi.fn(), warn, error: vi.fn(), debug: vi.fn() };
	return { logger, warn };
};

const app = (pattern: string | null) =>
	express()
		.use(createCors({ http: { cors: { origin: { pattern } } } }, { logger: recordingLogger().logger }))
		.use((req, res) => {
			res.status(200).send(`reached by ${req.method}`);
		});

const PATTERN = "^https://app\\.example$";

/** The names of the `Access-Control-*` fields an answer carries. */
const accessControlFields = (headers: Record<string, unknown>): string[] =>
	Object.keys(headers).filter((name) => name.startsWith("access-control-"));

describe("createCors", () => {
	describe("with a pattern", () => {
		it("answers a preflight 204 itself, granting an admitted origin with credentials", async () => {
			const res = await request(app(PATTERN))
				.options("/resource")
				.set("Origin", "https://app.example")
				.set("Access-Control-Request-Method", "PUT");

			expect(res.status).toBe(204);
			expect(res.headers["access-control-allow-origin"]).toBe("https://app.example");
			expect(res.headers["access-control-allow-credentials"]).toBe("true");
			expect(res.text).toBe("");
			// What lets a non-preflight OPTIONS go on without CORS fields: no
			// browser can send one cross-origin.
			expect(res.headers["access-control-allow-methods"].split(",")).not.toContain("OPTIONS");
		});

		it("answers a preflight from an origin the pattern does not admit 204, with no Access-Control-* field", async () => {
			const res = await request(app(PATTERN))
				.options("/resource")
				.set("Origin", "https://evil.example")
				.set("Access-Control-Request-Method", "PUT")
				.set("Access-Control-Request-Headers", "authorization");

			expect(res.status).toBe(204);
			expect(res.text).toBe("");
			expect(accessControlFields(res.headers)).toEqual([]);
			expect(res.headers.vary).toBe("Origin");
		});

		it.each([
			["from an origin the pattern does not admit", { Origin: "https://evil.example" }],
			["without Origin", {}],
		])("sends no Access-Control-* field on a request %s, varies by Origin, and passes it on", async (_label, headers) => {
			const res = await request(app(PATTERN)).put("/resource").set(headers);

			expect(res.status).toBe(200);
			expect(res.text).toBe("reached by PUT");
			expect(accessControlFields(res.headers)).toEqual([]);
			expect(res.headers.vary).toBe("Origin");
		});

		it.each([
			["without Origin", {}],
			["with Origin only", { Origin: "https://app.example" }],
			["with Access-Control-Request-Method only", { "Access-Control-Request-Method": "PUT" }],
		])("passes an OPTIONS %s on, without CORS fields", async (_label, headers) => {
			const res = await request(app(PATTERN)).options("/resource").set(headers);

			expect(res.status).toBe(200);
			expect(res.text).toBe("reached by OPTIONS");
			expect(accessControlFields(res.headers)).toEqual([]);
			expect(res.headers.vary).toBeUndefined();
		});

		it("grants an admitted origin on any other method, varies by Origin, and passes the request on", async () => {
			const res = await request(app(PATTERN)).put("/resource").set("Origin", "https://app.example");

			expect(res.status).toBe(200);
			expect(res.text).toBe("reached by PUT");
			expect(res.headers["access-control-allow-origin"]).toBe("https://app.example");
			expect(res.headers["access-control-allow-credentials"]).toBe("true");
			expect(res.headers.vary).toBe("Origin");
		});
	});

	// `cors` would test the pattern against the text "undefined" for a request
	// without Origin, which a pattern this loose matches.
	it("grants a request without Origin nothing, under a pattern that matches anything", async () => {
		const res = await request(app(".*")).put("/resource");

		expect(res.status).toBe(200);
		expect(accessControlFields(res.headers)).toEqual([]);
		expect(res.headers.vary).toBe("Origin");
	});

	// `CORS_ORIGIN_PATTERN` unset leaves the pattern null; set empty, it is "".
	it.each([[null], [""]])("with the pattern %j, does no CORS: a preflight is passed on", async (pattern) => {
		const res = await request(app(pattern))
			.options("/resource")
			.set("Origin", "https://app.example")
			.set("Access-Control-Request-Method", "PUT");

		expect(res.status).toBe(200);
		expect(res.text).toBe("reached by OPTIONS");
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
	});
});

// Said once, when CORS is built at boot, and never refused: a pattern is the
// only gate on a credentialed cross-origin read, and these are the ways one
// commonly admits more than its author meant. A syntactic check cannot be
// complete, so it warns rather than stopping a deployment that may be right.
describe("createCors warns at boot about a pattern that likely admits too much", () => {
	const warningsFor = (pattern: string | null): unknown[] => {
		const { logger, warn } = recordingLogger();
		createCors({ http: { cors: { origin: { pattern } } } }, { logger });
		return warn.mock.calls.map((call) => (typeof call[0] === "object" ? call[0].event : call[0]));
	};

	it.each([
		"^https://app\\.example\\.com$",
		"^https://(app|admin)\\.example\\.com$",
		"^https://app\\.example\\.com$|^https://admin\\.example\\.com$",
		"^https://[a-z0-9-]+\\.example\\.com$",
		"^https://.+\\.example\\.com$",
		"^https://[.a-z]+\\.example$",
		"^https://app\\.example\\\\$",
	])("says nothing about %j", (pattern) => {
		expect(warningsFor(pattern)).toEqual([]);
	});

	it.each([[null], [""]])("says nothing without a pattern (%j)", (pattern) => {
		expect(warningsFor(pattern)).toEqual([]);
	});

	// Unanchored, `https://app\.example\.com` also admits
	// `https://app.example.com.evil.net` and `https://evil.net/https://app.example.com`.
	it.each([
		"https://app\\.example\\.com",
		"^https://app\\.example\\.com",
		"https://app\\.example\\.com$",
		"^https://a\\.example$|https://b\\.example",
		"^https://app\\.example\\$",
		"^https://app\\.example[$]",
	])("warns that %j is not anchored on every alternative", (pattern) => {
		expect(warningsFor(pattern)).toContain("cors.origin_pattern_unanchored");
	});

	// `null` is what a sandboxed iframe, a `data:` document or a redirected
	// request sends, from any site.
	it("warns about a pattern that admits the origin null", () => {
		expect(warningsFor("^null$")).toEqual(["cors.origin_pattern_admits_null"]);
	});

	it.each(["^https://.*$", "^https?://[^/]+$"])("warns that %j admits an origin no deployment serves", (pattern) => {
		expect(warningsFor(pattern)).toEqual(["cors.origin_pattern_admits_foreign_origin"]);
	});

	it("warns about every concern a pattern has", () => {
		expect(warningsFor(".*")).toEqual([
			"cors.origin_pattern_unanchored",
			"cors.origin_pattern_admits_null",
			"cors.origin_pattern_admits_foreign_origin",
		]);
	});

	// `^https://app.example.com$` also admits `https://appxexample.com`, a
	// name anyone can register.
	it.each(["^https://app.example\\.com$", "^https://10.0.0.1$"])(
		"warns that %j has a dot that matches any character where a host name's dot was meant",
		(pattern) => {
			expect(warningsFor(pattern)).toEqual(["cors.origin_pattern_unescaped_dot"]);
		},
	);

	it("names the key and the pattern in the warning", () => {
		const { logger, warn } = recordingLogger();
		createCors({ http: { cors: { origin: { pattern: "https://app\\.example" } } } }, { logger });
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ event: "cors.origin_pattern_unanchored", pattern: "https://app\\.example" }),
			expect.stringMatching(/^http\.cors\.origin\.pattern /),
		);
	});
});
