// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * CORS (`cors.mts`) in front of a stand-in for the mode router, which
 * answers `200 reached` with the method it saw. Where it is mounted, under
 * the prefix, is pinned by `__tests__/app-entry.test.mts`.
 */
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createCors } from "../cors.mjs";

const app = (pattern: string | null) =>
	express()
		.use(createCors({ http: { cors: { origin: { pattern } } } }))
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
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
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
