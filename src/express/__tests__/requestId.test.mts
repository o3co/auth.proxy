// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Request-id correlation (`requestId.mts`).
 *
 * Both proxy modes mount this, and every log line and upstream call is
 * correlated by what it decides, so the header name and the reuse rule are
 * pinned here rather than in a dependency.
 */
import { once } from "node:events";
import { request as httpRequest, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import type { Request, RequestHandler, Response } from "express";
import express from "express";
import { describe, expect, it, vi } from "vitest";
import { createRequestIdMiddleware } from "../requestId.mjs";

function run(middleware: RequestHandler, headers: Record<string, string> = {}) {
	const req = { headers } as unknown as Request;
	const setHeader = vi.fn();
	const res = { setHeader } as unknown as Response;
	const next = vi.fn();
	middleware(req, res, next);
	return { req, setHeader, next };
}

describe("createRequestIdMiddleware", () => {
	it("generates an id when the request carries none", () => {
		const { req, setHeader, next } = run(
			createRequestIdMiddleware({ generator: () => "generated-id" }),
		);
		expect(req.headers["x-request-id"]).toBe("generated-id");
		expect(setHeader).toHaveBeenCalledWith("x-request-id", "generated-id");
		expect(next).toHaveBeenCalledOnce();
	});

	it("reuses an inbound id rather than replacing it", () => {
		const { req, setHeader } = run(
			createRequestIdMiddleware({ generator: () => "generated-id" }),
			{ "x-request-id": "caller-id" },
		);
		expect(req.headers["x-request-id"]).toBe("caller-id");
		expect(setHeader).toHaveBeenCalledWith("x-request-id", "caller-id");
	});

	it("echoes the id onto the response so a caller can correlate its own request", () => {
		const { setHeader } = run(createRequestIdMiddleware({ generator: () => "abc" }));
		expect(setHeader).toHaveBeenCalledWith("x-request-id", "abc");
	});

	it("honours a custom header name, lowercased to match Node's header keys", () => {
		const { req, setHeader } = run(
			createRequestIdMiddleware({ header: "X-Correlation-Id", generator: () => "abc" }),
		);
		expect(req.headers["x-correlation-id"]).toBe("abc");
		expect(setHeader).toHaveBeenCalledWith("x-correlation-id", "abc");
	});

	it("calls next exactly once even when it reuses an inbound id", () => {
		const { next } = run(createRequestIdMiddleware(), { "x-request-id": "caller-id" });
		expect(next).toHaveBeenCalledOnce();
	});

	it("defaults to an id that sorts by time and carries uuid entropy", () => {
		const { req } = run(createRequestIdMiddleware());
		expect(req.headers["x-request-id"]).toMatch(/^\d{14}_[0-9a-f]{32}$/);
	});

	it("takes the first value when the header arrives duplicated", () => {
		// Node types this `string | string[]`, and an upstream that sets the
		// header twice produces the array. Casting it to `string` let an array
		// reach `res.setHeader` and every log field built from it.
		const req = { headers: { "x-request-id": ["first-id", "second-id"] } } as unknown as Request;
		const setHeader = vi.fn();
		createRequestIdMiddleware()(req, { setHeader } as unknown as Response, vi.fn());
		expect(req.headers["x-request-id"]).toBe("first-id");
		expect(setHeader).toHaveBeenCalledWith("x-request-id", "first-id");
	});

	it("generates an id when the inbound header is present but empty", () => {
		// An empty correlation id is indistinguishable from none, and echoing it
		// back gives the caller nothing to correlate on.
		const { req } = run(createRequestIdMiddleware({ generator: () => "generated-id" }), {
			"x-request-id": "",
		});
		expect(req.headers["x-request-id"]).toBe("generated-id");
	});

	it("does not repeat a generated id across requests", () => {
		const middleware = createRequestIdMiddleware();
		const first = run(middleware).req.headers["x-request-id"];
		const second = run(middleware).req.headers["x-request-id"];
		expect(first).not.toBe(second);
	});

	describe("an inbound id is reused only within bounds", () => {
		const fresh = () => createRequestIdMiddleware({ generator: () => "generated-id" });

		it.each([
			["a UUID", "3f2b8c1e-9a4d-4e7b-8f21-6c0d5e9a1b2c"],
			["this proxy's own form", "20261021120000_0123456789abcdef0123456789abcdef"],
			["a ULID", "01HZX3Q8V9K2M4N6P7R8S9T0VW"],
			["base64 with padding", "dGhpcyBpcyBhbiBpZA=="],
			["base64url", "a-b_c.d~e"],
			["one character", "x"],
			["200 characters", "a".repeat(200)],
		])("reuses %s", (_label, id) => {
			const { req, setHeader } = run(fresh(), { "x-request-id": id });
			expect(req.headers["x-request-id"]).toBe(id);
			expect(setHeader).toHaveBeenCalledWith("x-request-id", id);
		});

		it.each([
			["201 characters", "a".repeat(201)],
			["kilobytes", "a".repeat(8192)],
			["a space", "abc def"],
			["a tab", "abc\tdef"],
			["a line break", "abc\ndef"],
			["a control character", "abc\u0001def"],
			["DEL", "abc\u007fdef"],
			["a non-ASCII character", "abcédef"],
			["a double quote", 'abc"def'],
			["a backslash", "abc\\def"],
			["a comma", "abc,def"],
			["a semicolon", "abc;def"],
			["a brace", '{"a":1}'],
			["a percent sign", "abc%0adef"],
		])("mints a fresh id in place of one with %s", (_label, id) => {
			const { req, setHeader } = run(fresh(), { "x-request-id": id });
			expect(req.headers["x-request-id"]).toBe("generated-id");
			expect(setHeader).toHaveBeenCalledWith("x-request-id", "generated-id");
		});

		it("bounds the first of a duplicated header too", () => {
			const req = { headers: { "x-request-id": ["a b", "ok-id"] } } as unknown as Request;
			createRequestIdMiddleware({ generator: () => "generated-id" })(
				req,
				{ setHeader: vi.fn() } as unknown as Response,
				vi.fn(),
			);
			expect(req.headers["x-request-id"]).toBe("generated-id");
		});

		// Node joins two `x-request-id` field lines with ", ", which is outside
		// the charset: two ids are not one, so neither is reused.
		it("mints a fresh id for two header lines on the wire", async () => {
			const app = express();
			app.use(createRequestIdMiddleware({ generator: () => "generated-id" }));
			app.use((req, res) => {
				res.end(String(req.headers["x-request-id"]));
			});
			const server = app.listen(0, "127.0.0.1");
			await once(server, "listening");
			try {
				const req = httpRequest({
					host: "127.0.0.1",
					port: (server.address() as AddressInfo).port,
					path: "/",
					headers: { "x-request-id": ["first-id", "second-id"] },
				});
				req.end();
				const [res] = (await once(req, "response")) as [IncomingMessage];
				let body = "";
				res.setEncoding("utf8");
				res.on("data", (chunk: string) => {
					body += chunk;
				});
				await once(res, "end");

				expect(body).toBe("generated-id");
				expect(res.headers["x-request-id"]).toBe("generated-id");
			} finally {
				server.close();
			}
		});
	});
});
