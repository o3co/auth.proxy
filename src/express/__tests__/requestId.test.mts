// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Request-id correlation, moved in from `@o3co/auth.utils/express`.
 *
 * Both proxy modes mount this, and every log line and upstream call is
 * correlated by what it decides, so the header name and the reuse rule are
 * pinned here rather than in a dependency.
 */
import type { Request, RequestHandler, Response } from "express";
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

	it("does not repeat a generated id across requests", () => {
		const middleware = createRequestIdMiddleware();
		const first = run(middleware).req.headers["x-request-id"];
		const second = run(middleware).req.headers["x-request-id"];
		expect(first).not.toBe(second);
	});
});
