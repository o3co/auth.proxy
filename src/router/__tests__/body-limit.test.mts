// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The body limit ahead of a mode's work (`body-limit.mts`), and the error
 * handler that ends a mode router (`error-handler.mts`): a request whose body
 * is over `http.bodyLimitSize` is answered `413` in the refusal shape and
 * logged, and anything else that reaches the end of the router is answered
 * in that shape and logged rather than left to express's HTML page.
 */
import { Readable } from "node:stream";
import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger.mjs";
import { createBodyLimitGuard } from "../body-limit.mjs";
import { createErrorHandler } from "../error-handler.mjs";

const makeLogger = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() });

/** The guard, then a stage that reads the body, then the error handler — a mode router's shape. */
const appWith = (limitBytes: number, logger: Logger, reached: { count: number }) =>
	express()
		.use((req: Request, _res: Response, next: NextFunction) => {
			req.headers["x-request-id"] = "rid-1";
			next();
		})
		.use(createBodyLimitGuard({ limitBytes, logger, mode: "validation" }))
		.use((req: Request, res: Response) => {
			reached.count++;
			req.resume();
			req.on("end", () => res.status(200).json({ ok: true }));
		})
		.use(createErrorHandler({ logger, mode: "validation" }));

describe("createBodyLimitGuard", () => {
	it("answers 413 in the refusal shape to a declared length over the limit, before the next stage", async () => {
		const logger = makeLogger();
		const reached = { count: 0 };

		const res = await request(appWith(1024, logger, reached))
			.post("/x")
			.set("content-type", "application/octet-stream")
			.send(Buffer.alloc(1025));

		expect(res.status).toBe(413);
		expect(res.body).toEqual({ code: 413, message: "Payload Too Large" });
		expect(reached.count).toBe(0);
		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-1", event: "validation.body_too_large", contentLength: 1025, limitBytes: 1024 },
			"request body over the limit",
		);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("passes a declared length at the limit", async () => {
		const logger = makeLogger();
		const reached = { count: 0 };

		const res = await request(appWith(1024, logger, reached))
			.post("/x")
			.set("content-type", "application/octet-stream")
			.send(Buffer.alloc(1024));

		expect(res.status).toBe(200);
		expect(reached.count).toBe(1);
		expect(logger.info).not.toHaveBeenCalled();
	});

	it("passes a request with no declared length: the stage that reads the body enforces it", async () => {
		const logger = makeLogger();
		const reached = { count: 0 };

		const res = await request(appWith(1024, logger, reached)).get("/x");

		expect(res.status).toBe(200);
		expect(reached.count).toBe(1);
	});
});

describe("createErrorHandler", () => {
	const failingApp = (err: unknown, logger: Logger) =>
		express()
			.use((req: Request, _res: Response, next: NextFunction) => {
				req.headers["x-request-id"] = "rid-2";
				next(err);
			})
			.use(createErrorHandler({ logger, mode: "injection" }));

	// What the upstream stage's body reader raises past the limit on a body
	// with no declared length: an http-errors 413.
	it("answers a 413 error as the guard does, and logs it under the same event", async () => {
		const logger = makeLogger();
		const err = Object.assign(new Error("request entity too large"), {
			status: 413,
			type: "entity.too.large",
			limit: 1024,
		});

		const res = await request(failingApp(err, logger)).post("/x");

		expect(res.status).toBe(413);
		expect(res.body).toEqual({ code: 413, message: "Payload Too Large" });
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-2", event: "injection.body_too_large", limitBytes: 1024 },
			"request body over the limit",
		);
	});

	it("answers another 4xx with its own status, logged at info", async () => {
		const logger = makeLogger();
		const err = Object.assign(new Error("request size did not match content length"), { status: 400 });

		const res = await request(failingApp(err, logger)).post("/x");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({ code: 400, message: "Bad Request" });
		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-2", event: "injection.request_failed", error: err },
			"request failed",
		);
		expect(logger.error).not.toHaveBeenCalled();
	});

	// An upstream that refuses the connection reaches here from the upstream
	// stage with no status of its own.
	it.each([
		["an error with no status", Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" })],
		["an error with a status that is not an error status", Object.assign(new Error("odd"), { status: 302 })],
		["a thrown non-Error", "boom"],
	])("answers %s 500, logged at error", async (_label, err) => {
		const logger = makeLogger();

		const res = await request(failingApp(err, logger)).get("/x");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({ code: 500, message: "Internal Server Error" });
		expect(logger.error).toHaveBeenCalledWith(
			{ requestId: "rid-2", event: "injection.request_failed", error: err },
			"request failed",
		);
	});

	it("answers a 5xx error with its own status, logged at error", async () => {
		const logger = makeLogger();
		const err = Object.assign(new Error("unavailable"), { statusCode: 503 });

		const res = await request(failingApp(err, logger)).get("/x");

		expect(res.status).toBe(503);
		expect(res.body).toEqual({ code: 503, message: "Service Unavailable" });
		expect(logger.error).toHaveBeenCalledTimes(1);
	});

	// Once the upstream's answer has started, the status is spent: express
	// closes the connection, and the handler only logs.
	it("leaves a response that has already started to express, and still logs", async () => {
		const logger = makeLogger();
		const err = new Error("upstream stream broke");
		const app = express()
			.use((req: Request, res: Response, next: NextFunction) => {
				req.headers["x-request-id"] = "rid-3";
				res.status(200).setHeader("content-type", "text/plain");
				Readable.from(["partial"]).on("end", () => next(err)).pipe(res, { end: false });
			})
			.use(createErrorHandler({ logger, mode: "validation" }));

		await request(app)
			.get("/x")
			.catch(() => undefined);

		expect(logger.error).toHaveBeenCalledWith(
			{ requestId: "rid-3", event: "validation.request_failed", error: err },
			"request failed",
		);
	});
});
