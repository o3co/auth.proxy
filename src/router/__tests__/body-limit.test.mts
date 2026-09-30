// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
/**
 * The body limit ahead of a mode (`body-limit.mts`), and the error handler
 * that ends a mode router (`error-handler.mts`): a request whose body is over
 * `http.bodyLimitSize` is refused `413`, and anything else that reaches the
 * end of the router is refused with its own status or `500` rather than left
 * to express's HTML page. What each refusal is — its reason and status — is
 * the stages'; how it is logged and what body answers it are the mode's
 * (`ModeRefusals`), so a double stands in for the mode here.
 */
import { Readable } from "node:stream";
import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { expectContinue } from "../../__tests__/expect-continue.mjs";
import { continueWithinLimit, createBodyLimitGuard } from "../body-limit.mjs";
import { createErrorHandler } from "../error-handler.mjs";
import type { ModeRefusals, StageRefusal } from "../refusal.mjs";

/** A mode that records what it was told and answers with what it was told. */
const recordingMode = () => {
	const logged: [unknown, StageRefusal][] = [];
	const refusals: ModeRefusals = {
		log: (requestId, refusal) => {
			logged.push([requestId, refusal]);
		},
		body: (refusal) => ({ reason: refusal.reason, status: refusal.status }),
	};
	return { logged, refusals };
};

/** The guard, then a stage that reads the body, then the error handler — a mode router's shape. */
const appWith = (limitBytes: number, refusals: ModeRefusals, reached: { count: number }) =>
	express()
		.use((req: Request, _res: Response, next: NextFunction) => {
			req.headers["x-request-id"] = "rid-1";
			next();
		})
		.use(createBodyLimitGuard({ limitBytes, refusals }))
		.use((req: Request, res: Response) => {
			reached.count++;
			req.resume();
			req.on("end", () => res.status(200).json({ ok: true }));
		})
		.use(createErrorHandler({ limitBytes, refusals }));

describe("createBodyLimitGuard", () => {
	it("refuses a declared length over the limit 413 with the mode's body, before the next stage", async () => {
		const { logged, refusals } = recordingMode();
		const reached = { count: 0 };

		const res = await request(appWith(1024, refusals, reached))
			.post("/x")
			.set("content-type", "application/octet-stream")
			.send(Buffer.alloc(1025));

		expect(res.status).toBe(413);
		expect(res.body).toEqual({ reason: "body_too_large", status: 413 });
		expect(reached.count).toBe(0);
		expect(logged).toEqual([
			["rid-1", { reason: "body_too_large", status: 413, limitBytes: 1024, contentLength: 1025 }],
		]);
	});

	it("passes a declared length at the limit", async () => {
		const { logged, refusals } = recordingMode();
		const reached = { count: 0 };

		const res = await request(appWith(1024, refusals, reached))
			.post("/x")
			.set("content-type", "application/octet-stream")
			.send(Buffer.alloc(1024));

		expect(res.status).toBe(200);
		expect(reached.count).toBe(1);
		expect(logged).toEqual([]);
	});

	it("passes a request with no declared length: the stage that reads the body enforces it", async () => {
		const { refusals } = recordingMode();
		const reached = { count: 0 };

		const res = await request(appWith(1024, refusals, reached)).get("/x");

		expect(res.status).toBe(200);
		expect(reached.count).toBe(1);
	});
});

describe("createErrorHandler", () => {
	const failingApp = (err: unknown, refusals: ModeRefusals) =>
		express()
			.use((req: Request, _res: Response, next: NextFunction) => {
				req.headers["x-request-id"] = "rid-2";
				next(err);
			})
			.use(createErrorHandler({ limitBytes: 1024, refusals }));

	// What the upstream stage's body reader raises past the limit on a body
	// with no declared length: an http-errors 413.
	it("refuses a 413 error as the guard does, with the configured limit", async () => {
		const { logged, refusals } = recordingMode();
		const err = Object.assign(new Error("request entity too large"), {
			status: 413,
			type: "entity.too.large",
		});

		const res = await request(failingApp(err, refusals)).post("/x");

		expect(res.status).toBe(413);
		expect(res.body).toEqual({ reason: "body_too_large", status: 413 });
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(logged).toEqual([["rid-2", { reason: "body_too_large", status: 413, limitBytes: 1024 }]]);
	});

	it("refuses another 4xx with its own status", async () => {
		const { logged, refusals } = recordingMode();
		const err = Object.assign(new Error("request size did not match content length"), { status: 400 });

		const res = await request(failingApp(err, refusals)).post("/x");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({ reason: "request_failed", status: 400 });
		expect(logged).toEqual([["rid-2", { reason: "request_failed", status: 400, error: err }]]);
	});

	// An upstream that refuses the connection reaches here from the upstream
	// stage with no status of its own.
	it.each([
		["an error with no status", Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" })],
		["an error whose status is not an error status", Object.assign(new Error("odd"), { status: 302 })],
		["a thrown non-Error", "boom"],
	])("refuses %s 500", async (_label, err) => {
		const { logged, refusals } = recordingMode();

		const res = await request(failingApp(err, refusals)).get("/x");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({ reason: "request_failed", status: 500 });
		expect(logged).toEqual([["rid-2", { reason: "request_failed", status: 500, error: err }]]);
	});

	// The order express's own handler reads them in: `status` when it is an
	// error status, then `statusCode`.
	it.each([
		["statusCode alone", { statusCode: 503 }, 503],
		["status over statusCode", { status: 502, statusCode: 503 }, 502],
		["statusCode when status is not an error status", { status: 302, statusCode: 503 }, 503],
	])("reads the status from %s", async (_label, fields, status) => {
		const { refusals } = recordingMode();

		const res = await request(failingApp(Object.assign(new Error("x"), fields), refusals)).get("/x");

		expect(res.status).toBe(status);
	});

	// Once the upstream's answer has started, its status is spent: the handler
	// logs the failure and closes the connection, as express would, without
	// handing the error on to express's stderr stack trace.
	it("logs a failure after the answer has started and closes the connection, handing nothing on", async () => {
		const { logged, refusals } = recordingMode();
		const err = new Error("upstream stream broke");
		let handedOn = false;
		const app = express()
			.use((req: Request, res: Response, next: NextFunction) => {
				req.headers["x-request-id"] = "rid-3";
				res.status(200).setHeader("content-type", "text/plain");
				Readable.from(["partial"])
					.on("end", () => next(err))
					.pipe(res, { end: false });
			})
			.use(createErrorHandler({ limitBytes: 1024, refusals }))
			.use((_err: unknown, _req: Request, _res: Response, _next: NextFunction) => {
				handedOn = true;
			});

		const outcome = await request(app)
			.get("/x")
			.then(
				() => "answered",
				() => "closed",
			);

		expect(outcome).toBe("closed");
		expect(handedOn).toBe(false);
		expect(logged).toEqual([["rid-3", { reason: "request_failed", status: 500, error: err }]]);
	});
});

// Node answers `Expect: 100-continue` itself unless the server installs a
// `checkContinue` listener; without one, an oversized upload is told to go
// ahead and is sent in full before the guard refuses it.
describe("continueWithinLimit", () => {
	const serverWith = async (limitBytes: number) => {
		const { refusals } = recordingMode();
		const handle = appWith(limitBytes, refusals, { count: 0 });
		const server = createServer();
		server.on("request", handle);
		server.on("checkContinue", continueWithinLimit(limitBytes, handle));
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as AddressInfo;
		return { origin: `http://127.0.0.1:${port}`, server };
	};
	const head = (length: number) =>
		`POST /x HTTP/1.1\r\nHost: t\r\nContent-Type: application/octet-stream\r\nContent-Length: ${length}\r\nExpect: 100-continue\r\n\r\n`;

	it("refuses a declared length over the limit without saying 100 Continue, so the body is never sent", async () => {
		const { origin, server } = await serverWith(1024);
		try {
			const exchange = await expectContinue(origin, head(4096), Buffer.alloc(4096));

			expect(exchange.statusLines).toEqual(["HTTP/1.1 413 Payload Too Large"]);
			expect(exchange.bodySent).toBe(false);
			expect(JSON.parse(exchange.body)).toEqual({ reason: "body_too_large", status: 413 });
		} finally {
			server.closeAllConnections();
			server.close();
		}
	});

	it("says 100 Continue to a declared length within the limit, then answers the request", async () => {
		const { origin, server } = await serverWith(1024);
		try {
			const exchange = await expectContinue(origin, head(5), Buffer.from("hello"));

			expect(exchange.statusLines).toEqual(["HTTP/1.1 100 Continue", "HTTP/1.1 200 OK"]);
			expect(exchange.bodySent).toBe(true);
			expect(JSON.parse(exchange.body)).toEqual({ ok: true });
		} finally {
			server.closeAllConnections();
			server.close();
		}
	});
});
