// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearCache } from "../introspect.mjs";
import { createRouter } from "../router.mjs";

describe("validation router", () => {
	let upstream: Server;
	let upstreamCalls: number;
	let upstreamHeaders: IncomingHttpHeaders[];
	let app: express.Express;

	beforeEach(async () => {
		clearCache();
		upstreamCalls = 0;
		upstreamHeaders = [];
		upstream = createServer((req, res) => {
			upstreamCalls++;
			upstreamHeaders.push({ ...req.headers });
			res.end("protected response");
		});
		await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
		const address = upstream.address() as AddressInfo;
		app = express();
		app.use(createRouter({ config: {
			http: {
				hostname: "127.0.0.1", port: 0, pathPrefix: "/",
				bodyLimitSize: "10mb", cors: { origin: { pattern: null } },
			},
			auth: { mode: "validation", validation: {
				client: { clientId: null, clientSecret: null },
				introspect: { url: "http://provider.test/introspect", cacheTtlSec: 30, cacheMaxEntries: 100, timeoutMs: 5000 },
			} },
			upstream: { baseURL: `http://127.0.0.1:${address.port}` },
		} }));
	});

	afterEach(async () => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
		upstream.closeAllConnections();
		await new Promise<void>((resolve, reject) => upstream.close((err) => err ? reject(err) : resolve()));
	});

	it("forwards a live token, then refuses it when its warm cache reaches exp", async () => {
		const start = 1_700_000_000_000;
		const clock = vi.spyOn(Date, "now").mockReturnValue(start);
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true, exp: start / 1000 + 1 })));
		expect((await request(app).get("/protected").set("Authorization", "Bearer t")).status).toBe(200);
		clock.mockReturnValue(start + 1000);
		expect((await request(app).get("/protected").set("Authorization", "Bearer t")).status).toBe(401);
		expect(upstreamCalls).toBe(1);
	});

	it.each([{ jkt: "key" }, { "x5t#S256": "certificate" }])("refuses bound token %j before forwarding", async (cnf) => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true, cnf })));
		const res = await request(app).get("/protected").set("Authorization", "Bearer t");
		expect(res.status).toBe(401);
		expect(upstreamCalls).toBe(0);
	});

	describe("the router's own mappings", () => {
		it("passes a request without Authorization through to upstream without consulting the provider", async () => {
			const fetchMock = vi.fn();
			vi.stubGlobal("fetch", fetchMock);
			const res = await request(app).get("/protected");
			expect(res.status).toBe(200);
			expect(res.text).toBe("protected response");
			expect(upstreamCalls).toBe(1);
			expect(upstreamHeaders[0].authorization).toBeUndefined();
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("answers 400 Invalid Token Type to a non-Bearer scheme without consulting the provider", async () => {
			const fetchMock = vi.fn();
			vi.stubGlobal("fetch", fetchMock);
			const res = await request(app).get("/protected").set("Authorization", "Basic dXNlcjpwYXNz");
			expect(res.status).toBe(400);
			expect(res.body).toEqual({ code: 400, message: "Invalid Token Type" });
			expect(upstreamCalls).toBe(0);
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("answers 401 Invalid Token when the provider answers 401", async () => {
			const fetchMock = vi.fn(async () => new Response("", { status: 401 }));
			vi.stubGlobal("fetch", fetchMock);
			const res = await request(app).get("/protected").set("Authorization", "Bearer t");
			expect(res.status).toBe(401);
			expect(res.body).toEqual({ code: 401, message: "Invalid Token" });
			expect(upstreamCalls).toBe(0);
			// The mapping was reached through introspection, not around it.
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});

		it.each([
			{ failure: "the provider answers 503 (IntrospectHttpError 503 from the status)", fetchImpl: async () => new Response("", { status: 503 }) },
			{ failure: "the provider answers 200 with a non-JSON body (IntrospectHttpError 502 raised by introspect itself)", fetchImpl: async () => new Response("<html>", { status: 200 }) },
			{ failure: "fetch rejects", fetchImpl: async () => { throw new Error("socket hang up"); } },
		])("answers 500 Internal Server Error when $failure", async ({ fetchImpl }) => {
			const fetchMock = vi.fn(fetchImpl);
			vi.stubGlobal("fetch", fetchMock);
			const res = await request(app).get("/protected").set("Authorization", "Bearer t");
			expect(res.status).toBe(500);
			expect(res.body).toEqual({ code: 500, message: "Internal Server Error" });
			expect(upstreamCalls).toBe(0);
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});
	});
});
