// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearCache } from "../introspect.mjs";
import { createRouter } from "../router.mjs";

describe("validation rejects credentials before the upstream handler", () => {
	let upstream: Server;
	let upstreamCalls: number;
	let app: express.Express;

	beforeEach(async () => {
		clearCache();
		upstreamCalls = 0;
		upstream = createServer((_req, res) => {
			upstreamCalls++;
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
});
