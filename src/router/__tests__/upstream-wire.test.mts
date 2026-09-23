// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The upstream stage on the wire, through the real express-http-proxy (#132).
 *
 * `upstream.test.mts` pins the options the stage hands to the library; this
 * file pins what the reason for keeping the decorator rests on: the header
 * name bytes an upstream receives. Node lower-cases every inbound name in
 * `req.headers`, and the library copies `req.headers` onto the outbound
 * request, so without the decorator an upstream would read `authorization`.
 * The names are read from `rawHeaders`, because `req.headers` lower-cases them
 * again on the upstream side and would hide the difference.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createUpstreamProxy } from "../upstream.mjs";

/** Every `[name, value]` pair whose name matches `name` case-insensitively, names as sent. */
const rawPairs = (rawHeaders: string[], name: string): [string, string][] =>
	Array.from({ length: rawHeaders.length / 2 }, (_, i): [string, string] => [
		rawHeaders[2 * i],
		rawHeaders[2 * i + 1],
	]).filter(([sent]) => sent.toLowerCase() === name.toLowerCase());

describe("createUpstreamProxy on the wire", () => {
	let upstream: Server;
	let received: string[][];
	let app: express.Express;

	beforeEach(async () => {
		received = [];
		upstream = createServer((req, res) => {
			received.push([...req.rawHeaders]);
			res.end("upstream response");
		});
		await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
		const { port } = upstream.address() as AddressInfo;
		app = express();
		app.use(
			createUpstreamProxy({
				http: { bodyLimitSize: "1mb" },
				upstream: { baseURL: `http://127.0.0.1:${port}` },
			}),
		);
	});

	afterEach(async () => {
		upstream.closeAllConnections();
		await new Promise<void>((resolve, reject) => upstream.close((err) => (err ? reject(err) : resolve())));
	});

	it("sends Authorization upstream once, in canonical casing, though it arrived in lower case", async () => {
		const res = await request(app)
			.get("/resource")
			.set("authorization", "Bearer inbound-7f3a")
			.set("x-request-id", "rid-2c9e");

		expect(res.status).toBe(200);
		expect(received).toHaveLength(1);
		expect(rawPairs(received[0], "authorization")).toEqual([["Authorization", "Bearer inbound-7f3a"]]);
		expect(rawPairs(received[0], "x-request-id")).toEqual([["x-request-id", "rid-2c9e"]]);
	});

	it("sends an empty Authorization upstream once, in canonical casing, as the other paths treat it as present (#132, #133)", async () => {
		const res = await request(app).get("/resource").set("authorization", "");

		expect(res.status).toBe(200);
		expect(received).toHaveLength(1);
		expect(rawPairs(received[0], "Authorization")).toEqual([["Authorization", ""]]);
	});

	it("sends no Authorization upstream when none arrived", async () => {
		const res = await request(app).get("/resource");

		expect(res.status).toBe(200);
		expect(received).toHaveLength(1);
		expect(rawPairs(received[0], "authorization")).toEqual([]);
	});
});
