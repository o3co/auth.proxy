// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The upstream stage on the wire, through the real express-http-proxy.
 *
 * `upstream.test.mts` pins the options the stage hands to the library; this
 * file pins what the reasons for keeping the decorator rest on: how the body
 * is framed on the way to a real upstream, and the header name bytes it
 * receives. Node lower-cases every inbound name in
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
import { postChunked } from "../../__tests__/post-chunked.mjs";
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
	let bodies: Buffer[];
	let app: express.Express;

	beforeEach(async () => {
		received = [];
		bodies = [];
		// A plain node:http server: its parser refuses a request framed by both
		// Transfer-Encoding and Content-Length, as a strict upstream does, before
		// this handler runs.
		upstream = createServer((req, res) => {
			received.push([...req.rawHeaders]);
			const parts: Buffer[] = [];
			req.on("data", (part: Buffer) => parts.push(part));
			req.on("end", () => {
				bodies.push(Buffer.concat(parts));
				res.end("upstream response");
			});
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

	it("sends an empty Authorization upstream once, in canonical casing, as the other paths treat it as present", async () => {
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

	// The stage reads the whole body before it sends it on, and the library
	// frames what it sends by Content-Length; the inbound Transfer-Encoding
	// described the inbound message only, so it is not sent on.
	describe("a body that arrived chunked", () => {
		it("reaches the upstream intact, framed by Content-Length alone", async () => {
			const res = await postChunked(app, "/upload", {}, [Buffer.from("hello, "), Buffer.from("world")]);

			expect(res.status).toBe(200);
			expect(bodies.map((body) => body.toString("utf8"))).toEqual(["hello, world"]);
			expect(rawPairs(received[0], "transfer-encoding")).toEqual([]);
			expect(rawPairs(received[0], "content-length").map(([, value]) => value)).toEqual(["12"]);
		});

		it("reaches the upstream as an empty body when it had no chunks", async () => {
			const res = await postChunked(app, "/upload", {}, []);

			expect(res.status).toBe(200);
			expect(bodies.map((body) => body.length)).toEqual([0]);
			expect(rawPairs(received[0], "transfer-encoding")).toEqual([]);
			expect(rawPairs(received[0], "content-length").map(([, value]) => value)).toEqual(["0"]);
		});

		// `Trailer` announces fields of the chunked framing the stage has taken
		// off; left on a request framed by Content-Length, Node refuses to send it.
		it("reaches the upstream without the Trailer it announced", async () => {
			const res = await postChunked(app, "/upload", { Trailer: "X-Sum" }, [Buffer.from("summed")]);

			expect(res.status).toBe(200);
			expect(bodies.map((body) => body.toString("utf8"))).toEqual(["summed"]);
			expect(rawPairs(received[0], "trailer")).toEqual([]);
		});

		// Node removes the chunked framing and hands on the rest still coded;
		// the stage cannot say how, so it refuses rather than forward the coded
		// bytes as if they were the body.
		it("is refused 501, and nothing reaches the upstream, when it carries another transfer coding", async () => {
			const res = await postChunked(app, "/upload", { "transfer-encoding": "gzip, chunked" }, [
				Buffer.from("not really gzip"),
			]);

			expect(res.status).toBe(501);
			expect(received).toEqual([]);
		});
	});

	it("sends a body that declared its length on unchanged", async () => {
		const res = await request(app)
			.post("/upload")
			.set("content-type", "application/octet-stream")
			.send(Buffer.from("declared"));

		expect(res.status).toBe(200);
		expect(bodies.map((body) => body.toString("utf8"))).toEqual(["declared"]);
		expect(rawPairs(received[0], "content-length").map(([, value]) => value)).toEqual(["8"]);
	});
});
