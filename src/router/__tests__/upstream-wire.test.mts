// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The upstream stage on the wire, through the real express-http-proxy.
 *
 * `upstream.test.mts` pins the options the stage hands to the library; this
 * file pins what the reasons for keeping the decorator rest on: how the body
 * is framed on the way to a real upstream, which fields reach it, and the
 * header name bytes it receives. Node lower-cases every inbound name in
 * `req.headers`, and the library copies `req.headers` onto the outbound
 * request, so without the decorator an upstream would read `authorization`.
 * The names are read from `rawHeaders`, because `req.headers` lower-cases them
 * again on the upstream side and would hide the difference.
 */
import { createServer, type Server } from "node:http";
import { type AddressInfo, connect } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { expectContinue } from "../../__tests__/expect-continue.mjs";
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

	// The stage has the whole body before it sends the request on, so there
	// is nothing to ask the upstream to wait for. Forwarded, the expectation
	// makes Node send the request's headers at once, before the library sets
	// the Content-Length it frames the body by, and the request fails.
	it("sends a body that expected 100-continue on without the expectation", async () => {
		const front = app.listen(0, "127.0.0.1");
		await new Promise<void>((resolve) => front.on("listening", resolve));
		try {
			const { port } = front.address() as AddressInfo;
			const exchange = await expectContinue(
				`http://127.0.0.1:${port}`,
				"POST /upload HTTP/1.1\r\nHost: t\r\nContent-Length: 8\r\nExpect: 100-continue\r\n\r\n",
				Buffer.from("expected"),
			);

			expect(exchange.statusLines).toEqual(["HTTP/1.1 100 Continue", "HTTP/1.1 200 OK"]);
			expect(bodies.map((body) => body.toString("utf8"))).toEqual(["expected"]);
			expect(rawPairs(received[0], "expect")).toEqual([]);
		} finally {
			front.closeAllConnections();
			front.close();
		}
	});

	// The fields for the connection to this proxy stay on it; the credential
	// for this hop is not handed to the next one.
	it("sends none of the hop-by-hop fields or Proxy-Authorization upstream", async () => {
		const res = await request(app)
			.get("/resource")
			.set("Connection", "close, X-Hop")
			.set("X-Hop", "1")
			.set("TE", "trailers")
			.set("Proxy-Authorization", "Basic cHJveHk6cHc=")
			.set("authorization", "Bearer inbound-7f3a");

		expect(res.status).toBe(200);
		for (const name of ["x-hop", "te", "proxy-authorization"]) {
			expect(rawPairs(received[0], name)).toEqual([]);
		}
		expect(rawPairs(received[0], "authorization")).toEqual([["Authorization", "Bearer inbound-7f3a"]]);
	});

	// Naming the proxy's own fields in Connection takes none of them away: the
	// upstream still gets the forwarded Authorization and request id, and a
	// connection the library closes after the one request.
	it("sends Authorization, the request id and Connection: close though the inbound Connection names them", async () => {
		const res = await request(app)
			.get("/resource")
			.set("Connection", "Authorization, X-Request-Id, Connection")
			.set("authorization", "Bearer inbound-7f3a")
			.set("x-request-id", "rid-2c9e");

		expect(res.status).toBe(200);
		expect(rawPairs(received[0], "authorization")).toEqual([["Authorization", "Bearer inbound-7f3a"]]);
		expect(rawPairs(received[0], "x-request-id")).toEqual([["x-request-id", "rid-2c9e"]]);
		expect(rawPairs(received[0], "connection").map(([, value]) => value.toLowerCase())).toEqual(["close"]);
	});
});

/**
 * The upstream's own connection fields, on the way back. The library sends
 * `connection: close` upstream, so a Node upstream answers `Connection: close`;
 * copied onto the caller's response, that field would close the caller's
 * keep-alive connection after every proxied answer.
 */
describe("createUpstreamProxy on the wire, the upstream's answer", () => {
	let upstream: Server;
	let proxyServer: Server;

	beforeEach(async () => {
		upstream = createServer((req, res) => {
			if (req.url === "/hop") {
				res.setHeader("Connection", "X-Up, X-Request-Id");
				res.setHeader("X-Up", "1");
				res.setHeader("Keep-Alive", "timeout=5");
				res.setHeader("Proxy-Connection", "keep-alive");
				res.setHeader("Proxy-Authenticate", 'Basic realm="upstream"');
				res.setHeader("Trailer", "X-Checksum");
				res.setHeader("X-Request-Id", "rid-upstream");
				res.setHeader("X-Kept", "yes");
			}
			res.end(`answer for ${req.url}`);
		});
		await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
		const { port } = upstream.address() as AddressInfo;
		const app = express();
		app.use(
			createUpstreamProxy({
				http: { bodyLimitSize: "1mb" },
				upstream: { baseURL: `http://127.0.0.1:${port}` },
			}),
		);
		proxyServer = createServer(app);
		await new Promise<void>((resolve) => proxyServer.listen(0, "127.0.0.1", resolve));
	});

	afterEach(async () => {
		for (const server of [proxyServer, upstream]) {
			server.closeAllConnections();
			await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
		}
	});

	/** Writes `requests` on one connection and reads until it closes or `settleMs` passes. */
	const exchange = async (requests: string, settleMs = 300): Promise<{ text: string; closed: boolean }> => {
		const { port } = proxyServer.address() as AddressInfo;
		const socket = connect(port, "127.0.0.1");
		let text = "";
		let closed = false;
		socket.on("data", (chunk: Buffer) => {
			text += chunk.toString("latin1");
		});
		socket.on("close", () => {
			closed = true;
		});
		socket.write(requests);
		await new Promise((resolve) => setTimeout(resolve, settleMs));
		socket.destroy();
		return { text, closed };
	};

	const get = (path: string) => `GET ${path} HTTP/1.1\r\nHost: proxy.test\r\n\r\n`;

	it("keeps the caller's connection open after a proxied answer", async () => {
		const { text, closed } = await exchange(get("/plain"));

		expect(text).toMatch(/^HTTP\/1\.1 200/);
		expect(text.toLowerCase()).not.toContain("connection: close");
		expect(closed).toBe(false);
	});

	it("answers both of two pipelined requests on one connection", async () => {
		const { text } = await exchange(get("/k1") + get("/k2"));

		expect(text.match(/HTTP\/1\.1 200/g)).toHaveLength(2);
		expect(text).toContain("answer for /k1");
		expect(text).toContain("answer for /k2");
	});

	it("drops the upstream's hop-by-hop fields and those its Connection names, but not the request id", async () => {
		const { text } = await exchange(get("/hop"));
		const head = text.slice(0, text.indexOf("\r\n\r\n")).toLowerCase();

		expect(head).toMatch(/^http\/1\.1 200/);
		for (const name of ["x-up", "keep-alive: timeout", "proxy-connection", "proxy-authenticate", "trailer"]) {
			expect(head).not.toContain(`\r\n${name}`);
		}
		expect(head).not.toMatch(/\r\nconnection: (?!keep-alive)/);
		expect(head).toContain("\r\nx-kept: yes");
		expect(head).toContain("\r\nx-request-id: rid-upstream");
	});
});
