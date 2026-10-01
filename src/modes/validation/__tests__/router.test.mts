// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { once } from "node:events";
import { createServer, request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type Server } from "node:http";
import { type AddressInfo, connect, createServer as createNetServer } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import { postChunked } from "../../../__tests__/post-chunked.mjs";
import type { Logger } from "../../../logger.mjs";
import logger from "../../../logger.mjs";
import { createRouter } from "../router.mjs";

const makeConfig = (
	upstreamPort: number,
	client: { clientId: string | null; clientSecret: string | null } = {
		clientId: null,
		clientSecret: null,
	},
	realm: string | null = null,
): AppConfig => ({
	http: {
		hostname: "127.0.0.1", port: 0, pathPrefix: "/",
		bodyLimitSize: "10mb", cors: { origin: { pattern: null } },
	},
	auth: { mode: "validation", validation: {
		client: { ...client, clientKey: null },
		providerIssuer: null,
		realm,
		introspect: { url: "http://provider.test/introspect", cacheTtlSec: 30, cacheMaxEntries: 100, timeoutMs: 5000 },
	} },
	upstream: { baseURL: `http://127.0.0.1:${upstreamPort}` },
});

/** A raw request, so the socket can be destroyed the way a client leaving does. */
const httpGet = (port: number, token: string) => {
	const req = httpRequest(
		{ host: "127.0.0.1", port, path: "/protected", headers: { Authorization: `Bearer ${token}` } },
		() => {},
	);
	// Resolves with the reset rather than rejecting: destroying the socket is
	// the point of the caller that goes away, and an unhandled rejection would
	// fail the run for the thing under test.
	const done = new Promise<{ status: number | null }>((resolve) => {
		req.on("response", (res) => {
			res.resume();
			res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
		});
		req.on("error", () => resolve({ status: null }));
	});
	req.end();
	return { destroy: () => req.destroy(), done };
};

describe("validation router", () => {
	let upstream: Server;
	let upstreamCalls: number;
	let upstreamHeaders: IncomingHttpHeaders[];
	let app: express.Express;
	let upstreamPort: number;

	beforeEach(async () => {
		upstreamCalls = 0;
		upstreamHeaders = [];
		upstream = createServer((req, res) => {
			upstreamCalls++;
			upstreamHeaders.push({ ...req.headers });
			res.end("protected response");
		});
		await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
		upstreamPort = (upstream.address() as AddressInfo).port;
		app = express();
		app.use(createRouter({ config: makeConfig(upstreamPort) }));
	});

	afterEach(async () => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
		upstream.closeAllConnections();
		await new Promise<void>((resolve, reject) => upstream.close((err) => err ? reject(err) : resolve()));
	});

	// The only cancellation is the provider timeout: no client takes a caller's
	// signal, so a disconnect cannot abort a flight other waiters share. Proven
	// rather than asserted about the code: the caller that disconnects is the
	// one that started the flight.
	it("a disconnect does not abort the flight its waiters share, and the answer is still cached", async () => {
		let releaseProvider!: () => void;
		let announceAsked!: () => void;
		const providerAsked = new Promise<void>((resolve) => {
			announceAsked = resolve;
		});
		const answered = new Promise<Response>((resolve) => {
			releaseProvider = () => resolve(Response.json({ active: true }));
		});
		// The mock honours init.signal, so this test can tell the difference it
		// claims to: if anything ever wired a caller's disconnect to the
		// outbound call, the flight would reject here instead of answering.
		const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
			announceAsked();
			return await Promise.race([
				answered,
				new Promise<never>((_, reject) => {
					init?.signal?.addEventListener("abort", () =>
						reject(new DOMException("The operation was aborted", "AbortError")),
					);
				}),
			]);
		});
		vi.stubGlobal("fetch", fetchMock);

		const server = app.listen(0, "127.0.0.1");
		await once(server, "listening");
		const port = (server.address() as AddressInfo).port;
		// A causal join signal instead of a sleep. Express is the server's first
		// "request" listener, and nothing between it and the flight awaits —
		// the cache read and SingleFlight.run's table check are synchronous — so
		// by the time this later listener sees the second request, the waiter
		// has joined the leader's flight.
		let arrived = 0;
		let waiterJoined!: () => void;
		const joined = new Promise<void>((resolve) => {
			waiterJoined = resolve;
		});
		server.on("request", () => {
			arrived += 1;
			if (arrived === 2) waiterJoined();
		});
		try {
			// The leader, which goes away mid-flight.
			const leader = httpGet(port, "one-token");
			await providerAsked;
			leader.destroy();
			expect(await leader.done).toEqual({ status: null });

			// A waiter that arrives while the flight is still open. Asserted to be
			// still waiting at the release, too: a waiter served from the cache
			// instead would satisfy every other assertion in this test.
			const waiter = httpGet(port, "one-token");
			let waiterSettled = false;
			void waiter.done.then(() => {
				waiterSettled = true;
			});
			await joined;
			await new Promise((r) => setImmediate(r));
			expect(waiterSettled).toBe(false);
			releaseProvider();

			expect((await waiter.done).status).toBe(200);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			// And the entry the abandoned flight produced is in the cache.
			const later = httpGet(port, "one-token");
			expect((await later.done).status).toBe(200);
			expect(fetchMock).toHaveBeenCalledTimes(1);
		} finally {
			server.closeAllConnections();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});

	it("forwards a live token, then refuses it when its warm cache reaches exp", async () => {
		const start = 1_700_000_000_000;
		const clock = vi.spyOn(Date, "now").mockReturnValue(start);
		const fetchMock = vi.fn(async () => Response.json({ active: true, exp: start / 1000 + 1 }));
		vi.stubGlobal("fetch", fetchMock);
		expect((await request(app).get("/protected").set("Authorization", "Bearer t")).status).toBe(200);
		// The inbound bytes reach the upstream on the production path too.
		expect(upstreamHeaders[0].authorization).toBe("Bearer t");
		clock.mockReturnValue(start + 1000);
		expect((await request(app).get("/protected").set("Authorization", "Bearer t")).status).toBe(401);
		expect(upstreamCalls).toBe(1);
		// The entry stops being served the instant it reaches `exp` (`expiresAt > now`,
		// not `>=`), so the second request misses and re-fetches; `introspect` then
		// refuses the response whose `exp` has passed. Two calls, one forward.
		expect(fetchMock).toHaveBeenCalledTimes(2);
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
			// Asserted by name rather than left implicit: RFC 6750 §3.1 keeps an
			// error code off a request that attempted an unsupported method, and
			// the challenge that would fit needs a realm, and this app configures
			// none.
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(upstreamCalls).toBe(0);
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("challenges with the configured realm, and names invalid_request on a malformed Bearer", async () => {
			const fetchMock = vi.fn();
			vi.stubGlobal("fetch", fetchMock);
			const own = express();
			own.use(createRouter({ config: makeConfig(upstreamPort, undefined, "orders api") }));

			const basic = await request(own).get("/protected").set("Authorization", "Basic dXNlcjpwYXNz");
			const malformed = await request(own).get("/protected").set("Authorization", "Bearer");

			expect(basic.status).toBe(400);
			expect(basic.headers["www-authenticate"]).toBe('Bearer realm="orders api"');
			expect(malformed.status).toBe(400);
			expect(malformed.headers["www-authenticate"]).toBe(
				'Bearer realm="orders api", error="invalid_request"',
			);
			expect(upstreamCalls).toBe(0);
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("answers 401 Invalid Token when the provider answers 401", async () => {
			const fetchMock = vi.fn(async () => new Response("", { status: 401 }));
			vi.stubGlobal("fetch", fetchMock);
			const res = await request(app).get("/protected").set("Authorization", "Bearer t");
			expect(res.status).toBe(401);
			expect(res.body).toEqual({ code: 401, message: "Invalid Token" });
			// RFC 6750 §3, on the wire.
			expect(res.headers["www-authenticate"]).toBe('Bearer error="invalid_token"');
			expect(upstreamCalls).toBe(0);
			// The mapping was reached through introspection, not around it.
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});

		// The same provider answer, read differently because the request carried
		// a different credential. With client credentials configured
		// the proxy authenticated as itself, so the 401 refused the proxy and
		// the caller's token was never examined.
		it("answers 502 Provider Configuration Error to a provider 401 when client credentials are configured", async () => {
			const configured = makeConfig(upstreamPort, {
				clientId: "my-proxy",
				clientSecret: "s3cret",
			});
			const configuredApp = express().use(createRouter({ config: configured }));
			const fetchMock = vi.fn(
				async (_url: string, _init: RequestInit) => new Response("", { status: 401 }),
			);
			vi.stubGlobal("fetch", fetchMock);

			const res = await request(configuredApp).get("/protected").set("Authorization", "Bearer t");

			expect(res.status).toBe(502);
			expect(res.body).toEqual({ code: 502, message: "Provider Configuration Error" });
			// The proxy's own credential was refused, not the caller's.
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(upstreamCalls).toBe(0);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			// The request it refused was the one carrying Basic, not the token.
			const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>;
			expect(headers.Authorization).toMatch(/^Basic /);
		});

		it("answers 502 Provider Configuration Error when the introspection endpoint redirects", async () => {
			const fetchMock = vi.fn(
				async (_url: string, _init: RequestInit) =>
					new Response("", { status: 302, headers: { Location: "https://elsewhere.test/" } }),
			);
			vi.stubGlobal("fetch", fetchMock);

			const res = await request(app).get("/protected").set("Authorization", "Bearer t");

			expect(res.status).toBe(502);
			expect(res.body).toEqual({ code: 502, message: "Provider Configuration Error" });
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(upstreamCalls).toBe(0);
			expect(fetchMock.mock.calls[0][1].redirect).toBe("manual");
		});

		it.each([
			{ failure: "the provider answers 503 (IntrospectHttpError 503 from the status)", fetchImpl: async () => new Response("", { status: 503 }) },
			{ failure: "the provider answers 200 with a non-JSON body (IntrospectHttpError 502 raised by introspect itself)", fetchImpl: async () => new Response("<html>", { status: 200 }) },
			{ failure: "the provider answers 201 with a live token (IntrospectHttpError 201 from the status)", fetchImpl: async () => Response.json({ active: true }, { status: 201 }) },
			{ failure: "the provider answers 204 (IntrospectHttpError 204 from the status)", fetchImpl: async () => new Response(null, { status: 204 }) },
			{ failure: "fetch rejects", fetchImpl: async () => { throw new TypeError("fetch failed"); } },
			{ failure: "the call times out", fetchImpl: async () => { throw new DOMException("The operation was aborted due to timeout", "TimeoutError"); } },
		])("answers 502 Bad Gateway when $failure", async ({ fetchImpl }) => {
			const fetchMock = vi.fn(fetchImpl);
			vi.stubGlobal("fetch", fetchMock);
			const res = await request(app).get("/protected").set("Authorization", "Bearer t");
			expect(res.status).toBe(502);
			expect(res.body).toEqual({ code: 502, message: "Bad Gateway" });
			// Not about the caller's credential, so no challenge.
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(upstreamCalls).toBe(0);
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});
	});

	describe("injected deps", () => {
		const fakeLogger = () => ({
			debug: vi.fn<Logger["debug"]>(),
			info: vi.fn<Logger["info"]>(),
			warn: vi.fn<Logger["warn"]>(),
			error: vi.fn<Logger["error"]>(),
		});

		it("accepts an injected introspector and logger: fetch and the singleton are not touched, and the inbound bytes are forwarded", async () => {
			const fetchMock = vi.fn();
			vi.stubGlobal("fetch", fetchMock);
			const introspect = vi.fn(async () => ({ active: true }));
			const injected = fakeLogger();
			const singletonInfo = vi.spyOn(logger, "info");
			const singletonError = vi.spyOn(logger, "error");
			const own = express();
			own.use(createRouter({ config: makeConfig(upstreamPort), deps: { introspect, logger: injected } }));

			const res = await request(own)
				.get("/protected")
				.set("Authorization", "Bearer t extra")
				.set("x-request-id", "rid-abc");

			expect(res.status).toBe(200);
			expect(upstreamCalls).toBe(1);
			// The first SP-delimited word is introspected, the inbound bytes are forwarded.
			expect(upstreamHeaders[0].authorization).toBe("Bearer t extra");
			// The request id the decision hands over is the one the request-id middleware settled on.
			expect(introspect).toHaveBeenCalledWith("t", "rid-abc");
			expect(res.headers["x-request-id"]).toBe("rid-abc");
			expect(fetchMock).not.toHaveBeenCalled();
			// The same vocabulary as every other line, in both modes.
			expect(injected.info).toHaveBeenCalledWith(
				{
					requestId: "rid-abc",
					event: "validation.incoming_request",
					method: "GET",
					path: "/protected",
				},
				"incoming request",
			);
			expect(singletonInfo).not.toHaveBeenCalled();
			expect(singletonError).not.toHaveBeenCalled();
		});

		it("an injected logger receives the introspect failure line", async () => {
			const err = new Error("boom");
			const introspect = vi.fn(async () => {
				throw err;
			});
			const injected = fakeLogger();
			const singletonError = vi.spyOn(logger, "error");
			const own = express();
			own.use(createRouter({ config: makeConfig(upstreamPort), deps: { introspect, logger: injected } }));

			const res = await request(own)
				.get("/protected")
				.set("Authorization", "Bearer t")
				.set("x-request-id", "rid-fail");

			expect(res.status).toBe(500);
			expect(res.body).toEqual({ code: 500, message: "Internal Server Error" });
			expect(upstreamCalls).toBe(0);
			expect(injected.error).toHaveBeenCalledWith(
				{ requestId: "rid-fail", event: "validation.unexpected_error", error: err },
				"introspect failed",
			);
			expect(singletonError).not.toHaveBeenCalled();
		});
	});

	// `http.bodyLimitSize` is enforced before the token is introspected when
	// the request declares its length, and by the upstream stage, once the
	// token has been checked, when it does not. Either way the answer is a
	// 413 in the refusal shape and nothing reaches the upstream.
	describe("the body limit", () => {
		const limitedApp = () => {
			const config = makeConfig(upstreamPort);
			return express().use(
				createRouter({ config: { ...config, http: { ...config.http, bodyLimitSize: "1kb" } } }),
			);
		};

		it("refuses a declared length over http.bodyLimitSize 413 without introspecting the token", async () => {
			const fetchMock = vi.fn(async () => Response.json({ active: true }));
			vi.stubGlobal("fetch", fetchMock);

			const res = await request(limitedApp())
				.post("/protected")
				.set("Authorization", "Bearer t")
				.set("content-type", "application/octet-stream")
				.send(Buffer.alloc(2048));

			expect(res.status).toBe(413);
			expect(res.body).toEqual({ code: 413, message: "Payload Too Large" });
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(fetchMock).not.toHaveBeenCalled();
			expect(upstreamCalls).toBe(0);
		});

		it("refuses a chunked body over the limit 413 in the refusal shape, once the token is checked", async () => {
			const fetchMock = vi.fn(async () => Response.json({ active: true }));
			vi.stubGlobal("fetch", fetchMock);

			const res = await postChunked(limitedApp(), "/protected", { Authorization: "Bearer t" }, [
				Buffer.alloc(1024),
				Buffer.alloc(1024),
			]);

			expect(res.status).toBe(413);
			expect(JSON.parse(res.text)).toEqual({ code: 413, message: "Payload Too Large" });
			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(upstreamCalls).toBe(0);
		});

		it("refuses any chunked body under a zero limit", async () => {
			vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));
			const config = makeConfig(upstreamPort);
			const app = express().use(
				createRouter({ config: { ...config, http: { ...config.http, bodyLimitSize: "0" } } }),
			);

			const res = await postChunked(app, "/protected", { Authorization: "Bearer t" }, [Buffer.from("x")]);

			expect(res.status).toBe(413);
			expect(upstreamCalls).toBe(0);
		});

		// The body reader stops reading when it refuses; the rest of the body
		// is drained, so a keep-alive connection answers its next request.
		it("drains a refused chunked body, so the connection answers its next request", async () => {
			vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));
			const server = limitedApp().listen(0, "127.0.0.1");
			await once(server, "listening");
			try {
				const { port } = server.address() as AddressInfo;
				const socket = connect(port, "127.0.0.1");
				let received = "";
				socket.on("data", (part: Buffer) => {
					received += part.toString("latin1");
				});
				const answers = () => received.match(/HTTP\/1\.1 \d{3}/g) ?? [];
				const until = async (count: number) => {
					for (let waited = 0; answers().length < count && waited < 3000; waited += 20) {
						await new Promise((resolve) => setTimeout(resolve, 20));
					}
				};
				const body = Buffer.alloc(200 * 1024, "x");
				socket.write(
					"POST /protected HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer t\r\nTransfer-Encoding: chunked\r\n\r\n",
				);
				socket.write(`${body.length.toString(16)}\r\n`);
				socket.write(body);
				socket.write("\r\n0\r\n\r\n");
				await until(1);
				socket.write("GET /protected HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer t\r\n\r\n");
				await until(2);
				socket.destroy();

				expect(answers()).toEqual(["HTTP/1.1 413", "HTTP/1.1 200"]);
			} finally {
				server.closeAllConnections();
				server.close();
			}
		});

		it("refuses to build with an http.bodyLimitSize that is not a byte size", () => {
			const config = makeConfig(upstreamPort);
			expect(() =>
				createRouter({ config: { ...config, http: { ...config.http, bodyLimitSize: "ten" } } }),
			).toThrow(/http\.bodyLimitSize must be a byte size/);
		});

		it("forwards a body at the limit", async () => {
			vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));

			const res = await request(limitedApp())
				.post("/protected")
				.set("Authorization", "Bearer t")
				.set("content-type", "application/octet-stream")
				.send(Buffer.alloc(1024));

			expect(res.status).toBe(200);
			expect(upstreamCalls).toBe(1);
		});
	});

	// An upstream that could not be reached is the upstream failing: 502, in
	// this mode's refusal shape.
	it("refuses an unreachable upstream 502 Bad Gateway in the refusal shape", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));
		const closed = createServer();
		closed.listen(0, "127.0.0.1");
		await once(closed, "listening");
		const closedPort = (closed.address() as AddressInfo).port;
		closed.close();
		await once(closed, "close");

		const res = await request(express().use(createRouter({ config: makeConfig(closedPort) })))
			.get("/protected")
			.set("Authorization", "Bearer t");

		expect(res.status).toBe(502);
		expect(res.body).toEqual({ code: 502, message: "Bad Gateway" });
	});

	// A reset reaches the router's error handler through the stage's
	// proxyErrorHandler, not the library's default handler.
	it("refuses an upstream that resets the connection 502 Bad Gateway in the refusal shape", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));
		const resetting = createNetServer((socket) => socket.on("data", () => socket.resetAndDestroy()));
		resetting.listen(0, "127.0.0.1");
		await once(resetting, "listening");
		try {
			const resettingPort = (resetting.address() as AddressInfo).port;

			const res = await request(express().use(createRouter({ config: makeConfig(resettingPort) })))
				.get("/protected")
				.set("Authorization", "Bearer t");

			expect(res.status).toBe(502);
			expect(res.body).toEqual({ code: 502, message: "Bad Gateway" });
		} finally {
			resetting.close();
		}
	});

	// A caller that hangs up before a slow upstream answers makes the library
	// abort its own request; that is the caller leaving, not the upstream
	// failing, so nothing is logged as an unavailable upstream.
	it("logs no unavailable upstream when the caller leaves before a slow upstream answers", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));
		let slowReached = 0;
		let reached: (req: IncomingMessage) => void = () => {};
		const upstreamRequest = new Promise<IncomingMessage>((resolve) => {
			reached = resolve;
		});
		const slow = createServer((req, res) => {
			slowReached++;
			reached(req);
			setTimeout(() => res.end("late"), 400);
		});
		slow.listen(0, "127.0.0.1");
		await once(slow, "listening");
		const logged = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
		const front = express()
			.use(createRouter({ config: makeConfig((slow.address() as AddressInfo).port), deps: { logger: logged } }))
			.listen(0, "127.0.0.1");
		await once(front, "listening");
		try {
			const caller = httpRequest({
				host: "127.0.0.1",
				port: (front.address() as AddressInfo).port,
				path: "/protected",
				headers: { Authorization: "Bearer t" },
			});
			caller.on("error", () => {});
			caller.end();
			// Leave once the request is at the upstream, and wait for the
			// library's abort to reach it there, then for the proxy's side of it.
			const atUpstream = await upstreamRequest;
			atUpstream.on("error", () => {});
			const aborted = new Promise((resolve) => atUpstream.once("close", resolve));
			caller.destroy();
			await aborted;
			await new Promise((resolve) => setTimeout(resolve, 50));

			// The request reached the upstream, so the library's own abort ran.
			expect(slowReached).toBe(1);
			const events = logged.error.mock.calls.map(([fields]) => (fields as { event?: string }).event);
			expect(events).not.toContain("validation.upstream_unavailable");
		} finally {
			front.closeAllConnections();
			front.close();
			slow.closeAllConnections();
			slow.close();
		}
	});

	// A caller that leaves partway through its body is the body reader's
	// 400, which carries its own status: still logged, at info, as the
	// request failing, though no one is left to answer.
	it("logs a caller that leaves partway through its body as request_failed at info", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ active: true })));
		const logged = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
		const front = express()
			.use(createRouter({ config: makeConfig(upstreamPort), deps: { logger: logged } }))
			.listen(0, "127.0.0.1");
		await once(front, "listening");
		try {
			const socket = connect((front.address() as AddressInfo).port, "127.0.0.1");
			socket.on("error", () => {});
			socket.write(
				"POST /protected HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer t\r\nContent-Length: 1000\r\n\r\n",
			);
			socket.write(Buffer.alloc(100, "x"));
			await new Promise((resolve) => setTimeout(resolve, 100));
			socket.destroy();
			// Until the refusal is logged, or a deadline that fails on the assertion.
			const events = () => logged.info.mock.calls.map(([fields]) => (fields as { event?: string }).event);
			for (let waited = 0; !events().includes("validation.request_failed") && waited < 3000; waited += 20) {
				await new Promise((resolve) => setTimeout(resolve, 20));
			}

			expect(events()).toContain("validation.request_failed");
			expect(upstreamCalls).toBe(0);
		} finally {
			front.closeAllConnections();
			front.close();
		}
	});
});
