// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Graceful shutdown against a real server and callers that keep their
 * connections alive. `close` stops new connections, but a connection busy
 * with a request when the drain starts would be kept alive after its answer
 * and hold the drain open until `keepAliveTimeout`. The drain closes each
 * connection after its last answer has been written out, and says so —
 * however the request arrived, whatever the answer set, and without cutting
 * an answer that is still being written, on that connection or another.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo, connect, type Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../logger.mjs";
import { installGracefulShutdown } from "../shutdown.mjs";

const logger: Logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

/** How long a drain may take here: far under `keepAliveTimeout`, so one that waits for it fails. */
const DRAINED_WITHIN_MS = 2_000;

/** An answer larger than any socket buffer, so it has ended long before it is written out. */
const LARGE = 8 * 1024 * 1024;

const get = (path: string) => `GET ${path} HTTP/1.1\r\nHost: proxy.test\r\n\r\n`;

/** The heads of every answer received, lower-cased. */
const heads = (text: string) =>
	text
		.toLowerCase()
		.split(/(?=http\/1\.1 \d{3})/)
		.filter((part) => part.startsWith("http/1.1"))
		.map((part) => part.slice(0, part.indexOf("\r\n\r\n")));

/** One connection to `server`, reading everything it is sent. */
const connectTo = (server: Server) => {
	const { port } = server.address() as AddressInfo;
	const socket = connect(port, "127.0.0.1");
	let received = Buffer.alloc(0);
	const closed = new Promise<void>((resolve) => socket.on("close", () => resolve()));
	socket.on("data", (chunk: Buffer) => {
		received = Buffer.concat([received, chunk]);
	});
	return {
		socket,
		send: (raw: string) => socket.write(raw),
		/** What arrived, as text. */
		received: () => received.toString("latin1"),
		/** How many bytes arrived. */
		bytes: () => received.length,
		/** Resolves when the server closes the connection. */
		closed,
	};
};

describe("graceful shutdown with kept-alive callers", () => {
	const servers: Server[] = [];
	const sockets: Socket[] = [];

	afterEach(() => {
		for (const socket of sockets.splice(0)) socket.destroy();
		for (const server of servers.splice(0)) server.closeAllConnections();
	});

	/**
	 * A server behind the shutdown under test. `/now` is answered at once,
	 * `/large` at once with {@link LARGE} bytes; any other waits for the test,
	 * which takes it from `nextRequest`. With `checkContinue`, a request that
	 * expects `100-continue` goes to that listener, as the app's own does.
	 */
	const start = async (options: { checkContinue?: boolean; connectionField?: string } = {}) => {
		const pending: ServerResponse[] = [];
		const arrived = new Set<() => void>();
		const answered = new Map<string, () => void>();
		const answeredAt = (path: string) =>
			new Promise<void>((resolve) => {
				answered.set(path, resolve);
			});
		const hold = (res: ServerResponse) => {
			if (options.connectionField !== undefined) res.setHeader("Connection", options.connectionField);
			pending.push(res);
			for (const notify of arrived) notify();
		};
		const server = createServer((req: IncomingMessage, res: ServerResponse) => {
			if (req.url === "/now") res.end("now");
			else if (req.url === "/large") res.end(Buffer.alloc(LARGE, "a"));
			else return hold(res);
			answered.get(req.url)?.();
		});
		servers.push(server);
		if (options.checkContinue) {
			server.on("checkContinue", (req: IncomingMessage, res: ServerResponse) => {
				res.writeContinue();
				req.resume();
				hold(res);
			});
		}
		// Far past the test's own timeout: a drain that waits for it fails the test.
		server.keepAliveTimeout = 60_000;
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		let exited: (code: number) => void = () => {};
		const exitCode = new Promise<number | "still draining">((resolve) => {
			exited = resolve;
			setTimeout(() => resolve("still draining"), DRAINED_WITHIN_MS).unref();
		});
		let signal: () => void = () => {};
		installGracefulShutdown(server, {
			logger,
			drainTimeoutMs: 60_000,
			exit: (code) => exited(code),
			onSignal: (name, handler) => {
				if (name === "SIGTERM") signal = handler;
			},
			offSignal: () => {},
		});
		const nextRequest = () =>
			new Promise<ServerResponse>((resolve) => {
				const check = () => {
					const res = pending.shift();
					if (res) {
						arrived.delete(check);
						resolve(res);
					}
				};
				arrived.add(check);
				check();
			});
		const caller = () => {
			const connected = connectTo(server);
			sockets.push(connected.socket);
			return connected;
		};
		return { caller, nextRequest, answeredAt, shutDown: () => signal(), exitCode };
	};

	it("answers a request in flight with Connection: close, closes its connection, and drains", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		caller.send(get("/held"));
		const res = await proxy.nextRequest();

		proxy.shutDown();
		res.end("in flight");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		expect(heads(caller.received())).toEqual([expect.stringContaining("\r\nconnection: close")]);
	});

	it("closes the connection of an answer already under way once it ends, and drains", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		caller.send(get("/held"));
		const res = await proxy.nextRequest();
		res.write("started");

		proxy.shutDown();
		res.end(" and ended");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received()).toContain("ended");
	});

	it("answers every pipelined request in flight, and closes after the last", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		caller.send(get("/one") + get("/two"));
		const first = await proxy.nextRequest();
		const second = await proxy.nextRequest();

		proxy.shutDown();
		first.end("first");
		second.end("second");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		const answered = heads(caller.received());
		expect(answered).toHaveLength(2);
		expect(answered[0]).not.toContain("\r\nconnection: close");
		expect(answered[1]).toContain("\r\nconnection: close");
		expect(caller.received()).toContain("second");
	});

	// A request pipelined behind the held one, answered at once while it
	// waits: its head is written before it is the connection's turn, while a
	// later request may still be on its way, so it is not told. The drain
	// closes the connection after it.
	it("answers a request that arrives during the drain, and closes after it", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		caller.send(get("/held"));
		const held = await proxy.nextRequest();

		proxy.shutDown();
		const nowAnswered = proxy.answeredAt("/now");
		caller.send(get("/now"));
		await nowAnswered;
		held.end("held");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		const answered = heads(caller.received());
		expect(answered).toHaveLength(2);
		expect(answered[0]).not.toContain("\r\nconnection: close");
		expect(caller.received()).toContain("now");
	});

	it("answers every request that arrives together during the drain", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		caller.send(get("/held"));
		const held = await proxy.nextRequest();

		proxy.shutDown();
		const largeAnswered = proxy.answeredAt("/large");
		caller.send(get("/now") + get("/large"));
		await largeAnswered;
		held.end("held");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		expect(heads(caller.received())).toHaveLength(3);
		expect(caller.bytes()).toBeGreaterThan(LARGE);
	});

	it("writes out a large answer that arrived during the drain before closing its connection", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		caller.send(get("/held"));
		const held = await proxy.nextRequest();

		proxy.shutDown();
		const largeAnswered = proxy.answeredAt("/large");
		caller.send(get("/large"));
		await largeAnswered;
		held.end("held");

		await caller.closed;
		expect(await proxy.exitCode).toBe(0);
		expect(caller.bytes()).toBeGreaterThan(LARGE);
	});

	// An answer that ends during the drain. One already ended but unwritten
	// when it starts is Node's: `server.close()` releases idle connections
	// itself, and counts an ended answer as idle.
	it("does not cut another connection's answer that has ended but is still being written", async () => {
		const proxy = await start();
		const slow = proxy.caller();
		slow.send(get("/slow"));
		const slowAnswer = await proxy.nextRequest();
		const busy = proxy.caller();
		busy.send(get("/held"));
		const held = await proxy.nextRequest();

		proxy.shutDown();
		// The slow caller reads nothing for now, so its answer stays buffered.
		slow.socket.pause();
		slowAnswer.end(Buffer.alloc(LARGE, "a"));
		held.end("held");
		await busy.closed;
		slow.socket.resume();

		await slow.closed;
		expect(await proxy.exitCode).toBe(0);
		expect(slow.bytes()).toBeGreaterThan(LARGE);
	});

	it("closes a kept-alive connection idle when the drain starts, and drains", async () => {
		const proxy = await start();
		const caller = proxy.caller();
		const nowAnswered = proxy.answeredAt("/now");
		caller.send(get("/now"));
		await nowAnswered;

		proxy.shutDown();

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received()).toContain("now");
	});

	it("closes after a request that expected 100-continue, which never fires request", async () => {
		const proxy = await start({ checkContinue: true });
		const caller = proxy.caller();
		caller.send("POST /upload HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi");
		const res = await proxy.nextRequest();

		proxy.shutDown();
		res.end("uploaded");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received()).toContain("uploaded");
	});

	it("still closes when the answer set a Connection field of its own", async () => {
		const proxy = await start({ connectionField: "keep-alive" });
		const caller = proxy.caller();
		caller.send(get("/held"));
		const res = await proxy.nextRequest();

		proxy.shutDown();
		res.end("kept, it said");

		expect(await proxy.exitCode).toBe(0);
		await caller.closed;
	});

	it("leaves another server's connections alone", async () => {
		const draining = await start();
		const other = await start();
		const caller = other.caller();
		caller.send(get("/held"));
		const res = await other.nextRequest();

		draining.shutDown();
		res.end("other");
		const nowAnswered = other.answeredAt("/now");
		caller.send(get("/now"));
		await nowAnswered;

		expect(await draining.exitCode).toBe(0);
		const answered = heads(caller.received());
		expect(answered.every((head) => !head.includes("connection: close"))).toBe(true);
	});
});
