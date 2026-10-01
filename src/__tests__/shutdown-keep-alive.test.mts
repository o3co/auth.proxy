// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Graceful shutdown against a real server and a caller that keeps its
 * connection alive. `close` stops new connections and `closeIdleConnections`
 * releases the idle ones, but a connection busy with a request when the drain
 * starts would be kept alive after its answer and hold the drain open until
 * `keepAliveTimeout`. The drain closes it as its last answer ends, and says
 * so — however the request arrived, and whatever the answer set.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo, connect, type Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../logger.mjs";
import { installGracefulShutdown } from "../shutdown.mjs";

const logger: Logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

/** How long a drain may take here: far under `keepAliveTimeout`, so one that waits for it fails. */
const DRAINED_WITHIN_MS = 2_000;

const get = (path: string) => `GET ${path} HTTP/1.1\r\nHost: proxy.test\r\n\r\n`;

describe("graceful shutdown with a kept-alive caller", () => {
	let server: Server;
	let socket: Socket | undefined;

	afterEach(() => {
		socket?.destroy();
		server?.closeAllConnections();
	});

	/**
	 * A server behind the shutdown under test. A request to `/now` is answered
	 * at once; any other waits for the test, which takes it from
	 * `nextRequest`. With `checkContinue`, a request that expects
	 * `100-continue` goes to that listener, as the app's own does.
	 */
	const start = async (options: { checkContinue?: boolean; connectionField?: string } = {}) => {
		const pending: ServerResponse[] = [];
		const arrived = new Set<() => void>();
		let answeredNow: () => void = () => {};
		const nowAnswered = new Promise<void>((resolve) => {
			answeredNow = resolve;
		});
		const hold = (res: ServerResponse) => {
			if (options.connectionField !== undefined) res.setHeader("Connection", options.connectionField);
			pending.push(res);
			for (const notify of arrived) notify();
		};
		server = createServer((req: IncomingMessage, res: ServerResponse) => {
			if (req.url === "/now") {
				res.end("now");
				answeredNow();
			} else hold(res);
		});
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
		const { port } = server.address() as AddressInfo;
		const caller = connect(port, "127.0.0.1");
		socket = caller;
		let text = "";
		const closed = new Promise<void>((resolve) => caller.on("close", () => resolve()));
		caller.on("data", (chunk: Buffer) => {
			text += chunk.toString("latin1");
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
		return {
			send: (raw: string) => caller.write(raw),
			nextRequest,
			/** Resolves once the server has answered `/now`, queued or not. */
			nowAnswered,
			shutDown: () => signal(),
			exitCode,
			received: () => text,
			/** Resolves when the server closes the caller's connection. */
			closed,
		};
	};

	/** The heads of every answer received, lower-cased. */
	const heads = (text: string) =>
		text
			.toLowerCase()
			.split(/(?=http\/1\.1 \d{3})/)
			.filter((part) => part.startsWith("http/1.1"))
			.map((part) => part.slice(0, part.indexOf("\r\n\r\n")));

	it("answers a request in flight with Connection: close, closes its connection, and drains", async () => {
		const caller = await start();
		caller.send(get("/held"));
		const res = await caller.nextRequest();

		caller.shutDown();
		res.end("in flight");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		expect(heads(caller.received())).toEqual([expect.stringContaining("\r\nconnection: close")]);
	});

	it("closes the connection of an answer already under way once it ends, and drains", async () => {
		const caller = await start();
		caller.send(get("/held"));
		const res = await caller.nextRequest();
		res.write("started");

		caller.shutDown();
		res.end(" and ended");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received()).toContain("ended");
	});

	it("answers every pipelined request in flight, and closes after the last", async () => {
		const caller = await start();
		caller.send(get("/one") + get("/two"));
		const first = await caller.nextRequest();
		const second = await caller.nextRequest();

		caller.shutDown();
		first.end("first");
		second.end("second");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		const answered = heads(caller.received());
		expect(answered).toHaveLength(2);
		expect(answered[0]).not.toContain("\r\nconnection: close");
		expect(answered[1]).toContain("\r\nconnection: close");
		expect(caller.received()).toContain("second");
	});

	it("tells a request that arrives during the drain the connection closes, though it is answered at once", async () => {
		const caller = await start();
		caller.send(get("/held"));
		const held = await caller.nextRequest();

		caller.shutDown();
		caller.send(get("/now"));
		await caller.nowAnswered;
		held.end("held");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		const answered = heads(caller.received());
		expect(answered).toHaveLength(2);
		expect(answered[1]).toContain("\r\nconnection: close");
		expect(answered[1]).not.toContain("keep-alive");
	});

	it("closes after a request that expected 100-continue, which never fires request", async () => {
		const caller = await start({ checkContinue: true });
		caller.send(
			"POST /upload HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi",
		);
		const res = await caller.nextRequest();

		caller.shutDown();
		res.end("uploaded");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received()).toContain("uploaded");
	});

	it("still closes when the answer set a Connection field of its own", async () => {
		const caller = await start({ connectionField: "keep-alive" });
		caller.send(get("/held"));
		const res = await caller.nextRequest();

		caller.shutDown();
		res.end("kept, it said");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
	});
});
