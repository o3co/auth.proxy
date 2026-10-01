// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Graceful shutdown against a real server and a caller that keeps its
 * connection alive. `close` stops new connections and `closeIdleConnections`
 * releases the idle ones, but a connection busy with a request when the drain
 * starts would be kept alive after its answer and hold the drain open until
 * `keepAliveTimeout`. The drain closes it as its answer ends, and says so.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo, connect, type Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../logger.mjs";
import { installGracefulShutdown } from "../shutdown.mjs";

const logger: Logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

describe("graceful shutdown with a kept-alive caller", () => {
	let server: Server;
	let socket: Socket | undefined;

	afterEach(() => {
		socket?.destroy();
		server?.closeAllConnections();
	});

	/** A server whose answers wait for the test, behind the shutdown under test. */
	const start = async () => {
		const pending: ServerResponse[] = [];
		const arrived = new Set<() => void>();
		server = createServer((_req: IncomingMessage, res: ServerResponse) => {
			pending.push(res);
			for (const notify of arrived) notify();
		});
		// Far past the test's own timeout: a drain that waits for it fails the test.
		server.keepAliveTimeout = 60_000;
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		let exited: (code: number) => void = () => {};
		const exitCode = new Promise<number>((resolve) => {
			exited = resolve;
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
		socket = connect(port, "127.0.0.1");
		let text = "";
		const closed = new Promise<void>((resolve) => socket?.on("close", () => resolve()));
		socket.on("data", (chunk: Buffer) => {
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
			send: () => socket?.write("GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n"),
			nextRequest,
			shutDown: () => signal(),
			exitCode,
			received: () => text,
			/** Resolves when the server closes the caller's connection. */
			closed,
		};
	};

	it("answers a request in flight with Connection: close, closes its connection, and drains", async () => {
		const caller = await start();
		caller.send();
		const res = await caller.nextRequest();

		caller.shutDown();
		res.end("in flight");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received().toLowerCase()).toContain("\r\nconnection: close");
	});

	it("closes the connection of an answer already under way once it ends, and drains", async () => {
		const caller = await start();
		caller.send();
		const res = await caller.nextRequest();
		res.write("started");

		caller.shutDown();
		res.end(" and ended");

		expect(await caller.exitCode).toBe(0);
		await caller.closed;
		expect(caller.received()).toContain("ended");
	});
});
