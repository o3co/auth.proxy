// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Graceful shutdown, moved in from `@o3co/auth.utils` — and given the deadline
 * it never had.
 *
 * `auth.utils@0.0.4`'s `gracefulShutdown` called `server.close()` with no
 * timeout, so a single stuck in-flight request meant the process never exited
 * on its own and the orchestrator's SIGKILL cut it down mid-flight: the
 * opposite of a graceful shutdown, arriving only under the load that produces
 * a stuck request. Its cleanup-failure path also wrote to `console.error`, one
 * bare line in a service whose every other line is NDJSON, and it always
 * exited zero, so an orchestrator could not tell a clean drain from a
 * truncated one.
 *
 * `auth.provider` reached the same conclusion in its issue #290 and moved the
 * behaviour into the code it deploys. This is that contract, for this proxy.
 */
import type { Server } from "node:http";
import { describe, expect, it, vi } from "vitest";
import type { Logger } from "../logger.mjs";
import { deferExit, installGracefulShutdown } from "../shutdown.mjs";

/** A `Server` double whose `close` callback fires only when we say so. */
function makeServer() {
	let closeCallback: ((err?: Error) => void) | undefined;
	const server = {
		close: vi.fn((cb?: (err?: Error) => void) => {
			closeCallback = cb;
			return server;
		}),
		closeIdleConnections: vi.fn(),
		closeAllConnections: vi.fn(),
	};
	return {
		server: server as unknown as Server,
		spies: server,
		/** Simulate the last in-flight request finishing. */
		finishDraining: () => closeCallback?.(),
		/** Simulate `close` reporting a failure through its callback. */
		failClose: (err: Error) => closeCallback?.(err),
	};
}

/** A `Logger`-shaped spy, typed so a future port method cannot slip past. */
const makeLogger = () => {
	const spy = {
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
	};
	return spy satisfies Logger;
};

/** Drive one shutdown without touching the real `process` or exiting. */
function install(opts: { cleanup?: () => void | Promise<void>; drainTimeoutMs?: number } = {}) {
	const { server, spies, finishDraining, failClose } = makeServer();
	const logger = makeLogger();
	const exit = vi.fn();
	const signals = new Map<string, () => void>();

	installGracefulShutdown(server, {
		logger,
		cleanup: opts.cleanup ?? (() => {}),
		...(opts.drainTimeoutMs === undefined ? {} : { drainTimeoutMs: opts.drainTimeoutMs }),
		exit,
		onSignal: (name, handler) => signals.set(name, handler),
		offSignal: (name) => signals.delete(name),
	});

	return { spies, logger, exit, signals, finishDraining, failClose };
}

/** Let the awaited cleanup inside `finish` settle. */
const settle = () => new Promise((resolve) => setImmediate(resolve));

describe("installGracefulShutdown", () => {
	it("listens for both SIGTERM and SIGINT", () => {
		const { signals } = install();
		expect([...signals.keys()].sort()).toEqual(["SIGINT", "SIGTERM"]);
	});

	it("stops accepting connections and releases idle keep-alive sockets", () => {
		const { signals, spies } = install();
		signals.get("SIGTERM")?.();
		expect(spies.close).toHaveBeenCalledOnce();
		expect(spies.closeIdleConnections).toHaveBeenCalledOnce();
	});

	it("runs cleanup once draining completes, then exits zero", async () => {
		const cleanup = vi.fn();
		const { signals, finishDraining, exit } = install({ cleanup });
		signals.get("SIGTERM")?.();
		expect(cleanup).not.toHaveBeenCalled();
		finishDraining();
		await settle();
		expect(cleanup).toHaveBeenCalledOnce();
		expect(exit).toHaveBeenCalledWith(0);
	});

	it("ignores a second signal instead of running cleanup twice", async () => {
		const cleanup = vi.fn();
		const { signals, spies, finishDraining, exit } = install({ cleanup });
		const handler = signals.get("SIGTERM");
		handler?.();
		handler?.();
		finishDraining();
		await settle();
		expect(spies.close).toHaveBeenCalledOnce();
		expect(cleanup).toHaveBeenCalledOnce();
		expect(exit).toHaveBeenCalledOnce();
	});

	it("forces the remaining connections closed when draining outruns the deadline", async () => {
		vi.useFakeTimers();
		try {
			const { signals, spies } = install({ drainTimeoutMs: 5_000 });
			signals.get("SIGTERM")?.();
			expect(spies.closeAllConnections).not.toHaveBeenCalled();
			vi.advanceTimersByTime(5_000);
			expect(spies.closeAllConnections).toHaveBeenCalledOnce();
		} finally {
			vi.useRealTimers();
		}
	});

	it("exits non-zero on a forced close, so the drain outcome is visible", async () => {
		vi.useFakeTimers();
		let exitSpy: ReturnType<typeof vi.fn>;
		try {
			const { signals, exit } = install({ drainTimeoutMs: 5_000 });
			exitSpy = exit;
			signals.get("SIGTERM")?.();
			vi.advanceTimersByTime(5_000);
		} finally {
			vi.useRealTimers();
		}
		await settle();
		expect(exitSpy).toHaveBeenCalledWith(1);
	});

	it("does not force-close a drain that finished in time", async () => {
		vi.useFakeTimers();
		try {
			const { signals, spies, finishDraining } = install({ drainTimeoutMs: 5_000 });
			signals.get("SIGTERM")?.();
			finishDraining();
			vi.advanceTimersByTime(10_000);
			expect(spies.closeAllConnections).not.toHaveBeenCalled();
		} finally {
			vi.useRealTimers();
		}
	});

	it("reports a cleanup failure through the app logger, not console", async () => {
		const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
		const err = new Error("redis disconnect failed");
		const { signals, finishDraining, logger, exit } = install({
			cleanup: () => Promise.reject(err),
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await settle();
		expect(logger.error).toHaveBeenCalledWith({ err }, expect.stringContaining("cleanup failed"));
		expect(consoleError).not.toHaveBeenCalled();
		expect(exit).toHaveBeenCalledWith(1);
		consoleError.mockRestore();
	});

	it("still exits when cleanup throws — a failed dispose must not wedge the process", async () => {
		const { signals, finishDraining, exit } = install({
			cleanup: () => {
				throw new Error("boom");
			},
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await settle();
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("does not report a failed close as a clean drain", async () => {
		const err = new Error("Server is not running");
		const { signals, failClose, logger, exit } = install();
		signals.get("SIGTERM")?.();
		failClose(err);
		await settle();
		expect(logger.error).toHaveBeenCalledWith({ err }, expect.stringContaining("close failed"));
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("still runs cleanup when close reports a failure", async () => {
		const cleanup = vi.fn();
		const { signals, failClose } = install({ cleanup });
		signals.get("SIGTERM")?.();
		failClose(new Error("nope"));
		await settle();
		expect(cleanup).toHaveBeenCalledOnce();
	});

	it("bounds cleanup so a hanging dispose cannot wedge the process (#81 review)", async () => {
		// The docstring promised cleanup "never wedges the process", but `finish`
		// awaited it with no deadline: a dispose that never settles meant `exit`
		// was never reached and the drain deadline had already been cleared.
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit, logger } = install({
				cleanup: () => new Promise<void>(() => {}),
				drainTimeoutMs: 5_000,
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(5_000);
			expect(logger.error).toHaveBeenCalledWith(
				expect.objectContaining({ cleanupTimeoutMs: 5_000 }),
				expect.stringContaining("cleanup timed out"),
			);
			expect(exit).toHaveBeenCalledWith(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not penalise a cleanup that finishes inside its budget", async () => {
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit } = install({
				cleanup: () => Promise.resolve(),
				drainTimeoutMs: 5_000,
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(10_000);
			expect(exit).toHaveBeenCalledExactlyOnceWith(0);
		} finally {
			vi.useRealTimers();
		}
	});

	it("defers the real exit a turn so a buffered log destination can flush (#81 review)", async () => {
		// pino's default destination is not synchronous, so calling
		// `process.exit` in the same tick can drop the very lines that say why
		// the shutdown failed.
		const exitProcess = vi.fn();
		deferExit(3, exitProcess);
		expect(exitProcess).not.toHaveBeenCalled();
		await new Promise((resolve) => setImmediate(resolve));
		expect(exitProcess).toHaveBeenCalledWith(3);
	});

	it("removes its own signal listeners once shutting down", () => {
		const { signals } = install();
		signals.get("SIGTERM")?.();
		expect(signals.size).toBe(0);
	});
});
