/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { subscribe, unsubscribe } from "node:diagnostics_channel";
import type { Server, ServerResponse } from "node:http";
import type { Socket } from "node:net";
import type { Logger } from "./logger.mjs";

/**
 * Graceful shutdown for the proxy. It lives here rather than in a dependency:
 * for the component in front of every protected upstream, "does SIGTERM wait
 * for in-flight requests, and for how long?" has to be answerable from the
 * code an operator deploys. The guarantees, pinned by this repository's tests:
 *
 * 1. **SIGTERM and SIGINT** both start it; a second signal is ignored rather
 *    than starting a second cleanup over the first one's work.
 * 2. **New connections stop immediately** (`close`), and each open one closes
 *    once its last answer has been written out — at once for an idle
 *    keep-alive connection, or one that has sent nothing, which would
 *    otherwise hold a quiet proxy for the whole deadline. A connection busy
 *    with a request is not kept alive past its last answer: pipelined
 *    answers before it still go out, a request arriving during the drain —
 *    or whose head was still arriving when it started — is answered too, and
 *    the last answer says `Connection: close` when its head is unwritten as
 *    it takes its turn on the connection, unless the answer set a
 *    `Connection` field of its own. Not one whose head was written while it
 *    waited, since a request pipelined after it may still be on its way. An
 *    answer that ends during the drain is written out before its connection
 *    closes, whichever connection finishes first. One that had ended but was
 *    still being written when the drain started is Node's to keep: `close`
 *    releases idle connections itself, and counts an ended answer as idle. A
 *    caller that stops halfway through a request's head holds the drain until
 *    the deadline. This is the plain HTTP server the proxy listens with.
 * 3. **In-flight requests get `drainTimeoutMs`** (default 10s) to finish;
 *    `server.close()` alone waits indefinitely on one stuck request.
 * 4. **Past the deadline, remaining connections are cut**
 *    (`closeAllConnections`) and the process exits **non-zero** — an
 *    orchestrator that only ever sees `0` cannot tell a clean drain from one
 *    that ran out of time.
 * 5. **`cleanup` runs after draining, before exit**, logged through the app
 *    logger and reflected in the exit code. It is bounded by
 *    `cleanupTimeoutMs`, so a dispose that never settles cannot wedge the
 *    process.
 * 6. **A `close` that fails is not reported as a clean drain.**
 *
 * Size `drainTimeoutMs` **below** the orchestrator's own kill grace period
 * (Kubernetes `terminationGracePeriodSeconds`, compose `stop_grace_period`,
 * both 30s by default), so the proxy closes on its own terms before SIGKILL
 * arrives.
 */
export interface GracefulShutdownOptions {
	readonly logger: Logger;
	/** Release whatever the proxy holds — caches, upstream agents. */
	readonly cleanup?: () => void | Promise<void>;
	/** How long in-flight requests get before connections are cut. Default 10s. */
	readonly drainTimeoutMs?: number;
	/**
	 * How long `cleanup` gets before the shutdown gives up on it. Defaults to
	 * `drainTimeoutMs`, so the worst-case shutdown is the two budgets in
	 * sequence — size both against the orchestrator's grace period, not one.
	 */
	readonly cleanupTimeoutMs?: number;
	/** Injected in tests; defaults to {@link deferExit}. */
	readonly exit?: (code: number) => void;
	/** Injected in tests; defaults to `process.on`. */
	readonly onSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
	/** Injected in tests; defaults to `process.removeListener`. */
	readonly offSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
}

const DEFAULT_DRAIN_TIMEOUT_MS = 10_000;
const SIGNALS: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT"];

/**
 * Exit after yielding the loop once.
 *
 * pino's default destination is not synchronous, so calling `process.exit` in
 * the same tick as the last `logger.error` can drop exactly the lines that say
 * why the shutdown failed. One turn is a flush window, not a guarantee: a
 * deployment that needs certainty should pass an `exit` that flushes its own
 * transport first.
 */
export function deferExit(code: number, exitProcess: (code: number) => void = process.exit): void {
	setImmediate(() => exitProcess(code));
}

export function installGracefulShutdown(server: Server, options: GracefulShutdownOptions): void {
	const {
		logger,
		cleanup,
		drainTimeoutMs = DEFAULT_DRAIN_TIMEOUT_MS,
		exit = deferExit,
		onSignal = (signal, handler): void => {
			process.on(signal, handler);
		},
		offSignal = (signal, handler): void => {
			process.removeListener(signal, handler);
		},
	} = options;

	const cleanupTimeoutMs = options.cleanupTimeoutMs ?? drainTimeoutMs;

	let shuttingDown = false;
	let finished = false;

	/** A connection's latest request: its answer, and whether Node meant to keep the connection after it. */
	interface Carried {
		readonly response: ServerResponse;
		readonly keepAlive: boolean;
	}

	/**
	 * Each open connection, and the latest request it carries — none before
	 * its first. That request's answer is the one the drain closes the
	 * connection after: answers to the requests pipelined before it still go
	 * out on the connection.
	 */
	const connections = new Map<Socket, Carried | undefined>();

	const track = (socket: Socket): void => {
		if (connections.has(socket)) return;
		connections.set(socket, undefined);
		socket.once("close", () => connections.delete(socket));
	};

	/**
	 * Closes `socket` after `res`, its latest answer, has been written out.
	 *
	 * The answer says `Connection: close` when its head is still unwritten as
	 * it takes its turn on the connection (Node assigns it then, and says so
	 * with `socket`), and only while it is still the latest. Not before: an
	 * answer queued behind another may have its head written while a request
	 * pipelined after it is still on its way, and a `close` it had said would
	 * make Node drop that request's answer. A later request restores what Node
	 * meant for the one before, while that one's head is unwritten.
	 *
	 * The close itself is the drain's own, not left to Node's: an answer
	 * whose head was written first has already said keep-alive, and a
	 * `Connection` field an answer set overrides `shouldKeepAlive`. It waits
	 * for the answer to finish — every byte written — so an answer that has
	 * ended but is still being written is not cut; and the connection is
	 * closed only while that answer is still its latest.
	 */
	const closeAfter = (socket: Socket, res: ServerResponse): void => {
		const announce = (): void => {
			if (!res.headersSent && connections.get(socket)?.response === res) res.shouldKeepAlive = false;
		};
		if (res.socket === socket) announce();
		else res.once("socket", announce);
		if (res.writableFinished) {
			socket.destroySoon();
			return;
		}
		res.once("finish", () => {
			if (connections.get(socket)?.response === res) socket.destroySoon();
		});
	};

	/**
	 * Every request this server receives, before any listener answers it —
	 * those that expect `100-continue` included, which never fire `request`.
	 * `shouldKeepAlive` is still what Node took from the request.
	 */
	const onRequest = (message: unknown): void => {
		const { server: from, socket, response } = message as {
			server: unknown;
			socket: Socket;
			response: ServerResponse;
		};
		if (from !== server) return;
		track(socket);
		const previous = connections.get(socket);
		connections.set(socket, { response, keepAlive: response.shouldKeepAlive });
		if (!shuttingDown) return;
		// A later request on the connection: it, not the one before, closes it.
		if (previous !== undefined && !previous.response.headersSent) {
			previous.response.shouldKeepAlive = previous.keepAlive;
		}
		closeAfter(socket, response);
	};
	subscribe("http.server.request.start", onRequest);
	server.on("connection", track);
	server.once("close", () => unsubscribe("http.server.request.start", onRequest));

	/** Sentinel so a timed-out cleanup is reported as that, not as a throw. */
	const CLEANUP_TIMED_OUT = Symbol("cleanup-timed-out");

	/**
	 * Await `cleanup`, but not forever. `cleanup()` is invoked inside the async
	 * wrapper so a synchronous throw lands in the same rejection path as an
	 * async one.
	 */
	const runCleanup = async (): Promise<typeof CLEANUP_TIMED_OUT | undefined> => {
		if (!cleanup) return;
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			return await Promise.race([
				(async (): Promise<undefined> => {
					await cleanup();
					return undefined;
				})(),
				new Promise<typeof CLEANUP_TIMED_OUT>((resolve) => {
					timer = setTimeout(() => resolve(CLEANUP_TIMED_OUT), cleanupTimeoutMs);
					timer.unref?.();
				}),
			]);
		} finally {
			if (timer) clearTimeout(timer);
		}
	};

	/** Run `cleanup` and exit. Called by whichever of drain / deadline wins. */
	const finish = async (code: number, reason: string): Promise<void> => {
		if (finished) return;
		finished = true;
		let exitCode = code;
		// `reason` names whatever decided the exit code, so the line an operator
		// alerts on cannot say "drained" next to a non-zero code. The drain
		// outcome keeps its own key rather than being overwritten — both facts
		// are wanted, and a stable shape is what makes the line queryable.
		let outcome = reason;
		try {
			if ((await runCleanup()) === CLEANUP_TIMED_OUT) {
				logger.error({ cleanupTimeoutMs }, "graceful shutdown: cleanup timed out");
				exitCode = 1;
				outcome = "cleanup-timeout";
			}
		} catch (err) {
			// Through the app logger, not `console.error`: a shutdown that
			// failed to release what it held is exactly the line an operator
			// needs to find later, and a bare write is the one their pipeline
			// drops.
			logger.error({ err }, "graceful shutdown: cleanup failed");
			exitCode = 1;
			outcome = "cleanup-failed";
		}
		logger.info({ reason: outcome, drain: reason, exitCode }, "graceful shutdown: complete");
		exit(exitCode);
	};

	const handler = (): void => {
		if (shuttingDown) return;
		shuttingDown = true;
		for (const signal of SIGNALS) offSignal(signal, handler);
		logger.info({ drainTimeoutMs }, "graceful shutdown: draining");

		const deadline = setTimeout(() => {
			logger.error(
				{ drainTimeoutMs },
				"graceful shutdown: drain deadline exceeded, closing remaining connections",
			);
			server.closeAllConnections();
			void finish(1, "drain-timeout");
		}, drainTimeoutMs);
		// The deadline must not be what keeps the process alive once the drain
		// has already finished.
		deadline.unref?.();

		server.close((err) => {
			clearTimeout(deadline);
			if (err) {
				// `close` reports through its callback — "Server is not running"
				// is the common one, but any listener teardown failure lands
				// here. Reporting "drained" and exiting 0 on it would tell an
				// orchestrator the shutdown went cleanly when the listener did
				// not actually come down.
				logger.error({ err }, "graceful shutdown: server close failed");
				void finish(1, "close-failed");
				return;
			}
			void finish(0, "drained");
		});
		// `close` has already released the idle connections it sees. Left are
		// the busy ones, which close after their latest answer, and two kinds
		// it keeps: one that has sent nothing, which Node counts as busy and
		// would hold until the deadline, so it is closed now; and one whose
		// next request's head is still arriving, which is left to close after
		// that request once it is whole.
		for (const [socket, carried] of connections) {
			if (socket.destroyed) continue;
			if (carried === undefined) {
				if (socket.bytesRead === 0) socket.destroySoon();
			} else if (!carried.response.writableFinished) {
				closeAfter(socket, carried.response);
			}
		}
	};

	for (const signal of SIGNALS) onSignal(signal, handler);
}
