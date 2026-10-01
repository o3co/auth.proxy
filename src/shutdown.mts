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
import type { IncomingMessage, Server, ServerResponse } from "node:http";
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
 *    once its last request is done with — its answer written out and its
 *    body arrived — at once for an idle keep-alive connection, or one that
 *    has sent nothing, which would otherwise hold a quiet proxy for the whole
 *    deadline. Pipelined answers before the last still go out, a request
 *    arriving during the drain — or whose head was still arriving when it
 *    started on a connection with no request in progress — is answered too,
 *    and no request the server read and handled goes unanswered at the HTTP
 *    level. The close is not announced with `Connection: close`, which
 *    would drop the answers to requests pipelined after it. So a caller
 *    reusing the connection can meet one reset for a request the server
 *    never read, which it can retry; so can a request whose head was still
 *    arriving behind one being answered, which closes with that answer. An
 *    answer that ends during the drain is written out before its connection
 *    closes, whichever connection finishes first. One that had ended but was
 *    still being written when the drain started is cut by Node's own
 *    `close`, which counts an ended answer as idle. A caller that stops
 *    halfway through a request's head, or through a body answered before it
 *    arrived, holds the drain until the deadline. This is the plain HTTP
 *    server the proxy listens with.
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

	/**
	 * Each open connection, and the request it is still busy with — the
	 * latest, when requests are pipelined; none before its first request, or
	 * once that request's answer has been written out and its body has
	 * arrived.
	 */
	const connections = new Map<Socket, ServerResponse | undefined>();

	const track = (socket: Socket): void => {
		if (connections.has(socket)) return;
		connections.set(socket, undefined);
		socket.once("close", () => connections.delete(socket));
	};

	/**
	 * Every request this server receives, before any listener answers it —
	 * those that expect `100-continue` included, which never fire `request`.
	 * Once its answer has been written out — every byte, so an answer that
	 * has ended but is still being written is not cut — and its body has
	 * arrived, which an answer given before reading it (a refusal) leaves
	 * behind, the connection lets go of it, and during the drain closes,
	 * unless a later request has arrived on it, which it closes after instead.
	 *
	 * The close is the drain's own and unannounced. An answer that said
	 * `Connection: close` would make Node drop the answer to any request
	 * pipelined after it, and the drain cannot know whether one is on its
	 * way. A caller sees its connection close after an answer, unlike
	 * `keepAliveTimeout`, which is advertised; one that reuses it meets a
	 * reset for a request the server never read. It also holds whatever
	 * `Connection` field an answer set.
	 */
	const onRequest = (message: unknown): void => {
		const { server: from, socket, request, response } = message as {
			server: unknown;
			socket: Socket;
			request: IncomingMessage;
			response: ServerResponse;
		};
		if (from !== server) return;
		track(socket);
		connections.set(socket, response);
		const done = (): void => {
			if (connections.get(socket) !== response) return;
			connections.set(socket, undefined);
			if (shuttingDown) socket.destroySoon();
		};
		response.once("finish", () => {
			if (request.complete) done();
			else request.once("end", done);
		});
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
		// the ones busy with a request, which close once it is done with
		// (`onRequest`), and two kinds it keeps: one that has sent nothing,
		// which Node counts as busy and would hold until the deadline, so it is
		// closed now; and one whose request's head is still arriving — its
		// first or a kept-alive connection's next — which closes once that
		// request, whole, is done with.
		for (const socket of connections.keys()) {
			if (socket.bytesRead === 0) socket.destroySoon();
		}
	};

	for (const signal of SIGNALS) onSignal(signal, handler);
}
