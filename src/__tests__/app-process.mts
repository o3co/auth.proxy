// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The proxy as it runs, for the composition tests (#144): the entry point,
 * `src/app.mts`, in a child process — configured the way an operator
 * configures it, by environment variables over the shipped
 * `config/application.conf`, and observed the way an operator observes it,
 * by its HTTP answers and what it writes to stdout and stderr. Test-only:
 * nothing outside a test imports it.
 *
 * Nothing in the child is replaced. The HOCON parse, the schema, the mode
 * router, the provider clients and their `fetch`, the upstream stage and the
 * logger are the ones production runs; the child is started with
 * `node --import tsx`, which only compiles the TypeScript, and with
 * `child-preload.mts`, which reports the bound port and ties the child's
 * life to the parent's.
 *
 * The child's environment is what the test passes, over `PATH`, `TMPDIR`,
 * `NODE_ENV=production` (as the Dockerfile sets it) and the loopback listen
 * address — nothing inherited, so a `CLIENT_ID` in a developer's shell cannot
 * change the configuration under test.
 *
 * The child listens on `HTTP_PORT=0`, so the OS picks a port no one holds, and
 * it is ready once the preload has reported the port it bound — not once it
 * logs `Server ready`, which is an info line a `LOG_LEVEL` above info drops.
 *
 * No child outlives its test: a boot that is neither ready nor exited within
 * {@link BOOT_DEADLINE_MS} is killed and rejected with its stderr; a stop that
 * SIGTERM does not finish within {@link STOP_GRACE_MS} ends in SIGKILL; the
 * worker kills what is left when it exits; and a worker that is itself killed
 * leaves the child's IPC channel disconnected, which the preload answers by
 * killing the child. The suites that use this set their timeouts above the
 * deadline, so a boot fails on its deadline and not on vitest's timer.
 *
 * The parent can read the answer to a request before the lines the child
 * logged about it, so a test waits for lines rather than racing them:
 * {@link ProxyProcess.linesFor} sends a barrier request and waits for the
 * barrier's own `incoming request` line. The child writes its lines in order,
 * so every line written before the barrier's has been read by then, and a line
 * still missing was never written. The barrier also has to reach the
 * upstream: a request refused earlier that the proxy wrongly forwarded as well
 * would reach it before the barrier, so a test that asserts "nothing reached
 * the upstream" after `linesFor` sees it.
 */

import { type ChildProcess, spawn } from "node:child_process";
import {
	request as httpRequest,
	type IncomingHttpHeaders,
	type OutgoingHttpHeaders,
} from "node:http";
import { fileURLToPath } from "node:url";
import type { RecordingUpstream } from "./recording-upstream.mjs";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const ENTRY_POINT = fileURLToPath(new URL("../app.mts", import.meta.url));
const PRELOAD = fileURLToPath(new URL("./child-preload.mts", import.meta.url));
/** The line `child-preload.mts` writes; not imported from it, which would subscribe here too. */
const LISTENING = /^composition-test: listening on port (\d+)\n/m;

/** How long a boot may take before the child is killed. Below the suites' hook timeout. */
export const BOOT_DEADLINE_MS = 20_000;
/** How long SIGTERM gets before SIGKILL. */
export const STOP_GRACE_MS = 3_000;
/** The timeouts the suites that start a child set: above the deadline and the grace together. */
export const SUITE_TIMEOUT_MS = 30_000;

/** pino's level names, by the number it writes. */
const LEVEL_NAMES: Readonly<Record<number, string>> = {
	10: "trace",
	20: "debug",
	30: "info",
	40: "warn",
	50: "error",
	60: "fatal",
};

/** One NDJSON line from the child, with `level` as its name. */
export interface LogLine {
	level: string;
	msg: string;
	event?: string;
	requestId?: string;
	/** The line exactly as written. */
	raw: string;
	[field: string]: unknown;
}

export interface ProxyProcess {
	/** `http://127.0.0.1:<port>`. */
	readonly origin: string;
	/** Every NDJSON line the child has written to stdout so far, in order. */
	readonly lines: readonly LogLine[];
	/** Every stdout line that is not a JSON object — a `console.log`, say — in order. */
	readonly unparsed: readonly string[];
	/** Everything the child has written to stderr. */
	stderr(): string;
	/**
	 * The lines carrying `requestId`, once every line the child wrote before
	 * this call has been read and the barrier has reached the upstream (see the
	 * file header).
	 */
	linesFor(requestId: string): Promise<LogLine[]>;
	/** SIGTERM, SIGKILL after {@link STOP_GRACE_MS}, and the child's exit. */
	stop(): Promise<void>;
}

/** How a boot ended: the child exited, or it listened (and was stopped). */
export interface BootOutcome {
	listened: boolean;
	code: number | null;
	stdout: string;
	stderr: string;
}

interface Child {
	process: ChildProcess;
	lines: LogLine[];
	unparsed: string[];
	stdout: () => string;
	stderr: () => string;
	/** Resolves with the first line `matches` accepts, including one already read. */
	waitForLine(matches: (line: LogLine) => boolean): Promise<LogLine>;
	/** Resolves with the port the child's server bound. */
	port: Promise<number>;
	/** Resolves once the child has exited and its stdout and stderr have ended. */
	exited: Promise<number | null>;
}

const children = new Set<ChildProcess>();
/** Log barriers sent from this worker, for their ids. */
let barriers = 0;
// A worker that ends without the suite's afterAll kills what it started. A
// worker that is killed cannot; the preload covers that case.
process.once("exit", () => {
	for (const child of children) child.kill("SIGKILL");
});

const launch = (env: Record<string, string>): Child => {
	const child = spawn(process.execPath, ["--import", "tsx", "--import", PRELOAD, ENTRY_POINT], {
		cwd: ROOT,
		env: {
			PATH: process.env.PATH ?? "",
			...(process.env.TMPDIR !== undefined ? { TMPDIR: process.env.TMPDIR } : {}),
			NODE_ENV: "production",
			HTTP_HOSTNAME: "127.0.0.1",
			HTTP_PORT: "0",
			...env,
		},
		// The IPC channel is only a lifeline: see `child-preload.mts`.
		stdio: ["ignore", "pipe", "pipe", "ipc"],
	});
	children.add(child);
	// Nothing is sent over it, and it must not keep the worker alive.
	child.channel?.unref();

	const lines: LogLine[] = [];
	const unparsed: string[] = [];
	const waiters: { matches: (line: LogLine) => boolean; resolve: (line: LogLine) => void }[] = [];
	let stdout = "";
	let stderr = "";
	let pending = "";
	let reportPort: (port: number) => void = () => {};
	const port = new Promise<number>((resolve) => {
		reportPort = resolve;
	});

	const read = (raw: string): void => {
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch {
			parsed = null;
		}
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
			unparsed.push(raw);
			return;
		}
		const fields = parsed as Record<string, unknown>;
		const line: LogLine = {
			...fields,
			level: LEVEL_NAMES[fields.level as number] ?? String(fields.level),
			msg: String(fields.msg ?? ""),
			raw,
		};
		lines.push(line);
		for (const waiter of [...waiters]) {
			if (waiter.matches(line)) {
				waiters.splice(waiters.indexOf(waiter), 1);
				waiter.resolve(line);
			}
		}
	};

	child.stdout?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		stdout += chunk;
		pending += chunk;
		const complete = pending.split("\n");
		pending = complete.pop() ?? "";
		for (const raw of complete) read(raw);
	});
	child.stderr?.setEncoding("utf8");
	child.stderr?.on("data", (chunk: string) => {
		stderr += chunk;
		const listening = LISTENING.exec(stderr);
		if (listening !== null) reportPort(Number(listening[1]));
	});

	// "close", not "exit": it follows the end of stdout and stderr, so what
	// the child wrote last has been read by the time `exited` resolves.
	const exited = new Promise<number | null>((resolve) => {
		child.once("close", (code) => {
			children.delete(child);
			if (pending !== "") read(pending);
			pending = "";
			resolve(code);
		});
	});

	return {
		process: child,
		lines,
		unparsed,
		stdout: () => stdout,
		stderr: () => stderr,
		waitForLine(matches) {
			const seen = lines.find(matches);
			if (seen !== undefined) return Promise.resolve(seen);
			return new Promise((resolve) => waiters.push({ matches, resolve }));
		},
		port,
		exited,
	};
};

const isRunning = (child: Child): boolean =>
	child.process.exitCode === null && child.process.signalCode === null;

const kill = async (child: Child): Promise<void> => {
	if (isRunning(child)) child.process.kill("SIGKILL");
	await child.exited;
};

/** SIGTERM, then SIGKILL once {@link STOP_GRACE_MS} has passed without an exit. */
const stopChild = async (child: Child): Promise<void> => {
	if (!isRunning(child)) {
		await child.exited;
		return;
	}
	child.process.kill("SIGTERM");
	let timer: NodeJS.Timeout | undefined;
	const grace = new Promise<"grace">((resolve) => {
		timer = setTimeout(() => resolve("grace"), STOP_GRACE_MS);
	});
	const ended = await Promise.race([child.exited.then(() => "exited" as const), grace]);
	clearTimeout(timer);
	if (ended === "grace") await kill(child);
};

/**
 * Listening — the port reported — or exited first. Neither within
 * {@link BOOT_DEADLINE_MS}: the child is killed and this rejects with its stderr.
 */
const boot = async (
	env: Record<string, string>,
): Promise<{ child: Child; port: number; listened: boolean; code: number | null }> => {
	const child = launch(env);
	let timer: NodeJS.Timeout | undefined;
	const deadline = new Promise<"deadline">((resolve) => {
		timer = setTimeout(() => resolve("deadline"), BOOT_DEADLINE_MS);
	});
	const outcome = await Promise.race([
		child.port.then((port) => ({ listened: true, port, code: null })),
		child.exited.then((code) => ({ listened: false, port: 0, code })),
		deadline,
	]);
	clearTimeout(timer);
	if (outcome === "deadline") {
		await kill(child);
		throw new Error(
			`the proxy neither listened nor exited within ${BOOT_DEADLINE_MS} ms and was killed:\n${child.stderr()}`,
		);
	}
	return { child, ...outcome };
};

/** The HTTP answer a test reads. */
export interface Answer {
	status: number;
	headers: IncomingHttpHeaders;
	text: string;
	/** The body as JSON; throws when it is not. */
	json(): unknown;
}

/**
 * One request on its own connection (`agent: false`), with exactly the
 * headers given — an empty value is sent as an empty header — and the body,
 * if any.
 */
export const send = (
	origin: string,
	{
		method = "GET",
		path = "/",
		headers = {},
		body,
	}: { method?: string; path?: string; headers?: OutgoingHttpHeaders; body?: string },
): Promise<Answer> =>
	new Promise((resolve, reject) => {
		const req = httpRequest(new URL(path, origin), { method, headers, agent: false }, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (chunk: Buffer) => chunks.push(chunk));
			res.on("error", reject);
			res.on("end", () => {
				const text = Buffer.concat(chunks).toString("utf8");
				resolve({
					status: res.statusCode ?? 0,
					headers: res.headers,
					text,
					json: () => JSON.parse(text),
				});
			});
		});
		req.on("error", reject);
		req.end(body);
	});

/**
 * Starts `src/app.mts` with `env` over the shipped conf, forwarding to
 * `upstream`, and resolves once it listens. Rejects, with the child's stderr,
 * when it exits first or misses the boot deadline.
 */
export const startProxy = async (
	env: Record<string, string>,
	upstream: RecordingUpstream,
): Promise<ProxyProcess> => {
	const { child, port, listened, code } = await boot({ ...env, UPSTREAM_BASEURL: upstream.origin });
	if (!listened) {
		throw new Error(`the proxy exited (${code}) before listening:\n${child.stderr()}`);
	}
	const origin = `http://127.0.0.1:${port}`;
	// Under `HTTP_PATH_PREFIX`, where the mode router is mounted and so where
	// a request is logged.
	const barrierPath = `${(env.HTTP_PATH_PREFIX ?? "/").replace(/\/$/, "")}/__log_barrier`;

	return {
		origin,
		get lines() {
			return child.lines;
		},
		get unparsed() {
			return child.unparsed;
		},
		stderr: () => child.stderr(),
		async linesFor(requestId) {
			barriers += 1;
			// Unique across the proxies that share one upstream.
			const barrierId = `log-barrier-${barriers}`;
			const answer = await send(origin, { path: barrierPath, headers: { "x-request-id": barrierId } });
			// The upstream records a request on arrival, before it answers, so a
			// barrier answered by the upstream has reached it.
			if (answer.status !== 200 || upstream.receivedFor(barrierId).length !== 1) {
				throw new Error(`the log barrier did not reach the upstream (${answer.status})`);
			}
			await child.waitForLine((line) => line.requestId === barrierId);
			return child.lines.filter((line) => line.requestId === requestId);
		},
		stop: () => stopChild(child),
	};
};

/**
 * Starts `src/app.mts` with `env` and reports how the boot ended. A child that
 * listens is stopped at once; the caller asserts `listened` is false.
 */
export const bootProxy = async (env: Record<string, string>): Promise<BootOutcome> => {
	const { child, listened, code } = await boot(env);
	if (listened) {
		await stopChild(child);
	}
	return { listened, code, stdout: child.stdout(), stderr: child.stderr() };
};
