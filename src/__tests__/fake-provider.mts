// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A fake provider on a real socket, for tests that drive the proxy's provider
 * clients through Node's own `fetch` (#143). Test-only: nothing outside a test
 * imports it.
 *
 * A `node:http` server on `127.0.0.1`, port 0. Each test programs what a path
 * answers, and the fake records every request it receives — method, target,
 * headers and raw body — together with the connection that carried it, so a
 * test can see whether a request was followed by another, which connection a
 * client reused, and when the client let a connection go.
 *
 * What an answer can be, beyond a status, headers and a body: a body that
 * trickles in chunks, one that stops mid-way and holds the connection open,
 * one that is dropped mid-way, one that never stops (it streams until the
 * client goes away), and no answer at all. Nothing here depends on how fast a
 * client reads: a body is past a bound because it never ends, not because it
 * arrived slowly, and a read times out because the fake never finishes it.
 *
 * A second instance serves as a cross-origin redirect target: its origin
 * differs from the first's by port.
 */

import {
	createServer,
	type IncomingHttpHeaders,
	type IncomingMessage,
	type OutgoingHttpHeaders,
	type ServerResponse,
} from "node:http";
import type { AddressInfo, Socket } from "node:net";

/** A request as the fake received it. */
export interface RecordedRequest {
	method: string;
	/** The request target as sent: the path and any query. */
	path: string;
	/**
	 * Node's view: names lower-cased. A repeated header is joined, except
	 * those Node keeps only once (`authorization`, `content-type` and others),
	 * whose repeats are dropped; `rawHeaders` has every one.
	 */
	headers: IncomingHttpHeaders;
	/** Names and values as sent, alternating. */
	rawHeaders: string[];
	/** The body as received, byte for byte. */
	body: Buffer;
	/** Which connection carried it: 1 for the first the fake accepted, and so on. */
	connection: number;
	/** Resolves once that connection's socket has closed, from either side. */
	connectionClosed: Promise<void>;
}

/**
 * A response body.
 *
 * - A string or bytes: sent whole, with a `Content-Length`.
 * - `trickle`: each chunk written `intervalMs` (default 10) after the
 *   previous one, chunked. Then, by `finish`: `"end"` (the default) ends
 *   the body; `"hold"` leaves it open and never ends it; `"drop"` destroys
 *   the connection mid-body.
 * - `repeat`: the chunk written again and again, honouring backpressure, until
 *   the client closes the connection. A body no bound can hold.
 */
export type FakeBody =
	| string
	| Uint8Array
	| {
			trickle: readonly (string | Uint8Array)[];
			intervalMs?: number;
			finish?: "end" | "hold" | "drop";
	  }
	| { repeat: string | Uint8Array };

/** An answer, or `{ hang: true }` for none: the headers never come. */
export type FakeResponse =
	| { status: number; headers?: OutgoingHttpHeaders; body?: FakeBody }
	| { hang: true };

/**
 * What a path answers: a fixed response, or one computed from the request —
 * asynchronously if the test wants to hold the answer back.
 */
export type Responder =
	| FakeResponse
	| ((req: RecordedRequest) => FakeResponse | Promise<FakeResponse>);

export interface FakeProvider {
	/** `http://127.0.0.1:<port>`. */
	readonly origin: string;
	/** `path` on this fake's origin. */
	url(path: string): string;
	/**
	 * Programs what `path` answers, for any method and query, until it is
	 * programmed again or the fake is reset. A path nobody programmed answers
	 * `404`, and the request is recorded all the same.
	 */
	respond(path: string, responder: Responder): void;
	/** Every request received, in the order its body completed. */
	readonly requests: readonly RecordedRequest[];
	/**
	 * Forgets the programmed answers and the recorded requests. Connections
	 * stay. Throws if a responder threw since the last reset: the fake answers
	 * that by dropping the connection, which a client reports as the provider
	 * being unreachable — an outcome tests expect — so a bug in a test's
	 * responder would otherwise pass as one. Call it in `afterEach`.
	 */
	reset(): void;
	/** Drops every connection and stops listening. */
	close(): Promise<void>;
}

/** A JSON body, with its `Content-Type`. */
export const json = (
	status: number,
	body: unknown,
	headers: OutgoingHttpHeaders = {},
): FakeResponse => ({
	status,
	headers: { "Content-Type": "application/json", ...headers },
	body: JSON.stringify(body),
});

/** A redirect to `location`, absolute or relative. */
export const redirect = (status: number, location: string): FakeResponse => ({
	status,
	headers: { Location: location },
	body: "",
});

const readBody = (req: IncomingMessage): Promise<Buffer> =>
	new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => chunks.push(chunk));
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Writes `body` to `res`; returns once it has been written, or the client left. */
const writeBody = async (res: ServerResponse, body: FakeBody | undefined): Promise<void> => {
	if (body === undefined || typeof body === "string" || body instanceof Uint8Array) {
		res.end(body);
		return;
	}
	// `res.closed` is the response's own close, which follows the socket's.
	if ("repeat" in body) {
		const chunk = body.repeat;
		await new Promise<void>((resolve) => {
			res.once("close", resolve);
			const pump = (): void => {
				while (!res.closed && res.write(chunk)) {
					// keep writing until the socket pushes back
				}
				if (!res.closed) {
					res.once("drain", pump);
				}
			};
			pump();
		});
		return;
	}
	const { trickle, intervalMs = 10, finish = "end" } = body;
	for (const [i, chunk] of trickle.entries()) {
		if (res.closed) {
			return;
		}
		if (i > 0) {
			await delay(intervalMs);
		}
		// Each chunk reaches the socket before the next step: a "drop" that
		// ran while it was still buffered would drop it, and the client would see
		// the connection close before the headers rather than mid-body.
		await new Promise<void>((resolve) => res.write(chunk, () => resolve()));
	}
	if (finish === "end") {
		res.end();
	} else if (finish === "drop") {
		res.socket?.destroy();
	}
	// "hold": the body stays open until the client or `close` ends it.
};

export const startFakeProvider = async (): Promise<FakeProvider> => {
	let responders = new Map<string, Responder>();
	let requests: RecordedRequest[] = [];
	let responderErrors: unknown[] = [];
	const connections = new WeakMap<Socket, { id: number; closed: Promise<void> }>();
	let connectionCount = 0;

	const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
		const body = await readBody(req);
		// Every socket is registered on "connection", which precedes its requests.
		const connection = connections.get(req.socket);
		if (connection === undefined) {
			throw new Error("fake provider: a request arrived on a socket it never registered");
		}
		const recorded: RecordedRequest = {
			method: req.method ?? "",
			path: req.url ?? "",
			headers: req.headers,
			rawHeaders: [...req.rawHeaders],
			body,
			connection: connection.id,
			connectionClosed: connection.closed,
		};
		requests.push(recorded);

		const pathname = new URL(recorded.path, "http://fake.invalid").pathname;
		const responder = responders.get(pathname);
		let response: FakeResponse;
		try {
			response =
				responder === undefined
					? json(404, { error: "not_found", path: pathname })
					: typeof responder === "function"
						? await responder(recorded)
						: responder;
		} catch (error) {
			responderErrors.push(error);
			throw error;
		}
		if ("hang" in response) {
			return;
		}
		if (res.closed) {
			return;
		}
		res.writeHead(response.status, response.headers);
		await writeBody(res, response.body);
	};

	// A request the client abandoned mid-body, or a responder that threw, ends
	// its connection rather than surfacing as an unhandled rejection in
	// whichever test happens to be running.
	const server = createServer((req, res) => {
		handle(req, res).catch(() => res.socket?.destroy());
	});

	server.on("connection", (socket: Socket) => {
		connectionCount += 1;
		connections.set(socket, {
			id: connectionCount,
			closed: new Promise<void>((resolve) => socket.once("close", () => resolve())),
		});
	});

	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	const origin = `http://127.0.0.1:${port}`;

	return {
		origin,
		url: (path) => new URL(path, origin).toString(),
		respond(path, responder) {
			responders.set(path, responder);
		},
		get requests() {
			return requests;
		},
		reset() {
			const errors = responderErrors;
			responders = new Map();
			requests = [];
			responderErrors = [];
			if (errors.length > 0) {
				throw new AggregateError(errors, "fake provider: a responder threw");
			}
		},
		close: () =>
			new Promise<void>((resolve, reject) => {
				server.closeAllConnections();
				server.close((err) => (err ? reject(err) : resolve()));
			}),
	};
};
