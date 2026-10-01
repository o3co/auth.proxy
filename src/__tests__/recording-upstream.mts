// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A real upstream for the composition tests: a `node:http` server on
 * `127.0.0.1`, port 0, that records every request the proxy forwards —
 * method, target, headers (names as sent) and body — and answers each one
 * `200 {"upstream":"reached","path":<target>}`, so a test can tell an answer
 * the upstream gave from one the proxy made. Test-only: nothing outside a
 * test imports it.
 */

import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";

export interface UpstreamRequest {
	method: string;
	path: string;
	/** Node's view: names lower-cased, repeated values joined. */
	headers: IncomingHttpHeaders;
	/** Names and values as sent, alternating. */
	rawHeaders: string[];
	/** The body as received. */
	body: Buffer;
}

export interface RecordingUpstream {
	/** `http://127.0.0.1:<port>`. */
	readonly origin: string;
	/** Every request received, in order. */
	readonly requests: readonly UpstreamRequest[];
	/** The requests whose `x-request-id` is `requestId`. */
	receivedFor(requestId: string): UpstreamRequest[];
	close(): Promise<void>;
}

/**
 * A path the upstream answers by resetting the connection instead: recorded
 * like any other request, then the socket is destroyed with a reset. How a
 * composition test reaches an upstream that fails mid-exchange while the log
 * barrier, which the upstream answers, still works.
 */
export const RESET_PATH = "/__upstream_resets";

/**
 * A path the upstream starts answering — status, headers and part of a body
 * of declared length — and then closes the connection on: an answer cut off
 * after it started.
 */
export const CUT_PATH = "/__upstream_cuts_off";

/**
 * A path the upstream sends only the head for — status and headers, a coding
 * among them — and then closes the connection on, before any of the body.
 */
export const HEAD_ONLY_PATH = "/__upstream_sends_only_the_head";

/**
 * A path the upstream starts answering and then keeps open, sending nothing
 * more until the connection closes: a download a caller can leave midway.
 */
export const TRICKLE_PATH = "/__upstream_trickles";

/** The body the upstream answers `path` with. */
export const upstreamBody = (path: string): { upstream: "reached"; path: string } => ({
	upstream: "reached",
	path,
});

/** Every `[name, value]` pair in `rawHeaders` whose name is `name`, compared case-insensitively; names as sent. */
export const headerPairs = (rawHeaders: readonly string[], name: string): [string, string][] =>
	Array.from({ length: rawHeaders.length / 2 }, (_, i): [string, string] => [
		rawHeaders[2 * i],
		rawHeaders[2 * i + 1],
	]).filter(([sent]) => sent.toLowerCase() === name.toLowerCase());

export const startRecordingUpstream = async (): Promise<RecordingUpstream> => {
	const requests: UpstreamRequest[] = [];
	const server = createServer((req, res) => {
		const path = req.url ?? "";
		const chunks: Buffer[] = [];
		const recorded: UpstreamRequest = {
			method: req.method ?? "",
			path,
			headers: req.headers,
			rawHeaders: [...req.rawHeaders],
			body: Buffer.alloc(0),
		};
		// Recorded on arrival, so a request is on the list before the proxy
		// can answer anything for it.
		requests.push(recorded);
		req.on("data", (chunk: Buffer) => chunks.push(chunk));
		req.on("end", () => {
			recorded.body = Buffer.concat(chunks);
			if (path.endsWith(RESET_PATH)) {
				req.socket.resetAndDestroy();
				return;
			}
			if (path.endsWith(HEAD_ONLY_PATH)) {
				res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "gzip", "Content-Length": "100" });
				res.flushHeaders();
				req.socket.end();
				return;
			}
			if (path.endsWith(CUT_PATH)) {
				res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
				res.write('{"partial":', () => req.socket.end());
				return;
			}
			if (path.endsWith(TRICKLE_PATH)) {
				res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
				res.write('{"partial":');
				return;
			}
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify(upstreamBody(path)));
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;

	return {
		origin: `http://127.0.0.1:${port}`,
		get requests() {
			return requests;
		},
		receivedFor: (requestId) =>
			requests.filter((request) => request.headers["x-request-id"] === requestId),
		close: () =>
			new Promise<void>((resolve, reject) => {
				server.closeAllConnections();
				server.close((err) => (err ? reject(err) : resolve()));
			}),
	};
};
