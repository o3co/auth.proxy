// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A request that sends `Expect: 100-continue` and holds its body back until
 * the server says `100 Continue`, as curl does for a large upload, on a raw
 * socket so the interim answer is visible. Test-only: nothing outside a test
 * imports it.
 */
import { connect } from "node:net";

export interface ContinueExchange {
	/** Every status line the server sent, interim ones included, in order. */
	statusLines: string[];
	/** The body of the final answer. */
	body: string;
	/** Whether the body was sent: only after a `100 Continue`. */
	bodySent: boolean;
}

/**
 * Sends `head` (the request line and headers, `Expect: 100-continue` among
 * them) and writes `body` only once `100 Continue` arrives. Resolves once the
 * final answer is complete or the connection closes.
 */
export const expectContinue = (origin: string, head: string, body: Buffer): Promise<ContinueExchange> =>
	new Promise((resolve, reject) => {
		const { hostname, port } = new URL(origin);
		const socket = connect(Number(port), hostname);
		let received = "";
		let bodySent = false;
		const settle = () => {
			const statusLines = received.split("\r\n").filter((line) => /^HTTP\/1\.1 \d{3}/.test(line));
			const final = received.lastIndexOf("\r\n\r\n");
			resolve({ statusLines, body: final === -1 ? "" : received.slice(final + 4), bodySent });
			socket.destroy();
		};
		socket.on("data", (part: Buffer) => {
			received += part.toString("latin1");
			if (!bodySent && received.includes("HTTP/1.1 100 Continue\r\n\r\n")) {
				bodySent = true;
				socket.write(body);
			}
			const heads = received.match(/HTTP\/1\.1 (\d{3})[^\r]*\r\n/g) ?? [];
			const finalHead = heads.find((line) => !line.startsWith("HTTP/1.1 100"));
			const lengthMatch = /\r\ncontent-length: (\d+)\r\n/i.exec(received.slice(received.lastIndexOf(finalHead ?? "\u0000")));
			if (finalHead && lengthMatch) {
				const bodyStart = received.indexOf("\r\n\r\n", received.lastIndexOf(finalHead)) + 4;
				if (Buffer.byteLength(received.slice(bodyStart), "latin1") >= Number(lengthMatch[1])) settle();
			}
		});
		socket.on("close", settle);
		socket.on("error", reject);
		socket.write(head);
	});
