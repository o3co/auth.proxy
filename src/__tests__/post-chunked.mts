// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A POST whose body declares no length: `Transfer-Encoding: chunked`, each
 * chunk written on its own. supertest always declares one, and the body
 * limit ahead of a mode reads only a declared length, so the chunked path
 * needs its own client. Test-only: nothing outside a test imports it.
 */
import { request as httpRequest, type OutgoingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

export interface ChunkedAnswer {
	status: number;
	headers: Record<string, string | string[] | undefined>;
	text: string;
}

/** Listens `app` on an ephemeral port, sends the chunks, and closes it once answered. */
export const postChunked = async (
	app: Express,
	path: string,
	headers: OutgoingHttpHeaders,
	chunks: Buffer[],
): Promise<ChunkedAnswer> => {
	const server: Server = await new Promise((resolve) => {
		const s = app.listen(0, "127.0.0.1", () => resolve(s));
	});
	try {
		const { port } = server.address() as AddressInfo;
		return await new Promise<ChunkedAnswer>((resolve, reject) => {
			const req = httpRequest(
				{
					host: "127.0.0.1",
					port,
					path,
					method: "POST",
					agent: false,
					// A caller's own `transfer-encoding` (another coding before
					// `chunked`) is sent as given; Node frames the body in chunks either way.
					headers: { "transfer-encoding": "chunked", ...headers },
				},
				(res) => {
					const parts: Buffer[] = [];
					res.on("data", (part: Buffer) => parts.push(part));
					res.on("error", reject);
					res.on("end", () =>
						resolve({
							status: res.statusCode ?? 0,
							headers: res.headers,
							text: Buffer.concat(parts).toString("utf8"),
						}),
					);
				},
			);
			req.on("error", reject);
			for (const chunk of chunks) req.write(chunk);
			req.end();
		});
	} finally {
		server.closeAllConnections();
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
};
