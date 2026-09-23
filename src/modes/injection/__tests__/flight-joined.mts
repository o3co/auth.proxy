import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type express from "express";

/**
 * Listens `app` and resolves `joined` once `count` requests have joined a
 * single-flight — a causal signal instead of a sleep (#95 F46).
 *
 * The reasoning is the F10 test's in `router.test.mts`: Express is the
 * server's first "request" listener, and nothing between it and
 * `SingleFlight.run` waits on I/O — the cookie parse, the assertion parse,
 * the cache read and the flight's table check are synchronous, and the only
 * hops are the microtasks from the router into the decision. So once this
 * later listener has seen `count` requests and one `setImmediate` has
 * passed, every one of them is in the flight, however loaded the runner is.
 * A sleep was a guess at how long that takes, and under the full suite it
 * was seen to guess wrong.
 */
export const listenForFlight = async (
	app: express.Express,
	count: number,
): Promise<{ server: Server; baseURL: string; joined: Promise<void> }> => {
	const server = app.listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	let arrived = 0;
	const allArrived = new Promise<void>((resolve) => {
		server.on("request", () => {
			arrived += 1;
			if (arrived === count) resolve();
		});
	});
	const { port } = server.address() as AddressInfo;
	return {
		server,
		baseURL: `http://127.0.0.1:${port}`,
		joined: allArrived.then(() => new Promise<void>((resolve) => setImmediate(resolve))),
	};
};
