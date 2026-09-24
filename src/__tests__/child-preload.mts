// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Preloaded with `--import` into the proxy child the composition tests start
 * (#144). Test-only. It does two things and nothing else:
 *
 * - It reports the port the child's server bound, so the child can listen on
 *   port 0: `app.mts` logs the port it was configured with, `0` there. A
 *   subscriber on Node's `net.server.listen` tracing channel writes one line
 *   to stderr once the server listens.
 * - It ties the child's life to its parent's. The parent spawns it with an IPC
 *   channel; when that channel disconnects — the test worker exited, or was
 *   killed — the child kills itself with SIGKILL. A child whose stdout lost
 *   its reader otherwise lives on as an orphan, and one that has may ignore
 *   SIGTERM while it retries a synchronous write. The channel is unref'd, so
 *   it never keeps the child alive by itself.
 *
 * Why the port is not chosen in the parent and passed in: a port probed and
 * released can be handed straight to another process's `listen(0)` on the
 * wildcard address, and on macOS the child's bind to `127.0.0.1` on that same
 * port then succeeds, taking that process's loopback connections. Port 0 in
 * the child leaves the choice to the OS, which never hands out a port in use.
 */

import { tracingChannel } from "node:diagnostics_channel";
import type { AddressInfo, Server } from "node:net";

/** The line the parent reads (`app-process.mts`). */
const LISTENING = "composition-test: listening on port";

tracingChannel<{ server: Server }>("net.server.listen").subscribe({
	start() {},
	end() {},
	asyncStart() {},
	error() {},
	asyncEnd(message) {
		const { port } = message.server.address() as AddressInfo;
		process.stderr.write(`${LISTENING} ${port}\n`);
	},
});

if (process.channel !== undefined) {
	process.once("disconnect", () => {
		process.kill(process.pid, "SIGKILL");
	});
	process.channel.unref();
}
