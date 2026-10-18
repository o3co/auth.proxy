// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The same-origin gate in front of the session cache: `isSameOriginRequest`
 * says whether a browser request showed that it came from this proxy's own
 * pages, the condition for answering it from the cache or from a flight
 * another request started.
 *
 * The provider holds a session grant to a same-origin check, and a cache hit
 * or a joined flight never reaches the provider, so without this gate a
 * request the provider would refuse could be handed a token another request
 * obtained. A request the gate does not admit is not refused here: it asks the
 * provider itself, with its own headers, and the provider's answer is the
 * answer. The gate can only send a request to the provider; it never admits
 * one the provider has not seen an admitted request for.
 *
 * Admitted: an `Origin` equal to `auth.injection.publicOrigin`, or no `Origin`
 * and `Sec-Fetch-Site: same-origin`. A browser sets both and a page cannot
 * forge either. Either signal, when present, can only refuse: a different
 * `Origin` is evidence the request came from elsewhere, whatever
 * `Sec-Fetch-Site` says, and a `Sec-Fetch-Site` other than `same-origin` is the
 * same evidence, whatever `Origin` says. So the gate never admits what either
 * signal tells the provider to refuse, and while `publicOrigin` is unset no
 * request with an `Origin` is admitted.
 */

import type { CallerContext } from "./session-grant-client.mjs";

export const isSameOriginRequest = (
	caller: Pick<CallerContext, "origin" | "secFetchSite">,
	publicOrigin: string | null,
): boolean => {
	if (caller.secFetchSite !== null && caller.secFetchSite !== "same-origin") return false;
	return caller.origin !== null
		? publicOrigin !== null && caller.origin === publicOrigin
		: caller.secFetchSite === "same-origin";
};
