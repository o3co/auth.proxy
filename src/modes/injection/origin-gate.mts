// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The same-origin gate in front of the session cache: `createSameOriginGate`
 * builds, once per router from `auth.injection.publicOrigin`, the function
 * that says whether a browser request showed that it came from this proxy's
 * own pages, the condition for answering it from the cache or from a flight
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
 * It decides as the provider's check does, from what the proxy can see:
 *
 *   - The scheme this proxy vouches for (`request-source.mts`) must be
 *     `auth.injection.publicOrigin`'s, and `https` while it is unset. The
 *     provider refuses a plain-http request when its cookies are secure, which
 *     the proxy cannot see, so it requires the scheme the public origin names.
 *   - The origins `Origin` and `Referer` name must all be `publicOrigin`. A
 *     `Referer` that does not parse as a URL, or whose origin is opaque
 *     (`null`), names none. An `Origin` of `null` is kept as named, so it
 *     refuses: the provider would read it as naming none, and refusing what
 *     the provider admits only sends the request to the provider.
 *   - `Sec-Fetch-Site`, when present, must be `same-origin`.
 *   - Then: an `Origin` equal to `publicOrigin`, or `Sec-Fetch-Site:
 *     same-origin`.
 *
 * A browser sets these headers and a page cannot forge them. Each can only
 * refuse when it disagrees, so while `publicOrigin` is unset no request with
 * an `Origin` or a `Referer` naming an origin is admitted.
 */

import type { CallerContext } from "./session-grant-client.mjs";

/** The origin a `Referer` names; `null` for one that is not a URL or whose origin is opaque. */
const refererOrigin = (referer: string | null): string | null => {
	if (referer === null) return null;
	const origin = URL.parse(referer)?.origin;
	return origin === undefined || origin === "null" ? null : origin;
};

/** What the gate reads of a request. */
export type SameOriginSignals = Pick<CallerContext, "origin" | "secFetchSite" | "referer" | "protocol">;

/** Whether a request may be answered from the session cache or a flight another request started. */
export type SameOriginGate = (caller: SameOriginSignals) => boolean;

/**
 * The gate for `publicOrigin`, which is read here, once: its scheme is what
 * every request's must be. Throws on a `publicOrigin` that is not a URL, which
 * the schema has already refused.
 */
export const createSameOriginGate = (publicOrigin: string | null): SameOriginGate => {
	const scheme = publicOrigin === null ? "https" : new URL(publicOrigin).protocol.slice(0, -1);
	return (caller) => {
		if (caller.protocol !== scheme) return false;
		const named = [caller.origin, refererOrigin(caller.referer)].filter((origin) => origin !== null);
		if (named.some((origin) => origin !== publicOrigin)) return false;
		if (caller.secFetchSite !== null && caller.secFetchSite !== "same-origin") return false;
		return (caller.origin !== null && caller.origin === publicOrigin) || caller.secFetchSite === "same-origin";
	};
};
