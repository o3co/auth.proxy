// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The request-id middleware, `createRequestIdMiddleware`: it settles one id
 * per request — the caller's when it is within bounds, a fresh one otherwise —
 * writes it back into `req.headers` and echoes it on the response.
 */

import crypto from "node:crypto";
import type { RequestHandler } from "express";

export interface RequestIdOptions {
	/** Header to read and echo. Compared lowercased, as Node stores it. */
	header?: string;
	/** Override the id source; the tests use it, and so can a deployment. */
	generator?: () => string;
}

/**
 * An inbound id this proxy reuses: 1 to 200 characters, each an RFC 3986
 * unreserved character (`ALPHA DIGIT - . _ ~`) or one of base64's `+ / =`.
 *
 * The id goes on every log line about the request and on every call the
 * proxy makes for it, so the caller must not choose its size or put in it what
 * a log reader or a header parser would read as structure: whitespace, a
 * control character, a quote, a backslash, a `,` or `;` separator, a non-ASCII
 * byte. The set still admits the forms in common use — UUID, ULID, base64 and
 * base64url, W3C trace ids, this proxy's own — and 200 is Heroku's bound for
 * the same header.
 */
const ACCEPTED_ID = /^[A-Za-z0-9\-._~+/=]{1,200}$/;

/**
 * A timestamp prefix so ids sort by arrival in a log search, plus uuid
 * entropy so two requests in the same second stay distinct.
 */
function defaultGenerator(): string {
	const ts = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
	const uid = crypto.randomUUID().replace(/-/g, "");
	return `${ts}_${uid}`;
}

/**
 * Correlates a request across the proxy's logs and its upstream call.
 *
 * An inbound id is reused rather than replaced when it is within bounds
 * ({@link ACCEPTED_ID}): the caller has already logged it, and minting a
 * second one for the same request severs the trace at this hop. An id out of
 * bounds is replaced by a fresh one, as an absent one is, and not logged —
 * that would put back on the log line what the bound keeps off it. The id is
 * echoed onto the response, so the caller can correlate a request it did not
 * label itself or whose id was replaced.
 */
export function createRequestIdMiddleware(options?: RequestIdOptions): RequestHandler {
	const headerKey = (options?.header ?? "x-request-id").toLowerCase();
	const generate = options?.generator ?? defaultGenerator;

	return (req, res, next) => {
		// Node types an inbound header `string | string[]`, so take the first
		// value of an array rather than let one reach `res.setHeader` and the
		// log fields. Node itself joins a repeated `x-request-id` into one
		// string with ", ", which the bound refuses. An empty value is out of
		// bounds too: echoing it back gives the caller nothing to correlate on.
		const inbound = req.headers[headerKey];
		const supplied = Array.isArray(inbound) ? inbound[0] : inbound;
		const requestId = supplied !== undefined && ACCEPTED_ID.test(supplied) ? supplied : generate();
		req.headers[headerKey] = requestId;
		res.setHeader(headerKey, requestId);
		next();
	};
}
