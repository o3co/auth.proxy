// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import type { RequestHandler } from "express";

export interface RequestIdOptions {
	/** Header to read and echo. Compared lowercased, as Node stores it. */
	header?: string;
	/** Override the id source; the tests use it, and so can a deployment. */
	generator?: () => string;
}

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
 * An inbound id is reused rather than replaced: the caller has already logged
 * it, and minting a second one for the same request severs the trace at this
 * hop. The id is echoed onto the response so the caller can correlate a
 * request it did not label itself.
 */
export function createRequestIdMiddleware(options?: RequestIdOptions): RequestHandler {
	const headerKey = (options?.header ?? "x-request-id").toLowerCase();
	const generate = options?.generator ?? defaultGenerator;

	return (req, res, next) => {
		const requestId = (req.headers[headerKey] as string | undefined) ?? generate();
		req.headers[headerKey] = requestId;
		res.setHeader(headerKey, requestId);
		next();
	};
}
