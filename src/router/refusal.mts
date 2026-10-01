// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The contract between the stages both mode routers share and the mode that
 * mounts them. A stage decides that a request is refused and why — a
 * `StageRefusal` — and the mode says it in its own vocabulary: the log line
 * (its events, its `error` field) and the body (validation's
 * `{ "code", "message" }`, injection's `{ "error", "error_description" }`).
 * The stages never name an event or build a body themselves.
 */

import type { Request, Response } from "express";

/** Why a shared stage refused a request, with the status it is answered with. */
export type StageRefusal =
	/** The body is over `http.bodyLimitSize`: declared up front, or found while reading it. */
	| { reason: "body_too_large"; status: 413; limitBytes: number; contentLength?: number }
	/**
	 * The upstream could not be reached or dropped the exchange: `502`, or
	 * `504` when it timed out. Before its answer started, the refusal answers
	 * the caller; partway through it, the status is spent, and the refusal is
	 * only logged as the caller's connection is closed. `error` is what the
	 * connection threw.
	 */
	| { reason: "upstream_unavailable"; status: 502 | 504; error: unknown }
	/** Anything else that reached the end of the router unanswered. */
	| { reason: "request_failed"; status: number; error: unknown };

/** How a mode says a shared stage's refusal. */
export interface ModeRefusals {
	/** Logs the refusal as the mode's own event, with the request id. */
	log(requestId: unknown, refusal: StageRefusal): void;
	/** The JSON body that answers it. */
	body(refusal: StageRefusal): object;
}

/** Logs `refusal` and answers it, both in the mode's vocabulary. */
export const refuse = (
	req: Request,
	res: Response,
	refusals: ModeRefusals,
	refusal: StageRefusal,
): void => {
	refusals.log(req.headers["x-request-id"], refusal);
	res.status(refusal.status).json(refusals.body(refusal));
};
