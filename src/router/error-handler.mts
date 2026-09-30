// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The error handler that ends both mode routers, `createErrorHandler`.
 *
 * What reaches it is what no stage answered: the upstream stage's own
 * failures — a body over the limit that declared no length, a body that
 * ended early, a transfer coding it cannot forward (`501`), an upstream that
 * refused the connection — and anything a mode's middleware threw. Without it, express answers these with its HTML
 * page, and prints the stack to stderr outside the logger. With it, each is
 * a `StageRefusal` the mode logs and answers in its own vocabulary.
 *
 * The status is read as express reads it: the error's `status` when it is a
 * `4xx` or `5xx`, then its `statusCode`, and `500` otherwise. A `413` is the
 * body limit, refused exactly as `createBodyLimitGuard` refuses it; anything
 * else is `request_failed`.
 */

import type { ErrorRequestHandler } from "express";
import { type ModeRefusals, refuse } from "./refusal.mjs";

const isErrorStatus = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && value >= 400 && value <= 599;

/** The error's own `4xx` / `5xx` status, or `500`. */
const statusOf = (err: unknown): number => {
	if (typeof err === "object" && err !== null) {
		const { status, statusCode } = err as { status?: unknown; statusCode?: unknown };
		if (isErrorStatus(status)) return status;
		if (isErrorStatus(statusCode)) return statusCode;
	}
	return 500;
};

export const createErrorHandler = ({
	limitBytes,
	refusals,
}: {
	limitBytes: number;
	refusals: ModeRefusals;
}): ErrorRequestHandler => {
	return (err, req, res, _next) => {
		const status = statusOf(err);
		// Once the answer has started its status is spent: the failure is
		// logged, and the connection closed, which is all express would do
		// with it besides printing the stack.
		if (res.headersSent) {
			refusals.log(req.headers["x-request-id"], { reason: "request_failed", status, error: err });
			req.socket.destroy();
			return;
		}
		// The body reader stops reading the body when it gives up on it. What
		// is left is drained, as Node drains a body nothing read, so a
		// keep-alive connection reaches its next request.
		if (!req.complete) {
			req.resume();
		}
		refuse(
			req,
			res,
			refusals,
			status === 413
				? { reason: "body_too_large", status, limitBytes }
				: { reason: "request_failed", status, error: err },
		);
	};
};
