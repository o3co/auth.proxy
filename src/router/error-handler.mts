// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The error handler that ends both mode routers, `createErrorHandler`.
 *
 * What reaches it is what no stage answered: the upstream stage's own
 * failures — a body over the limit that declared no length, a body that
 * ended early, an upstream that refused the connection — and anything a
 * mode's middleware threw. Without it, express answers these with its HTML
 * page and logs nothing. With it, each is answered in the refusal shape both
 * modes use, `{ "code", "message" }`, and logged with the request id.
 *
 * The status is the error's own when it carries a `4xx` or `5xx` (`status`
 * or `statusCode`, as express reads it), and `500` otherwise. A `413` is the
 * body limit, answered and logged exactly as `createBodyLimitGuard` answers
 * it. Any other error is `<mode>.request_failed`: at info for a `4xx`, which
 * is about the request, and at error otherwise.
 */

import { STATUS_CODES } from "node:http";
import type { ErrorRequestHandler } from "express";
import type { Logger } from "../logger.mjs";
import { type RouterMode, refuseBodyTooLarge } from "./body-limit.mjs";

/** The error's own `4xx` / `5xx` status, or `500`. */
const statusOf = (err: unknown): number => {
	if (typeof err === "object" && err !== null) {
		const { status, statusCode } = err as { status?: unknown; statusCode?: unknown };
		const own = typeof status === "number" ? status : statusCode;
		if (typeof own === "number" && Number.isInteger(own) && own >= 400 && own <= 599) return own;
	}
	return 500;
};

export const createErrorHandler = ({
	limitBytes,
	logger,
	mode,
}: {
	limitBytes: number;
	logger: Logger;
	mode: RouterMode;
}): ErrorRequestHandler => {
	return (err, req, res, next) => {
		const requestId = req.headers["x-request-id"];
		const status = statusOf(err);
		if (status === 413 && !res.headersSent) {
			refuseBodyTooLarge(res, logger, { requestId, mode, limitBytes });
			return;
		}
		const log = status < 500 ? logger.info : logger.error;
		log.call(logger, { requestId, event: `${mode}.request_failed`, error: err }, "request failed");
		// Once the answer has started its status is spent: express closes the
		// connection instead.
		if (res.headersSent) {
			next(err);
			return;
		}
		res.status(status).json({ code: status, message: STATUS_CODES[status] ?? "Error" });
	};
};
