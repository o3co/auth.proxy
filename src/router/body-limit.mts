// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The body limit ahead of a mode, `createBodyLimitGuard`, and the refusal it
 * shares with the error handler that ends a mode router.
 *
 * `http.bodyLimitSize` is enforced where the body is read: in the upstream
 * stage, after the mode has introspected a token or minted one. A request
 * that declares its length says up front whether it is over, so the guard
 * refuses it before the mode runs, and an oversized request spends none of
 * the provider's budget. A request that does not declare its length — a
 * chunked body — can only be measured by reading it, which the upstream
 * stage does; its refusal reaches `createErrorHandler` and is answered the
 * same way.
 */

import type { RequestHandler, Response } from "express";
import { parseByteSize } from "../byte-size.mjs";
import type { Logger } from "../logger.mjs";

/**
 * `http.bodyLimitSize` in bytes: the one number the guard, the upstream
 * stage and the error handler all enforce. The schema has refused a value
 * that is not a byte size; a config built by hand that carries one is
 * refused here, when the router is built.
 */
export const bodyLimitBytes = (config: { http: { bodyLimitSize: string } }): number => {
	const bytes = parseByteSize(config.http.bodyLimitSize);
	if (bytes === null) {
		throw new Error(
			`http.bodyLimitSize must be a byte size (got ${JSON.stringify(config.http.bodyLimitSize)})`,
		);
	}
	return bytes;
};

/** The mode a router serves, which prefixes the events it logs. */
export type RouterMode = "validation" | "injection";

/**
 * Answers `413` in the refusal shape both modes use, and logs it at info: an
 * oversized body is the caller's to fix, not the proxy failing.
 */
export const refuseBodyTooLarge = (
	res: Response,
	logger: Logger,
	fields: { requestId: unknown; mode: RouterMode; limitBytes: number; contentLength?: number },
): void => {
	const { requestId, mode, ...sizes } = fields;
	logger.info(
		{ requestId, event: `${mode}.body_too_large`, ...sizes },
		"request body over the limit",
	);
	res.status(413).json({ code: 413, message: "Payload Too Large" });
};

/**
 * Refuses a request whose declared `Content-Length` is over `limitBytes`
 * before anything after it runs. Node has already refused a request whose
 * `Content-Length` is not a number, so the header is either absent or a
 * length. A request without one passes: the upstream stage measures it.
 */
export const createBodyLimitGuard = ({
	limitBytes,
	logger,
	mode,
}: {
	limitBytes: number;
	logger: Logger;
	mode: RouterMode;
}): RequestHandler => {
	return (req, res, next) => {
		const declared = req.headers["content-length"];
		if (declared !== undefined && Number(declared) > limitBytes) {
			refuseBodyTooLarge(res, logger, {
				requestId: req.headers["x-request-id"],
				mode,
				limitBytes,
				contentLength: Number(declared),
			});
			return;
		}
		next();
	};
};
