// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The body limit ahead of a mode, `createBodyLimitGuard`, and the byte count
 * every stage enforces, `bodyLimitBytes`.
 *
 * `http.bodyLimitSize` is enforced where the body is read: in the upstream
 * stage, after the mode has introspected a token or minted one. A request
 * that declares its length says up front whether it is over, so the guard
 * refuses it before the mode runs, and an oversized request spends none of
 * the provider's budget. A request that does not declare its length — a
 * chunked body — can only be measured by reading it, which the upstream
 * stage does; its refusal reaches `createErrorHandler` and is refused the
 * same way.
 */

import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";
import type { RequestHandler } from "express";
import { parseByteSize } from "../byte-size.mjs";
import { type ModeRefusals, refuse } from "./refusal.mjs";

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

/**
 * Refuses a request whose declared `Content-Length` is over `limitBytes`
 * before anything after it runs. Node has already refused a request whose
 * `Content-Length` is not a length, or that carries it with
 * `Transfer-Encoding`, so the header is either absent or a length. A request
 * without one passes: the upstream stage measures it. Node drains the unread
 * body once the refusal is sent, so a keep-alive connection goes on.
 */
export const createBodyLimitGuard = ({
	limitBytes,
	refusals,
}: {
	limitBytes: number;
	refusals: ModeRefusals;
}): RequestHandler => {
	return (req, res, next) => {
		const declared = req.headers["content-length"];
		if (declared !== undefined && Number(declared) > limitBytes) {
			refuse(req, res, refusals, {
				reason: "body_too_large",
				status: 413,
				limitBytes,
				contentLength: Number(declared),
			});
			return;
		}
		next();
	};
};

/**
 * The server's `checkContinue` listener: the body limit for a request that
 * sends `Expect: 100-continue` and waits to be told to send its body. Node
 * says `100 Continue` itself unless a listener is installed, so without this
 * one an oversized upload is invited, sent in full, and only then refused.
 *
 * It says `100 Continue` when the declared length is within the limit, or
 * none is declared, and hands the request to `handle` either way. An
 * oversized one reaches `createBodyLimitGuard` without the client having been
 * told to send, and is refused there, in the mode's own shape, before its
 * body is sent; Node closes the connection after that answer.
 */
export const continueWithinLimit =
	(limitBytes: number, handle: RequestListener) =>
	(req: IncomingMessage, res: ServerResponse): void => {
		const declared = req.headers["content-length"];
		if (declared === undefined || Number(declared) <= limitBytes) {
			res.writeContinue();
		}
		handle(req, res);
	};
