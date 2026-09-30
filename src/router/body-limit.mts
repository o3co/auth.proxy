// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The body limit ahead of a mode, `createBodyLimitGuard`; the byte count
 * every stage enforces, `bodyLimitBytes`; and `continueWithinLimit`, the
 * server's `checkContinue` listener, which says `100 Continue` exactly to the
 * requests the guard lets through. The listener is not a stage of a mode:
 * `app.mts` installs it on the server, where Node asks it before any router
 * runs.
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
 * The declared `Content-Length`, when it is over `limitBytes`; `null` when
 * the request declares none or one within the limit. The guard refuses
 * exactly these requests, and the listener says `100 Continue` to exactly the
 * others, so one test decides both.
 */
const declaredOverLimit = (req: IncomingMessage, limitBytes: number): number | null => {
	const declared = req.headers["content-length"];
	return declared !== undefined && Number(declared) > limitBytes ? Number(declared) : null;
};

/**
 * Refuses a request whose declared `Content-Length` is over `limitBytes`
 * before anything after it runs. Node has already refused a request whose
 * `Content-Length` is not a length, or that carries it with
 * `Transfer-Encoding`, so the header is either absent or a length. A request
 * without one passes: the upstream stage measures it. Node drains the unread
 * body once the refusal is sent, so a keep-alive connection goes on — except
 * for a request that expected `100-continue` and was not told to send its
 * body, whose connection Node closes after the refusal.
 */
export const createBodyLimitGuard = ({
	limitBytes,
	refusals,
}: {
	limitBytes: number;
	refusals: ModeRefusals;
}): RequestHandler => {
	return (req, res, next) => {
		const contentLength = declaredOverLimit(req, limitBytes);
		if (contentLength !== null) {
			refuse(req, res, refusals, { reason: "body_too_large", status: 413, limitBytes, contentLength });
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
 * told to send, and is refused there, in the mode's own shape, before a
 * client that waits for the go-ahead sends its body; Node closes the
 * connection after that answer. A client that sends the body without waiting,
 * as RFC 9110 §10.1.1 allows, may meet the closed connection before it reads
 * the refusal.
 */
export const continueWithinLimit =
	(limitBytes: number, handle: RequestListener) =>
	(req: IncomingMessage, res: ServerResponse): void => {
		if (declaredOverLimit(req, limitBytes) === null) {
			res.writeContinue();
		}
		handle(req, res);
	};
