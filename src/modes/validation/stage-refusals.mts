// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { STATUS_CODES } from "node:http";
import type { Logger } from "../../logger.mjs";
import type { ModeRefusals } from "../../router/refusal.mjs";

/**
 * The shared stages' refusals in this mode's vocabulary: the
 * `{ "code", "message" }` body every validation refusal has, and
 * `validation.*` events with the `Error` itself under `error`. A body over
 * the limit is the caller's to fix, as is any other `4xx`, so both are logged
 * at info; anything else is a `5xx`, logged at error — the proxy or its
 * upstream failing, or a request the proxy cannot forward (`501`).
 */
export const stageRefusals = (logger: Logger): ModeRefusals => ({
	log: (requestId, refusal) => {
		if (refusal.reason === "body_too_large") {
			const { limitBytes, contentLength } = refusal;
			logger.info(
				{ requestId, event: "validation.body_too_large", limitBytes, contentLength },
				"request body over the limit",
			);
			return;
		}
		const line = { requestId, event: "validation.request_failed", error: refusal.error };
		if (refusal.status < 500) logger.info(line, "request failed");
		else logger.error(line, "request failed");
	},
	body: (refusal) => ({ code: refusal.status, message: STATUS_CODES[refusal.status] ?? "Error" }),
});
