// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { STATUS_CODES } from "node:http";
import type { Logger } from "../../logger.mjs";
import type { ModeRefusals } from "../../router/refusal.mjs";

/**
 * The shared stages' refusals in this mode's vocabulary: the
 * `{ "error", "error_description" }` body every injection refusal has, with
 * the stage's reason as the `error` code, and `injection.*` events with the
 * error as a string under `error`, as every injection failure line has it. A
 * body over the limit is the caller's to fix, as is any other `4xx`, so both
 * are logged at info; anything else is the proxy or its upstream failing, at
 * error.
 */
export const stageRefusals = (logger: Logger): ModeRefusals => ({
	log: (requestId, refusal) => {
		if (refusal.reason === "body_too_large") {
			const { limitBytes, contentLength } = refusal;
			logger.info(
				{ requestId, event: "injection.body_too_large", limitBytes, contentLength },
				"request body over the limit",
			);
			return;
		}
		const { error } = refusal;
		const line = {
			requestId,
			event: "injection.request_failed",
			error: error instanceof Error ? error.message : String(error),
		};
		if (refusal.status < 500) logger.info(line, "request failed");
		else logger.error(line, "request failed");
	},
	body: (refusal) =>
		refusal.reason === "body_too_large"
			? { error: "body_too_large", error_description: "request body over the limit" }
			: {
					error: "request_failed",
					error_description: STATUS_CODES[refusal.status] ?? "request failed",
				},
});
