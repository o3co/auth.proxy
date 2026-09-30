// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The shared stages' refusals as validation says them (`stage-refusals.mts`):
 * `validation.*` events with the `Error` itself under `error`, and the
 * `{ "code", "message" }` body every validation refusal has.
 */
import { describe, expect, it, vi } from "vitest";
import { stageRefusals } from "../stage-refusals.mjs";

const makeLogger = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() });

describe("validation's stage refusals", () => {
	it("logs a body over the limit at info, and answers 413 Payload Too Large", () => {
		const logger = makeLogger();
		const refusals = stageRefusals(logger);
		const refusal = { reason: "body_too_large", status: 413, limitBytes: 1024, contentLength: 4096 } as const;

		refusals.log("rid-1", refusal);

		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-1", event: "validation.body_too_large", limitBytes: 1024, contentLength: 4096 },
			"request body over the limit",
		);
		expect(refusals.body(refusal)).toEqual({ code: 413, message: "Payload Too Large" });
	});

	it("logs a 4xx failure at info, with the Error under error", () => {
		const logger = makeLogger();
		const error = new Error("request aborted");

		stageRefusals(logger).log("rid-2", { reason: "request_failed", status: 400, error });

		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-2", event: "validation.request_failed", error },
			"request failed",
		);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("logs any other failure at error, with the Error under error, and answers its reason phrase", () => {
		const logger = makeLogger();
		const error = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
		const refusal = { reason: "request_failed", status: 500, error } as const;
		const refusals = stageRefusals(logger);

		refusals.log("rid-3", refusal);

		expect(logger.error).toHaveBeenCalledWith(
			{ requestId: "rid-3", event: "validation.request_failed", error },
			"request failed",
		);
		expect(refusals.body(refusal)).toEqual({ code: 500, message: "Internal Server Error" });
	});
});
