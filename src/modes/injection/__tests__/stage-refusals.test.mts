// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The shared stages' refusals as injection says them (`stage-refusals.mts`):
 * `injection.*` events with the error as a string under `error`, as every
 * injection failure line has it, and the `{ "error", "error_description" }`
 * body every injection refusal has, the stage's reason as the code.
 */
import { describe, expect, it, vi } from "vitest";
import { stageRefusals } from "../stage-refusals.mjs";

const makeLogger = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() });

describe("injection's stage refusals", () => {
	it("logs a body over the limit at info, and answers body_too_large", () => {
		const logger = makeLogger();
		const refusals = stageRefusals(logger);
		const refusal = { reason: "body_too_large", status: 413, limitBytes: 1024 } as const;

		refusals.log("rid-1", refusal);

		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-1", event: "injection.body_too_large", limitBytes: 1024, contentLength: undefined },
			"request body over the limit",
		);
		expect(refusals.body(refusal)).toEqual({
			error: "body_too_large",
			error_description: "request body over the limit",
		});
	});

	it("logs a 4xx failure at info, with the error's message under error", () => {
		const logger = makeLogger();

		stageRefusals(logger).log("rid-2", {
			reason: "request_failed",
			status: 400,
			error: new Error("request aborted"),
		});

		expect(logger.info).toHaveBeenCalledWith(
			{ requestId: "rid-2", event: "injection.request_failed", error: "request aborted" },
			"request failed",
		);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("logs any other failure at error, a thrown non-Error as its string, and answers request_failed", () => {
		const logger = makeLogger();
		const refusal = { reason: "request_failed", status: 500, error: "boom" } as const;
		const refusals = stageRefusals(logger);

		refusals.log("rid-3", refusal);

		expect(logger.error).toHaveBeenCalledWith(
			{ requestId: "rid-3", event: "injection.request_failed", error: "boom" },
			"request failed",
		);
		expect(refusals.body(refusal)).toEqual({
			error: "request_failed",
			error_description: "Internal Server Error",
		});
	});
});
