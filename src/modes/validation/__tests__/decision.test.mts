// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The validation decision on its own (#95 F3): `decideValidation` takes the
 * two header values and the injectable deps, and returns `forward` or
 * `reject` for the middleware to apply. Nothing here touches Express or
 * `fetch`; the wire shape of each outcome and the real introspection call are
 * pinned by `router.test.mts` and `introspect.test.mts`.
 */
import { describe, expect, it, vi } from "vitest";
import type { Logger } from "../../../logger.mjs";
import {
	decideValidation,
	type ValidationDeps,
	type ValidationInputs,
	type ValidationOutcome,
} from "../decision.mjs";
import { IntrospectHttpError, type IntrospectionResult } from "../introspection-client.mjs";

const fakeLogger = () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() });
type FakeLogger = ReturnType<typeof fakeLogger>;

const makeDeps = () => {
	const logger: FakeLogger & Logger = fakeLogger();
	const introspect = vi.fn<(token: string, requestId: string) => Promise<IntrospectionResult>>();
	const deps: ValidationDeps = { introspect, logger };
	return { deps, logger, introspect };
};

const inputs = (authorization: string | undefined, requestId = "rid-1"): ValidationInputs => ({
	requestId,
	authorization,
});

describe("decideValidation", () => {
	describe("forward without consulting the provider", () => {
		it.each([undefined, ""])("forwards when Authorization is %j", async (authorization) => {
			const { deps, introspect, logger } = makeDeps();
			const outcome = await decideValidation(inputs(authorization), deps);
			expect(outcome).toEqual<ValidationOutcome>({ kind: "forward" });
			expect(introspect).not.toHaveBeenCalled();
			expect(logger.error).not.toHaveBeenCalled();
		});
	});

	describe("reject without consulting the provider", () => {
		it.each([
			["the scheme is case-sensitive", "Basic dXNlcjpwYXNz"],
			["the scheme is case-sensitive", "bearer t"],
			// The scheme is right and there is no credential behind it. What
			// makes these worth pinning here rather than only on the parser:
			// they are the headers a parser regression would turn into an empty
			// token, and an empty token must not reach the provider as `token=`.
			["the scheme carries no token", "Bearer"],
			["the scheme carries no token", "Bearer "],
			["a second space leaves the token empty", "Bearer  t"],
		])("answers 400 Invalid Token Type to %j (%s)", async (_reason, authorization) => {
			const { deps, introspect } = makeDeps();
			const outcome = await decideValidation(inputs(authorization), deps);
			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 400,
				body: { code: 400, message: "Invalid Token Type" },
			});
			expect(introspect).not.toHaveBeenCalled();
		});
	});

	describe("introspection", () => {
		it("forwards an active token, handing the introspector the first SP-delimited word and the request id", async () => {
			const { deps, introspect, logger } = makeDeps();
			introspect.mockResolvedValueOnce({ active: true });
			const outcome = await decideValidation(inputs("Bearer abc extra", "rid-7"), deps);
			expect(outcome).toEqual<ValidationOutcome>({ kind: "forward" });
			expect(introspect).toHaveBeenCalledTimes(1);
			expect(introspect).toHaveBeenCalledWith("abc", "rid-7");
			expect(logger.error).not.toHaveBeenCalled();
		});

		it.each([{ active: "false" }, { active: 1 }, { active: "true" }])(
			"answers 401 Invalid Token when a supplied introspector resolves a non-boolean active (%j), never forwarding on truthiness",
			async (result) => {
				const { deps, introspect } = makeDeps();
				introspect.mockResolvedValueOnce(result as unknown as IntrospectionResult);
				const outcome = await decideValidation(inputs("Bearer t"), deps);
				expect(outcome).toMatchObject({ kind: "reject", status: 401, body: { code: 401 } });
			},
		);

		it("answers 401 Invalid Token to an inactive token, logging nothing at error", async () => {
			const { deps, introspect, logger } = makeDeps();
			introspect.mockResolvedValueOnce({ active: false });
			const outcome = await decideValidation(inputs("Bearer t"), deps);
			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 401,
				body: { code: 401, message: "Invalid Token" },
			});
			expect(logger.error).not.toHaveBeenCalled();
		});

		it("answers 401 Invalid Token when the provider answers 401, logging the failure with the request id", async () => {
			const { deps, introspect, logger } = makeDeps();
			const err = new IntrospectHttpError(401, "introspect failed: 401");
			introspect.mockRejectedValueOnce(err);
			const outcome = await decideValidation(inputs("Bearer t"), deps);
			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 401,
				body: { code: 401, message: "Invalid Token" },
			});
			expect(logger.error).toHaveBeenCalledWith(
				{ "x-request-id": "rid-1", error: err },
				"introspect failed",
			);
		});

		it.each([
			{ failure: "an IntrospectHttpError with another status", err: new IntrospectHttpError(503, "introspect failed: 503") },
			{ failure: "a rejection that is not an IntrospectHttpError", err: new Error("socket hang up") },
		])("answers 500 Internal Server Error on $failure, logging it", async ({ err }) => {
			const { deps, introspect, logger } = makeDeps();
			introspect.mockRejectedValueOnce(err);
			const outcome = await decideValidation(inputs("Bearer t"), deps);
			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 500,
				body: { code: 500, message: "Internal Server Error" },
			});
			expect(logger.error).toHaveBeenCalledWith(
				{ "x-request-id": "rid-1", error: err },
				"introspect failed",
			);
		});
	});
});
