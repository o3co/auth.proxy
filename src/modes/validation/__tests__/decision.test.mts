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

// RFC 6750 §3 makes `WWW-Authenticate` a MUST on a refusal and a SHOULD to
// name the `error` when the request included an access token. Only one of
// this path's four refusals meets that second condition (#95 F29) — the other
// three are stated here rather than left to be read off the outcome tables
// below, which is what F27's `toEqual` on the body used to leave implicit.
describe("the RFC 6750 challenge", () => {
	const rejectionOf = async (
		authorization: string | undefined,
		arrange: (introspect: ReturnType<typeof makeDeps>["introspect"]) => void = () => {},
	) => {
		const { deps, introspect } = makeDeps();
		arrange(introspect);
		const outcome = await decideValidation(inputs(authorization), deps);
		if (outcome.kind !== "reject") throw new Error(`expected a reject, got ${outcome.kind}`);
		return outcome;
	};

	it("names invalid_token when the provider says the token is not live", async () => {
		const outcome = await rejectionOf("Bearer t", (introspect) => {
			introspect.mockResolvedValueOnce({ active: false });
		});

		expect(outcome.challenge).toBe('Bearer error="invalid_token"');
	});

	it("names invalid_token when the provider refuses the token itself", async () => {
		const outcome = await rejectionOf("Bearer t", (introspect) => {
			introspect.mockRejectedValueOnce(
				new IntrospectHttpError(401, "introspect returned 401", "token"),
			);
		});

		expect(outcome.challenge).toBe('Bearer error="invalid_token"');
	});

	// §3.1's last paragraph: a request that "attempted using an unsupported
	// authentication method" SHOULD NOT carry an error code, and §3's SHOULD is
	// conditioned on an access token having been included. Answering
	// `Bearer realm="…"` instead needs a name nothing configures, so this
	// refusal carries no challenge at all — tracked as F45 on #95.
	it.each(["Basic dXNlcjpwYXNz", "bearer t", "Bearer", "Bearer  t"])(
		"carries no challenge for %j, which included no access token",
		async (authorization) => {
			expect((await rejectionOf(authorization)).challenge).toBeNull();
		},
	);

	// A failure of the proxy or the provider is not a statement about the
	// caller's credential, so there is nothing to challenge them with: a
	// client that re-authenticated would be answering the wrong question.
	it.each([
		[
			"the proxy's own client credentials were refused",
			new IntrospectHttpError(401, "introspect returned 401", "client"),
		],
		["the provider is unavailable", new IntrospectHttpError(503, "introspect returned 503")],
	])("carries no challenge when %s", async (_label, err) => {
		const outcome = await rejectionOf("Bearer t", (introspect) => {
			introspect.mockRejectedValueOnce(err);
		});

		expect(outcome.challenge).toBeNull();
	});
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
				challenge: null,
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
				challenge: 'Bearer error="invalid_token"',
			});
			expect(logger.error).not.toHaveBeenCalled();
		});

		// Without client credentials the inbound token IS the introspection
		// credential, so the provider's 401 is about it. With them the proxy
		// authenticates as itself, and a 401 means the provider refused the
		// proxy — an operator's configuration, not the caller's token (#95 F7).
		it("answers 502 when the provider refused the proxy's own client credentials", async () => {
			const { deps, introspect, logger } = makeDeps();
			const err = new IntrospectHttpError(401, "introspect returned 401", "client");
			introspect.mockRejectedValueOnce(err);

			const outcome = await decideValidation(inputs("Bearer t"), deps);

			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 502,
				body: { code: 502, message: "Provider Configuration Error" },
				challenge: null,
			});
			// One line, not both: the generic `introspect failed` must not also
			// fire, or an operator filtering on it sees the config error twice
			// and under the wrong name.
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ "x-request-id": "rid-1", error: err },
				"introspect refused the proxy's client credentials",
			);
		});

		// #95 F43: a redirecting introspection endpoint is the deployment's
		// configuration, not the caller's token and not an outage — reported
		// like F7's refused client credentials.
		it.each([301, 302, 307, 308])(
			"answers 502 Provider Configuration Error when the endpoint redirects (%d)",
			async (status) => {
				const { deps, introspect, logger } = makeDeps();
				const err = new IntrospectHttpError(status, `introspect returned ${status}`);
				introspect.mockRejectedValueOnce(err);

				const outcome = await decideValidation(inputs("Bearer t"), deps);

				expect(outcome).toEqual<ValidationOutcome>({
					kind: "reject",
					status: 502,
					body: { code: 502, message: "Provider Configuration Error" },
					challenge: null,
				});
				expect(logger.error).toHaveBeenCalledTimes(1);
				expect(logger.error).toHaveBeenCalledWith(
					{ "x-request-id": "rid-1", error: err },
					"introspect endpoint redirected",
				);
			},
		);

		it("still answers 401 Invalid Token when the refused credential was the inbound token", async () => {
			const { deps, introspect, logger } = makeDeps();
			const err = new IntrospectHttpError(401, "introspect returned 401", "token");
			introspect.mockRejectedValueOnce(err);

			await expect(decideValidation(inputs("Bearer t"), deps)).resolves.toEqual({
				kind: "reject",
				status: 401,
				body: { code: 401, message: "Invalid Token" },
				challenge: 'Bearer error="invalid_token"',
			});
			expect(logger.error).toHaveBeenCalledWith(
				{ "x-request-id": "rid-1", error: err },
				"introspect failed",
			);
		});

		// The class says only a 401 carries a mark, but nothing enforces it and
		// `deps.introspect` is injectable: an out-of-contract error must not
		// reach the 502 branch, whose whole meaning is "the provider refused our
		// client authentication".
		it("ignores a client mark on a status that is not 401", async () => {
			const { deps, introspect } = makeDeps();
			introspect.mockRejectedValueOnce(
				new IntrospectHttpError(503, "introspect returned 503", "client"),
			);

			await expect(decideValidation(inputs("Bearer t"), deps)).resolves.toEqual({
				kind: "reject",
				status: 500,
				body: { code: 500, message: "Internal Server Error" },
				challenge: null,
			});
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
				challenge: 'Bearer error="invalid_token"',
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
				challenge: null,
			});
			expect(logger.error).toHaveBeenCalledWith(
				{ "x-request-id": "rid-1", error: err },
				"introspect failed",
			);
		});
	});
});
