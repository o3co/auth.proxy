// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The validation decision on its own (#95 F3): `decideValidation` takes the
 * two header values and the injectable deps, and returns `forward` or
 * `reject` for the middleware to apply. Nothing here touches Express or
 * `fetch`; the wire shape of each outcome and the real introspection call are
 * pinned by `router.test.mts` and `introspect.test.mts`.
 */
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { createProxyLogger, type Logger } from "../../../logger.mjs";
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
// name the `error` when the request included an access token: the 401's
// `invalid_token` (#95 F29) and a malformed Bearer's `invalid_request` (F45).
// Every refusal's challenge is stated here rather than left to be read off the
// outcome tables below, which is what F27's `toEqual` on the body used to
// leave implicit.
describe("the RFC 6750 challenge", () => {
	const rejectionOf = async (
		authorization: string | undefined,
		arrange: (introspect: ReturnType<typeof makeDeps>["introspect"]) => void = () => {},
		realm: string | null = null,
	) => {
		const { deps, introspect } = makeDeps();
		arrange(introspect);
		const outcome = await decideValidation(inputs(authorization), deps, { realm });
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
	// conditioned on an access token having been included. What §3 offers
	// instead is `Bearer realm="…"`, and with no realm configured there is no
	// auth-param to satisfy its "one or more", so no challenge at all (#95 F45).
	// A lowercase `bearer` is refused by this proxy's own stricter rule
	// (`extractBearerToken`), so it is read as another method, not as malformed.
	it.each(["Basic dXNlcjpwYXNz", "bearer t", "Token t"])(
		"carries no challenge for %j when no realm is configured",
		async (authorization) => {
			expect((await rejectionOf(authorization)).challenge).toBeNull();
		},
	);

	// A `Bearer` with no usable token after it is §3.1's "otherwise malformed"
	// request: `invalid_request`, which is also the auth-param §3 needs (#95 F45).
	it.each(["Bearer", "Bearer ", "Bearer  t"])(
		"names invalid_request for the malformed Bearer %j",
		async (authorization) => {
			const outcome = await rejectionOf(authorization);

			expect(outcome.status).toBe(400);
			expect(outcome.challenge).toBe('Bearer error="invalid_request"');
		},
	);

	describe("with auth.validation.realm configured (#95 F45)", () => {
		it.each(["Basic dXNlcjpwYXNz", "bearer t"])(
			"answers %j with the realm alone, as §3.1's own example does",
			async (authorization) => {
				expect((await rejectionOf(authorization, () => {}, "api")).challenge).toBe(
					'Bearer realm="api"',
				);
			},
		);

		it("puts the realm before the error on a malformed Bearer", async () => {
			expect((await rejectionOf("Bearer", () => {}, "api")).challenge).toBe(
				'Bearer realm="api", error="invalid_request"',
			);
		});

		it("puts the realm before the error on the 401", async () => {
			const outcome = await rejectionOf(
				"Bearer t",
				(introspect) => {
					introspect.mockResolvedValueOnce({ active: false });
				},
				"api",
			);

			expect(outcome.challenge).toBe('Bearer realm="api", error="invalid_token"');
		});

		it("puts the realm before the error on the provider's own 401 too", async () => {
			const outcome = await rejectionOf(
				"Bearer t",
				(introspect) => {
					introspect.mockRejectedValueOnce(
						new IntrospectHttpError(401, "introspect returned 401", "token"),
					);
				},
				"api",
			);

			expect(outcome.challenge).toBe('Bearer realm="api", error="invalid_token"');
		});

		it("still challenges nothing on a provider failure", async () => {
			const outcome = await rejectionOf(
				"Bearer t",
				(introspect) => {
					introspect.mockRejectedValueOnce(new IntrospectHttpError(503, "introspect returned 503"));
				},
				"api",
			);

			expect(outcome.challenge).toBeNull();
		});
	});

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
			expect(outcome).toMatchObject({
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
			// and under the wrong name. At error, because the proxy's own
			// configuration is refused, not the caller's token (#134).
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ requestId: "rid-1", event: "validation.provider_config_error", error: err },
				"introspect refused the proxy's client credentials",
			);
			expect(logger.info).not.toHaveBeenCalled();
		});

		// #95 F43: a redirecting introspection endpoint is the deployment's
		// configuration, not the caller's token and not an outage — reported
		// like F7's refused client credentials.
		it.each([301, 302, 303, 307, 308])(
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
					{ requestId: "rid-1", event: "validation.provider_config_error", error: err },
					"introspect endpoint redirected",
				);
			},
		);

		// #134: a 401 about the caller's token is the caller's refusal, not the
		// proxy failing, so it is logged at info — the level the injection path
		// gives `injection.session_unauthorized`. Only the proxy's own failures
		// are errors.
		it("still answers 401 Invalid Token when the refused credential was the inbound token, logging it at info", async () => {
			const { deps, introspect, logger } = makeDeps();
			const err = new IntrospectHttpError(401, "introspect returned 401", "token");
			introspect.mockRejectedValueOnce(err);

			await expect(decideValidation(inputs("Bearer t"), deps)).resolves.toEqual({
				kind: "reject",
				status: 401,
				body: { code: 401, message: "Invalid Token" },
				challenge: 'Bearer error="invalid_token"',
			});
			expect(logger.info).toHaveBeenCalledTimes(1);
			expect(logger.info).toHaveBeenCalledWith(
				{ requestId: "rid-1", event: "validation.token_unauthorized", error: err },
				"introspect failed",
			);
			expect(logger.error).not.toHaveBeenCalled();
		});

		// The class says only a 401 carries a mark, but nothing enforces it and
		// `deps.introspect` is injectable: an out-of-contract error must not
		// reach the Provider Configuration Error branch, whose whole meaning is
		// "the provider refused our client authentication".
		it("ignores a client mark on a status that is not 401", async () => {
			const { deps, introspect } = makeDeps();
			introspect.mockRejectedValueOnce(
				new IntrospectHttpError(503, "introspect returned 503", "client"),
			);

			await expect(decideValidation(inputs("Bearer t"), deps)).resolves.toEqual({
				kind: "reject",
				status: 502,
				body: { code: 502, message: "Bad Gateway" },
				challenge: null,
			});
		});

		// A supplied introspector that marks nothing is read the way it always
		// was: its 401 is about the token, and logged as the token's (#134).
		it("answers 401 Invalid Token when the provider answers an unmarked 401, logging it at info with the request id", async () => {
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
			expect(logger.info).toHaveBeenCalledTimes(1);
			expect(logger.info).toHaveBeenCalledWith(
				{ requestId: "rid-1", event: "validation.token_unauthorized", error: err },
				"introspect failed",
			);
			expect(logger.error).not.toHaveBeenCalled();
		});

		// #95 F42: what the provider did is a 502, as on the injection path;
		// only what the proxy did not expect is a 500.
		it.each([
			{ failure: "the provider's 503", err: new IntrospectHttpError(503, "introspect returned 503") },
			{ failure: "the provider's 429", err: new IntrospectHttpError(429, "introspect returned 429") },
			{ failure: "the provider's 400", err: new IntrospectHttpError(400, "introspect returned 400") },
			{ failure: "a 200 that is not an introspection response", err: new IntrospectHttpError(502, "introspect returned 200 but …") },
			{ failure: "a call that never answered", err: new IntrospectHttpError(502, "introspect call failed: timeout") },
		])("answers 502 Bad Gateway on $failure, logging it at error", async ({ err }) => {
			const { deps, introspect, logger } = makeDeps();
			introspect.mockRejectedValueOnce(err);
			const outcome = await decideValidation(inputs("Bearer t"), deps);
			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 502,
				body: { code: 502, message: "Bad Gateway" },
				challenge: null,
			});
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ requestId: "rid-1", event: "validation.provider_error", error: err },
				"introspect failed",
			);
			expect(logger.info).not.toHaveBeenCalled();
		});

		it.each([
			{ failure: "a rejection that is not an IntrospectHttpError", err: new Error("socket hang up") },
			{ failure: "a thrown non-Error", err: "boom" },
		])("answers 500 Internal Server Error on $failure, logging it at error", async ({ err }) => {
			const { deps, introspect, logger } = makeDeps();
			introspect.mockRejectedValueOnce(err);
			const outcome = await decideValidation(inputs("Bearer t"), deps);
			expect(outcome).toEqual<ValidationOutcome>({
				kind: "reject",
				status: 500,
				body: { code: 500, message: "Internal Server Error" },
				challenge: null,
			});
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ requestId: "rid-1", event: "validation.unexpected_error", error: err },
				"introspect failed",
			);
		});
	});
});

// #95 F48: the fake logger above records the Error object, so it could not see
// that the real one wrote `"error":{…}` with no message, stack or cause. This
// one reads the line the proxy actually emits.
describe("the failure line on the real logger", () => {
	it("carries the error's message, status and cause", async () => {
		const stream = new PassThrough();
		const lines: string[] = [];
		stream.on("data", (chunk: Buffer) => lines.push(chunk.toString()));
		const logger = createProxyLogger({ destination: stream, level: "error" });
		const refused = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:1"), {
			code: "ECONNREFUSED",
		});
		const introspect = vi.fn(async (): Promise<IntrospectionResult> => {
			throw new IntrospectHttpError(502, "introspect call failed: fetch failed", null, new TypeError("fetch failed", { cause: refused }));
		});

		await decideValidation(inputs("Bearer t"), { introspect, logger });
		await new Promise((resolve) => setImmediate(resolve));

		const entry = JSON.parse(lines.join("").trim());
		expect(entry.msg).toBe("introspect failed");
		// The one vocabulary both modes log in (#134): `requestId` and `event`,
		// never the header name.
		expect(entry.requestId).toBe("rid-1");
		expect(entry.event).toBe("validation.provider_error");
		expect(entry).not.toHaveProperty("x-request-id");
		expect(entry.error).toMatchObject({
			type: "IntrospectHttpError",
			message: "introspect call failed: fetch failed",
			status: 502,
			cause: { message: "fetch failed", cause: { code: "ECONNREFUSED" } },
		});
	});

	// #134: the level says whose failure it was. The caller's token refused by
	// the provider is info, as `injection.session_unauthorized` is; the
	// provider refusing the proxy's own client is the deployment's, so error.
	// Read off the emitted line, where pino's numeric level is what a query
	// matches (30 info, 50 error).
	it.each([
		{
			refused: "the inbound token",
			err: new IntrospectHttpError(401, "introspect returned 401", "token"),
			level: 30,
			event: "validation.token_unauthorized",
		},
		{
			refused: "the proxy's own client",
			err: new IntrospectHttpError(401, "introspect returned 401", "client"),
			level: 50,
			event: "validation.provider_config_error",
		},
	])("logs a provider 401 that refused $refused at level $level", async ({ err, level, event }) => {
		const stream = new PassThrough();
		const lines: string[] = [];
		stream.on("data", (chunk: Buffer) => lines.push(chunk.toString()));
		const logger = createProxyLogger({ destination: stream, level: "info" });
		const introspect = vi.fn(async (): Promise<IntrospectionResult> => {
			throw err;
		});

		await decideValidation(inputs("Bearer t"), { introspect, logger });
		await new Promise((resolve) => setImmediate(resolve));

		const entries = lines.join("").trim().split("\n").map((line) => JSON.parse(line));
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({ level, event, requestId: "rid-1" });
		expect(entries[0].error).toMatchObject({ type: "IntrospectHttpError", status: 401 });
	});
});
