// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The jwt-bearer client through Node's own `fetch`, against a fake provider
 * on a real socket (#143).
 *
 * `jwt-bearer-client.test.mts` pins the same contract against a stubbed
 * `fetch` that returns hand-built responses; this file pins what that stub
 * cannot show: that `redirect: "manual"` sends nothing further on the wire —
 * the body carries the assertion and the header the proxy's secret — that a
 * body past its bound or never finished releases its connection, that
 * `AbortSignal.timeout` ends a call or a body read on a real socket, and what
 * reaches the provider.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
	type FakeProvider,
	json,
	redirect,
	startFakeProvider,
} from "../../../__tests__/fake-provider.mjs";
import { controlledTimeout, timeoutAfterResponseHeaders } from "../../../__tests__/provider-timeout.mjs";
import {
	createJwtBearerClient,
	JWT_BEARER_GRANT_TYPE,
	type JwtBearerClientConfig,
	JwtBearerError,
} from "../jwt-bearer-client.mjs";

const PATH = "/oauth/token";
const ASSERTION = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcCJ9.c2ln";

describe("createJwtBearerClient on the wire", () => {
	let fake: FakeProvider;
	let elsewhere: FakeProvider;

	beforeAll(async () => {
		[fake, elsewhere] = await Promise.all([startFakeProvider(), startFakeProvider()]);
	});
	afterAll(async () => {
		await Promise.all([fake.close(), elsewhere.close()]);
	});
	beforeEach(() => {
		fake.reset();
		elsewhere.reset();
	});

	const client = (overrides: Partial<JwtBearerClientConfig> = {}) =>
		createJwtBearerClient({
			providerOrigin: fake.origin,
			timeoutMs: 5000,
			clientId: "proxy-exchange",
			clientSecret: "exchange-s3cret",
			scope: "orders:read",
			audience: "https://api.example.test",
			resource: null,
			...overrides,
		});

	const exchange = (overrides: Partial<JwtBearerClientConfig> = {}) =>
		client(overrides).exchange({ assertion: ASSERTION, requestId: "rid-9d0f" });

	/** The rejection, which must be a `JwtBearerError`. */
	const refusal = async (promise: Promise<unknown>): Promise<JwtBearerError> => {
		const err = await promise.then(
			() => {
				throw new Error("expected the exchange to be refused");
			},
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(JwtBearerError);
		return err as JwtBearerError;
	};

	/** Runs `run` with the provider call timing out once the response headers are in. */
	const timingOutMidBody = async <T,>(run: () => Promise<T>): Promise<T> => {
		const timeout = timeoutAfterResponseHeaders();
		try {
			return await run();
		} finally {
			timeout.restore();
		}
	};

	describe("what reaches the provider", () => {
		it("one form-encoded POST with the assertion, authenticated by client_secret_basic, and no Cookie", async () => {
			fake.respond(PATH, json(200, { access_token: "at-1", token_type: "Bearer" }));

			await exchange();

			expect(fake.requests).toHaveLength(1);
			const [req] = fake.requests;
			expect(req.method).toBe("POST");
			expect(req.path).toBe(PATH);
			expect(req.headers["content-type"]).toBe("application/x-www-form-urlencoded");
			expect(req.headers.authorization).toBe(
				`Basic ${Buffer.from("proxy-exchange:exchange-s3cret").toString("base64")}`,
			);
			expect(req.headers.cookie).toBeUndefined();
			expect(req.headers["x-request-id"]).toBe("rid-9d0f");
			expect(req.headers.accept).toBe("application/json");
			expect(Object.fromEntries(new URLSearchParams(req.body.toString("utf8")))).toEqual({
				grant_type: JWT_BEARER_GRANT_TYPE,
				assertion: ASSERTION,
				scope: "orders:read",
				audience: "https://api.example.test",
			});
		});
	});

	describe("a 200", () => {
		it("returns the access token and expires_in", async () => {
			fake.respond(PATH, json(200, { access_token: "at-1", token_type: "Bearer", expires_in: 300 }));

			await expect(exchange()).resolves.toEqual({ accessToken: "at-1", expiresIn: 300 });
		});

		it("returns a token response that trickles in, once it ends", async () => {
			fake.respond(PATH, {
				status: 200,
				headers: { "Content-Type": "application/json" },
				body: { trickle: ['{"access_token":"at-2",', '"token_type":"bearer"', "}"] },
			});

			await expect(exchange()).resolves.toEqual({ accessToken: "at-2", expiresIn: null });
		});

		for (const [label, body] of [
			["a body that is not JSON", "<html>oops</html>"],
			["an empty body", ""],
			["no access_token", '{"token_type":"Bearer"}'],
			["no token_type", '{"access_token":"at-3"}'],
			["a DPoP token_type", '{"access_token":"at-3","token_type":"DPoP"}'],
		] as const) {
			it(`is provider_invalid_response for ${label}`, async () => {
				fake.respond(PATH, { status: 200, body });

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "provider_invalid_response", status: 502 });
			});
		}

		it("is provider_invalid_response for a body past the bound, and the connection is closed", async () => {
			fake.respond(PATH, { status: 200, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_invalid_response", status: 502 });
			await fake.requests[0].connectionClosed;
		});

		it("is provider_invalid_response for a timeout mid-body, and the connection is closed", async () => {
			fake.respond(PATH, { status: 200, body: { trickle: ['{"access_token":'], finish: "hold" } });

			const err = await timingOutMidBody(() => refusal(exchange()));

			expect(err).toMatchObject({ code: "provider_invalid_response", status: 502 });
			await fake.requests[0].connectionClosed;
		});

		it("is provider_invalid_response for a connection dropped mid-body", async () => {
			fake.respond(PATH, { status: 200, body: { trickle: ['{"access_token":'], finish: "drop" } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_invalid_response", status: 502 });
		});
	});

	describe("provider refusals", () => {
		it("400 invalid_grant is credential_rejected, passing Retry-After through", async () => {
			fake.respond(PATH, json(400, { error: "invalid_grant" }, { "Retry-After": "11" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({
				code: "credential_rejected",
				status: 401,
				retryAfter: "11",
				providerError: "invalid_grant",
			});
		});

		for (const error of ["invalid_scope", "invalid_target", "unauthorized_client"]) {
			it(`400 ${error} is exchange_not_permitted`, async () => {
				fake.respond(PATH, json(400, { error }));

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "exchange_not_permitted", status: 403, providerError: error });
			});
		}

		it("another 400 is provider_config_error", async () => {
			fake.respond(PATH, json(400, { error: "invalid_request" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({
				code: "provider_config_error",
				status: 502,
				providerError: "invalid_request",
			});
		});

		it("401 invalid_client is provider_config_error: the proxy's own authentication", async () => {
			fake.respond(PATH, json(401, { error: "invalid_client" }, { "Retry-After": "13" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({
				code: "provider_config_error",
				status: 502,
				message: "provider rejected the proxy's client authentication",
				retryAfter: "13",
				providerError: "invalid_client",
			});
		});

		it("a 401 without a body is provider_config_error as well", async () => {
			fake.respond(PATH, { status: 401 });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_config_error", status: 502, providerError: null });
		});

		it("a 400 body past the bound is provider_config_error with no code, and the connection is closed", async () => {
			fake.respond(PATH, { status: 400, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_config_error", status: 502, providerError: null });
			await fake.requests[0].connectionClosed;
		});

		it("a 400 body that times out mid-read is provider_config_error with no code", async () => {
			fake.respond(PATH, { status: 400, body: { trickle: ['{"error":"invalid_'], finish: "hold" } });

			const err = await timingOutMidBody(() => refusal(exchange()));

			expect(err).toMatchObject({ code: "provider_config_error", status: 502, providerError: null });
			await fake.requests[0].connectionClosed;
		});
	});

	describe("provider_unavailable", () => {
		for (const status of [429, 500, 503]) {
			it(`${status}, passing Retry-After through and keeping the validated code`, async () => {
				fake.respond(PATH, json(status, { error: "temporarily_unavailable" }, { "Retry-After": "120" }));

				const err = await refusal(exchange());

				expect(err).toMatchObject({
					code: "provider_unavailable",
					status: 502,
					message: `provider call failed: returned ${status}`,
					retryAfter: "120",
					providerError: "temporarily_unavailable",
				});
			});
		}

		for (const status of [403, 404]) {
			it(`${status}, as an unexpected status`, async () => {
				fake.respond(PATH, json(status, { error: "x" }));

				const err = await refusal(exchange());

				expect(err).toMatchObject({
					code: "provider_unavailable",
					status: 502,
					message: `unexpected provider response: ${status}`,
				});
			});
		}

		it("a 5xx body past the bound: no code, and the connection is closed", async () => {
			fake.respond(PATH, { status: 503, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_unavailable", status: 502, providerError: null });
			await fake.requests[0].connectionClosed;
		});

		it("a timeout before the headers, on the real timer", async () => {
			// A fake of its own: a request the timer abandons before the fake has
			// read it must not land in another test's record.
			const silent = await startFakeProvider();
			try {
				silent.respond(PATH, { hang: true });

				const err = await refusal(exchange({ providerOrigin: silent.origin, timeoutMs: 50 }));

				expect(err).toMatchObject({ code: "provider_unavailable", status: 502, retryAfter: null });
			} finally {
				await silent.close();
			}
		});

		it("a timeout while the provider holds the request, whose connection is then closed", async () => {
			const timeout = controlledTimeout();
			try {
				fake.respond(PATH, () => {
					timeout.fire();
					return { hang: true };
				});

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "provider_unavailable", status: 502, retryAfter: null });
				expect(err.message).toMatch(/timeout/);
				await fake.requests[0].connectionClosed;
			} finally {
				timeout.restore();
			}
		});

		it("a refused connection", async () => {
			const gone = await startFakeProvider();
			const providerOrigin = gone.origin;
			await gone.close();

			const err = await refusal(exchange({ providerOrigin }));

			expect(err).toMatchObject({ code: "provider_unavailable", status: 502 });
		});
	});

	describe("a redirect is not followed", () => {
		for (const status of [301, 302, 303, 307, 308]) {
			it(`${status} to the same origin: one request, and provider_config_error`, async () => {
				fake.respond(PATH, redirect(status, "/oauth/token/"));
				fake.respond("/oauth/token/", json(200, { access_token: "at-moved", token_type: "Bearer" }));

				const err = await refusal(exchange());

				expect(err).toMatchObject({
					code: "provider_config_error",
					status: 502,
					message: `provider token endpoint redirected (${status})`,
				});
				expect(fake.requests.map((r) => r.path)).toEqual([PATH]);
			});

			it(`${status} to another origin: nothing reaches it`, async () => {
				elsewhere.respond(PATH, json(200, { access_token: "at-elsewhere", token_type: "Bearer" }));
				fake.respond(PATH, redirect(status, elsewhere.url(PATH)));

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "provider_config_error", status: 502 });
				expect(fake.requests).toHaveLength(1);
				expect(elsewhere.requests).toHaveLength(0);
			});
		}

		it("releases a redirect body that does not stop: the connection is closed, not held", async () => {
			fake.respond(PATH, {
				status: 307,
				headers: { Location: "/oauth/token/" },
				body: { repeat: "x".repeat(4096) },
			});

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_config_error", status: 502 });
			await fake.requests[0].connectionClosed;
		});

		it("releases a redirect body that stops mid-way at once, rather than at the timeout", async () => {
			fake.respond(PATH, {
				status: 307,
				headers: { Location: "/oauth/token/" },
				body: { trickle: ["<html>"], finish: "hold" },
			});

			const err = await refusal(exchange({ timeoutMs: 60_000 }));

			expect(err).toMatchObject({ code: "provider_config_error", status: 502 });
			await fake.requests[0].connectionClosed;
		});
	});
});
