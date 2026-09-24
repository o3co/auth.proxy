// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The session-grant client through Node's own `fetch`, against a fake
 * provider on a real socket (#143).
 *
 * `session-grant-client.test.mts` pins the same contract against a stubbed
 * `fetch` that returns hand-built responses; this file pins what that stub
 * cannot show: that `redirect: "manual"` sends nothing further on the wire,
 * that a body past its bound or never finished releases its connection, that
 * `AbortSignal.timeout` ends a call — or a body read — on a real socket, and
 * what reaches the provider.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
	type FakeProvider,
	json,
	redirect,
	startFakeProvider,
} from "../../../__tests__/fake-provider.mjs";
import { controlledTimeout, timeoutAfterResponseHeaders } from "../../../__tests__/provider-timeout.mjs";
import { MAX_ERROR_BODY_BYTES } from "../provider-error.mjs";
import {
	createSessionGrantClient,
	type SessionGrantClientConfig,
	SessionGrantError,
} from "../session-grant-client.mjs";
import { MAX_TOKEN_BODY_BYTES } from "../token-endpoint.mjs";

const PATH = "/oauth/token";
const COOKIE_VALUE = "sess-5b2d";

describe("createSessionGrantClient on the wire", () => {
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

	const client = (overrides: Partial<SessionGrantClientConfig> = {}) =>
		createSessionGrantClient({
			providerOrigin: fake.origin,
			clientId: "proxy-client",
			scope: "openid profile",
			sessionCookieName: "sid",
			timeoutMs: 5000,
			...overrides,
		});

	const exchange = (overrides: Partial<SessionGrantClientConfig> = {}) =>
		client(overrides).exchange({ sessionCookieValue: COOKIE_VALUE, requestId: "rid-4e8b" });

	/** The rejection, which must be a `SessionGrantError`. */
	const refusal = async (promise: Promise<unknown>): Promise<SessionGrantError> => {
		const err = await promise.then(
			() => {
				throw new Error("expected the grant to be refused");
			},
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(SessionGrantError);
		return err as SessionGrantError;
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
		it("one form-encoded POST with the session as the only cookie, and no Authorization", async () => {
			fake.respond(PATH, json(200, { access_token: "at-1", token_type: "Bearer" }));

			await exchange();

			expect(fake.requests).toHaveLength(1);
			const [req] = fake.requests;
			expect(req.method).toBe("POST");
			expect(req.path).toBe(PATH);
			expect(req.headers["content-type"]).toBe("application/x-www-form-urlencoded");
			expect(req.headers.cookie).toBe(`sid=${COOKIE_VALUE}`);
			expect(req.headers.authorization).toBeUndefined();
			expect(req.headers["x-request-id"]).toBe("rid-4e8b");
			expect(req.headers.accept).toBe("application/json");
			expect(Object.fromEntries(new URLSearchParams(req.body.toString("utf8")))).toEqual({
				grant_type: "session",
				client_id: "proxy-client",
				scope: "openid profile",
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
				body: { trickle: ['{"access_', 'token":"at-2",', '"expires_in":60}'] },
			});

			await expect(exchange()).resolves.toEqual({ accessToken: "at-2", expiresIn: 60 });
		});

		for (const [label, body] of [
			["a body that is not JSON", "<html>oops</html>"],
			["an empty body", ""],
			["no access_token", '{"token_type":"Bearer"}'],
		] as const) {
			it(`is provider_invalid_response for ${label}`, async () => {
				fake.respond(PATH, { status: 200, body });

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "provider_invalid_response", status: 502 });
			});
		}

		it("is provider_invalid_response for a body past MAX_TOKEN_BODY_BYTES, and the connection is closed", async () => {
			fake.respond(PATH, { status: 200, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_invalid_response", status: 502 });
			expect(MAX_TOKEN_BODY_BYTES).toBe(64 * 1024);
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

	it("refuses a 204 as an unexpected status", async () => {
		fake.respond(PATH, { status: 204 });

		const err = await refusal(exchange());

		expect(err).toMatchObject({
			code: "provider_unavailable",
			status: 502,
			message: "unexpected provider response: 204",
		});
	});

	describe("a 400", () => {
		it("invalid_grant is the expired session", async () => {
			fake.respond(PATH, json(400, { error: "invalid_grant" }, { "Retry-After": "5" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "session_unauthorized", status: 401, retryAfter: "5" });
		});

		it("anything else is provider_config_error, relaying a safe error_description", async () => {
			fake.respond(PATH, json(400, { error: "invalid_scope", error_description: "scope not allowed" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({
				code: "provider_config_error",
				status: 502,
				message: "scope not allowed",
			});
		});

		it("with a body past MAX_ERROR_BODY_BYTES is provider_config_error, and the connection is closed", async () => {
			fake.respond(PATH, { status: 400, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_config_error", status: 502 });
			expect(MAX_ERROR_BODY_BYTES).toBe(16 * 1024);
			await fake.requests[0].connectionClosed;
		});

		it("with a body that times out mid-read is provider_config_error", async () => {
			fake.respond(PATH, { status: 400, body: { trickle: ['{"error":'], finish: "hold" } });

			const err = await timingOutMidBody(() => refusal(exchange()));

			expect(err).toMatchObject({ code: "provider_config_error", status: 502 });
			await fake.requests[0].connectionClosed;
		});
	});

	describe("a 401", () => {
		it("is the expired session, passing Retry-After through", async () => {
			fake.respond(PATH, json(401, { error: "unauthorized" }, { "Retry-After": "7" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "session_unauthorized", status: 401, retryAfter: "7" });
		});

		it("invalid_client is the proxy's own client refused: provider_config_error", async () => {
			fake.respond(PATH, json(401, { error: "invalid_client" }, { "Retry-After": "9" }));

			const err = await refusal(exchange());

			expect(err).toMatchObject({
				code: "provider_config_error",
				status: 502,
				message: "provider rejected the proxy's client (client_id)",
				retryAfter: "9",
			});
		});

		it("with a body past the bound is the expired session, and the connection is closed", async () => {
			fake.respond(PATH, { status: 401, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "session_unauthorized", status: 401 });
			await fake.requests[0].connectionClosed;
		});

		it("with a body that times out mid-read is the expired session, and the connection is closed", async () => {
			fake.respond(PATH, { status: 401, body: { trickle: ['{"error":"invalid_'], finish: "hold" } });

			const err = await timingOutMidBody(() => refusal(exchange()));

			expect(err).toMatchObject({ code: "session_unauthorized", status: 401 });
			await fake.requests[0].connectionClosed;
		});
	});

	describe("provider_unavailable", () => {
		for (const status of [429, 500, 503]) {
			it(`${status}, passing Retry-After through`, async () => {
				fake.respond(PATH, json(status, { error: "x" }, { "Retry-After": "120" }));

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "provider_unavailable", status: 502, retryAfter: "120" });
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

		it("releases a 5xx body that does not stop: the connection is closed, not held", async () => {
			fake.respond(PATH, { status: 503, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(exchange());

			expect(err).toMatchObject({ code: "provider_unavailable", status: 502 });
			await fake.requests[0].connectionClosed;
		});

		it("releases a 5xx body that stops mid-way at once, rather than at the timeout", async () => {
			fake.respond(PATH, { status: 503, body: { trickle: ['{"error":'], finish: "hold" } });

			const err = await refusal(exchange({ timeoutMs: 60_000 }));

			expect(err).toMatchObject({ code: "provider_unavailable", status: 502 });
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
				fake.respond("/oauth/token/", json(200, { access_token: "at-moved" }));

				const err = await refusal(exchange());

				expect(err).toMatchObject({
					code: "provider_config_error",
					status: 502,
					message: `provider token endpoint redirected (${status})`,
				});
				expect(fake.requests.map((r) => r.path)).toEqual([PATH]);
			});

			it(`${status} to another origin: nothing reaches it`, async () => {
				elsewhere.respond(PATH, json(200, { access_token: "at-elsewhere" }));
				fake.respond(PATH, redirect(status, elsewhere.url(PATH)));

				const err = await refusal(exchange());

				expect(err).toMatchObject({ code: "provider_config_error", status: 502 });
				expect(fake.requests).toHaveLength(1);
				expect(elsewhere.requests).toHaveLength(0);
			});
		}
	});
});
