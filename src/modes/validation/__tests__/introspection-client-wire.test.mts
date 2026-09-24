// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The introspection client through Node's own `fetch`, against a fake
 * provider on a real socket (#143).
 *
 * `introspection-client.test.mts` pins the same contract against a stubbed
 * `fetch` that returns hand-built responses; this file pins what that stub
 * cannot show: that `redirect: "manual"` sends nothing further on the wire,
 * that a body past the bound or never finished releases its connection,
 * that `AbortSignal.timeout` ends a call on a real socket, and what reaches
 * the provider.
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
	createIntrospectionClient,
	IntrospectHttpError,
	type IntrospectionClientConfig,
	MAX_INTROSPECTION_BODY_BYTES,
} from "../introspection-client.mjs";

const PATH = "/oauth/introspect";
const TOKEN = "tok-3f9a+/=";

describe("createIntrospectionClient on the wire", () => {
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

	const client = (overrides: Partial<IntrospectionClientConfig> = {}) =>
		createIntrospectionClient({
			url: fake.url(PATH),
			timeoutMs: 5000,
			credentials: null,
			...overrides,
		});

	/** The rejection, which must be an `IntrospectHttpError`. */
	const refusal = async (promise: Promise<unknown>): Promise<IntrospectHttpError> => {
		const err = await promise.then(
			() => {
				throw new Error("expected the call to be refused");
			},
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(IntrospectHttpError);
		return err as IntrospectHttpError;
	};

	describe("what reaches the provider", () => {
		it("one form-encoded POST carrying the token, the request id and the token as Bearer", async () => {
			fake.respond(PATH, json(200, { active: true }));

			await client().introspect(TOKEN, "rid-7c1e");

			expect(fake.requests).toHaveLength(1);
			const [req] = fake.requests;
			expect(req.method).toBe("POST");
			expect(req.path).toBe(PATH);
			expect(req.headers["content-type"]).toBe("application/x-www-form-urlencoded");
			expect(req.headers.authorization).toBe(`Bearer ${TOKEN}`);
			expect(req.headers["x-request-id"]).toBe("rid-7c1e");
			expect(req.headers.cookie).toBeUndefined();
			expect(req.body.toString("utf8")).toBe("token=tok-3f9a%2B%2F%3D");
			expect(new URLSearchParams(req.body.toString("utf8")).get("token")).toBe(TOKEN);
		});

		it("the proxy's Basic header instead, when client credentials are configured", async () => {
			fake.respond(PATH, json(200, { active: true }));

			await client({ credentials: { clientId: "proxy", clientSecret: "s3cret" } }).introspect(TOKEN, "r");

			const [req] = fake.requests;
			expect(req.headers.authorization).toBe(`Basic ${Buffer.from("proxy:s3cret").toString("base64")}`);
			expect(new URLSearchParams(req.body.toString("utf8")).get("token")).toBe(TOKEN);
		});
	});

	describe("a 200", () => {
		it("returns a valid RFC 7662 response as it stands", async () => {
			fake.respond(PATH, json(200, { active: true, sub: "user-1", scope: "read" }));

			await expect(client().introspect(TOKEN, "r")).resolves.toEqual({
				active: true,
				sub: "user-1",
				scope: "read",
			});
		});

		it("returns a body that trickles in, once it ends", async () => {
			fake.respond(PATH, {
				status: 200,
				headers: { "Content-Type": "application/json" },
				body: { trickle: ['{"act', 'ive":', "false", "}"] },
			});

			await expect(client().introspect(TOKEN, "r")).resolves.toEqual({ active: false });
		});

		for (const [label, body] of [
			["a body that is not JSON", "<html>oops</html>"],
			["an empty body", ""],
			["a JSON array", "[]"],
			["a non-boolean active", '{"active":"true"}'],
		] as const) {
			it(`is a 502 for ${label}`, async () => {
				fake.respond(PATH, { status: 200, body });

				const err = await refusal(client().introspect(TOKEN, "r"));

				expect(err.status).toBe(502);
				expect(err.refusedCredential).toBeNull();
			});
		}

		it("is a 502 for a body that does not stop, and the connection is closed rather than read to the end", async () => {
			fake.respond(PATH, { status: 200, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(client().introspect(TOKEN, "r"));

			expect(err.status).toBe(502);
			expect(err.message).toMatch(/size bound/);
			await fake.requests[0].connectionClosed;
		});

		it("reads a body of exactly the bound", async () => {
			const prefix = '{"active":true,"pad":"';
			const suffix = '"}';
			const pad = "p".repeat(MAX_INTROSPECTION_BODY_BYTES - prefix.length - suffix.length);
			fake.respond(PATH, { status: 200, body: { trickle: [prefix, pad, suffix] } });

			await expect(client().introspect(TOKEN, "r")).resolves.toMatchObject({ active: true });
		});

		it("is a 502 for a body that times out mid-read, and the connection is closed", async () => {
			fake.respond(PATH, { status: 200, body: { trickle: ['{"active":'], finish: "hold" } });
			const timeout = timeoutAfterResponseHeaders();
			try {
				const err = await refusal(client().introspect(TOKEN, "r"));

				expect(err.status).toBe(502);
				await fake.requests[0].connectionClosed;
			} finally {
				timeout.restore();
			}
		});

		it("is a 502 for a connection dropped mid-body", async () => {
			fake.respond(PATH, { status: 200, body: { trickle: ['{"active":'], finish: "drop" } });

			const err = await refusal(client().introspect(TOKEN, "r"));

			expect(err.status).toBe(502);
		});
	});

	describe("a refusal keeps the provider's status", () => {
		for (const status of [400, 403, 404, 429, 500, 503]) {
			it(`${status}, with no refused credential`, async () => {
				fake.respond(PATH, json(status, { error: "x" }, { "Retry-After": "30" }));

				const err = await refusal(client().introspect(TOKEN, "r"));

				expect(err.status).toBe(status);
				expect(err.refusedCredential).toBeNull();
			});
		}

		it("401 names the inbound token when it was the credential", async () => {
			fake.respond(PATH, json(401, { error: "invalid_token" }));

			const err = await refusal(client().introspect(TOKEN, "r"));

			expect(err.status).toBe(401);
			expect(err.refusedCredential).toBe("token");
		});

		it("401 names the proxy's client when its credentials were presented", async () => {
			fake.respond(PATH, json(401, { error: "invalid_client" }));

			const err = await refusal(
				client({ credentials: { clientId: "proxy", clientSecret: "s3cret" } }).introspect(TOKEN, "r"),
			);

			expect(err.status).toBe(401);
			expect(err.refusedCredential).toBe("client");
		});

		it("releases a refusal body that does not stop: the connection is closed, not held", async () => {
			fake.respond(PATH, { status: 503, body: { repeat: "x".repeat(4096) } });

			const err = await refusal(client().introspect(TOKEN, "r"));

			expect(err.status).toBe(503);
			await fake.requests[0].connectionClosed;
		});

		it("releases a refusal body that stops mid-way at once, rather than at the timeout", async () => {
			fake.respond(PATH, { status: 503, body: { trickle: ['{"error":'], finish: "hold" } });

			const err = await refusal(client({ timeoutMs: 60_000 }).introspect(TOKEN, "r"));

			expect(err.status).toBe(503);
			await fake.requests[0].connectionClosed;
		});
	});

	describe("a redirect is not followed", () => {
		for (const status of [301, 302, 303, 307, 308]) {
			it(`${status} to the same origin: one request, and the status comes back`, async () => {
				fake.respond(PATH, redirect(status, "/moved/introspect"));
				fake.respond("/moved/introspect", json(200, { active: true }));

				const err = await refusal(client().introspect(TOKEN, "r"));

				expect(err.status).toBe(status);
				expect(fake.requests.map((r) => r.path)).toEqual([PATH]);
			});

			it(`${status} to another origin: nothing reaches it`, async () => {
				elsewhere.respond(PATH, json(200, { active: true }));
				fake.respond(PATH, redirect(status, elsewhere.url(PATH)));

				const err = await refusal(client().introspect(TOKEN, "r"));

				expect(err.status).toBe(status);
				expect(fake.requests).toHaveLength(1);
				expect(elsewhere.requests).toHaveLength(0);
			});
		}
	});

	describe("a call that never answered is a 502, the failure kept as the cause", () => {
		it("a timeout before the headers, on the real timer", async () => {
			// A fake of its own: a request the timer abandons before the fake has
			// read it must not land in another test's record.
			const silent = await startFakeProvider();
			try {
				silent.respond(PATH, { hang: true });

				const err = await refusal(client({ url: silent.url(PATH), timeoutMs: 50 }).introspect(TOKEN, "r"));

				expect(err.status).toBe(502);
				expect(err.cause).toMatchObject({ name: "TimeoutError" });
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

				const err = await refusal(client().introspect(TOKEN, "r"));

				expect(err.status).toBe(502);
				expect(err.cause).toMatchObject({ name: "TimeoutError" });
				await fake.requests[0].connectionClosed;
			} finally {
				timeout.restore();
			}
		});

		it("a refused connection", async () => {
			const gone = await startFakeProvider();
			const url = gone.url(PATH);
			await gone.close();

			const err = await refusal(client({ url }).introspect(TOKEN, "r"));

			expect(err.status).toBe(502);
			expect(err.cause).toBeInstanceOf(TypeError);
		});

		it("a URL carrying credentials, which fetch refuses without sending anything", async () => {
			const url = fake.url(PATH).replace("http://", "http://user:pass@");

			const err = await refusal(client({ url }).introspect(TOKEN, "r"));

			expect(err.status).toBe(502);
			expect(err.cause).toBeInstanceOf(TypeError);
			expect(fake.requests).toHaveLength(0);
		});
	});
});
