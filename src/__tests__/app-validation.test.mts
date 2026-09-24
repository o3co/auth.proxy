// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Validation mode as it runs (#144): `src/app.mts` in a child process,
 * configured by environment variables over the shipped conf, in front of a
 * recording upstream, asking the fake provider over the real `fetch`.
 * Nothing is mocked — not a router, a client, `fetch` or the schema.
 *
 * Each configuration the README distinguishes gets its own process: without
 * client credentials, with `CLIENT_ID` / `CLIENT_SECRET`, and with
 * `VALIDATION_REALM`. Each is sent the request shapes validation answers,
 * and each case asserts the answer (status, body, `WWW-Authenticate`), what
 * the upstream received (its `Authorization`, names as sent), what the
 * provider received (the endpoint, the credential, the form) and the log
 * events written for the request.
 *
 * The expected values are the documented contract, not the code's: the
 * README's challenge table and "What a provider 401 means", the validation
 * README's invariants 1 and 8, and the v0.7.0 CHANGELOG.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { type ProxyProcess, SUITE_TIMEOUT_MS, send, startProxy } from "./app-process.mjs";
import { type FakeProvider, type FakeResponse, json, redirect, startFakeProvider } from "./fake-provider.mjs";
import {
	headerPairs,
	type RecordingUpstream,
	startRecordingUpstream,
	upstreamBody,
} from "./recording-upstream.mjs";

// Above the harness's boot deadline and stop grace, so a stuck child fails on
// those — killed, with its stderr — rather than on vitest's timer.
vi.setConfig({ hookTimeout: SUITE_TIMEOUT_MS, testTimeout: SUITE_TIMEOUT_MS });

const INTROSPECT_PATH = "/oauth/introspect";
const RESOURCE = "/resource?q=1";

let fake: FakeProvider;
let upstream: RecordingUpstream;

beforeAll(async () => {
	[fake, upstream] = await Promise.all([startFakeProvider(), startRecordingUpstream()]);
});
afterAll(async () => {
	await Promise.all([fake?.close(), upstream?.close()]);
});
// After, not before: a responder that threw is blamed on the test that ran it.
afterEach(() => {
	fake.reset();
});

type Line = { event: string; level: string } & Record<string, unknown>;
const INCOMING: Line = { event: "validation.incoming_request", level: "info", msg: "incoming request" };
/**
 * A provider failure line: the event, the level and the message the README
 * and the v0.7.0 CHANGELOG name, and the error itself under `error`, through
 * the logger's allowlist — an object with the class and the message, never
 * the string injection logs (`src/README.md`, #95 F48).
 */
const failure = (event: string, level: string, msg: string): Line => ({
	event,
	level,
	msg,
	error: { type: "IntrospectHttpError", message: expect.any(String), stack: expect.any(String) },
});

/** A configuration as the README describes it. */
interface Setup {
	name: string;
	env: Record<string, string>;
	/** The `Authorization` the introspection request carries for `token`. */
	introspectionCredential: (token: string) => string;
	/** This configuration's column of the README's challenge table. */
	challenge: { invalidToken: string; invalidRequest: string; otherMethod: string | null };
	/** "What a provider 401 means" for this configuration. */
	provider401: { status: number; message: string; challenge: string | null; line: Line };
	/** Configured credential bytes, in every form the proxy holds them, that must be written nowhere. */
	secrets: string[];
}

const NO_REALM = {
	invalidToken: 'Bearer error="invalid_token"',
	invalidRequest: 'Bearer error="invalid_request"',
	otherMethod: null,
};

const SETUPS: Setup[] = [
	{
		name: "without client credentials",
		env: {},
		// The inbound token is the introspection credential (README:
		// "Without client authentication").
		introspectionCredential: (token) => `Bearer ${token}`,
		challenge: NO_REALM,
		provider401: {
			status: 401,
			message: "Invalid Token",
			challenge: NO_REALM.invalidToken,
			line: failure("validation.token_unauthorized", "info", "introspect failed"),
		},
		secrets: [],
	},
	{
		name: "with CLIENT_ID / CLIENT_SECRET",
		// Raw, reserved characters included: the README says not to pre-encode.
		env: { CLIENT_ID: "orders-proxy", CLIENT_SECRET: "s3:cr t+/%" },
		// RFC 6749 §2.3.1: each half form-urlencoded, then joined and base64'd.
		introspectionCredential: () =>
			`Basic ${Buffer.from("orders-proxy:s3%3Acr%20t%2B%2F%25").toString("base64")}`,
		challenge: NO_REALM,
		// The provider refused the proxy, not the caller (#95 F7).
		provider401: {
			status: 502,
			message: "Provider Configuration Error",
			challenge: null,
			line: failure(
				"validation.provider_config_error",
				"error",
				"introspect refused the proxy's client credentials",
			),
		},
		// Raw, form-encoded, and the Basic value built from them.
		secrets: [
			"s3:cr t+/%",
			"s3%3Acr%20t%2B%2F%25",
			Buffer.from("orders-proxy:s3%3Acr%20t%2B%2F%25").toString("base64"),
		],
	},
	{
		name: "with VALIDATION_REALM",
		env: { VALIDATION_REALM: "orders api" },
		introspectionCredential: (token) => `Bearer ${token}`,
		challenge: {
			invalidToken: 'Bearer realm="orders api", error="invalid_token"',
			invalidRequest: 'Bearer realm="orders api", error="invalid_request"',
			otherMethod: 'Bearer realm="orders api"',
		},
		provider401: {
			status: 401,
			message: "Invalid Token",
			challenge: 'Bearer realm="orders api", error="invalid_token"',
			line: failure("validation.token_unauthorized", "info", "introspect failed"),
		},
		secrets: [],
	},
];

/** One request shape and what the documentation says the app does with it. */
interface Case {
	name: string;
	/** The inbound `Authorization` for this case's token; absent: none sent. */
	authorization?: (token: string) => string;
	/** What the introspection endpoint answers; absent: it must not be asked. */
	introspection?: FakeResponse;
	status: number;
	/**
	 * `forwarded`: the upstream's own answer, and the upstream received the
	 * inbound `Authorization` exactly as sent (validation invariant 1).
	 * Otherwise the refusal body, and nothing reached the upstream.
	 */
	answer: "forwarded" | { code: number; message: string };
	challenge: string | null;
	/** The log events for the request, in order. */
	lines: Line[];
}

const casesFor = (setup: Setup): Case[] => [
	{
		name: "forwards a request with no Authorization unchanged, and does not ask the provider",
		status: 200,
		answer: "forwarded",
		challenge: null,
		lines: [INCOMING],
	},
	{
		name: "forwards an empty Authorization unchanged, sent upstream as `Authorization` (#132)",
		authorization: () => "",
		status: 200,
		answer: "forwarded",
		challenge: null,
		lines: [INCOMING],
	},
	{
		name: "forwards an active token with the inbound header, after introspecting it",
		authorization: (token) => `Bearer ${token}`,
		introspection: json(200, { active: true, token_type: "Bearer" }),
		status: 200,
		answer: "forwarded",
		challenge: null,
		lines: [INCOMING],
	},
	{
		name: "introspects the first word of `Bearer <token> extra` and forwards the header as received (F14)",
		authorization: (token) => `Bearer ${token} extra`,
		introspection: json(200, { active: true }),
		status: 200,
		answer: "forwarded",
		challenge: null,
		lines: [INCOMING],
	},
	{
		name: "refuses a token the provider calls inactive: 401 Invalid Token with the invalid_token challenge, not logged",
		authorization: (token) => `Bearer ${token}`,
		introspection: json(200, { active: false }),
		status: 401,
		answer: { code: 401, message: "Invalid Token" },
		challenge: setup.challenge.invalidToken,
		lines: [INCOMING],
	},
	{
		name: "refuses an active token whose introspection carries `cnf`: 401 Invalid Token, this path cannot check possession",
		authorization: (token) => `Bearer ${token}`,
		introspection: json(200, { active: true, cnf: { jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } }),
		status: 401,
		answer: { code: 401, message: "Invalid Token" },
		challenge: setup.challenge.invalidToken,
		lines: [INCOMING],
	},
	{
		name: `answers a provider 401 ${setup.provider401.status} ${setup.provider401.message}, logged ${setup.provider401.line.event}`,
		authorization: (token) => `Bearer ${token}`,
		introspection: json(401, { error: "invalid_token" }),
		status: setup.provider401.status,
		answer: { code: setup.provider401.status, message: setup.provider401.message },
		challenge: setup.provider401.challenge,
		lines: [INCOMING, setup.provider401.line],
	},
	{
		name: "refuses `Bearer` with no token: 400 Invalid Token Type with the invalid_request challenge",
		authorization: () => "Bearer",
		status: 400,
		answer: { code: 400, message: "Invalid Token Type" },
		challenge: setup.challenge.invalidRequest,
		lines: [INCOMING],
	},
	{
		name: "refuses `Bearer  <token>` (two spaces): 400 Invalid Token Type with the invalid_request challenge",
		authorization: (token) => `Bearer  ${token}`,
		status: 400,
		answer: { code: 400, message: "Invalid Token Type" },
		challenge: setup.challenge.invalidRequest,
		lines: [INCOMING],
	},
	{
		name: "refuses another method (Basic): 400 Invalid Token Type, challenged with the realm alone or not at all",
		authorization: () => "Basic dXNlcjpwYXNz",
		status: 400,
		answer: { code: 400, message: "Invalid Token Type" },
		challenge: setup.challenge.otherMethod,
		lines: [INCOMING],
	},
	{
		name: "refuses a lowercase `bearer` as another method",
		authorization: (token) => `bearer ${token}`,
		status: 400,
		answer: { code: 400, message: "Invalid Token Type" },
		challenge: setup.challenge.otherMethod,
		lines: [INCOMING],
	},
	{
		name: "answers a provider 5xx 502 Bad Gateway with no challenge, logged validation.provider_error",
		authorization: (token) => `Bearer ${token}`,
		introspection: json(503, { error: "temporarily_unavailable" }, { "Retry-After": "30" }),
		status: 502,
		answer: { code: 502, message: "Bad Gateway" },
		challenge: null,
		lines: [INCOMING, failure("validation.provider_error", "error", "introspect failed")],
	},
	{
		name: "does not follow a redirect from the introspection endpoint: 502 Provider Configuration Error, one provider request (#95 F43)",
		authorization: (token) => `Bearer ${token}`,
		introspection: redirect(307, "/oauth/introspect/"),
		status: 502,
		answer: { code: 502, message: "Provider Configuration Error" },
		challenge: null,
		lines: [
			INCOMING,
			failure("validation.provider_config_error", "error", "introspect endpoint redirected"),
		],
	},
];

/** What reached the provider for one request, in the terms the README states it. */
const providerRequestsFor = (requestId: string) =>
	fake.requests
		.filter((request) => request.headers["x-request-id"] === requestId)
		.map((request) => ({
			method: request.method,
			path: request.path,
			authorization: request.headers.authorization,
			cookie: request.headers.cookie,
			form: Object.fromEntries(new URLSearchParams(request.body.toString("utf8"))),
		}));

describe.each(SETUPS)("the app in validation mode, $name", (setup) => {
	let proxy: ProxyProcess;

	beforeAll(async () => {
		proxy = await startProxy({
			AUTH_MODE: "validation",
			INTROSPECT_URL: fake.url(INTROSPECT_PATH),
			LOG_LEVEL: "debug",
			// Far above the suite timeout, so a case that hangs fails on vitest's
			// timer and not because the client gave up first.
			INTROSPECT_TIMEOUT_MS: "60000",
			...setup.env,
		}, upstream);
	});
	afterAll(async () => {
		await proxy?.stop();
	});

	for (const [index, c] of casesFor(setup).entries()) {
		it(c.name, async () => {
			const requestId = `validation-${SETUPS.indexOf(setup)}-${index}`;
			const token = `tok-${requestId}`;
			const authorization = c.authorization?.(token);
			fake.respond(INTROSPECT_PATH, c.introspection ?? json(500, { error: "must_not_be_asked" }));

			const res = await send(proxy.origin, {
				path: RESOURCE,
				headers: {
					"x-request-id": requestId,
					...(authorization !== undefined ? { authorization } : {}),
				},
			});

			// The answer.
			expect(res.status).toBe(c.status);
			expect(res.json()).toEqual(c.answer === "forwarded" ? upstreamBody(RESOURCE) : c.answer);
			expect(res.headers["www-authenticate"]).toBe(c.challenge ?? undefined);
			// Validation passes no Retry-After through (validation invariant 8).
			expect(res.headers["retry-after"]).toBeUndefined();

			// What was logged, and that the token was not. First, because it is
			// also the barrier after which a request the proxy should not have
			// sent anywhere would have arrived (see `linesFor`).
			const lines = await proxy.linesFor(requestId);
			expect(lines).toMatchObject(c.lines);
			for (const line of lines) {
				expect(line.raw).not.toContain(token);
			}

			// What reached the upstream: the inbound header as sent, or nothing.
			const reached = upstream.receivedFor(requestId);
			if (c.answer === "forwarded") {
				expect(reached).toHaveLength(1);
				expect(headerPairs(reached[0].rawHeaders, "authorization")).toEqual(
					authorization === undefined ? [] : [["Authorization", authorization]],
				);
			} else {
				expect(reached).toEqual([]);
			}

			// What reached the provider: one introspection of the token, with
			// this configuration's credential, or nothing.
			expect(providerRequestsFor(requestId)).toEqual(
				c.introspection === undefined
					? []
					: [
							{
								method: "POST",
								path: INTROSPECT_PATH,
								authorization: setup.introspectionCredential(token),
								cookie: undefined,
								// The token in the body, as the README says; the rest of
								// the form is the client's, pinned by its wire test.
								form: expect.objectContaining({ token }),
							},
						],
			);
		});
	}

	it("forwards a POST body intact once the token is introspected", async () => {
		const requestId = `validation-${SETUPS.indexOf(setup)}-post`;
		const token = `tok-${requestId}`;
		const body = JSON.stringify({ order: 42, note: "x".repeat(4096) });
		fake.respond(INTROSPECT_PATH, json(200, { active: true }));

		const res = await send(proxy.origin, {
			method: "POST",
			path: "/orders",
			headers: {
				"x-request-id": requestId,
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			body,
		});

		expect(res.status).toBe(200);
		const reached = upstream.receivedFor(requestId);
		expect(reached.map((request) => [request.method, request.path, request.body.toString("utf8")])).toEqual([
			["POST", "/orders", body],
		]);
		expect(providerRequestsFor(requestId)).toHaveLength(1);
	});

	it("generates a request id when none is sent, echoes it, and carries it to the provider, the upstream and the log", async () => {
		const token = `tok-generated-${SETUPS.indexOf(setup)}`;
		fake.respond(INTROSPECT_PATH, json(200, { active: true }));

		const res = await send(proxy.origin, { path: RESOURCE, headers: { authorization: `Bearer ${token}` } });

		expect(res.status).toBe(200);
		const requestId = res.headers["x-request-id"];
		expect(requestId).toEqual(expect.any(String));
		expect(upstream.receivedFor(String(requestId))).toHaveLength(1);
		expect(providerRequestsFor(String(requestId))).toHaveLength(1);
		expect(await proxy.linesFor(String(requestId))).toMatchObject([INCOMING]);
	});

	it("wrote every line about a request with its requestId and a validation.* event (#134), nothing else, and no configured secret", async () => {
		await proxy.linesFor("validation-every-line");
		// Nothing outside the logger: no stdout line that is not NDJSON, and
		// nothing on stderr but the harness's own listening line.
		expect(proxy.unparsed).toEqual([]);
		expect(proxy.stderr()).toMatch(/^composition-test: listening on port \d+\n$/);
		for (const secret of setup.secrets) {
			for (const line of proxy.lines) expect(line.raw).not.toContain(secret);
		}
		const aboutRequests = proxy.lines.filter((line) => !line.msg.startsWith("Server ready at"));
		expect(aboutRequests.length).toBeGreaterThan(0);
		for (const line of aboutRequests) {
			expect(line).toMatchObject({ requestId: expect.any(String), event: expect.stringMatching(/^validation\./) });
		}
	});
});
