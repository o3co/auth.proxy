// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The entry point itself (#144): what `src/app.mts` does before and around
 * the mode router, in a child process configured by environment variables
 * over the shipped conf.
 *
 * - A configuration the documentation says is refused stops the process
 *   before it listens: non-zero exit, no `Server ready` line, the key named
 *   where the documentation says it is, and a refused value that carries a
 *   credential not printed. `config.test.mts` pins the schema alone; this
 *   pins that the entry point applies it.
 * - The healthcheck is mounted first, at the root, outside `http.pathPrefix`
 *   and CORS (`src/README.md`), and the mode router answers under the prefix
 *   with CORS for an origin the pattern admits.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { bootProxy, type ProxyProcess, SUITE_TIMEOUT_MS, send, startProxy } from "./app-process.mjs";
import { type FakeProvider, json, startFakeProvider } from "./fake-provider.mjs";
import { type RecordingUpstream, startRecordingUpstream, upstreamBody } from "./recording-upstream.mjs";

// Above the harness's boot deadline and stop grace, so a stuck child fails on
// those — killed, with its stderr — rather than on vitest's timer.
vi.setConfig({ hookTimeout: SUITE_TIMEOUT_MS, testTimeout: SUITE_TIMEOUT_MS });

const VALIDATION = { AUTH_MODE: "validation", INTROSPECT_URL: "http://127.0.0.1:9/oauth/introspect" };
const INJECTION = {
	AUTH_MODE: "injection",
	INJECTION_PROVIDER_ORIGIN: "http://127.0.0.1:9",
	INJECTION_CLIENT_ID: "bff-spa",
	INJECTION_SCOPE: "api",
};

/** A configuration the documentation says is refused at boot. */
interface Refusal {
	name: string;
	env: Record<string, string>;
	/** The path of the schema issue that refuses it, as the ZodError prints it. */
	path: string[];
	/** Keys the refusal must name, where the documentation says it names one. */
	names: string[];
	/** Bytes of the refused value that must not be printed. */
	unprinted: string[];
}

/** `"path": [ "auth", "mode" ]` as the ZodError prints it, across lines. */
const issuePath = (segments: string[]): RegExp =>
	new RegExp(`"path": \\[\\s*${segments.map((segment) => `"${segment}"`).join(",\\s*")}\\s*\\]`);

describe("the entry point at boot", () => {
	it.concurrent.for([
		{ mode: "validation", env: VALIDATION },
		{ mode: "injection", env: INJECTION },
		// Ready is the bound port, not the info-level `Server ready` line.
		{ mode: "validation at LOG_LEVEL=warn", env: { ...VALIDATION, LOG_LEVEL: "warn" } },
	])("boots $mode with the base configuration the refusals below vary", async ({ env }, { expect }) => {
		expect(await bootProxy(env)).toMatchObject({ listened: true });
	});

	it.concurrent.for<Refusal>([
		{
			name: "refuses to start without AUTH_MODE (README: Operating modes)",
			env: { INTROSPECT_URL: VALIDATION.INTROSPECT_URL },
			path: ["auth", "mode"],
			names: [],
			unprinted: [],
		},
		{
			name: "refuses to start on a typo in AUTH_MODE",
			env: { ...VALIDATION, AUTH_MODE: "validate" },
			path: ["auth", "mode"],
			names: [],
			unprinted: [],
		},
		{
			name: "refuses an INTROSPECT_URL with userinfo, naming the key and not quoting the value (#140)",
			env: { ...VALIDATION, INTROSPECT_URL: "http://orders-proxy:pa55-w0rd@127.0.0.1:9/oauth/introspect" },
			path: ["auth", "validation", "introspect", "url"],
			names: ["auth.validation.introspect.url"],
			unprinted: ["pa55-w0rd"],
		},
		{
			name: "refuses a data: INTROSPECT_URL, which admitted every token in 0.6.0 (#140)",
			env: { ...VALIDATION, INTROSPECT_URL: 'data:application/json,{"active":true}' },
			path: ["auth", "validation", "introspect", "url"],
			names: ["auth.validation.introspect.url"],
			unprinted: [],
		},
		{
			name: "refuses CLIENT_ID without CLIENT_SECRET",
			env: { ...VALIDATION, CLIENT_ID: "orders-proxy" },
			path: ["auth", "validation", "client"],
			names: ["auth.validation.client.clientId", "auth.validation.client.clientSecret"],
			unprinted: [],
		},
		{
			name: "refuses a VALIDATION_REALM a quoted-string cannot carry, naming the key",
			env: { ...VALIDATION, VALIDATION_REALM: 'orders"api' },
			path: ["auth", "validation", "realm"],
			names: ["auth.validation.realm"],
			unprinted: [],
		},
		{
			name: "refuses INJECTION_EXCHANGE_ENABLED=true without its credentials, naming both keys",
			env: { ...INJECTION, INJECTION_EXCHANGE_ENABLED: "true" },
			path: ["auth", "injection", "exchange"],
			names: ["auth.injection.exchange.clientId", "auth.injection.exchange.clientSecret"],
			unprinted: [],
		},
		{
			name: "refuses INJECTION_EXCHANGE_ENABLED=true with a client id and no secret, naming the secret",
			env: { ...INJECTION, INJECTION_EXCHANGE_ENABLED: "true", INJECTION_EXCHANGE_CLIENT_ID: "bff-exchanger" },
			path: ["auth", "injection", "exchange"],
			names: ["auth.injection.exchange.clientSecret"],
			unprinted: [],
		},
		{
			name: "refuses an INJECTION_EXCHANGE_ENABLED that is neither true nor false",
			env: { ...INJECTION, INJECTION_EXCHANGE_ENABLED: "yes" },
			path: ["auth", "injection", "exchange", "enabled"],
			names: ["auth.injection.exchange.enabled"],
			unprinted: [],
		},
		{
			name: "refuses an INJECTION_STRIP_INBOUND_AUTHORIZATION that is neither true nor false",
			env: { ...INJECTION, INJECTION_STRIP_INBOUND_AUTHORIZATION: "on" },
			path: ["auth", "injection", "stripInboundAuthorization"],
			names: ["auth.injection.stripInboundAuthorization"],
			unprinted: [],
		},
		{
			name: "refuses an INJECTION_SESSION_COOKIE_NAME that is not a cookie-name, naming the key",
			env: { ...INJECTION, INJECTION_SESSION_COOKIE_NAME: "sid x" },
			path: ["auth", "injection", "sessionCookieName"],
			names: ["auth.injection.sessionCookieName"],
			unprinted: [],
		},
		{
			name: "refuses an INJECTION_PROVIDER_ORIGIN with a path",
			env: { ...INJECTION, INJECTION_PROVIDER_ORIGIN: "http://127.0.0.1:9/auth" },
			path: ["auth", "injection", "providerOrigin"],
			names: ["providerOrigin"],
			unprinted: [],
		},
		{
			name: "refuses to start without INJECTION_CLIENT_ID (required)",
			env: { ...INJECTION, INJECTION_CLIENT_ID: "" },
			path: ["auth", "injection", "clientId"],
			names: [],
			unprinted: [],
		},
	])("$name", async ({ env, path, names, unprinted }, { expect }) => {
		const outcome = await bootProxy(env);

		expect(outcome.listened).toBe(false);
		expect(outcome.code).not.toBe(0);
		expect(outcome.code).not.toBeNull();
		expect(outcome.stdout).not.toContain("Server ready");
		// Refused by the schema, for this key — not any other failure to start.
		expect(outcome.stderr).toMatch(/ZodError/);
		expect(outcome.stderr).toMatch(issuePath(path));
		for (const name of names) {
			expect(outcome.stderr).toContain(name);
		}
		for (const value of unprinted) {
			expect(outcome.stdout + outcome.stderr).not.toContain(value);
		}
	});
});

describe("the entry point's mounts: healthcheck at the root, the mode router under HTTP_PATH_PREFIX with CORS", () => {
	let fake: FakeProvider;
	let upstream: RecordingUpstream;
	let proxy: ProxyProcess;

	beforeAll(async () => {
		[fake, upstream] = await Promise.all([startFakeProvider(), startRecordingUpstream()]);
		proxy = await startProxy({
			AUTH_MODE: "validation",
			INTROSPECT_URL: fake.url("/oauth/introspect"),
			INTROSPECT_TIMEOUT_MS: "60000",
			HTTP_PATH_PREFIX: "/api",
			CORS_ORIGIN_PATTERN: "^https://app\\.example$",
			LOG_LEVEL: "debug",
		}, upstream);
	});
	afterAll(async () => {
		await proxy?.stop();
		await Promise.all([fake?.close(), upstream?.close()]);
	});
	afterEach(() => {
		fake.reset();
	});

	it("answers /_healthcheck at the root, before the mode router, without CORS and without a request id", async () => {
		// An Authorization the validation router would refuse 400: the probe
		// never reaches it.
		const res = await send(proxy.origin, {
			path: "/_healthcheck",
			headers: { "x-request-id": "entry-hc", origin: "https://app.example", authorization: "Basic eDp5" },
		});

		expect(res.status).toBe(200);
		expect(res.json()).toEqual({ status: "ok" });
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		// No request id: `src/README.md`, and the header of `Healthcheck.mts`.
		expect(res.headers["x-request-id"]).toBeUndefined();
		expect(upstream.receivedFor("entry-hc")).toEqual([]);
		expect(fake.requests).toEqual([]);
		expect(await proxy.linesFor("entry-hc")).toEqual([]);
	});

	it("routes a request under the prefix through the mode router, with CORS for an origin the pattern admits", async () => {
		fake.respond("/oauth/introspect", json(200, { active: true }));
		const res = await send(proxy.origin, {
			path: "/api/resource",
			headers: { "x-request-id": "entry-cors", origin: "https://app.example", authorization: "Bearer tok-entry" },
		});

		expect(res.status).toBe(200);
		const [reached] = upstream.receivedFor("entry-cors");
		expect(res.json()).toEqual(upstreamBody(reached.path));
		expect(res.headers["access-control-allow-origin"]).toBe("https://app.example");
		expect(res.headers["access-control-allow-credentials"]).toBe("true");
		expect(fake.requests.map((request) => request.headers["x-request-id"])).toEqual(["entry-cors"]);
		expect((await proxy.linesFor("entry-cors")).map((line) => line.event)).toEqual([
			"validation.incoming_request",
		]);
	});

	it("gives no CORS headers to an origin the pattern does not admit", async () => {
		const res = await send(proxy.origin, {
			path: "/api/resource",
			headers: { "x-request-id": "entry-no-cors", origin: "https://evil.example" },
		});

		expect(res.status).toBe(200);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		expect(upstream.receivedFor("entry-no-cors")).toHaveLength(1);
	});

	it("does not route a request outside the prefix to the mode router: 404, nothing upstream, nothing logged", async () => {
		const res = await send(proxy.origin, {
			path: "/resource",
			headers: { "x-request-id": "entry-outside", authorization: "Bearer tok-outside" },
		});

		expect(res.status).toBe(404);
		expect(await proxy.linesFor("entry-outside")).toEqual([]);
		expect(upstream.receivedFor("entry-outside")).toEqual([]);
		expect(fake.requests).toEqual([]);
	});
});
