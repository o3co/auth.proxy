// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The entry point itself: what `src/app.mts` does before and around the mode
 * router, in a child process configured by environment variables over the
 * shipped conf.
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

import { generateKeyPairSync } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { bootProxy, type ProxyProcess, SUITE_TIMEOUT_MS, send, startProxy } from "./app-process.mjs";
import { expectContinue } from "./expect-continue.mjs";
import { type FakeProvider, json, startFakeProvider } from "./fake-provider.mjs";
import {
	PROXY_FIELDS_PATH,
	type RecordingUpstream,
	startRecordingUpstream,
	upstreamBody,
} from "./recording-upstream.mjs";

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

/** A private JWK with an algorithm that does not fit it: a key the proxy cannot sign with. */
const UNUSABLE_JWK = { ...generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }), alg: "HS256" };
const USABLE_KEY = JSON.stringify(generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }));

/** The names of the `Access-Control-*` fields an answer carries. */
const accessControlFields = (headers: Record<string, unknown>): string[] =>
	Object.keys(headers).filter((name) => name.startsWith("access-control-"));

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
			name: "refuses an INTROSPECT_URL with userinfo, naming the key and not quoting the value",
			env: { ...VALIDATION, INTROSPECT_URL: "http://orders-proxy:pa55-w0rd@127.0.0.1:9/oauth/introspect" },
			path: ["auth", "validation", "introspect", "url"],
			names: ["auth.validation.introspect.url"],
			unprinted: ["pa55-w0rd"],
		},
		{
			name: "refuses a data: INTROSPECT_URL, naming the key",
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
			name: "refuses a CLIENT_KEY it cannot sign with, naming the key and not quoting it",
			env: {
				...VALIDATION,
				CLIENT_ID: "orders-proxy",
				CLIENT_KEY: JSON.stringify(UNUSABLE_JWK),
				VALIDATION_PROVIDER_ISSUER: "https://auth.example.test",
			},
			path: ["auth", "validation", "client", "clientKey"],
			names: ["auth.validation.client.clientKey"],
			unprinted: [UNUSABLE_JWK.d as string],
		},
		{
			name: "refuses an INJECTION_CLIENT_KEY without INJECTION_PROVIDER_ISSUER, naming the issuer",
			env: { ...INJECTION, INJECTION_CLIENT_KEY: USABLE_KEY },
			path: ["auth", "injection", "providerIssuer"],
			names: ["auth.injection.providerIssuer"],
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
			names: ["auth.injection.providerOrigin"],
			unprinted: [],
		},
		{
			name: "refuses an UPSTREAM_BASEURL with a path, which the upstream proxy would drop, naming the key",
			env: { ...VALIDATION, UPSTREAM_BASEURL: "http://127.0.0.1:9/v1" },
			path: ["upstream", "baseURL"],
			names: ["upstream.baseURL"],
			unprinted: [],
		},
		{
			name: "refuses an UPSTREAM_BASEURL without a scheme, naming the key",
			env: { ...VALIDATION, UPSTREAM_BASEURL: "upstream:8080" },
			path: ["upstream", "baseURL"],
			names: ["upstream.baseURL"],
			unprinted: [],
		},
		{
			name: "refuses an empty HTTP_PORT, which would listen on a random port, naming the key",
			env: { ...VALIDATION, HTTP_PORT: "" },
			path: ["http", "port"],
			names: ["http.port"],
			unprinted: [],
		},
		{
			name: "refuses an HTTP_PATH_PREFIX without its leading /, which would mount the mode router nowhere",
			env: { ...VALIDATION, HTTP_PATH_PREFIX: "api" },
			path: ["http", "pathPrefix"],
			names: ["http.pathPrefix"],
			unprinted: [],
		},
		{
			name: "refuses a CORS_ORIGIN_PATTERN that does not compile, naming the key",
			env: { ...VALIDATION, CORS_ORIGIN_PATTERN: "(" },
			path: ["http", "cors", "origin", "pattern"],
			names: ["http.cors.origin.pattern"],
			unprinted: [],
		},
		{
			name: "refuses a negative INTROSPECT_CACHE_TTL_SEC, naming the key",
			env: { ...VALIDATION, INTROSPECT_CACHE_TTL_SEC: "-5" },
			path: ["auth", "validation", "introspect", "cacheTtlSec"],
			names: ["auth.validation.introspect.cacheTtlSec"],
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

// A warning, not a refusal: the proxy still boots on the pattern.
describe("the entry point warns at boot about a CORS origin pattern that is not anchored", () => {
	const eventsIn = (stdout: string): unknown[] =>
		stdout
			.split("\n")
			.filter((line) => line.startsWith("{"))
			.map((line) => (JSON.parse(line) as { event?: unknown }).event);

	it.concurrent.for([
		{ pattern: "https://app\\.example", warned: true },
		{ pattern: "^https://app\\.example$", warned: false },
	])("pattern $pattern: warned $warned", async ({ pattern, warned }, { expect }) => {
		const outcome = await bootProxy({ ...VALIDATION, CORS_ORIGIN_PATTERN: pattern });

		expect(outcome.listened).toBe(true);
		expect(eventsIn(outcome.stdout).includes("cors.origin_pattern_unanchored")).toBe(warned);
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
			HTTP_BODY_LIMIT_SIZE: "1kb",
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
		expect(accessControlFields(res.headers)).toEqual([]);
		expect(upstream.receivedFor("entry-no-cors")).toHaveLength(1);
	});

	// A CORS preflight (Fetch): OPTIONS with Origin and Access-Control-Request-Method.
	const preflight = (requestId: string, origin: string) => ({
		"x-request-id": requestId,
		origin,
		"access-control-request-method": "PUT",
		"access-control-request-headers": "authorization",
	});

	it("answers a preflight under the prefix 204 itself: nothing upstream, nothing logged", async () => {
		const res = await send(proxy.origin, {
			method: "OPTIONS",
			path: "/api/resource",
			headers: preflight("entry-preflight", "https://app.example"),
		});

		expect(res.status).toBe(204);
		expect(res.headers["access-control-allow-origin"]).toBe("https://app.example");
		expect(res.headers["access-control-allow-credentials"]).toBe("true");
		expect(res.headers["access-control-allow-headers"]).toBe("authorization");
		expect(upstream.receivedFor("entry-preflight")).toEqual([]);
		expect(await proxy.linesFor("entry-preflight")).toEqual([]);
	});

	it("answers a preflight from an origin the pattern does not admit 204 itself, granting nothing", async () => {
		const res = await send(proxy.origin, {
			method: "OPTIONS",
			path: "/api/resource",
			headers: preflight("entry-preflight-refused", "https://evil.example"),
		});

		expect(res.status).toBe(204);
		expect(accessControlFields(res.headers)).toEqual([]);
		expect(upstream.receivedFor("entry-preflight-refused")).toEqual([]);
	});

	it("answers OPTIONS outside the prefix 404, a preflight included, without CORS fields", async () => {
		const res = await send(proxy.origin, {
			method: "OPTIONS",
			path: "/resource",
			headers: preflight("entry-preflight-outside", "https://app.example"),
		});

		expect(res.status).toBe(404);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		expect(res.headers.vary).toBeUndefined();
		expect(upstream.receivedFor("entry-preflight-outside")).toEqual([]);
	});

	// Not a preflight: an ordinary request to the mode router, which checks its
	// token, forwards it and logs it like any other.
	it.for([
		{ name: "without Origin", requestId: "entry-options-plain", headers: {} },
		{
			name: "with Origin but no Access-Control-Request-Method",
			requestId: "entry-options-origin",
			headers: { origin: "https://app.example" },
		},
		{
			name: "with Access-Control-Request-Method but no Origin",
			requestId: "entry-options-acrm",
			headers: { "access-control-request-method": "PUT" },
		},
	])("routes an OPTIONS under the prefix $name to the mode router", async ({ requestId, headers }) => {
		fake.respond("/oauth/introspect", json(200, { active: true }));
		const res = await send(proxy.origin, {
			method: "OPTIONS",
			path: "/api/resource",
			// A token of its own: a cached answer would not reach the provider.
			headers: { ...headers, "x-request-id": requestId, authorization: `Bearer tok-${requestId}` },
		});

		expect(res.status).toBe(200);
		expect(upstream.receivedFor(requestId).map((request) => request.method)).toEqual(["OPTIONS"]);
		expect(fake.requests).toHaveLength(1);
		expect((await proxy.linesFor(requestId)).map((line) => line.event)).toEqual(["validation.incoming_request"]);
	});

	// The request id and the CORS grant are the proxy's; Vary lists what both
	// sides' choices read; X-Powered-By is the upstream's, the proxy announcing
	// none of its own.
	it("keeps the proxy's request id and CORS grant on a proxied answer, merges Vary, and passes X-Powered-By on", async () => {
		fake.respond("/oauth/introspect", json(200, { active: true }));
		const res = await send(proxy.origin, {
			path: `/api${PROXY_FIELDS_PATH}`,
			headers: { "x-request-id": "entry-fields", origin: "https://app.example", authorization: "Bearer tok-fields" },
		});

		expect(res.status).toBe(200);
		expect(upstream.receivedFor("entry-fields")).toHaveLength(1);
		expect(res.headers["x-request-id"]).toBe("entry-fields");
		expect(res.headers["access-control-allow-origin"]).toBe("https://app.example");
		expect(res.headers["access-control-allow-credentials"]).toBe("true");
		expect(res.headers.vary).toBe("Origin, Cookie");
		expect(res.headers["x-powered-by"]).toBe("upstream-framework");
	});

	it("grants an origin the pattern does not admit nothing, though the upstream grants any", async () => {
		fake.respond("/oauth/introspect", json(200, { active: true }));
		const res = await send(proxy.origin, {
			path: `/api${PROXY_FIELDS_PATH}`,
			headers: {
				"x-request-id": "entry-fields-refused",
				origin: "https://evil.example",
				authorization: "Bearer tok-fields-refused",
			},
		});

		expect(res.status).toBe(200);
		expect(upstream.receivedFor("entry-fields-refused")).toHaveLength(1);
		expect(accessControlFields(res.headers)).toEqual([]);
	});

	it("announces no X-Powered-By on an answer of its own", async () => {
		const answers = await Promise.all([
			send(proxy.origin, { path: "/_healthcheck" }),
			send(proxy.origin, { path: "/resource" }),
			send(proxy.origin, { path: "/api/resource", headers: { authorization: "Basic eDp5" } }),
		]);

		expect(answers.map((res) => res.status)).toEqual([200, 404, 400]);
		for (const res of answers) expect(res.headers["x-powered-by"]).toBeUndefined();
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

	// An oversized upload that expected 100-continue is not invited to send its
	// body. Outside the prefix no body limit refuses it, so the 404 must not
	// wait for a body the client was never told to send.
	it("answers an oversized upload outside the prefix 404 at once, without inviting its body", async () => {
		const exchange = await expectContinue(
			proxy.origin,
			"POST /resource HTTP/1.1\r\nHost: t\r\nx-request-id: entry-outside-expect\r\nContent-Length: 4096\r\nExpect: 100-continue\r\n\r\n",
			Buffer.alloc(4096, "x"),
		);

		expect(exchange.statusLines).toEqual(["HTTP/1.1 404 Not Found"]);
		expect(exchange.bodySent).toBe(false);
		expect(upstream.receivedFor("entry-outside-expect")).toEqual([]);
	});
});
