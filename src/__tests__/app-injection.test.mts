// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Injection mode as it runs (#144): `src/app.mts` in a child process,
 * configured by environment variables over the shipped conf, in front of a
 * recording upstream, calling the fake provider's token endpoint over the real
 * `fetch`. Nothing is mocked — not a router, a client, `fetch` or the schema.
 *
 * Each combination of the two options gets its own process: the session
 * grant alone, with `INJECTION_STRIP_INBOUND_AUTHORIZATION=true`, with
 * `INJECTION_EXCHANGE_ENABLED=true` and its credentials, and with both. Each
 * is sent the request shapes injection answers — no credential, a session
 * cookie, a cookie the provider refuses, a cookie that fails the grammar
 * check, a client's own `Authorization` beside or instead of the cookie, and
 * with the exchange an assertion — and each case asserts the answer (status,
 * body, no `WWW-Authenticate`, `Retry-After`), the `Authorization` the
 * upstream received (names as sent), the grant the provider received, and the
 * log events written for the request, with no credential in them.
 *
 * The expected statuses, `error` codes, headers and grants are the documented
 * contract, not the code's: the README's Injection mode, Inbound
 * Authorization headers, Cookie forwarding and External credential exchange
 * sections, the injection README's invariants 2, 3 and 9, and the v0.7.0
 * CHANGELOG. The events, their levels and their fields are the injection
 * README's Log events tables. Where the documentation names no wording, an
 * `error_description` is the one the client or the decision writes, which
 * their own tests pin; the tests assert it, and that is the one assertion here
 * the documentation does not back.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { type ProxyProcess, SUITE_TIMEOUT_MS, send, startProxy } from "./app-process.mjs";
import { type FakeProvider, type FakeResponse, json, startFakeProvider } from "./fake-provider.mjs";
import {
	headerPairs,
	type RecordingUpstream,
	startRecordingUpstream,
	upstreamBody,
} from "./recording-upstream.mjs";

// Above the harness's boot deadline and stop grace, so a stuck child fails on
// those — killed, with its stderr — rather than on vitest's timer.
vi.setConfig({ hookTimeout: SUITE_TIMEOUT_MS, testTimeout: SUITE_TIMEOUT_MS });

const TOKEN_PATH = "/oauth/token";
const RESOURCE = "/orders/42";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

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

/** The session grant's configuration, shared by every setup. */
const sessionEnv = (): Record<string, string> => ({
	AUTH_MODE: "injection",
	INJECTION_PROVIDER_ORIGIN: fake.origin,
	INJECTION_CLIENT_ID: "bff-spa",
	INJECTION_SCOPE: "api read",
	INJECTION_SESSION_COOKIE_NAME: "sid",
	LOG_LEVEL: "debug",
	// Far above the suite timeout, so a case that hangs fails on vitest's timer and
	// not because the client gave up first.
	INJECTION_TIMEOUT_MS: "60000",
});

/** The exchange's configuration; the secret raw, reserved characters included. */
const EXCHANGE_ENV = {
	INJECTION_EXCHANGE_ENABLED: "true",
	INJECTION_EXCHANGE_CLIENT_ID: "bff-exchanger",
	INJECTION_EXCHANGE_CLIENT_SECRET: "ex:s3cret /+",
	INJECTION_EXCHANGE_SCOPE: "orders:read",
	INJECTION_EXCHANGE_AUDIENCE: "https://api.example",
};
/** RFC 6749 §2.3.1: each half form-urlencoded, then joined and base64'd. */
const EXCHANGE_BASIC = `Basic ${Buffer.from("bff-exchanger:ex%3As3cret%20%2F%2B").toString("base64")}`;
/** The exchange's client secret in every form the proxy holds it: raw, form-encoded, in the Basic value. */
const EXCHANGE_SECRETS = [
	EXCHANGE_ENV.INJECTION_EXCHANGE_CLIENT_SECRET,
	"ex%3As3cret%20%2F%2B",
	Buffer.from("bff-exchanger:ex%3As3cret%20%2F%2B").toString("base64"),
];

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
/** A JWS compact JWT the proxy reads unverified; the signature is never checked here. */
const jwt = (claims: Record<string, unknown>): string =>
	`${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({
		exp: Math.floor(Date.now() / 1000) + 3600,
		...claims,
	})}.c2lnbmF0dXJl`;

/** A token response the provider mints. */
const issued = (accessToken: string): FakeResponse =>
	json(200, { access_token: accessToken, token_type: "Bearer", expires_in: 300 });

/** What reached the provider for one request, in the terms the README states it. */
interface Grant {
	method: string;
	path: string;
	authorization: string | undefined;
	cookie: string | undefined;
	form: Record<string, string>;
}

/** The session grant: a public client, the session as the only cookie, no `Authorization`. */
const sessionGrant = (value: string): Grant => ({
	method: "POST",
	path: TOKEN_PATH,
	authorization: undefined,
	cookie: `sid=${value}`,
	form: { grant_type: "session", client_id: "bff-spa", scope: "api read" },
});

/** The RFC 7523 exchange: `client_secret_basic`, the assertion unchanged, no cookie. */
const exchangeGrant = (assertion: string): Grant => ({
	method: "POST",
	path: TOKEN_PATH,
	authorization: EXCHANGE_BASIC,
	cookie: undefined,
	form: {
		grant_type: JWT_BEARER,
		assertion,
		scope: "orders:read",
		audience: "https://api.example",
	},
});

type Line = { event: string; level: string } & Record<string, unknown>;
const line = (event: string, level: string, fields: Record<string, unknown> = {}): Line => ({
	event,
	level,
	...fields,
});
const INCOMING = line("injection.incoming_request", "info", { msg: "incoming request" });
/**
 * A provider failure line: injection logs the error as a string, not the
 * object validation logs (`src/README.md`, #134).
 */
const failed = (event: string, level: string, fields: Record<string, unknown> = {}): Line =>
	line(event, level, { error: expect.any(String), ...fields });

/** One request shape and what the documentation says the app does with it. */
interface Case {
	name: string;
	cookie?: string;
	authorization?: string;
	/** What the token endpoint answers, and the grant it must receive; absent: it must not be asked. */
	provider?: { answer: FakeResponse; grant: Grant };
	status: number;
	/** `forwarded`: the upstream's own answer. Otherwise the refusal body, and nothing reached the upstream. */
	answer: "forwarded" | { error: string; error_description: string };
	retryAfter?: string;
	/** The `Authorization` pairs the upstream received, names as sent, when forwarded. */
	upstreamAuthorization?: [string, string][];
	/** The log events for the request, in order, with the fields that say what happened. */
	lines: Line[];
	/** Credential bytes that must be in no log line. */
	unlogged: string[];
}

/** A case whose request carries none of its own `Authorization` upstream. */
const NONE: [string, string][] = [];
const bearer = (token: string): [string, string][] => [["Authorization", `Bearer ${token}`]];

const CLIENT_OWN = "client-own-7c1e";
const ASSERTION = jwt({ iss: "https://idp.example", sub: "alice", jti: "a-1" });
const ASSERTION_REFUSED = jwt({ iss: "https://idp.example", sub: "mallory", jti: "a-2" });
const ASSERTION_FAILING = jwt({ iss: "https://idp.example", sub: "bob", jti: "a-3" });
const ASSERTION_LOWERCASE = jwt({ iss: "https://idp.example", sub: "carol", jti: "a-5" });
const ASSERTION_OTHER_COOKIES = jwt({ iss: "https://idp.example", sub: "dave", jti: "a-6" });
const ASSERTION_OTHER_ISSUER = jwt({ iss: "https://unlisted.example", sub: "eve", jti: "a-4" });

const SESSION_REFUSED_401 = {
	error: "session_required",
	error_description: "provider reported the session is invalid or expired",
};
const SESSION_REFUSED_400 = {
	error: "session_required",
	error_description: "provider rejected the session grant",
};
const UNSUPPORTED = {
	error: "credential_unsupported",
	error_description: "Authorization must be a Bearer JWT assertion",
};
const AMBIGUOUS = {
	error: "credential_ambiguous",
	error_description: "send either the session cookie or an Authorization header, not both",
};

/** Shapes every setup answers the same way, exchange or not, strip or not. */
const noCredential: Case = {
	name: "forwards a request with no cookie and no Authorization without one, and does not ask the provider",
	status: 200,
	answer: "forwarded",
	upstreamAuthorization: NONE,
	lines: [INCOMING, line("injection.no_cookie", "debug", { action: "forward" })],
	unlogged: [],
};

const sessionMinted = (value: string, token: string): Case => ({
	name: "exchanges the session cookie for a token and injects it; the other cookies go upstream, not to the provider",
	cookie: `theme=dark; sid=${value}; _ga=GA1.2`,
	provider: { answer: issued(token), grant: sessionGrant(value) },
	status: 200,
	answer: "forwarded",
	upstreamAuthorization: bearer(token),
	lines: [
		INCOMING,
		line("injection.grant_fetch", "info"),
		line("injection.grant_success", "info", { expiresIn: 300 }),
	],
	unlogged: [value, token],
});

const sessionOverridesOwn = (value: string, token: string): Case => ({
	name: "replaces a client's own Authorization with the minted token when the session cookie mints one, logged as an override",
	cookie: `sid=${value}`,
	authorization: `Bearer ${CLIENT_OWN}`,
	provider: { answer: issued(token), grant: sessionGrant(value) },
	status: 200,
	answer: "forwarded",
	upstreamAuthorization: bearer(token),
	lines: [
		INCOMING,
		line("injection.grant_fetch", "info"),
		line("injection.grant_success", "info"),
		line("injection.authorization_override", "warn"),
	],
	unlogged: [value, token, CLIENT_OWN],
});

const sessionRefused = (value: string): Case => ({
	name: "answers a session the provider refuses (401) 401 session_required, with no challenge, logged at info",
	cookie: `sid=${value}`,
	provider: { answer: json(401, { error: "unauthorized" }), grant: sessionGrant(value) },
	status: 401,
	answer: SESSION_REFUSED_401,
	lines: [
		INCOMING,
		line("injection.grant_fetch", "info"),
		failed("injection.session_unauthorized", "info"),
	],
	unlogged: [value],
});

const SETUPS: { name: string; env: () => Record<string, string>; cases: Case[] }[] = [
	{
		name: "session grant only",
		env: sessionEnv,
		cases: [
			noCredential,
			{
				name: "forwards a client's own Authorization untouched when there is no session cookie (Inbound Authorization headers)",
				authorization: `Bearer ${CLIENT_OWN}`,
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer(CLIENT_OWN),
				lines: [INCOMING, line("injection.no_cookie", "debug", { action: "forward" })],
				unlogged: [CLIENT_OWN],
			},
			{
				name: "does not exchange a Bearer JWT while the exchange is off: forwarded as received",
				authorization: `Bearer ${ASSERTION}`,
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer(ASSERTION),
				lines: [INCOMING, line("injection.no_cookie", "debug", { action: "forward" })],
				unlogged: [ASSERTION],
			},
			sessionMinted("sess-s1-valid", "minted-s1-a"),
			sessionOverridesOwn("sess-s1-override", "minted-s1-b"),
			{
				name: "logs an empty inbound Authorization that the minted token replaces as an override (#133)",
				cookie: "sid=sess-s1-empty-auth",
				authorization: "",
				provider: { answer: issued("minted-s1-d"), grant: sessionGrant("sess-s1-empty-auth") },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("minted-s1-d"),
				lines: [
					INCOMING,
					line("injection.grant_fetch", "info"),
					line("injection.grant_success", "info"),
					line("injection.authorization_override", "warn"),
				],
				unlogged: ["sess-s1-empty-auth", "minted-s1-d"],
			},
			sessionRefused("sess-s1-expired"),
			{
				name: "answers a revoked session (400 invalid_grant) 401 session_required",
				cookie: "sid=sess-s1-revoked",
				provider: {
					answer: json(400, { error: "invalid_grant" }),
					grant: sessionGrant("sess-s1-revoked"),
				},
				status: 401,
				answer: SESSION_REFUSED_400,
				lines: [
					INCOMING,
					line("injection.grant_fetch", "info"),
					failed("injection.session_unauthorized", "info"),
				],
				unlogged: ["sess-s1-revoked"],
			},
			{
				name: "answers a 401 invalid_client 502 provider_config_error: the proxy's clientId, not the session (#95 F47)",
				cookie: "sid=sess-s1-client",
				provider: {
					answer: json(401, { error: "invalid_client" }),
					grant: sessionGrant("sess-s1-client"),
				},
				status: 502,
				answer: {
					error: "provider_config_error",
					error_description: "provider rejected the proxy's client (client_id)",
				},
				lines: [
					INCOMING,
					line("injection.grant_fetch", "info"),
					failed("injection.provider_config_error", "error"),
				],
				unlogged: ["sess-s1-client"],
			},
			{
				name: "answers a provider 503 502 provider_unavailable and passes its Retry-After through",
				cookie: "sid=sess-s1-outage",
				provider: {
					answer: json(503, { error: "temporarily_unavailable" }, { "Retry-After": "17" }),
					grant: sessionGrant("sess-s1-outage"),
				},
				status: 502,
				answer: {
					error: "provider_unavailable",
					error_description: "provider call failed: returned 503",
				},
				retryAfter: "17",
				lines: [
					INCOMING,
					line("injection.grant_fetch", "info"),
					failed("injection.provider_unavailable", "error"),
				],
				unlogged: ["sess-s1-outage"],
			},
			{
				name: "forwards a cookie that fails the grammar check without a minted token and without asking the provider, logged cookie_rejected",
				cookie: "sid=bad,value",
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "grammar", action: "forward" }),
				],
				unlogged: ["bad,value"],
			},
			{
				name: "forwards a client's own Authorization beside a refused cookie untouched",
				cookie: 'sid="half-quoted',
				authorization: `Bearer ${CLIENT_OWN}`,
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer(CLIENT_OWN),
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "quoting", action: "forward" }),
				],
				unlogged: ["half-quoted", CLIENT_OWN],
			},
			{
				name: "skips a malformed same-name pair and exchanges the next well-formed one, logged cookie_rejected with action fallback",
				cookie: "sid=bad,val; sid=sess-s1-second",
				provider: { answer: issued("minted-s1-c"), grant: sessionGrant("sess-s1-second") },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("minted-s1-c"),
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "grammar", action: "fallback" }),
					line("injection.grant_fetch", "info"),
					line("injection.grant_success", "info"),
				],
				unlogged: ["bad,val", "sess-s1-second", "minted-s1-c"],
			},
		],
	},
	{
		name: "with INJECTION_STRIP_INBOUND_AUTHORIZATION=true",
		env: () => ({ ...sessionEnv(), INJECTION_STRIP_INBOUND_AUTHORIZATION: "true" }),
		cases: [
			noCredential,
			{
				name: "strips a client's own Authorization when there is no session cookie, logged at warn with reason no_cookie",
				authorization: `Bearer ${CLIENT_OWN}`,
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.no_cookie", "debug", { action: "forward_stripped" }),
					line("injection.inbound_authorization_stripped", "warn", { reason: "no_cookie" }),
				],
				unlogged: [CLIENT_OWN],
			},
			{
				name: "strips an empty Authorization like any other (#95 F40)",
				authorization: "",
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.no_cookie", "debug", { action: "forward_stripped" }),
					line("injection.inbound_authorization_stripped", "warn", { reason: "no_cookie" }),
				],
				unlogged: [],
			},
			sessionMinted("sess-s2-valid", "minted-s2-a"),
			sessionOverridesOwn("sess-s2-override", "minted-s2-b"),
			sessionRefused("sess-s2-expired"),
			{
				name: "strips a client's own Authorization beside a cookie that fails the grammar check, with reason cookie_rejected",
				cookie: "sid=bad value",
				authorization: `Bearer ${CLIENT_OWN}`,
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "grammar", action: "forward_stripped" }),
					line("injection.inbound_authorization_stripped", "warn", { reason: "cookie_rejected" }),
				],
				unlogged: [CLIENT_OWN],
			},
			{
				name: "forwards a DQUOTE-wrapped cookie value to the provider verbatim, quotes preserved",
				cookie: 'sid="sess-s2-quoted"',
				provider: { answer: issued("minted-s2-c"), grant: sessionGrant('"sess-s2-quoted"') },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("minted-s2-c"),
				lines: [INCOMING, line("injection.grant_fetch", "info"), line("injection.grant_success", "info")],
				unlogged: ["sess-s2-quoted", "minted-s2-c"],
			},
			{
				name: "forwards an empty session cookie without a minted token, and has nothing to strip",
				cookie: "sid=",
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "empty", action: "forward" }),
				],
				unlogged: [],
			},
		],
	},
	{
		name: "with INJECTION_EXCHANGE_ENABLED=true",
		env: () => ({ ...sessionEnv(), ...EXCHANGE_ENV }),
		cases: [
			noCredential,
			sessionMinted("sess-s3-valid", "minted-s3-a"),
			sessionRefused("sess-s3-expired"),
			{
				name: "exchanges a Bearer JWT at the token endpoint and sends only the issued token upstream",
				authorization: `Bearer ${ASSERTION}`,
				provider: { answer: issued("exchanged-s3"), grant: exchangeGrant(ASSERTION) },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("exchanged-s3"),
				lines: [
					INCOMING,
					line("injection.exchange_fetch", "info"),
					line("injection.exchange_success", "info", { cached: true }),
				],
				unlogged: [ASSERTION, "exchanged-s3", EXCHANGE_ENV.INJECTION_EXCHANGE_CLIENT_SECRET],
			},
			{
				name: "matches the Bearer scheme case-insensitively: `bearer <JWT>` is exchanged too",
				authorization: `bearer ${ASSERTION_LOWERCASE}`,
				provider: { answer: issued("exchanged-s3-b"), grant: exchangeGrant(ASSERTION_LOWERCASE) },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("exchanged-s3-b"),
				lines: [
					INCOMING,
					line("injection.exchange_fetch", "info"),
					line("injection.exchange_success", "info"),
				],
				unlogged: [ASSERTION_LOWERCASE, "exchanged-s3-b"],
			},
			{
				name: "answers an assertion the provider refuses (400 invalid_grant) 401 credential_rejected, forwarding nothing",
				authorization: `Bearer ${ASSERTION_REFUSED}`,
				provider: {
					answer: json(400, { error: "invalid_grant" }),
					grant: exchangeGrant(ASSERTION_REFUSED),
				},
				status: 401,
				answer: {
					error: "credential_rejected",
					error_description: "the provider rejected the credential",
				},
				lines: [
					INCOMING,
					line("injection.exchange_fetch", "info"),
					failed("injection.exchange_rejected", "info", { providerError: "invalid_grant" }),
				],
				unlogged: [ASSERTION_REFUSED],
			},
			{
				name: "answers a provider 503 on the exchange 502 provider_unavailable and passes its Retry-After through",
				authorization: `Bearer ${ASSERTION_FAILING}`,
				provider: {
					answer: json(503, { error: "temporarily_unavailable" }, { "Retry-After": "9" }),
					grant: exchangeGrant(ASSERTION_FAILING),
				},
				status: 502,
				answer: {
					error: "provider_unavailable",
					error_description: "provider call failed: returned 503",
				},
				retryAfter: "9",
				lines: [
					INCOMING,
					line("injection.exchange_fetch", "info"),
					failed("injection.exchange_provider_unavailable", "error"),
				],
				unlogged: [ASSERTION_FAILING],
			},
			{
				name: "refuses a Bearer credential that is not a JWT 401 credential_unsupported (format), without asking the provider",
				authorization: `Bearer ${CLIENT_OWN}`,
				status: 401,
				answer: UNSUPPORTED,
				lines: [
					INCOMING,
					line("injection.exchange_credential_unsupported", "info", { reason: "format" }),
				],
				unlogged: [CLIENT_OWN],
			},
			{
				name: "refuses another scheme 401 credential_unsupported (scheme)",
				authorization: "Basic dXNlcjpwYXNz",
				status: 401,
				answer: UNSUPPORTED,
				lines: [
					INCOMING,
					line("injection.exchange_credential_unsupported", "info", { reason: "scheme" }),
				],
				unlogged: ["dXNlcjpwYXNz"],
			},
			{
				name: "refuses an empty Authorization 401 credential_unsupported",
				authorization: "",
				status: 401,
				answer: UNSUPPORTED,
				lines: [INCOMING, line("injection.exchange_credential_unsupported", "info")],
				unlogged: [],
			},
			{
				name: "refuses a session cookie beside an Authorization 400 credential_ambiguous, asking the provider for neither",
				cookie: "sid=sess-s3-both",
				authorization: `Bearer ${ASSERTION}`,
				status: 400,
				answer: AMBIGUOUS,
				lines: [
					INCOMING,
					line("injection.exchange_credential_ambiguous", "warn"),
				],
				unlogged: ["sess-s3-both", ASSERTION],
			},
			{
				name: "does not count other cookies as a session: a Bearer JWT beside them is exchanged, not refused as ambiguous",
				cookie: "theme=dark; csrf=abc123",
				authorization: `Bearer ${ASSERTION_OTHER_COOKIES}`,
				provider: { answer: issued("exchanged-s3-c"), grant: exchangeGrant(ASSERTION_OTHER_COOKIES) },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("exchanged-s3-c"),
				lines: [
					INCOMING,
					line("injection.exchange_fetch", "info"),
					line("injection.exchange_success", "info"),
				],
				unlogged: [ASSERTION_OTHER_COOKIES, "exchanged-s3-c"],
			},
			{
				name: "counts a cookie that fails the grammar check as present: 400 credential_ambiguous beside an Authorization",
				cookie: "sid=bad,value",
				authorization: `Bearer ${ASSERTION}`,
				status: 400,
				answer: AMBIGUOUS,
				lines: [
					INCOMING,
					line("injection.exchange_credential_ambiguous", "warn"),
				],
				unlogged: ["bad,value", ASSERTION],
			},
			{
				name: "forwards a cookie that fails the grammar check, with no Authorization, without a minted token",
				cookie: "sid=bad,value",
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "grammar", action: "forward" }),
				],
				unlogged: ["bad,value"],
			},
		],
	},
	{
		name: "with the exchange enabled and INJECTION_STRIP_INBOUND_AUTHORIZATION=true",
		env: () => ({
			...sessionEnv(),
			...EXCHANGE_ENV,
			INJECTION_STRIP_INBOUND_AUTHORIZATION: "true",
			INJECTION_EXCHANGE_ALLOWED_ISSUERS: "https://idp.example https://idp2.example",
		}),
		cases: [
			noCredential,
			sessionMinted("sess-s4-valid", "minted-s4-a"),
			{
				name: "answers a revoked session (400 invalid_grant) 401 session_required",
				cookie: "sid=sess-s4-revoked",
				provider: {
					answer: json(400, { error: "invalid_grant" }),
					grant: sessionGrant("sess-s4-revoked"),
				},
				status: 401,
				answer: SESSION_REFUSED_400,
				lines: [
					INCOMING,
					line("injection.grant_fetch", "info"),
					failed("injection.session_unauthorized", "info"),
				],
				unlogged: ["sess-s4-revoked"],
			},
			{
				name: "exchanges a Bearer JWT from a listed issuer, with nothing stripped",
				authorization: `Bearer ${ASSERTION}`,
				provider: { answer: issued("exchanged-s4"), grant: exchangeGrant(ASSERTION) },
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: bearer("exchanged-s4"),
				lines: [
					INCOMING,
					line("injection.exchange_fetch", "info"),
					line("injection.exchange_success", "info"),
				],
				unlogged: [ASSERTION, "exchanged-s4"],
			},
			{
				name: "refuses an issuer outside INJECTION_EXCHANGE_ALLOWED_ISSUERS 401 credential_rejected, without asking the provider",
				authorization: `Bearer ${ASSERTION_OTHER_ISSUER}`,
				status: 401,
				answer: { error: "credential_rejected", error_description: "the credential was rejected" },
				lines: [INCOMING, line("injection.exchange_issuer_refused", "info")],
				unlogged: [ASSERTION_OTHER_ISSUER, "https://unlisted.example"],
			},
			{
				name: "refuses a client's own non-JWT Authorization 401 credential_unsupported rather than stripping it and forwarding",
				authorization: `Bearer ${CLIENT_OWN}`,
				status: 401,
				answer: UNSUPPORTED,
				lines: [
					INCOMING,
					line("injection.exchange_credential_unsupported", "info", { reason: "format" }),
				],
				unlogged: [CLIENT_OWN],
			},
			{
				name: "refuses a session cookie beside an Authorization 400 credential_ambiguous",
				cookie: "sid=sess-s4-both",
				authorization: `Bearer ${ASSERTION}`,
				status: 400,
				answer: AMBIGUOUS,
				lines: [INCOMING, line("injection.exchange_credential_ambiguous", "warn")],
				unlogged: ["sess-s4-both", ASSERTION],
			},
			{
				name: "forwards a cookie that fails the grammar check, with no Authorization and so nothing to strip",
				cookie: "sid=bad,value",
				status: 200,
				answer: "forwarded",
				upstreamAuthorization: NONE,
				lines: [
					INCOMING,
					line("injection.cookie_rejected", "warn", { reason: "grammar", action: "forward" }),
				],
				unlogged: ["bad,value"],
			},
		],
	},
];

/** What reached the provider for one request. */
const grantsFor = (requestId: string): Grant[] =>
	fake.requests
		.filter((request) => request.headers["x-request-id"] === requestId)
		.map((request) => ({
			method: request.method,
			path: request.path,
			authorization: request.headers.authorization,
			cookie: request.headers.cookie,
			form: Object.fromEntries(new URLSearchParams(request.body.toString("utf8"))),
		}));

describe.each(SETUPS)("the app in injection mode, $name", (setup) => {
	let proxy: ProxyProcess;

	beforeAll(async () => {
		proxy = await startProxy(setup.env(), upstream);
	});
	afterAll(async () => {
		await proxy?.stop();
	});

	for (const [index, c] of setup.cases.entries()) {
		it(c.name, async () => {
			const requestId = `injection-${SETUPS.indexOf(setup)}-${index}`;
			fake.respond(TOKEN_PATH, c.provider?.answer ?? json(500, { error: "must_not_be_asked" }));

			const res = await send(proxy.origin, {
				path: RESOURCE,
				headers: {
					"x-request-id": requestId,
					...(c.cookie !== undefined ? { cookie: c.cookie } : {}),
					...(c.authorization !== undefined ? { authorization: c.authorization } : {}),
				},
			});

			// The answer. Injection never challenges (injection invariant 9).
			expect(res.status).toBe(c.status);
			expect(res.json()).toEqual(c.answer === "forwarded" ? upstreamBody(RESOURCE) : c.answer);
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(res.headers["retry-after"]).toBe(c.retryAfter);

			// What was logged, and that no credential was. First, because it is
			// also the barrier after which a request the proxy should not have
			// sent anywhere would have arrived (see `linesFor`).
			const lines = await proxy.linesFor(requestId);
			expect(lines).toMatchObject(c.lines);
			for (const logged of lines) {
				for (const secret of c.unlogged) {
					expect(logged.raw).not.toContain(secret);
				}
			}

			// What reached the upstream: the decided Authorization and every other
			// inbound header as sent (the Cookie included), or nothing at all.
			const reached = upstream.receivedFor(requestId);
			if (c.answer === "forwarded") {
				expect(reached).toHaveLength(1);
				expect(headerPairs(reached[0].rawHeaders, "authorization")).toEqual(c.upstreamAuthorization);
				expect(reached[0].headers.cookie).toBe(c.cookie);
			} else {
				expect(reached).toEqual([]);
			}

			// What reached the provider: one grant, or nothing.
			expect(grantsFor(requestId)).toEqual(c.provider === undefined ? [] : [c.provider.grant]);
		});
	}

	it("answers a repeat of the session cookie from the cache: no provider call, the same token injected", async () => {
		const [first, second] = [`injection-${SETUPS.indexOf(setup)}-cache-1`, `injection-${SETUPS.indexOf(setup)}-cache-2`];
		fake.respond(TOKEN_PATH, issued("minted-cached"));
		const cookie = "sid=sess-cached";

		expect((await send(proxy.origin, { path: RESOURCE, headers: { "x-request-id": first, cookie } })).status).toBe(200);
		fake.respond(TOKEN_PATH, json(500, { error: "must_not_be_asked" }));
		const res = await send(proxy.origin, { path: RESOURCE, headers: { "x-request-id": second, cookie } });

		expect(res.status).toBe(200);
		expect(grantsFor(first)).toEqual([sessionGrant("sess-cached")]);
		expect(grantsFor(second)).toEqual([]);
		expect(headerPairs(upstream.receivedFor(second)[0].rawHeaders, "authorization")).toEqual(
			bearer("minted-cached"),
		);
		expect(await proxy.linesFor(second)).toMatchObject([INCOMING, line("injection.cache_hit", "debug")]);
	});

	it("forwards a POST body intact once the session cookie is exchanged", async () => {
		const requestId = `injection-${SETUPS.indexOf(setup)}-post`;
		const body = JSON.stringify({ order: 42, note: "x".repeat(4096) });
		fake.respond(TOKEN_PATH, issued("minted-post"));

		const res = await send(proxy.origin, {
			method: "POST",
			path: "/orders",
			headers: { "x-request-id": requestId, cookie: "sid=sess-post", "content-type": "application/json" },
			body,
		});

		expect(res.status).toBe(200);
		const reached = upstream.receivedFor(requestId);
		expect(reached.map((request) => [request.method, request.path, request.body.toString("utf8")])).toEqual([
			["POST", "/orders", body],
		]);
		expect(headerPairs(reached[0].rawHeaders, "authorization")).toEqual(bearer("minted-post"));
		expect(grantsFor(requestId)).toEqual([sessionGrant("sess-post")]);
	});

	it("generates a request id when none is sent, echoes it, and carries it to the provider, the upstream and the log", async () => {
		fake.respond(TOKEN_PATH, issued("minted-generated"));

		const res = await send(proxy.origin, { path: RESOURCE, headers: { cookie: "sid=sess-generated" } });

		expect(res.status).toBe(200);
		const requestId = String(res.headers["x-request-id"]);
		expect(requestId).not.toBe("undefined");
		expect(upstream.receivedFor(requestId)).toHaveLength(1);
		expect(grantsFor(requestId)).toEqual([sessionGrant("sess-generated")]);
		expect(await proxy.linesFor(requestId)).toMatchObject([
			INCOMING,
			line("injection.grant_fetch", "info"),
			line("injection.grant_success", "info"),
		]);
	});

	it("wrote every line about a request with its requestId and an injection.* event (#134), nothing else, and no configured secret", async () => {
		await proxy.linesFor("injection-every-line");
		// Nothing outside the logger: no stdout line that is not NDJSON, and
		// nothing on stderr but the harness's own listening line.
		expect(proxy.unparsed).toEqual([]);
		expect(proxy.stderr()).toMatch(/^composition-test: listening on port \d+\n$/);
		for (const secret of EXCHANGE_SECRETS) {
			for (const logged of proxy.lines) expect(logged.raw).not.toContain(secret);
		}
		const aboutRequests = proxy.lines.filter((logged) => !logged.msg.startsWith("Server ready at"));
		expect(aboutRequests.length).toBeGreaterThan(0);
		for (const logged of aboutRequests) {
			expect(logged).toMatchObject({ requestId: expect.any(String), event: expect.stringMatching(/^injection\./) });
		}
	});
});
