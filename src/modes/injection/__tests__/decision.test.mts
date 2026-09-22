// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The session decision on its own (#95 F1 / F4): `decideInjection` takes three
 * plain header values and the injectable deps, and returns an outcome the
 * middleware applies. Nothing here touches Express; the wire shape of each
 * outcome is pinned by `router.test.mts`, the exchange path's refusals by
 * `exchange-router.test.mts` (the exchange handler itself is F2 and is only
 * handed off to from here).
 */
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import type { Logger } from "../../../logger.mjs";
import {
	decideInjection,
	type InjectionDeps,
	type InjectionInputs,
	type InjectionOutcome,
} from "../decision.mjs";
import { SessionGrantError, type SessionGrantResult } from "../session-grant-client.mjs";
import { createSingleFlight } from "../single-flight.mjs";
import { createTokenCache } from "../token-cache.mjs";

type InjectionCfg = Extract<AppConfig["auth"], { mode: "injection" }>["injection"];

const baseCfg: InjectionCfg = {
	providerOrigin: "http://provider.example",
	clientId: "my-spa",
	scope: "api",
	sessionCookieName: "sid",
	stripInboundAuthorization: false,
	tokenCache: { ttlSeconds: 60, maxEntries: 100, safetyMarginSeconds: 5 },
	timeoutMs: 5000,
	exchange: { enabled: false },
};

const fakeLogger = () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() });
type FakeLogger = ReturnType<typeof fakeLogger>;

/** The overrides a test may ask for; the fakes it gets back are always the ones wired in. */
const makeDeps = (
	cfgOverrides: Partial<InjectionCfg> = {},
	depOverrides: { exchangeEnabled?: boolean } = {},
) => {
	const logger: FakeLogger & Logger = fakeLogger();
	const grantClient = { exchange: vi.fn<() => Promise<SessionGrantResult>>() };
	const deps: InjectionDeps = {
		cfg: { ...baseCfg, ...cfgOverrides },
		tokenCache: createTokenCache({ maxEntries: 100 }),
		singleFlight: createSingleFlight<string>(),
		grantClient,
		exchangeEnabled: depOverrides.exchangeEnabled ?? false,
		logger,
	};
	return { deps, logger, grantClient };
};

const inputs = (overrides: Partial<InjectionInputs> = {}): InjectionInputs => ({
	requestId: "rid-1",
	cookieHeader: undefined,
	authorization: undefined,
	...overrides,
});

const grant = (accessToken: string, expiresIn: number | null = 120): SessionGrantResult => ({
	accessToken,
	expiresIn,
});

type LogFields = Record<string, unknown>;
const fieldsOf = (spy: ReturnType<typeof vi.fn>): LogFields[] =>
	spy.mock.calls
		.map(([first]) => first)
		.filter((first): first is LogFields => typeof first === "object" && first !== null);
const eventsOf = (spy: ReturnType<typeof vi.fn>): unknown[] =>
	fieldsOf(spy).map((fields) => fields.event);
const sha256Hex = (s: string): string => createHash("sha256").update(s).digest("hex");

describe("decideInjection", () => {
	describe("forward: no session cookie, or one the grammar refuses", () => {
		it("forwards as received when the Cookie header is absent, consulting nothing", async () => {
			const { deps, logger, grantClient } = makeDeps();
			const outcome = await decideInjection(inputs(), deps);
			expect(outcome).toEqual<InjectionOutcome>({ kind: "forward" });
			expect(grantClient.exchange).not.toHaveBeenCalled();
			expect(fieldsOf(logger.debug)).toContainEqual(
				expect.objectContaining({ event: "injection.no_cookie", requestId: "rid-1", action: "forward" }),
			);
			expect(eventsOf(logger.warn)).not.toContain("injection.cookie_rejected");
		});

		it("forwards as received when only other cookies are present", async () => {
			const { deps, grantClient } = makeDeps();
			expect(await decideInjection(inputs({ cookieHeader: "other=foo" }), deps)).toEqual({ kind: "forward" });
			expect(grantClient.exchange).not.toHaveBeenCalled();
		});

		it("forwards as received with an inbound Authorization when stripping is off", async () => {
			const { deps, logger } = makeDeps();
			const outcome = await decideInjection(inputs({ authorization: "Bearer own" }), deps);
			expect(outcome).toEqual({ kind: "forward" });
			expect(eventsOf(logger.warn)).not.toContain("injection.inbound_authorization_stripped");
		});

		it("forwards as received when stripping is on but there is no Authorization to strip", async () => {
			const { deps, logger } = makeDeps({ stripInboundAuthorization: true });
			expect(await decideInjection(inputs(), deps)).toEqual({ kind: "forward" });
			expect(eventsOf(logger.warn)).not.toContain("injection.inbound_authorization_stripped");
		});

		it.each([
			{ cookieHeader: "sid=", reason: "empty", bytes: null },
			{ cookieHeader: 'sid="a"b"', reason: "quoting", bytes: '"a"b"' },
			{ cookieHeader: "sid=abc,def", reason: "grammar", bytes: "abc,def" },
		])("forwards a refused cookie ($cookieHeader) anonymously and logs only the reason class $reason", async ({ cookieHeader, reason, bytes }) => {
			const { deps, logger, grantClient } = makeDeps();
			expect(await decideInjection(inputs({ cookieHeader }), deps)).toEqual({ kind: "forward" });
			expect(grantClient.exchange).not.toHaveBeenCalled();
			const rejected = fieldsOf(logger.warn).filter((f) => f.event === "injection.cookie_rejected");
			expect(rejected).toEqual([
				expect.objectContaining({ reason, action: "forward", requestId: "rid-1" }),
			]);
			if (bytes !== null) {
				expect(JSON.stringify(logger.warn.mock.calls)).not.toContain(bytes);
			}
			expect(eventsOf(logger.debug)).not.toContain("injection.no_cookie");
		});
	});

	describe("forward_stripped: stripInboundAuthorization on and an inbound Authorization present", () => {
		it("strips with reason no_cookie when the cookie is absent", async () => {
			const { deps, logger } = makeDeps({ stripInboundAuthorization: true });
			const outcome = await decideInjection(inputs({ authorization: "Bearer own" }), deps);
			expect(outcome).toEqual<InjectionOutcome>({ kind: "forward_stripped", reason: "no_cookie" });
			expect(fieldsOf(logger.warn)).toContainEqual(
				expect.objectContaining({
					event: "injection.inbound_authorization_stripped",
					reason: "no_cookie",
					requestId: "rid-1",
					metric: "auth_proxy_injection_inbound_authorization_stripped",
				}),
			);
		});

		it("strips with reason cookie_rejected when the cookie is refused", async () => {
			const { deps, logger } = makeDeps({ stripInboundAuthorization: true });
			const outcome = await decideInjection(
				inputs({ cookieHeader: "sid=", authorization: "Bearer own" }),
				deps,
			);
			expect(outcome).toEqual({ kind: "forward_stripped", reason: "cookie_rejected" });
			expect(eventsOf(logger.warn)).toEqual([
				"injection.cookie_rejected",
				"injection.inbound_authorization_stripped",
			]);
		});
	});

	describe("inject: a session cookie the grammar accepts", () => {
		it("mints on a cache miss: one grant call with the cookie value and the request id", async () => {
			const { deps, logger, grantClient } = makeDeps();
			grantClient.exchange.mockResolvedValueOnce(grant("tok-1"));
			const outcome = await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			expect(outcome).toEqual<InjectionOutcome>({ kind: "inject", token: "tok-1" });
			expect(grantClient.exchange).toHaveBeenCalledTimes(1);
			expect(grantClient.exchange).toHaveBeenCalledWith({ sessionCookieValue: "s1", requestId: "rid-1" });
			expect(eventsOf(logger.info)).toEqual(["injection.grant_fetch", "injection.grant_success"]);
			expect(fieldsOf(logger.info)[1]).toMatchObject({ expiresIn: 120 });
		});

		it("caches the minted token under sha256(cookie value): the second call is a hit", async () => {
			const { deps, logger, grantClient } = makeDeps();
			grantClient.exchange.mockResolvedValueOnce(grant("tok-1"));
			await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			expect(deps.tokenCache.get(sha256Hex("s1"))).toBe("tok-1");
			const second = await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			expect(second).toEqual({ kind: "inject", token: "tok-1" });
			expect(grantClient.exchange).toHaveBeenCalledTimes(1);
			expect(eventsOf(logger.debug)).toContain("injection.cache_hit");
		});

		it("serves a pre-existing cache entry without any grant call", async () => {
			const { deps, grantClient } = makeDeps();
			deps.tokenCache.set(sha256Hex("s1"), "tok-cached", Date.now() + 60_000);
			expect(await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps)).toEqual({
				kind: "inject",
				token: "tok-cached",
			});
			expect(grantClient.exchange).not.toHaveBeenCalled();
		});

		it("does not cache a grant whose expiry is already past, so the next call mints again", async () => {
			const { deps, grantClient } = makeDeps({
				tokenCache: { ttlSeconds: 60, maxEntries: 100, safetyMarginSeconds: 5 },
			});
			// expires_in shorter than the safety margin: computeCacheExpiresAt says "do not cache".
			grantClient.exchange.mockResolvedValueOnce(grant("tok-1", 3)).mockResolvedValueOnce(grant("tok-2", 3));
			expect(await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps)).toEqual({ kind: "inject", token: "tok-1" });
			expect(deps.tokenCache.size()).toBe(0);
			expect(await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps)).toEqual({ kind: "inject", token: "tok-2" });
			expect(grantClient.exchange).toHaveBeenCalledTimes(2);
		});

		it("logs injection.authorization_override when an inbound Authorization is about to be replaced", async () => {
			const { deps, logger, grantClient } = makeDeps();
			grantClient.exchange.mockResolvedValueOnce(grant("tok-1"));
			const outcome = await decideInjection(
				inputs({ cookieHeader: "sid=s1", authorization: "Bearer attacker-supplied" }),
				deps,
			);
			expect(outcome).toEqual({ kind: "inject", token: "tok-1" });
			expect(fieldsOf(logger.warn)).toContainEqual(
				expect.objectContaining({
					event: "injection.authorization_override",
					metric: "auth_proxy_injection_authorization_override",
				}),
			);
		});

		it("uses the first well-formed same-name pair and logs the skipped one as a fallback", async () => {
			const { deps, logger, grantClient } = makeDeps();
			grantClient.exchange.mockResolvedValueOnce(grant("tok-good"));
			const outcome = await decideInjection(inputs({ cookieHeader: "sid=bad,val; sid=good" }), deps);
			expect(outcome).toEqual({ kind: "inject", token: "tok-good" });
			expect(grantClient.exchange).toHaveBeenCalledWith({ sessionCookieValue: "good", requestId: "rid-1" });
			expect(fieldsOf(logger.warn)).toEqual([
				expect.objectContaining({ event: "injection.cookie_rejected", reason: "grammar", action: "fallback" }),
			]);
			expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("bad,val");
		});

		it("coalesces concurrent calls for the same cookie into one grant call and shares the token", async () => {
			const { deps, logger, grantClient } = makeDeps();
			let release: ((value: SessionGrantResult) => void) | null = null;
			grantClient.exchange.mockReturnValueOnce(
				new Promise<SessionGrantResult>((resolve) => {
					release = resolve;
				}),
			);
			const first = decideInjection(inputs({ cookieHeader: "sid=s1", requestId: "rid-a" }), deps);
			const second = decideInjection(inputs({ cookieHeader: "sid=s1", requestId: "rid-b" }), deps);
			await new Promise((resolve) => setTimeout(resolve, 0));
			(release as ((value: SessionGrantResult) => void) | null)?.(grant("tok-shared"));
			expect(await first).toEqual({ kind: "inject", token: "tok-shared" });
			expect(await second).toEqual({ kind: "inject", token: "tok-shared" });
			expect(grantClient.exchange).toHaveBeenCalledTimes(1);
			expect(fieldsOf(logger.debug)).toContainEqual(
				expect.objectContaining({ event: "injection.single_flight_wait", requestId: "rid-b" }),
			);
		});
	});

	describe("respond: the grant failed", () => {
		it.each([
			{
				label: "session_unauthorized is answered as session_required, Retry-After passed through, logged at info",
				err: new SessionGrantError("session_unauthorized", 401, "session expired", "30"),
				status: 401,
				error: "session_required",
				retryAfter: "30",
				level: "info" as const,
				event: "injection.session_unauthorized",
			},
			{
				label: "provider_config_error",
				err: new SessionGrantError("provider_config_error", 502, "provider refused the client"),
				status: 502,
				error: "provider_config_error",
				retryAfter: null,
				level: "error" as const,
				event: "injection.provider_config_error",
			},
			{
				label: "provider_invalid_response",
				err: new SessionGrantError("provider_invalid_response", 502, "no access_token"),
				status: 502,
				error: "provider_invalid_response",
				retryAfter: null,
				level: "error" as const,
				event: "injection.provider_invalid_response",
			},
			{
				label: "provider_unavailable with Retry-After",
				err: new SessionGrantError("provider_unavailable", 502, "provider call failed: timeout", "30"),
				status: 502,
				error: "provider_unavailable",
				retryAfter: "30",
				level: "error" as const,
				event: "injection.provider_unavailable",
			},
		])("$label", async ({ err, status, error, retryAfter, level, event }) => {
			const { deps, logger, grantClient } = makeDeps();
			grantClient.exchange.mockRejectedValueOnce(err);
			const outcome = await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			expect(outcome).toEqual<InjectionOutcome>({
				kind: "respond",
				status,
				body: { error, error_description: err.message },
				retryAfter,
			});
			expect(fieldsOf(logger[level])).toContainEqual(
				expect.objectContaining({ event, requestId: "rid-1", error: err.message }),
			);
		});

		it("answers 502 provider_unavailable for an unclassified throw and logs it as a string", async () => {
			const { deps, logger, grantClient } = makeDeps();
			grantClient.exchange.mockRejectedValueOnce(new Error("boom"));
			const outcome = await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			expect(outcome).toEqual<InjectionOutcome>({
				kind: "respond",
				status: 502,
				body: { error: "provider_unavailable", error_description: "provider call failed" },
				retryAfter: null,
			});
			expect(fieldsOf(logger.error)).toContainEqual(
				expect.objectContaining({ event: "injection.unexpected_error", error: "Error: boom" }),
			);
		});

		it("does not cache a failure: the next identical call reaches the client again", async () => {
			const { deps, grantClient } = makeDeps();
			grantClient.exchange
				.mockRejectedValueOnce(new SessionGrantError("provider_unavailable", 502, "down"))
				.mockResolvedValueOnce(grant("tok-after"));
			expect((await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps)).kind).toBe("respond");
			expect(deps.tokenCache.size()).toBe(0);
			expect(await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps)).toEqual({ kind: "inject", token: "tok-after" });
			expect(grantClient.exchange).toHaveBeenCalledTimes(2);
		});

		it("shares a rejection with every concurrent waiter without a second grant call", async () => {
			const { deps, grantClient } = makeDeps();
			let reject: ((reason: unknown) => void) | null = null;
			grantClient.exchange.mockReturnValueOnce(
				new Promise<SessionGrantResult>((_resolve, rej) => {
					reject = rej;
				}),
			);
			const first = decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			const second = decideInjection(inputs({ cookieHeader: "sid=s1" }), deps);
			await new Promise((resolve) => setTimeout(resolve, 0));
			(reject as ((reason: unknown) => void) | null)?.(
				new SessionGrantError("session_unauthorized", 401, "session expired"),
			);
			for (const outcome of [await first, await second]) {
				expect(outcome).toEqual<InjectionOutcome>({
					kind: "respond",
					status: 401,
					body: { error: "session_required", error_description: "session expired" },
					retryAfter: null,
				});
			}
			expect(grantClient.exchange).toHaveBeenCalledTimes(1);
		});
	});

	describe("exchange: the hand-off to the exchange handler (F2), not decided here", () => {
		it.each([
			{ cookieHeader: undefined, sessionCookie: "absent" as const },
			{ cookieHeader: "sid=s1", sessionCookie: "found" as const },
			{ cookieHeader: "sid=", sessionCookie: "rejected" as const },
		])("hands off any inbound Authorization with the cookie's classification ($sessionCookie)", async ({ cookieHeader, sessionCookie }) => {
			const { deps, logger, grantClient } = makeDeps({}, { exchangeEnabled: true });
			const outcome = await decideInjection(
				inputs({ cookieHeader, authorization: "Bearer any" }),
				deps,
			);
			expect(outcome).toEqual<InjectionOutcome>({
				kind: "exchange",
				args: { requestId: "rid-1", authorization: "Bearer any", sessionCookie },
			});
			expect(grantClient.exchange).not.toHaveBeenCalled();
			expect([logger.debug, logger.info, logger.warn, logger.error].flatMap(eventsOf)).toEqual([]);
		});

		it("hands off an empty Authorization too — any scheme, even empty (#90)", async () => {
			const { deps } = makeDeps({}, { exchangeEnabled: true });
			expect(await decideInjection(inputs({ authorization: "" }), deps)).toEqual({
				kind: "exchange",
				args: { requestId: "rid-1", authorization: "", sessionCookie: "absent" },
			});
		});

		it("takes the session path as usual when the exchange is on but no Authorization is present", async () => {
			const { deps, grantClient } = makeDeps({}, { exchangeEnabled: true });
			grantClient.exchange.mockResolvedValueOnce(grant("tok-1"));
			expect(await decideInjection(inputs({ cookieHeader: "sid=s1" }), deps)).toEqual({ kind: "inject", token: "tok-1" });
		});

		it("with the exchange off, an inbound Authorization is not handed off: it is forwarded as received", async () => {
			const { deps } = makeDeps();
			expect(await decideInjection(inputs({ authorization: "Bearer jwt" }), deps)).toEqual({ kind: "forward" });
		});
	});
});
