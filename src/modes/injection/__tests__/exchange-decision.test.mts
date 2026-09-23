// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The exchange decision on its own (#95 F2): `decideExchange` takes the
 * hand-off arguments the session decision produced and the injectable deps,
 * and returns `inject` or `respond` for the middleware to apply. Nothing here
 * touches Express; the wire shape of each outcome, the request the real
 * client sends and what the router does with an injected dependency are pinned
 * by `exchange-router.test.mts`.
 */
import { describe, expect, it, vi } from "vitest";
import type { ExchangeConfig } from "../../../../config/application.schema.mjs";
import type { Logger } from "../../../logger.mjs";
import { createSingleFlight } from "../../../single-flight.mjs";
import type { ExchangeArgs } from "../decision.mjs";
import {
	decideExchange,
	type ExchangeDeps,
	type ExchangeOutcome,
	exchangeCacheKey,
	exchangeContext,
} from "../exchange.mjs";
import {
	JwtBearerError,
	type JwtBearerErrorCode,
	type JwtBearerResult,
} from "../jwt-bearer-client.mjs";
import { createTokenCache } from "../token-cache.mjs";

const ENABLED: Extract<ExchangeConfig, { enabled: true }> = {
	enabled: true,
	clientId: "proxy-exchange",
	clientSecret: "s3cret",
	scope: null,
	audience: null,
	resource: null,
	allowedIssuers: [],
};

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

let assertionCounter = 0;
/** An unsigned-looking JWS compact JWT; the provider (faked) is what verifies. */
const makeAssertion = (claims: Record<string, unknown> = {}): string => {
	assertionCounter += 1;
	return `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({
		iss: "https://idp-a.example",
		sub: "user-1",
		aud: "http://provider.example",
		exp: Math.floor(Date.now() / 1000) + 600,
		jti: `jti-${assertionCounter}`,
		...claims,
	})}.c2lnbmF0dXJl`;
};

const fakeLogger = () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() });
type FakeLogger = ReturnType<typeof fakeLogger>;

type Exchange = (args: { assertion: string; requestId: string }) => Promise<JwtBearerResult>;

/** The overrides a test may ask for; the fakes it gets back are always the ones wired in. */
const makeDeps = (
	overrides: { allowedIssuers?: readonly string[]; cachePolicy?: ExchangeDeps["cachePolicy"] } = {},
) => {
	const logger: FakeLogger & Logger = fakeLogger();
	const client = { exchange: vi.fn<Exchange>() };
	const deps: ExchangeDeps = {
		context: exchangeContext("http://provider.example", ENABLED),
		allowedIssuers: new Set(overrides.allowedIssuers ?? []),
		cachePolicy: overrides.cachePolicy ?? { ttlSeconds: 60, safetyMarginSeconds: 5 },
		client,
		tokenCache: createTokenCache({ maxEntries: 100 }),
		singleFlight: createSingleFlight<string>(),
		logger,
	};
	return { deps, logger, client };
};

const args = (assertion: string, overrides: Partial<ExchangeArgs> = {}): ExchangeArgs => ({
	requestId: "rid-1",
	authorization: `Bearer ${assertion}`,
	sessionCookie: "absent",
	...overrides,
});

const issued = (accessToken: string, expiresIn: number | null = 300): JwtBearerResult => ({
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
const everythingLogged = (logger: FakeLogger): string =>
	JSON.stringify([logger.debug, logger.info, logger.warn, logger.error].map((spy) => spy.mock.calls));

describe("decideExchange", () => {
	describe("refusals before any provider call", () => {
		it("responds 400 credential_ambiguous when a session cookie was found, calling nothing", async () => {
			const { deps, logger, client } = makeDeps();
			const outcome = await decideExchange(args(makeAssertion(), { sessionCookie: "found" }), deps);
			expect(outcome).toEqual<ExchangeOutcome>({
				kind: "respond",
				status: 400,
				body: {
					error: "credential_ambiguous",
					error_description: "send either the session cookie or an Authorization header, not both",
				},
				retryAfter: null,
			});
			expect(client.exchange).not.toHaveBeenCalled();
			expect(fieldsOf(logger.warn)).toContainEqual(
				expect.objectContaining({
					event: "injection.exchange_credential_ambiguous",
					requestId: "rid-1",
					sessionCookie: "found",
					metric: "auth_proxy_injection_exchange_credential_ambiguous",
				}),
			);
		});

		it("treats a rejected session cookie as a second credential too", async () => {
			const { deps, logger, client } = makeDeps();
			const outcome = await decideExchange(args(makeAssertion(), { sessionCookie: "rejected" }), deps);
			expect(outcome).toMatchObject({ kind: "respond", status: 400 });
			expect(client.exchange).not.toHaveBeenCalled();
			expect(fieldsOf(logger.warn)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_credential_ambiguous", sessionCookie: "rejected" }),
			);
		});

		it("responds 401 credential_unsupported when Authorization is not a Bearer JWT, with the reason class", async () => {
			const { deps, logger, client } = makeDeps();
			const scheme = await decideExchange(args("", { authorization: "Basic abc" }), deps);
			expect(scheme).toEqual<ExchangeOutcome>({
				kind: "respond",
				status: 401,
				body: {
					error: "credential_unsupported",
					error_description: "Authorization must be a Bearer JWT assertion",
				},
				retryAfter: null,
			});
			const format = await decideExchange(args("not-a-jwt"), deps);
			expect(format).toMatchObject({ kind: "respond", status: 401 });
			expect(client.exchange).not.toHaveBeenCalled();
			expect(fieldsOf(logger.info)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_credential_unsupported", reason: "scheme" }),
			);
			expect(fieldsOf(logger.info)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_credential_unsupported", reason: "format" }),
			);
		});
	});

	describe("allowedIssuers prefilter", () => {
		it("refuses an issuer outside the list with 401 credential_rejected, no provider call and no issuer in the log", async () => {
			const { deps, logger, client } = makeDeps({ allowedIssuers: ["https://idp-a.example"] });
			const assertion = makeAssertion({ iss: "https://idp-z.example" });
			const outcome = await decideExchange(args(assertion), deps);
			expect(outcome).toEqual<ExchangeOutcome>({
				kind: "respond",
				status: 401,
				body: { error: "credential_rejected", error_description: "the credential was rejected" },
				retryAfter: null,
			});
			expect(client.exchange).not.toHaveBeenCalled();
			expect(eventsOf(logger.info)).toContain("injection.exchange_issuer_refused");
			expect(everythingLogged(logger)).not.toContain("idp-z.example");
			expect(everythingLogged(logger)).not.toContain(assertion);
		});

		it("refuses a listed-out issuer before the cache is consulted: a seeded entry for it is not served", async () => {
			const { deps, client } = makeDeps({ allowedIssuers: ["https://idp-a.example"] });
			const assertion = makeAssertion({ iss: "https://idp-z.example" });
			deps.tokenCache.set(exchangeCacheKey(deps.context, assertion), "issued-seeded", Date.now() + 60_000);
			const outcome = await decideExchange(args(assertion), deps);
			expect(outcome).toMatchObject({ kind: "respond", status: 401, body: { error: "credential_rejected" } });
			expect(client.exchange).not.toHaveBeenCalled();
		});

		it("refuses an assertion without iss when the list is set", async () => {
			const { deps, client } = makeDeps({ allowedIssuers: ["https://idp-a.example"] });
			const outcome = await decideExchange(args(makeAssertion({ iss: undefined })), deps);
			expect(outcome).toMatchObject({ kind: "respond", status: 401, body: { error: "credential_rejected" } });
			expect(client.exchange).not.toHaveBeenCalled();
		});

		it("submits an issuer on the list", async () => {
			const { deps, client } = makeDeps({ allowedIssuers: ["https://idp-a.example", "https://idp-b.example"] });
			client.exchange.mockResolvedValueOnce(issued("issued-1"));
			const outcome = await decideExchange(args(makeAssertion({ iss: "https://idp-b.example" })), deps);
			expect(outcome).toEqual<ExchangeOutcome>({ kind: "inject", token: "issued-1" });
			expect(client.exchange).toHaveBeenCalledTimes(1);
		});

		it("applies no prefilter when the list is empty", async () => {
			const { deps, client } = makeDeps({ allowedIssuers: [] });
			client.exchange.mockResolvedValueOnce(issued("issued-1"));
			const outcome = await decideExchange(args(makeAssertion({ iss: "https://idp-z.example" })), deps);
			expect(outcome).toEqual<ExchangeOutcome>({ kind: "inject", token: "issued-1" });
			expect(client.exchange).toHaveBeenCalledTimes(1);
		});
	});

	describe("exchange and cache", () => {
		it("submits the assertion once, injects the issued token and caches it under the exchange key", async () => {
			const { deps, logger, client } = makeDeps();
			const assertion = makeAssertion();
			client.exchange.mockResolvedValueOnce(issued("issued-1", 300));

			const first = await decideExchange(args(assertion), deps);
			expect(first).toEqual<ExchangeOutcome>({ kind: "inject", token: "issued-1" });
			expect(client.exchange).toHaveBeenCalledWith({ assertion, requestId: "rid-1" });
			expect(deps.tokenCache.get(exchangeCacheKey(deps.context, assertion))).toBe("issued-1");
			expect(eventsOf(logger.info)).toContain("injection.exchange_fetch");
			expect(fieldsOf(logger.info)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_success", requestId: "rid-1", expiresIn: 300, cached: true }),
			);

			const second = await decideExchange(args(assertion, { requestId: "rid-2" }), deps);
			expect(second).toEqual<ExchangeOutcome>({ kind: "inject", token: "issued-1" });
			expect(client.exchange).toHaveBeenCalledTimes(1);
			expect(fieldsOf(logger.debug)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_cache_hit", requestId: "rid-2" }),
			);
		});

		it("does not cache when the assertion carries no exp, and says so", async () => {
			const { deps, logger, client } = makeDeps();
			const assertion = makeAssertion({ exp: undefined });
			client.exchange.mockResolvedValue(issued("issued-1", 300));

			await decideExchange(args(assertion), deps);
			expect(deps.tokenCache.get(exchangeCacheKey(deps.context, assertion))).toBeNull();
			expect(fieldsOf(logger.info)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_success", cached: false }),
			);
			await decideExchange(args(assertion), deps);
			expect(client.exchange).toHaveBeenCalledTimes(2);
		});

		it("anchors the entry's expiry at the request instant, not at the response", async () => {
			vi.useFakeTimers();
			try {
				const start = 1_700_000_000_000;
				vi.setSystemTime(start);
				const { deps, client } = makeDeps({ cachePolicy: { ttlSeconds: 60, safetyMarginSeconds: 5 } });
				const assertion = makeAssertion({ exp: Math.floor(start / 1000) + 600 });
				client.exchange.mockImplementationOnce(async () => {
					vi.setSystemTime(start + 10_000);
					return issued("issued-late", 20);
				});

				await decideExchange(args(assertion), deps);
				// min(start + 60 s, start + 20 s, exp) − 5 s = start + 15 s, counted from the request.
				const key = exchangeCacheKey(deps.context, assertion);
				vi.setSystemTime(start + 14_000);
				expect(deps.tokenCache.get(key)).toBe("issued-late");
				vi.setSystemTime(start + 16_000);
				expect(deps.tokenCache.get(key)).toBeNull();
			} finally {
				vi.useRealTimers();
			}
		});

		it("coalesces concurrent submissions of one assertion into one provider call, logging the wait once", async () => {
			const { deps, logger, client } = makeDeps();
			const assertion = makeAssertion();
			let release: (result: JwtBearerResult) => void = () => {};
			client.exchange.mockImplementationOnce(
				() =>
					new Promise<JwtBearerResult>((resolve) => {
						release = resolve;
					}),
			);

			const pending = Promise.all([
				decideExchange(args(assertion, { requestId: "rid-a" }), deps),
				decideExchange(args(assertion, { requestId: "rid-b" }), deps),
			]);
			await vi.waitFor(() => expect(client.exchange).toHaveBeenCalledTimes(1));
			release(issued("issued-1"));
			const outcomes = await pending;

			expect(outcomes).toEqual<ExchangeOutcome[]>([
				{ kind: "inject", token: "issued-1" },
				{ kind: "inject", token: "issued-1" },
			]);
			expect(client.exchange).toHaveBeenCalledTimes(1);
			expect(
				eventsOf(logger.debug).filter((event) => event === "injection.exchange_single_flight_wait"),
			).toHaveLength(1);
		});

		it("shares the rejection among waiters and caches nothing", async () => {
			const { deps, client } = makeDeps();
			const assertion = makeAssertion();
			let fail: (err: unknown) => void = () => {};
			client.exchange.mockImplementationOnce(
				() =>
					new Promise<JwtBearerResult>((_resolve, reject) => {
						fail = reject;
					}),
			);

			const pending = Promise.all([
				decideExchange(args(assertion), deps),
				decideExchange(args(assertion), deps),
			]);
			await vi.waitFor(() => expect(client.exchange).toHaveBeenCalledTimes(1));
			fail(new JwtBearerError("credential_rejected", 401, "the credential was rejected"));
			const outcomes = await pending;

			expect(outcomes.map((outcome) => outcome.kind)).toEqual(["respond", "respond"]);
			expect(client.exchange).toHaveBeenCalledTimes(1);
			expect(deps.tokenCache.get(exchangeCacheKey(deps.context, assertion))).toBeNull();
			client.exchange.mockResolvedValueOnce(issued("issued-2"));
			await decideExchange(args(assertion), deps);
			expect(client.exchange).toHaveBeenCalledTimes(2);
		});
	});

	describe("provider answers", () => {
		const answers: [
			JwtBearerErrorCode,
			number,
			"info" | "warn" | "error",
			string,
			string | null,
			string,
		][] = [
			["credential_rejected", 401, "info", "injection.exchange_rejected", null, "exchange rejected"],
			["exchange_not_permitted", 403, "warn", "injection.exchange_not_permitted", null, "exchange not permitted"],
			["provider_config_error", 502, "error", "injection.exchange_provider_config_error", null, "exchange failed"],
			["provider_invalid_response", 502, "error", "injection.exchange_provider_invalid_response", null, "exchange failed"],
			["provider_unavailable", 503, "error", "injection.exchange_provider_unavailable", "7", "exchange failed"],
		];

		it.each(answers)(
			"%s is answered %i with the client's message, logged at %s as %s",
			async (code, status, level, event, retryAfter, message) => {
				const { deps, logger, client } = makeDeps();
				client.exchange.mockRejectedValueOnce(
					new JwtBearerError(code, status, `message for ${code}`, retryAfter, "provider_said"),
				);
				const outcome = await decideExchange(args(makeAssertion()), deps);
				expect(outcome).toEqual<ExchangeOutcome>({
					kind: "respond",
					status,
					body: { error: code, error_description: `message for ${code}` },
					retryAfter,
				});
				expect(fieldsOf(logger[level])).toContainEqual(
					expect.objectContaining({
						event,
						requestId: "rid-1",
						providerError: "provider_said",
						error: `message for ${code}`,
					}),
				);
				// The line's message too, now that it is data in a table (#95 F41).
				expect(logger[level]).toHaveBeenCalledWith(expect.objectContaining({ event }), message);
			},
		);

		// #95 F41. The exchange client is injectable (F2), and a supplied one is
		// not bound by JwtBearerErrorCode at runtime. logFailure was a switch
		// with no default returning void, so an undeclared code fell out of it
		// and the refusal was answered with no log line at all. The prototype
		// keys are here for the reason #109 found them on the session path.
		it.each(["provider_exploded", "constructor", "toString", "__proto__"])(
			"logs a refusal whose code the union does not declare (%j), rather than nothing",
			async (code) => {
				const { deps, logger, client } = makeDeps();
				client.exchange.mockRejectedValueOnce(
					new JwtBearerError(code as JwtBearerErrorCode, 502, "a supplied client invented this"),
				);

				const outcome = await decideExchange(args(makeAssertion()), deps);

				expect(outcome).toMatchObject({ kind: "respond", status: 502 });
				expect(fieldsOf(logger.error)).toContainEqual(
					expect.objectContaining({
						event: "injection.exchange_provider_unavailable",
						requestId: "rid-1",
						error: "a supplied client invented this",
					}),
				);
			},
		);

		it("answers 502 provider_unavailable on an error that is not a JwtBearerError, logging it as unexpected", async () => {
			const { deps, logger, client } = makeDeps();
			client.exchange.mockRejectedValueOnce(new Error("boom"));
			const outcome = await decideExchange(args(makeAssertion()), deps);
			expect(outcome).toEqual<ExchangeOutcome>({
				kind: "respond",
				status: 502,
				body: { error: "provider_unavailable", error_description: "provider call failed" },
				retryAfter: null,
			});
			expect(fieldsOf(logger.error)).toContainEqual(
				expect.objectContaining({ event: "injection.exchange_unexpected_error", error: "Error: boom" }),
			);
		});

		it("never caches a failure: the next presentation is submitted again", async () => {
			const { deps, client } = makeDeps();
			const assertion = makeAssertion();
			client.exchange.mockRejectedValueOnce(new JwtBearerError("provider_unavailable", 503, "down"));
			await decideExchange(args(assertion), deps);
			client.exchange.mockResolvedValueOnce(issued("issued-2"));
			const outcome = await decideExchange(args(assertion), deps);
			expect(outcome).toEqual<ExchangeOutcome>({ kind: "inject", token: "issued-2" });
			expect(client.exchange).toHaveBeenCalledTimes(2);
		});
	});

	describe("what is never logged", () => {
		it("logs neither the assertion, the issued token, the issuer nor the client secret on any path", async () => {
			const { deps, logger, client } = makeDeps({ allowedIssuers: ["https://idp-a.example"] });
			const accepted = makeAssertion();
			const refused = makeAssertion({ iss: "https://idp-z.example" });
			const rejected = makeAssertion({ sub: "user-2" });
			client.exchange.mockResolvedValueOnce(issued("issued-secret-token"));
			client.exchange.mockRejectedValueOnce(
				new JwtBearerError("credential_rejected", 401, "the credential was rejected", null, "invalid_grant"),
			);

			await decideExchange(args(accepted), deps);
			await decideExchange(args(accepted), deps);
			await decideExchange(args(refused), deps);
			await decideExchange(args(rejected), deps);
			await decideExchange(args(accepted, { sessionCookie: "found" }), deps);
			await decideExchange(args("", { authorization: "Bearer opaque-secret" }), deps);

			const logged = everythingLogged(logger);
			expect(
				[logger.debug, logger.info, logger.warn, logger.error].flatMap((spy) => eventsOf(spy)),
			).toEqual(
				expect.arrayContaining([
					"injection.exchange_fetch",
					"injection.exchange_success",
					"injection.exchange_cache_hit",
					"injection.exchange_issuer_refused",
					"injection.exchange_rejected",
					"injection.exchange_credential_ambiguous",
					"injection.exchange_credential_unsupported",
				]),
			);
			for (const secret of [accepted, refused, rejected, "issued-secret-token", "s3cret", "opaque-secret", "idp-z.example"]) {
				expect(logged).not.toContain(secret);
			}
		});
	});
});
