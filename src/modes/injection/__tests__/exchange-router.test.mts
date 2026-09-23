import type { IncomingMessage, Server, ServerResponse } from "node:http";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppConfig, ExchangeConfig } from "../../../../config/application.schema.mjs";
import type { Logger } from "../../../logger.mjs";
import logger from "../../../logger.mjs";
import { createSingleFlight, type SingleFlight } from "../../../single-flight.mjs";
import { exchangeCacheKey, exchangeContext } from "../exchange.mjs";
import { createRouter } from "../router.mjs";
import { createTokenCache } from "../token-cache.mjs";
import { listenForFlight } from "./flight-joined.mjs";

// External credential exchange (#90): with auth.injection.exchange enabled, an
// inbound `Authorization: Bearer <JWT>` is submitted to the provider as an
// RFC 7523 jwt-bearer assertion and only the issued token reaches upstream.

type Received = { method: string; url: string; headers: IncomingMessage["headers"] };

const startUpstream = async () => {
	const received: Received[] = [];
	const server: Server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
		received.push({ method: req.method ?? "", url: req.url ?? "", headers: { ...req.headers } });
		req.resume();
		req.on("end", () => {
			res.statusCode = 204;
			res.end();
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	return {
		baseURL: `http://127.0.0.1:${port}`,
		received,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
};

const ENABLED: Extract<ExchangeConfig, { enabled: true }> = {
	enabled: true,
	clientId: "proxy-exchange",
	clientSecret: "s3cret",
	scope: null,
	audience: null,
	resource: null,
	allowedIssuers: [],
};

const makeConfig = (
	upstreamBaseURL: string,
	exchange: ExchangeConfig = ENABLED,
	injectionOverrides: Record<string, unknown> = {},
): AppConfig => ({
	http: {
		hostname: "127.0.0.1",
		port: 0,
		pathPrefix: "/",
		bodyLimitSize: "10mb",
		cors: { origin: { pattern: null } },
	},
	auth: {
		mode: "injection" as const,
		injection: {
			providerOrigin: "http://provider.example",
			clientId: "my-spa",
			scope: "api",
			sessionCookieName: "sid",
			stripInboundAuthorization: false,
			tokenCache: { ttlSeconds: 60, maxEntries: 100, safetyMarginSeconds: 5 },
			timeoutMs: 5000,
			exchange,
			...injectionOverrides,
		},
	},
	upstream: { baseURL: upstreamBaseURL },
});

const mountApp = (config: AppConfig): express.Express => {
	const app = express();
	app.use(createRouter({ config }));
	return app;
};

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

let assertionCounter = 0;
/** An unsigned-looking JWS compact JWT; the provider (mocked) is what verifies. */
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

const jsonResponse = (
	status: number,
	body: unknown,
	headers: Record<string, string> = {},
): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});

const okToken = (accessToken: string, expiresIn: number | null = 300): Response =>
	jsonResponse(200, {
		access_token: accessToken,
		token_type: "Bearer",
		...(expiresIn === null ? {} : { expires_in: expiresIn }),
	});

describe("injection router — external credential exchange (#90)", () => {
	let upstream: Awaited<ReturnType<typeof startUpstream>>;
	let fetchMock: ReturnType<typeof vi.fn>;

	const providerCall = (index = 0) => {
		const [url, init] = fetchMock.mock.calls[index] as [string, RequestInit];
		return {
			url,
			headers: init.headers as Record<string, string>,
			params: new URLSearchParams(init.body as string),
		};
	};

	beforeEach(async () => {
		fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		upstream = await startUpstream();
	});

	afterEach(async () => {
		vi.useRealTimers();
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
		await upstream.close();
	});

	describe("accepted assertion", () => {
		it("exchanges the assertion and forwards only the issued Bearer upstream", async () => {
			const assertion = makeAssertion();
			fetchMock.mockResolvedValueOnce(okToken("issued-1"));
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app).get("/orders").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(204);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			const call = providerCall();
			expect(call.url).toBe("http://provider.example/oauth/token");
			expect(call.params.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
			expect(call.params.get("assertion")).toBe(assertion);
			expect(call.headers.Authorization).toBe(
				`Basic ${Buffer.from("proxy-exchange:s3cret").toString("base64")}`,
			);

			expect(upstream.received).toHaveLength(1);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-1");
			// The external credential never reaches the backend, in any header.
			expect(JSON.stringify(upstream.received[0])).not.toContain(assertion);
		});

		it("sends the configured scope, audience and resource", async () => {
			fetchMock.mockResolvedValueOnce(okToken("issued-1"));
			const app = mountApp(
				makeConfig(upstream.baseURL, {
					...ENABLED,
					scope: "orders.read",
					audience: "https://api.example.com",
					resource: "https://api.example.com/orders",
				}),
			);

			await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);

			const { params } = providerCall();
			expect(params.get("scope")).toBe("orders.read");
			expect(params.get("audience")).toBe("https://api.example.com");
			expect(params.get("resource")).toBe("https://api.example.com/orders");
		});

		it("accepts assertions from several issuers without a proxy allowlist", async () => {
			const fromA = makeAssertion({ iss: "https://idp-a.example" });
			const fromB = makeAssertion({ iss: "https://idp-b.example" });
			fetchMock
				.mockResolvedValueOnce(okToken("issued-a"))
				.mockResolvedValueOnce(okToken("issued-b"));
			const app = mountApp(makeConfig(upstream.baseURL));

			const resA = await request(app).get("/").set("Authorization", `Bearer ${fromA}`);
			const resB = await request(app).get("/").set("Authorization", `Bearer ${fromB}`);

			expect([resA.status, resB.status]).toEqual([204, 204]);
			expect(providerCall(0).params.get("assertion")).toBe(fromA);
			expect(providerCall(1).params.get("assertion")).toBe(fromB);
			expect(upstream.received.map((r) => r.headers.authorization)).toEqual([
				"Bearer issued-a",
				"Bearer issued-b",
			]);
		});

		it("replaces the inbound header even with stripInboundAuthorization on", async () => {
			const warnSpy = vi.spyOn(logger, "warn");
			fetchMock.mockResolvedValueOnce(okToken("issued-1"));
			const app = mountApp(
				makeConfig(upstream.baseURL, ENABLED, { stripInboundAuthorization: true }),
			);

			const res = await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-1");
			expect(JSON.stringify(warnSpy.mock.calls)).not.toContain(
				"injection.inbound_authorization_stripped",
			);
		});
	});

	describe("allowedIssuers prefilter", () => {
		it("refuses an unlisted iss with 401 without calling the provider", async () => {
			const app = mountApp(
				makeConfig(upstream.baseURL, { ...ENABLED, allowedIssuers: ["https://idp-a.example"] }),
			);

			for (const assertion of [
				makeAssertion({ iss: "https://evil.example" }),
				makeAssertion({ iss: undefined }),
			]) {
				const res = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

				expect(res.status).toBe(401);
				expect(res.body.error).toBe("credential_rejected");
				expect(typeof res.body.error_description).toBe("string");
				expect(res.headers["www-authenticate"]).toBeUndefined();
			}
			expect(fetchMock).not.toHaveBeenCalled();
			expect(upstream.received).toHaveLength(0);
		});

		it("still exchanges a listed iss — the provider remains the one that verifies it", async () => {
			fetchMock.mockResolvedValueOnce(okToken("issued-1"));
			const app = mountApp(
				makeConfig(upstream.baseURL, {
					...ENABLED,
					allowedIssuers: ["https://idp-a.example", "https://idp-b.example"],
				}),
			);

			const res = await request(app)
				.get("/")
				.set("Authorization", `Bearer ${makeAssertion({ iss: "https://idp-b.example" })}`);

			expect(res.status).toBe(204);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-1");
		});
	});

	describe("provider refusals — no pass-through, no session fallback", () => {
		const refusals = [
			["an invalid or expired assertion", "invalid_grant", 401, "credential_rejected"],
			["a wrong audience", "invalid_grant", 401, "credential_rejected"],
			["an unregistered issuer", "invalid_grant", 401, "credential_rejected"],
			["a disallowed scope", "invalid_scope", 403, "exchange_not_permitted"],
			["a disallowed target", "invalid_target", 403, "exchange_not_permitted"],
			["a disallowed client", "unauthorized_client", 403, "exchange_not_permitted"],
		] as const;

		for (const [label, providerError, status, error] of refusals) {
			it(`answers ${status} ${error} for ${label} (provider ${providerError})`, async () => {
				fetchMock.mockResolvedValueOnce(
					jsonResponse(400, { error: providerError, error_description: "refused" }),
				);
				const app = mountApp(makeConfig(upstream.baseURL));

				const res = await request(app)
					.get("/")
					.set("Authorization", `Bearer ${makeAssertion()}`);

				expect(res.status).toBe(status);
				expect(res.body.error).toBe(error);
				expect(typeof res.body.error_description).toBe("string");
				expect(res.headers["www-authenticate"]).toBeUndefined();
				expect(upstream.received).toHaveLength(0);
				// One jwt-bearer submission: no retry, and no session grant.
				expect(fetchMock).toHaveBeenCalledTimes(1);
				expect(providerCall().params.get("grant_type")).toBe(
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
				);
			});
		}

		it("does not cache a failure: the next identical request is submitted again", async () => {
			const assertion = makeAssertion();
			fetchMock
				.mockResolvedValueOnce(jsonResponse(400, { error: "invalid_grant" }))
				.mockResolvedValueOnce(jsonResponse(400, { error: "invalid_grant" }));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			const res = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(401);
			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(upstream.received).toHaveLength(0);
		});

		it("answers 502 provider_config_error when the provider refuses the proxy's client", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse(401, { error: "invalid_client" }));
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("provider_config_error");
			expect(upstream.received).toHaveLength(0);
		});

		it("answers 502 provider_invalid_response for a non-Bearer token_type", async () => {
			fetchMock.mockResolvedValueOnce(
				jsonResponse(200, { access_token: "bound", token_type: "DPoP", expires_in: 300 }),
			);
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("provider_invalid_response");
			expect(upstream.received).toHaveLength(0);
		});
	});

	describe("provider unavailable", () => {
		it("answers 502 provider_unavailable with Retry-After on a provider 503", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse(503, {}, { "Retry-After": "30" }));
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("provider_unavailable");
			expect(res.headers["retry-after"]).toBe("30");
			expect(upstream.received).toHaveLength(0);
		});

		it("answers 502 provider_unavailable on a network error or timeout", async () => {
			fetchMock
				.mockRejectedValueOnce(new TypeError("fetch failed"))
				.mockRejectedValueOnce(new DOMException("timed out", "TimeoutError"));
			const app = mountApp(makeConfig(upstream.baseURL));

			for (let i = 0; i < 2; i++) {
				const res = await request(app)
					.get("/")
					.set("Authorization", `Bearer ${makeAssertion()}`);
				expect(res.status).toBe(502);
				expect(res.body.error).toBe("provider_unavailable");
			}
			expect(upstream.received).toHaveLength(0);
		});
	});

	describe("cache", () => {
		it("reuses the issued token for the same assertion without resubmitting it", async () => {
			const assertion = makeAssertion();
			fetchMock.mockResolvedValueOnce(okToken("issued-1"));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			const res = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(204);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(upstream.received.map((r) => r.headers.authorization)).toEqual([
				"Bearer issued-1",
				"Bearer issued-1",
			]);
		});

		it("keeps a separate entry per assertion", async () => {
			fetchMock
				.mockResolvedValueOnce(okToken("issued-1"))
				.mockResolvedValueOnce(okToken("issued-2"));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);
			await request(app).get("/").set("Authorization", `Bearer ${makeAssertion()}`);

			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(upstream.received.map((r) => r.headers.authorization)).toEqual([
				"Bearer issued-1",
				"Bearer issued-2",
			]);
		});

		it("does not share entries with the session cache", async () => {
			// A session cookie whose value happens to equal an assertion must not
			// be answered from the exchange cache, and vice versa.
			const assertion = makeAssertion();
			fetchMock
				.mockResolvedValueOnce(okToken("issued-exchange"))
				.mockResolvedValueOnce(okToken("issued-session"));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			await request(app).get("/").set("Cookie", `sid=${assertion}`);

			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(providerCall(1).params.get("grant_type")).toBe("session");
			expect(upstream.received[1].headers.authorization).toBe("Bearer issued-session");
		});

		// Fake only Date: expiry is decided from Date.now(), while supertest and
		// the upstream recorder need real timers (see router.test.mts).
		it("never outlives the provider's expires_in", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			const assertion = makeAssertion({ exp: Math.floor(Date.now() / 1000) + 3600 });
			// min(ttl 60, expires_in 20, exp +3600) - margin 5 = 15 s
			fetchMock
				.mockResolvedValueOnce(okToken("issued-1", 20))
				.mockResolvedValueOnce(okToken("issued-2", 20));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			vi.setSystemTime(Date.now() + 14_000);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			vi.setSystemTime(Date.now() + 2_000);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(upstream.received[2].headers.authorization).toBe("Bearer issued-2");
		});

		// expires_in counts from issuance. Anchoring it at the response instead
		// of the request would let a slow provider push the entry past the
		// issued token's real expiry, and inject an expired token.
		it("counts expires_in from the request, not from a slow response", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			const requestedAt = Date.now();
			const assertion = makeAssertion({ exp: Math.floor(requestedAt / 1000) + 3600 });
			// issued with expires_in 20; the answer takes 10 s to arrive.
			// Entry must expire at requestedAt + 20 - margin 5 = requestedAt + 15 s.
			fetchMock
				.mockImplementationOnce(async () => {
					vi.setSystemTime(requestedAt + 10_000);
					return okToken("issued-1", 20);
				})
				.mockResolvedValueOnce(okToken("issued-2", 20));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			vi.setSystemTime(requestedAt + 14_000);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			vi.setSystemTime(requestedAt + 16_000);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(upstream.received[2].headers.authorization).toBe("Bearer issued-2");
		});

		it("does not cache at all when the response arrives after expires_in minus the margin", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			const requestedAt = Date.now();
			const assertion = makeAssertion({ exp: Math.floor(requestedAt / 1000) + 3600 });
			fetchMock
				.mockImplementationOnce(async () => {
					vi.setSystemTime(requestedAt + 16_000);
					return okToken("issued-1", 20);
				})
				.mockResolvedValueOnce(okToken("issued-2", 20));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(upstream.received.map((r) => r.headers.authorization)).toEqual([
				"Bearer issued-1",
				"Bearer issued-2",
			]);
		});

		it("never outlives the assertion's exp", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			const assertion = makeAssertion({ exp: Math.floor(Date.now() / 1000) + 30 });
			// min(ttl 60, expires_in 300, exp +30) - margin 5 = 25 s
			fetchMock
				.mockResolvedValueOnce(okToken("issued-1", 300))
				.mockResolvedValueOnce(jsonResponse(400, { error: "invalid_grant" }));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			vi.setSystemTime(Date.now() + 23_000);
			const hit = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(hit.status).toBe(204);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			vi.setSystemTime(Date.now() + 3_000);
			const miss = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(miss.status).toBe(401);
			expect(upstream.received).toHaveLength(2);
		});

		it("never outlives the configured ttlSeconds", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			const assertion = makeAssertion({ exp: Math.floor(Date.now() / 1000) + 3600 });
			// min(ttl 60, expires_in 3600, exp +3600) - margin 5 = 55 s
			fetchMock
				.mockResolvedValueOnce(okToken("issued-1", 3600))
				.mockResolvedValueOnce(okToken("issued-2", 3600));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			vi.setSystemTime(Date.now() + 54_000);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			vi.setSystemTime(Date.now() + 2_000);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			expect(fetchMock).toHaveBeenCalledTimes(2);
		});

		it("does not cache when the assertion has no exp", async () => {
			const assertion = makeAssertion({ exp: undefined });
			fetchMock
				.mockResolvedValueOnce(okToken("issued-1"))
				.mockResolvedValueOnce(okToken("issued-2"));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(upstream.received.map((r) => r.headers.authorization)).toEqual([
				"Bearer issued-1",
				"Bearer issued-2",
			]);
		});

		it("does not cache when the assertion's remaining validity is within the safety margin", async () => {
			const assertion = makeAssertion({ exp: Math.floor(Date.now() / 1000) + 3 });
			fetchMock
				.mockResolvedValueOnce(okToken("issued-1"))
				.mockResolvedValueOnce(okToken("issued-2"));
			const app = mountApp(makeConfig(upstream.baseURL));

			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect(fetchMock).toHaveBeenCalledTimes(2);
		});
	});

	describe("single-flight", () => {
		const deferred = () => {
			const control = { resolve: (_: Response) => {} };
			const promise = new Promise<Response>((resolve) => {
				control.resolve = resolve;
			});
			return { promise, resolve: (r: Response) => control.resolve(r) };
		};

		it("submits an assertion once for concurrent identical requests", async () => {
			const assertion = makeAssertion();
			const pending = deferred();
			fetchMock.mockReturnValueOnce(pending.promise);
			const { baseURL, joined, close } = await listenForFlight(mountApp(makeConfig(upstream.baseURL)), 3);

			try {
				const inflight = Promise.all(
					["/a", "/b", "/c"].map((path) =>
						request(baseURL).get(path).set("Authorization", `Bearer ${assertion}`),
					),
				);
				await joined;
				pending.resolve(okToken("issued-shared"));
				const responses = await inflight;

				expect(fetchMock).toHaveBeenCalledTimes(1);
				expect(responses.map((r) => r.status)).toEqual([204, 204, 204]);
				expect(upstream.received.map((r) => r.headers.authorization)).toEqual([
					"Bearer issued-shared",
					"Bearer issued-shared",
					"Bearer issued-shared",
				]);
			} finally {
				await close();
			}
		});

		it("shares a refusal with every concurrent identical request instead of resubmitting", async () => {
			const assertion = makeAssertion();
			const pending = deferred();
			fetchMock.mockReturnValueOnce(pending.promise);
			const { baseURL, joined, close } = await listenForFlight(mountApp(makeConfig(upstream.baseURL)), 2);

			try {
				const inflight = Promise.all(
					["/a", "/b"].map((path) =>
						request(baseURL).get(path).set("Authorization", `Bearer ${assertion}`),
					),
				);
				await joined;
				pending.resolve(jsonResponse(400, { error: "invalid_grant" }));
				const responses = await inflight;

				expect(fetchMock).toHaveBeenCalledTimes(1);
				expect(responses.map((r) => r.status)).toEqual([401, 401]);
				expect(upstream.received).toHaveLength(0);
			} finally {
				await close();
			}
		});
	});

	describe("request shape", () => {
		it("rejects a session cookie together with an Authorization header (400), calling nothing", async () => {
			const app = mountApp(makeConfig(upstream.baseURL));

			for (const [cookie, authorization] of [
				["sid=s1", `Bearer ${makeAssertion()}`],
				// a cookie the grammar check refuses is still a session cookie sent
				["sid=abc,def", `Bearer ${makeAssertion()}`],
				["sid=s1", "Basic dXNlcjpwYXNz"],
			]) {
				const res = await request(app)
					.get("/")
					.set("Cookie", cookie)
					.set("Authorization", authorization);

				expect(res.status, cookie).toBe(400);
				expect(res.body.error).toBe("credential_ambiguous");
				expect(typeof res.body.error_description).toBe("string");
				expect(res.headers["www-authenticate"]).toBeUndefined();
			}
			expect(fetchMock).not.toHaveBeenCalled();
			expect(upstream.received).toHaveLength(0);
		});

		it("still forwards a request whose Cookie header carries only other cookies", async () => {
			fetchMock.mockResolvedValueOnce(okToken("issued-1"));
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app)
				.get("/")
				.set("Cookie", "analytics=xyz")
				.set("Authorization", `Bearer ${makeAssertion()}`);

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-1");
		});

		it("rejects an Authorization that is not a Bearer JWT (401), without a provider call or pass-through", async () => {
			const app = mountApp(makeConfig(upstream.baseURL));

			for (const authorization of [
				"",
				"Basic dXNlcjpwYXNz",
				"Bearer opaque-access-token",
				"Bearer a.b",
				"DPoP eyJ.eyJ.sig",
			]) {
				const res = await request(app).get("/").set("Authorization", authorization);

				expect(res.status, authorization).toBe(401);
				expect(res.body.error).toBe("credential_unsupported");
				expect(typeof res.body.error_description).toBe("string");
				expect(res.headers["www-authenticate"]).toBeUndefined();
			}
			expect(fetchMock).not.toHaveBeenCalled();
			expect(upstream.received).toHaveLength(0);
		});

		it("forwards a request with no credential anonymously, as without the exchange", async () => {
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app).get("/any");

			expect(res.status).toBe(204);
			expect(upstream.received).toHaveLength(1);
			expect(upstream.received[0].headers.authorization).toBeUndefined();
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("keeps the session path unchanged for a cookie-only request", async () => {
			fetchMock.mockResolvedValueOnce(okToken("session-tok"));
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app).get("/any").set("Cookie", "sid=s1");

			expect(res.status).toBe(204);
			expect(providerCall().params.get("grant_type")).toBe("session");
			expect(providerCall().headers.Authorization).toBeUndefined();
			expect(upstream.received[0].headers.authorization).toBe("Bearer session-tok");
		});

		it("with the exchange disabled, forwards a Bearer JWT untouched and calls nothing", async () => {
			const assertion = makeAssertion();
			const app = mountApp(makeConfig(upstream.baseURL, { enabled: false }));

			const res = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe(`Bearer ${assertion}`);
			expect(fetchMock).not.toHaveBeenCalled();
		});
	});

	describe("logging", () => {
		it("does not log a credential a provider echoes back as its error code", async () => {
			const spies = (["debug", "info", "warn", "error"] as const).map((level) =>
				vi.spyOn(logger, level),
			);
			const app = mountApp(makeConfig(upstream.baseURL));
			const assertion = makeAssertion();
			fetchMock
				.mockResolvedValueOnce(jsonResponse(400, { error: assertion, error_description: assertion }))
				.mockResolvedValueOnce(jsonResponse(401, { error: "s3cret", error_description: "s3cret" }));

			const first = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);
			const second = await request(app).get("/").set("Authorization", `Bearer ${assertion}`);

			expect([first.status, second.status]).toEqual([502, 502]);
			const logged = JSON.stringify(spies.map((spy) => spy.mock.calls));
			expect(logged).toContain("invalid_error_code");
			expect(logged).not.toContain(assertion);
			expect(logged).not.toContain("s3cret");
			expect(JSON.stringify([first.body, second.body])).not.toContain(assertion);
		});

		it("never logs the assertion, the issued token or the client secret", async () => {
			const spies = (["debug", "info", "warn", "error"] as const).map((level) =>
				vi.spyOn(logger, level),
			);
			const app = mountApp(
				makeConfig(upstream.baseURL, { ...ENABLED, allowedIssuers: ["https://idp-a.example"] }),
			);
			const accepted = makeAssertion();
			const refused = makeAssertion({ iss: "https://idp-z.example" });
			const rejected = makeAssertion();
			fetchMock
				.mockResolvedValueOnce(okToken("issued-secret-token"))
				.mockResolvedValueOnce(jsonResponse(400, { error: "invalid_grant" }));

			await request(app).get("/").set("Authorization", `Bearer ${accepted}`);
			await request(app).get("/").set("Authorization", `Bearer ${accepted}`);
			await request(app).get("/").set("Authorization", `Bearer ${refused}`);
			await request(app).get("/").set("Authorization", `Bearer ${rejected}`);
			await request(app).get("/").set("Cookie", "sid=s1").set("Authorization", `Bearer ${accepted}`);
			await request(app).get("/").set("Authorization", "Bearer opaque-secret");

			const logged = JSON.stringify(spies.map((spy) => spy.mock.calls));
			const events = spies
				.flatMap((spy) => spy.mock.calls)
				.map(([first]) => (typeof first === "object" && first !== null ? first.event : undefined));
			expect(events).toEqual(
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
			for (const secret of [
				accepted,
				refused,
				rejected,
				"issued-secret-token",
				"s3cret",
				"opaque-secret",
				"idp-z.example",
			]) {
				expect(logged).not.toContain(secret);
			}
		});
	});

	describe("injected deps (#95 F2)", () => {
		const eventsOf = (spy: ReturnType<typeof vi.fn>): unknown[] =>
			spy.mock.calls
				.map(([first]) => first)
				.filter((first): first is Record<string, unknown> => typeof first === "object" && first !== null)
				.map((fields) => fields.event);

		it("accepts an injected exchange client: the supplied client replaces fetch", async () => {
			const assertion = makeAssertion();
			const client = { exchange: vi.fn(async () => ({ accessToken: "issued-injected", expiresIn: 300 })) };
			const app = express();
			app.use(createRouter({ config: makeConfig(upstream.baseURL), deps: { exchange: { client } } }));

			const res = await request(app).get("/orders").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-injected");
			expect(fetchMock).not.toHaveBeenCalled();
			expect(client.exchange).toHaveBeenCalledWith({ assertion, requestId: expect.any(String) });
		});

		it("accepts an injected exchange token cache: a pre-seeded entry is served with no client or fetch call", async () => {
			const assertion = makeAssertion();
			const tokenCache = createTokenCache({ maxEntries: 10 });
			tokenCache.set(
				exchangeCacheKey(exchangeContext("http://provider.example", ENABLED), assertion),
				"issued-seeded",
				Date.now() + 60_000,
			);
			const client = { exchange: vi.fn() };
			const app = express();
			app.use(
				createRouter({ config: makeConfig(upstream.baseURL), deps: { exchange: { client, tokenCache } } }),
			);

			const res = await request(app).get("/orders").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-seeded");
			expect(client.exchange).not.toHaveBeenCalled();
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("accepts an injected exchange single flight: the supplied run is what coalesces the submission", async () => {
			const assertion = makeAssertion();
			const real = createSingleFlight<string>();
			const singleFlight: SingleFlight<string> = { run: vi.fn(real.run), _sizeForTesting: real._sizeForTesting };
			fetchMock.mockResolvedValueOnce(okToken("issued-flight"));
			const app = express();
			app.use(createRouter({ config: makeConfig(upstream.baseURL), deps: { exchange: { singleFlight } } }));

			const res = await request(app).get("/orders").set("Authorization", `Bearer ${assertion}`);

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer issued-flight");
			expect(singleFlight.run).toHaveBeenCalledTimes(1);
			expect(singleFlight.run).toHaveBeenCalledWith(
				exchangeCacheKey(exchangeContext("http://provider.example", ENABLED), assertion),
				expect.any(Function),
			);
		});

		it("refuses deps.exchange while the exchange is disabled, at construction", () => {
			const client = { exchange: vi.fn() };
			expect(() =>
				createRouter({
					config: makeConfig(upstream.baseURL, { enabled: false }),
					deps: { exchange: { client } },
				}),
			).toThrow("deps.exchange supplied while auth.injection.exchange.enabled is false");
		});

		it("an injected logger receives the provider-path events too, and the singleton stays silent", async () => {
			const injected = {
				debug: vi.fn<Logger["debug"]>(),
				info: vi.fn<Logger["info"]>(),
				warn: vi.fn<Logger["warn"]>(),
				error: vi.fn<Logger["error"]>(),
			};
			const singletonInfo = vi.spyOn(logger, "info");
			const singletonDebug = vi.spyOn(logger, "debug");
			fetchMock.mockResolvedValueOnce(okToken("issued-logged"));
			const app = express();
			app.use(createRouter({ config: makeConfig(upstream.baseURL), deps: { logger: injected } }));
			const assertion = makeAssertion();

			expect((await request(app).get("/orders").set("Authorization", `Bearer ${assertion}`)).status).toBe(204);
			expect((await request(app).get("/orders").set("Authorization", `Bearer ${assertion}`)).status).toBe(204);

			expect(eventsOf(injected.info)).toEqual(
				expect.arrayContaining(["injection.exchange_fetch", "injection.exchange_success"]),
			);
			expect(eventsOf(injected.debug)).toContain("injection.exchange_cache_hit");
			expect(singletonInfo).not.toHaveBeenCalled();
			expect(singletonDebug).not.toHaveBeenCalled();
		});

		it("an injected logger reaches the exchange path and the singleton stays silent", async () => {
			const injected = {
				debug: vi.fn<Logger["debug"]>(),
				info: vi.fn<Logger["info"]>(),
				warn: vi.fn<Logger["warn"]>(),
				error: vi.fn<Logger["error"]>(),
			};
			const singletonInfo = vi.spyOn(logger, "info");
			const singletonWarn = vi.spyOn(logger, "warn");
			const app = express();
			app.use(createRouter({ config: makeConfig(upstream.baseURL), deps: { logger: injected } }));

			const res = await request(app).get("/orders").set("Authorization", "Basic abc");

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("credential_unsupported");
			expect(eventsOf(injected.info)).toContain("injection.exchange_credential_unsupported");
			expect(singletonInfo).not.toHaveBeenCalled();
			expect(singletonWarn).not.toHaveBeenCalled();
		});
	});
});
