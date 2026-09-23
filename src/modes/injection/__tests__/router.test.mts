import type { IncomingMessage, Server, ServerResponse } from "node:http";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import type { Logger } from "../../../logger.mjs";
import logger from "../../../logger.mjs";
import { createSingleFlight, type SingleFlight } from "../../../single-flight.mjs";
import { sessionCacheKey } from "../decision.mjs";
import { createRouter } from "../router.mjs";
import { createTokenCache } from "../token-cache.mjs";

type UpstreamRecorder = {
	server: Server;
	baseURL: string;
	received: { method: string; url: string; headers: IncomingMessage["headers"] }[];
	respond: (status: number, body?: string) => void;
	close: () => Promise<void>;
};

const startUpstream = async (): Promise<UpstreamRecorder> => {
	const received: UpstreamRecorder["received"] = [];
	let respondStatus = 204;
	let respondBody = "";
	const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
		received.push({
			method: req.method ?? "",
			url: req.url ?? "",
			headers: { ...req.headers },
		});
		req.resume();
		req.on("end", () => {
			res.statusCode = respondStatus;
			res.end(respondBody);
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address() as AddressInfo;
	const baseURL = `http://127.0.0.1:${address.port}`;

	return {
		server,
		baseURL,
		received,
		respond: (s, b = "") => {
			respondStatus = s;
			respondBody = b;
		},
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
};

/** Narrows the union so a test can read the grant context it just built. */
const injectionOf = (config: AppConfig) => {
	if (config.auth.mode !== "injection") throw new Error("not an injection config");
	return config.auth.injection;
};

const makeConfig = (
	upstreamBaseURL: string,
	injectionOverrides: Partial<Extract<AppConfig["auth"], { mode: "injection" }>["injection"]> = {},
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
			exchange: { enabled: false },
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

const jsonResponse = (
	status: number,
	body: unknown,
	headers: Record<string, string> = {},
): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});

const okGrantResponse = (accessToken = "grant-tok", expiresIn: number | null = 120): Response =>
	jsonResponse(200, {
		access_token: accessToken,
		token_type: "Bearer",
		...(expiresIn !== null ? { expires_in: expiresIn } : {}),
	});

type LogField = Record<string, unknown>;
// Every Logger method shares one signature, so a debug spy fits this type too.
type LogSpy = MockInstance<Logger["warn"]>;

const loggedFields = (spy: LogSpy): LogField[] =>
	spy.mock.calls
		.map(([first]) => first)
		.filter((first): first is LogField => typeof first === "object" && first !== null);

const eventsOf = (spy: LogSpy): unknown[] =>
	loggedFields(spy).map((fields) => fields.event);

describe("injection router", () => {
	let upstream: UpstreamRecorder;
	let fetchMock: ReturnType<typeof vi.fn>;

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

	it("forwards without Authorization when cookie is absent", async () => {
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any");

		expect(res.status).toBe(204);
		expect(upstream.received).toHaveLength(1);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("exchanges cookie -> Bearer on cache miss and forwards", async () => {
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-1"));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(204);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");
	});

	it("returns cached token on second request with same cookie", async () => {
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-1"));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1");
		await request(app).get("/any").set("Cookie", "sid=s1");

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(upstream.received).toHaveLength(2);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");
		expect(upstream.received[1].headers.authorization).toBe("Bearer tok-1");
	});

	it("coalesces concurrent requests with the same cookie into one provider call", async () => {
		const grantControl = { resolve: null as ((v: Response) => void) | null };
		fetchMock.mockReturnValueOnce(
			new Promise<Response>((resolve) => {
				grantControl.resolve = resolve;
			}),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const inflight = Promise.all([
			request(app).get("/a").set("Cookie", "sid=s1"),
			request(app).get("/b").set("Cookie", "sid=s1"),
			request(app).get("/c").set("Cookie", "sid=s1"),
		]);
		await new Promise((r) => setTimeout(r, 10));
		grantControl.resolve?.(okGrantResponse("tok-shared"));
		await inflight;

		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	// #95 F10. No client takes a caller's signal, so the only cancellation is
	// AbortSignal.timeout — and a caller that leaves cannot abort a flight the
	// other waiters share. The one that leaves here is the leader.
	it("a disconnect does not abort the flight its waiters share, and the token is still cached", async () => {
		let askedProvider!: () => void;
		const providerAsked = new Promise<void>((resolve) => {
			askedProvider = resolve;
		});
		let answerProvider!: () => void;
		const answered = new Promise<Response>((resolve) => {
			answerProvider = () => resolve(okGrantResponse("tok-abandoned"));
		});
		// The mock honours init.signal, so this test can tell the difference it
		// claims to: if anything ever wired a caller's disconnect to the
		// outbound call, the flight would reject here instead of answering.
		fetchMock.mockImplementationOnce(async (_url: unknown, init?: RequestInit) => {
			askedProvider();
			return await Promise.race([
				answered,
				new Promise<never>((_, reject) => {
					init?.signal?.addEventListener("abort", () =>
						reject(new DOMException("The operation was aborted", "AbortError")),
					);
				}),
			]);
		});
		const debugSpy = vi.spyOn(logger, "debug");
		const server = mountApp(makeConfig(upstream.baseURL)).listen(0, "127.0.0.1");
		await new Promise((resolve) => server.once("listening", resolve));
		const port = (server.address() as AddressInfo).port;
		// A causal join signal instead of a sleep. Express is the server's first
		// "request" listener, and nothing between it and the flight awaits —
		// the cookie parse, the cache read and SingleFlight.run's table check
		// are synchronous — so by the time this later listener sees the second
		// request, the waiter has joined the leader's flight.
		let arrived = 0;
		let waiterJoined!: () => void;
		const joined = new Promise<void>((resolve) => {
			waiterJoined = resolve;
		});
		server.on("request", () => {
			arrived += 1;
			if (arrived === 2) waiterJoined();
		});
		const get = (path: string) => {
			const req = http.request({ host: "127.0.0.1", port, path, headers: { Cookie: "sid=s1" } });
			// Resolves with null on a reset rather than rejecting: destroying the
			// socket is the point, and an unhandled rejection would fail the run
			// for the thing under test.
			const done = new Promise<number | null>((resolve) => {
				req.on("response", (res) => {
					res.resume();
					res.on("end", () => resolve(res.statusCode ?? 0));
				});
				req.on("error", () => resolve(null));
			});
			req.end();
			return { req, done };
		};

		try {
			const leader = get("/leader");
			await providerAsked;
			leader.req.destroy();
			expect(await leader.done).toBeNull();

			const waiter = get("/waiter");
			await joined;
			await new Promise((r) => setImmediate(r));
			answerProvider();

			expect(await waiter.done).toBe(204);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			// It joined the abandoned leader's flight rather than being served
			// from a cache the leader had already written — without this, a
			// waiter that arrived late would satisfy every other assertion.
			expect(eventsOf(debugSpy)).toContain("injection.single_flight_wait");
			expect(eventsOf(debugSpy)).not.toContain("injection.cache_hit");

			// The grant the abandoned request started is in the cache.
			const later = get("/later");
			expect(await later.done).toBe(204);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(eventsOf(debugSpy)).toContain("injection.cache_hit");
			expect(upstream.received.at(-1)?.headers.authorization).toBe("Bearer tok-abandoned");
		} finally {
			server.closeAllConnections();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});

	it("returns 401 session_required on provider 401 (no WWW-Authenticate)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(401, { error: "invalid_grant" }));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("session_required");
		expect(typeof res.body.error_description).toBe("string");
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(upstream.received).toHaveLength(0);
	});

	it("propagates Retry-After on provider 401", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(401, { error: "invalid_grant" }, { "retry-after": "30" }),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(401);
		expect(res.headers["retry-after"]).toBe("30");
	});

	it("returns 502 provider_config_error on provider 400", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(400, { error: "invalid_scope" }));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(502);
		expect(res.body.error).toBe("provider_config_error");
		expect(upstream.received).toHaveLength(0);
	});

	it("neither logs nor returns a session cookie the provider echoes in error_description", async () => {
		const spies = (["debug", "info", "warn", "error"] as const).map((level) =>
			vi.spyOn(logger, level),
		);
		fetchMock.mockResolvedValueOnce(
			jsonResponse(400, {
				error: "invalid_scope",
				error_description: "session secret-session-value rejected",
			}),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=secret-session-value");

		expect(res.status).toBe(502);
		expect(res.body.error).toBe("provider_config_error");
		expect(JSON.stringify(res.body)).not.toContain("secret-session-value");
		expect(JSON.stringify(spies.map((spy) => spy.mock.calls))).not.toContain(
			"secret-session-value",
		);
	});

	it("returns 502 provider_unavailable with Retry-After passthrough on provider 503", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(503, {}, { "retry-after": "30" }));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(502);
		expect(res.headers["retry-after"]).toBe("30");
		expect(res.body.error).toBe("provider_unavailable");
	});

	it("silently overrides an inbound Authorization header with the injected Bearer", async () => {
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-injected"));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app)
			.get("/any")
			.set("Cookie", "sid=s1")
			.set("Authorization", "Bearer attacker-supplied");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-injected");
	});

	it("forwards only the configured cookie to the provider (cookie-name filtering)", async () => {
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-ok"));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1; analytics=xyz; other=foo");

		const init = fetchMock.mock.calls[0][1] as RequestInit;
		const headers = init.headers as Record<string, string>;
		expect(headers.Cookie).toBe("sid=s1");
	});

	it("logs injection.no_cookie at debug when the session cookie is absent (#73)", async () => {
		const debugSpy = vi.spyOn(logger, "debug");
		const warnSpy = vi.spyOn(logger, "warn");
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app)
			.get("/any")
			.set("Cookie", "other=foo")
			.set("X-Request-Id", "req-absent");

		expect(res.status).toBe(204);
		expect(loggedFields(debugSpy)).toContainEqual(
			expect.objectContaining({ event: "injection.no_cookie", requestId: "req-absent" }),
		);
		expect(eventsOf(warnSpy)).not.toContain("injection.cookie_rejected");
	});

	it("forwards an empty session cookie value anonymously and logs injection.cookie_rejected with reason empty (#73)", async () => {
		const warnSpy = vi.spyOn(logger, "warn");
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();
		expect(loggedFields(warnSpy)).toContainEqual(
			expect.objectContaining({ event: "injection.cookie_rejected", reason: "empty" }),
		);
	});

	it("forwards a grammar-rejected session cookie anonymously and logs injection.cookie_rejected at warn (#23, #73)", async () => {
		const debugSpy = vi.spyOn(logger, "debug");
		const warnSpy = vi.spyOn(logger, "warn");
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app)
			.get("/any")
			.set("Cookie", "sid=abc,def")
			.set("X-Request-Id", "req-rejected");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();

		const rejected = loggedFields(warnSpy).filter(
			(fields) => fields.event === "injection.cookie_rejected",
		);
		expect(rejected).toHaveLength(1);
		expect(rejected[0]).toMatchObject({ reason: "grammar", requestId: "req-rejected" });
		// The reason is a bounded class; the offending value never reaches the log.
		expect(JSON.stringify(warnSpy.mock.calls)).not.toContain("abc,def");
		expect(eventsOf(debugSpy)).not.toContain("injection.no_cookie");
	});

	it("uses the first well-formed same-name pair and logs the skipped malformed one (#74)", async () => {
		const warnSpy = vi.spyOn(logger, "warn");
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-good"));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app)
			.get("/any")
			.set("Cookie", "sid=bad,val; sid=good")
			.set("X-Request-Id", "req-fallback");

		expect(res.status).toBe(204);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const init = fetchMock.mock.calls[0][1] as RequestInit;
		expect((init.headers as Record<string, string>).Cookie).toBe("sid=good");
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-good");

		const rejected = loggedFields(warnSpy).filter(
			(fields) => fields.event === "injection.cookie_rejected",
		);
		expect(rejected).toHaveLength(1);
		expect(rejected[0]).toMatchObject({
			reason: "grammar",
			requestId: "req-fallback",
			action: "fallback",
		});
		expect(JSON.stringify(warnSpy.mock.calls)).not.toContain("bad,val");
	});

	it("passes through upstream 5xx unchanged after Bearer injection", async () => {
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-1"));
		upstream.respond(503, "upstream is sad");
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(503);
		expect(res.text).toBe("upstream is sad");
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");
	});

	it("returns 502 provider_invalid_response when provider 200 has no access_token", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { token_type: "Bearer" }));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(502);
		expect(res.body.error).toBe("provider_invalid_response");
		expect(upstream.received).toHaveLength(0);
	});

	it("re-fetches after cache expiry", async () => {
		// Fake only Date: cache expiry is decided from Date.now() (token-cache.mts,
		// cache-expiry.mts computeCacheExpiresAt), while supertest and the upstream recorder
		// need real timers and real IO for their HTTP round trips. Faking
		// setTimeout & co. would stall those, and a real 1.1 s sleep was slow and
		// CI-flaky (#24). With the default ttlSeconds=60 / safetyMarginSeconds=5
		// and expires_in=120 the effective TTL is 55 s.
		vi.useFakeTimers({ toFake: ["Date"] });
		fetchMock
			.mockResolvedValueOnce(okGrantResponse("tok-1", 120))
			.mockResolvedValueOnce(okGrantResponse("tok-2", 120));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");

		vi.setSystemTime(Date.now() + 30_000);
		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(upstream.received[1].headers.authorization).toBe("Bearer tok-1");
		expect(fetchMock).toHaveBeenCalledTimes(1);

		vi.setSystemTime(Date.now() + 30_000);
		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(upstream.received[2].headers.authorization).toBe("Bearer tok-2");
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
	// expires_in counts from issuance. Anchoring the cache entry at the
	// response instead of the request would let a slow provider push it past
	// the token's real expiry, and inject an expired token.
	it("counts the grant's expires_in from the request, not from a slow response", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const requestedAt = Date.now();
		// issued with expires_in 20; the answer takes 10 s to arrive.
		// Entry must expire at requestedAt + 20 - margin 5 = requestedAt + 15 s.
		fetchMock
			.mockImplementationOnce(async () => {
				vi.setSystemTime(requestedAt + 10_000);
				return okGrantResponse("tok-1", 20);
			})
			.mockResolvedValueOnce(okGrantResponse("tok-2", 20));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1");
		vi.setSystemTime(requestedAt + 14_000);
		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(fetchMock).toHaveBeenCalledTimes(1);

		vi.setSystemTime(requestedAt + 16_000);
		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(upstream.received[2].headers.authorization).toBe("Bearer tok-2");
	});

	it("does not cache a grant whose response arrives after expires_in minus the margin", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const requestedAt = Date.now();
		fetchMock
			.mockImplementationOnce(async () => {
				vi.setSystemTime(requestedAt + 16_000);
				return okGrantResponse("tok-1", 20);
			})
			.mockResolvedValueOnce(okGrantResponse("tok-2", 20));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1");
		await request(app).get("/any").set("Cookie", "sid=s1");

		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(upstream.received[1].headers.authorization).toBe("Bearer tok-2");
	});

	// The proxy overrides an inbound Authorization only on the paths where a
	// session cookie actually produced a token. On the two paths where it did
	// not mint one — no cookie, or a cookie refused by the grammar check — the
	// header is forwarded untouched, so an upstream service cannot read "a
	// Bearer header arrived from the proxy" as "the proxy minted this".
	// `stripInboundAuthorization` lets a deployment close that gap; it defaults
	// to the pass-through behaviour so no existing deployment changes silently.
	describe("inbound Authorization on a request the proxy did not mint for", () => {
		it("forwards an inbound Authorization untouched when the cookie is absent (default)", async () => {
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app)
				.get("/any")
				.set("Authorization", "Bearer client-supplied");

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer client-supplied");
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("forwards an inbound Authorization untouched when the cookie is refused (default)", async () => {
			const app = mountApp(makeConfig(upstream.baseURL));

			const res = await request(app)
				.get("/any")
				.set("Cookie", "sid=abc,def")
				.set("Authorization", "Bearer client-supplied");

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer client-supplied");
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("strips an inbound Authorization when the cookie is absent and the flag is on", async () => {
			const warnSpy = vi.spyOn(logger, "warn");
			const app = mountApp(
				makeConfig(upstream.baseURL, { stripInboundAuthorization: true }),
			);

			const res = await request(app)
				.get("/any")
				.set("Authorization", "Bearer client-supplied")
				.set("X-Request-Id", "req-strip-absent");

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBeUndefined();
			expect(fetchMock).not.toHaveBeenCalled();
			expect(loggedFields(warnSpy)).toContainEqual(
				expect.objectContaining({
					event: "injection.inbound_authorization_stripped",
					requestId: "req-strip-absent",
					reason: "no_cookie",
				}),
			);
			// The stripped credential never reaches the log.
			expect(JSON.stringify(warnSpy.mock.calls)).not.toContain("client-supplied");
		});

		it("strips an inbound Authorization when the cookie is refused and the flag is on", async () => {
			const warnSpy = vi.spyOn(logger, "warn");
			const app = mountApp(
				makeConfig(upstream.baseURL, { stripInboundAuthorization: true }),
			);

			const res = await request(app)
				.get("/any")
				.set("Cookie", "sid=abc,def")
				.set("Authorization", "Bearer client-supplied")
				.set("X-Request-Id", "req-strip-rejected");

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBeUndefined();
			expect(fetchMock).not.toHaveBeenCalled();
			expect(loggedFields(warnSpy)).toContainEqual(
				expect.objectContaining({
					event: "injection.inbound_authorization_stripped",
					requestId: "req-strip-rejected",
					reason: "cookie_rejected",
				}),
			);
		});

		it("logs nothing extra when the flag is on and no inbound Authorization was sent", async () => {
			const warnSpy = vi.spyOn(logger, "warn");
			const app = mountApp(
				makeConfig(upstream.baseURL, { stripInboundAuthorization: true }),
			);

			const res = await request(app).get("/any");

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBeUndefined();
			expect(eventsOf(warnSpy)).not.toContain("injection.inbound_authorization_stripped");
		});

		it("still injects the minted Bearer when the flag is on and a cookie produced a token", async () => {
			const warnSpy = vi.spyOn(logger, "warn");
			fetchMock.mockResolvedValueOnce(okGrantResponse("tok-minted"));
			const app = mountApp(
				makeConfig(upstream.baseURL, { stripInboundAuthorization: true }),
			);

			const res = await request(app)
				.get("/any")
				.set("Cookie", "sid=s1")
				.set("Authorization", "Bearer client-supplied");

			expect(res.status).toBe(204);
			expect(upstream.received[0].headers.authorization).toBe("Bearer tok-minted");
			expect(eventsOf(warnSpy)).toContain("injection.authorization_override");
			expect(eventsOf(warnSpy)).not.toContain("injection.inbound_authorization_stripped");
		});
	});

	it("accepts injected deps: a supplied grant client and logger replace fetch and the singleton (#95 F4)", async () => {
		const grantClient = {
			exchange: vi.fn(async () => ({ accessToken: "tok-injected-dep", expiresIn: 120 })),
		};
		const injected = {
			debug: vi.fn<Logger["debug"]>(),
			info: vi.fn<Logger["info"]>(),
			warn: vi.fn<Logger["warn"]>(),
			error: vi.fn<Logger["error"]>(),
		};
		const singletonInfo = vi.spyOn(logger, "info");
		const singletonWarn = vi.spyOn(logger, "warn");
		const app = express();
		app.use(createRouter({ config: makeConfig(upstream.baseURL), deps: { grantClient, logger: injected } }));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-injected-dep");
		expect(fetchMock).not.toHaveBeenCalled();
		expect(grantClient.exchange).toHaveBeenCalledWith({
			sessionCookieValue: "s1",
			requestId: expect.any(String),
		});
		expect(eventsOf(injected.info)).toContain("injection.grant_success");
		expect(injected.info.mock.calls.map((call) => call[1])).toContain("incoming request");
		expect(singletonInfo).not.toHaveBeenCalled();
		expect(singletonWarn).not.toHaveBeenCalled();
	});

	it("accepts an injected tokenCache: a pre-seeded entry is a hit with no grant client call (#95 F4)", async () => {
		const tokenCache = createTokenCache({ maxEntries: 10 });
		const config = makeConfig(upstream.baseURL);
		// Seeded under the router's own grant context, which is what the key
		// carries since #95 F33 — the cookie hash alone no longer finds it.
		tokenCache.set(sessionCacheKey(injectionOf(config), "s1"), "tok-seeded", Date.now() + 60_000);
		const grantClient = { exchange: vi.fn() };
		const app = express();
		app.use(createRouter({ config, deps: { tokenCache, grantClient } }));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-seeded");
		expect(grantClient.exchange).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("accepts an injected single flight: the supplied run is what coalesces the grant call (#95 F4)", async () => {
		const real = createSingleFlight<string>();
		const singleFlight: SingleFlight<string> = {
			run: vi.fn(real.run),
			_sizeForTesting: real._sizeForTesting,
		};
		fetchMock.mockResolvedValueOnce(okGrantResponse("tok-flight"));
		const config = makeConfig(upstream.baseURL);
		const app = express();
		app.use(createRouter({ config, deps: { singleFlight } }));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-flight");
		expect(singleFlight.run).toHaveBeenCalledTimes(1);
		expect(singleFlight.run).toHaveBeenCalledWith(
			sessionCacheKey(injectionOf(config), "s1"),
			expect.any(Function),
		);
	});
});
