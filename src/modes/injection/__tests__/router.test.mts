import type { IncomingMessage, Server, ServerResponse } from "node:http";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import { createRouter } from "../router.mjs";

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

const makeConfig = (upstreamBaseURL: string): AppConfig => ({
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
			tokenCache: { ttlSeconds: 60, maxEntries: 100, safetyMarginSeconds: 5 },
			timeoutMs: 5000,
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

	it("treats empty-value session cookie as absent", async () => {
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("treats a session cookie value outside the RFC 6265 cookie-octet grammar as absent (#23)", async () => {
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=abc,def");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();
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
		// router.mts computeExpiresAt), while supertest and the upstream recorder
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
});
