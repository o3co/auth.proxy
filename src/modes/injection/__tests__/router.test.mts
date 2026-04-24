import type { IncomingMessage, Server, ServerResponse } from "node:http";
import http from "node:http";
import type { AddressInfo } from "node:net";
import axios from "axios";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import { createRouter } from "../router.mjs";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

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

const okGrant = (accessToken = "grant-tok", expiresIn: number | null = 120) => ({
	status: 200,
	statusText: "OK",
	headers: {},
	data: {
		access_token: accessToken,
		token_type: "Bearer",
		...(expiresIn !== null ? { expires_in: expiresIn } : {}),
	},
	config: { headers: {} } as unknown,
});

describe("injection router", () => {
	let upstream: UpstreamRecorder;

	beforeEach(async () => {
		vi.clearAllMocks();
		mockedAxios.isAxiosError.mockImplementation(
			(e: unknown) =>
				typeof (e as { isAxiosError?: boolean }).isAxiosError === "boolean",
		);
		upstream = await startUpstream();
	});

	afterEach(async () => {
		await upstream.close();
	});

	it("forwards without Authorization when cookie is absent", async () => {
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any");

		expect(res.status).toBe(204);
		expect(upstream.received).toHaveLength(1);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(mockedAxios.post).not.toHaveBeenCalled();
	});

	it("exchanges cookie -> Bearer on cache miss and forwards", async () => {
		mockedAxios.post.mockResolvedValueOnce(okGrant("tok-1"));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(204);
		expect(mockedAxios.post).toHaveBeenCalledTimes(1);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");
	});

	it("returns cached token on second request with same cookie", async () => {
		mockedAxios.post.mockResolvedValueOnce(okGrant("tok-1"));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1");
		await request(app).get("/any").set("Cookie", "sid=s1");

		expect(mockedAxios.post).toHaveBeenCalledTimes(1);
		expect(upstream.received).toHaveLength(2);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");
		expect(upstream.received[1].headers.authorization).toBe("Bearer tok-1");
	});

	it("coalesces concurrent requests with the same cookie into one provider call", async () => {
		const grantControl = { resolve: null as ((v: unknown) => void) | null };
		mockedAxios.post.mockReturnValueOnce(
			new Promise((resolve) => {
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
		grantControl.resolve?.(okGrant("tok-shared"));
		await inflight;

		expect(mockedAxios.post).toHaveBeenCalledTimes(1);
	});

	it("returns 401 session_required on provider 401 (no WWW-Authenticate)", async () => {
		mockedAxios.post.mockRejectedValueOnce(
			Object.assign(new Error("Unauthorized"), {
				isAxiosError: true,
				response: {
					status: 401,
					data: { error: "invalid_grant" },
					headers: {},
					statusText: "Unauthorized",
					config: { headers: {} },
				},
			}),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("session_required");
		expect(typeof res.body.error_description).toBe("string");
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(upstream.received).toHaveLength(0);
	});

	it("propagates Retry-After on provider 401", async () => {
		mockedAxios.post.mockRejectedValueOnce(
			Object.assign(new Error("Unauthorized"), {
				isAxiosError: true,
				response: {
					status: 401,
					data: { error: "invalid_grant" },
					headers: { "retry-after": "30" },
					statusText: "Unauthorized",
					config: { headers: {} },
				},
			}),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(401);
		expect(res.headers["retry-after"]).toBe("30");
	});

	it("returns 502 provider_config_error on provider 400", async () => {
		mockedAxios.post.mockRejectedValueOnce(
			Object.assign(new Error("Bad Request"), {
				isAxiosError: true,
				response: {
					status: 400,
					data: { error: "invalid_scope" },
					headers: {},
					statusText: "Bad Request",
					config: { headers: {} },
				},
			}),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(502);
		expect(res.body.error).toBe("provider_config_error");
		expect(upstream.received).toHaveLength(0);
	});

	it("returns 502 provider_unavailable with Retry-After passthrough on provider 503", async () => {
		mockedAxios.post.mockRejectedValueOnce(
			Object.assign(new Error("Unavailable"), {
				isAxiosError: true,
				response: {
					status: 503,
					data: {},
					headers: { "retry-after": "30" },
					statusText: "Unavailable",
					config: { headers: {} },
				},
			}),
		);
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=s1");

		expect(res.status).toBe(502);
		expect(res.headers["retry-after"]).toBe("30");
		expect(res.body.error).toBe("provider_unavailable");
	});

	it("silently overrides an inbound Authorization header with the injected Bearer", async () => {
		mockedAxios.post.mockResolvedValueOnce(okGrant("tok-injected"));
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app)
			.get("/any")
			.set("Cookie", "sid=s1")
			.set("Authorization", "Bearer attacker-supplied");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-injected");
	});

	it("forwards only the configured cookie to the provider (cookie-name filtering)", async () => {
		mockedAxios.post.mockResolvedValueOnce(okGrant("tok-ok"));
		const app = mountApp(makeConfig(upstream.baseURL));

		await request(app).get("/any").set("Cookie", "sid=s1; analytics=xyz; other=foo");

		const opts = mockedAxios.post.mock.calls[0][2];
		const headers = opts?.headers as Record<string, string>;
		expect(headers.Cookie).toBe("sid=s1");
	});

	it("treats empty-value session cookie as absent", async () => {
		const app = mountApp(makeConfig(upstream.baseURL));

		const res = await request(app).get("/any").set("Cookie", "sid=");

		expect(res.status).toBe(204);
		expect(upstream.received[0].headers.authorization).toBeUndefined();
		expect(mockedAxios.post).not.toHaveBeenCalled();
	});

	it("re-fetches after cache expiry", async () => {
		mockedAxios.post
			.mockResolvedValueOnce(okGrant("tok-1", 1))
			.mockResolvedValueOnce(okGrant("tok-2", 120));

		const cfg = makeConfig(upstream.baseURL);
		if (cfg.auth.mode !== "injection") throw new Error("narrow");
		cfg.auth.injection.tokenCache.ttlSeconds = 1;
		cfg.auth.injection.tokenCache.safetyMarginSeconds = 0;

		const app = mountApp(cfg);

		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(upstream.received[0].headers.authorization).toBe("Bearer tok-1");

		await new Promise((r) => setTimeout(r, 1100));

		await request(app).get("/any").set("Cookie", "sid=s1");
		expect(upstream.received[1].headers.authorization).toBe("Bearer tok-2");
		expect(mockedAxios.post).toHaveBeenCalledTimes(2);
	});
});
