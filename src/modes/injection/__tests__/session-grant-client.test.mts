import axios, { AxiosError, type AxiosResponse } from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	createSessionGrantClient,
	SessionGrantError,
} from "../session-grant-client.mjs";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

const baseCfg = {
	providerOrigin: "http://provider.example",
	clientId: "my-spa",
	scope: "api.read api.write",
	sessionCookieName: "sid",
	timeoutMs: 5000,
};

describe("createSessionGrantClient.exchange", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	const okResponse = (): AxiosResponse => ({
		status: 200,
		data: { access_token: "tok-123", token_type: "Bearer", expires_in: 120 },
		statusText: "OK",
		headers: {},
		config: { headers: {} } as unknown as AxiosResponse["config"],
	});

	it("returns access token and expires_in on provider 200", async () => {
		mockedAxios.post.mockResolvedValueOnce(okResponse());
		const client = createSessionGrantClient(baseCfg);

		const result = await client.exchange({
			sessionCookieValue: "cookie-abc",
			requestId: "req-1",
		});

		expect(result).toEqual({ accessToken: "tok-123", expiresIn: 120 });
	});

	it("sends POST to <providerOrigin>/oauth/token", async () => {
		mockedAxios.post.mockResolvedValueOnce(okResponse());
		const client = createSessionGrantClient(baseCfg);
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		expect(mockedAxios.post).toHaveBeenCalledTimes(1);
		expect(mockedAxios.post.mock.calls[0][0]).toBe("http://provider.example/oauth/token");
	});

	it("tolerates providerOrigin with a trailing slash", async () => {
		mockedAxios.post.mockResolvedValueOnce(okResponse());
		const client = createSessionGrantClient({
			...baseCfg,
			providerOrigin: "http://provider.example/",
		});
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		expect(mockedAxios.post.mock.calls[0][0]).toBe("http://provider.example/oauth/token");
	});

	it("sends form-urlencoded body with grant_type=session, client_id, scope", async () => {
		mockedAxios.post.mockResolvedValueOnce(okResponse());
		const client = createSessionGrantClient(baseCfg);
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		const body = mockedAxios.post.mock.calls[0][1] as string;
		const params = new URLSearchParams(body);
		expect(params.get("grant_type")).toBe("session");
		expect(params.get("client_id")).toBe("my-spa");
		expect(params.get("scope")).toBe("api.read api.write");
	});

	it("sends only isolated headers (no Authorization, no extra cookies)", async () => {
		mockedAxios.post.mockResolvedValueOnce(okResponse());
		const client = createSessionGrantClient(baseCfg);
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		const opts = mockedAxios.post.mock.calls[0][2];
		const headers = opts?.headers as Record<string, string>;
		expect(Object.keys(headers).sort()).toEqual([
			"Accept",
			"Content-Type",
			"Cookie",
			"X-Request-Id",
		]);
		expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
		expect(headers.Cookie).toBe("sid=cookie-abc");
		expect(headers["X-Request-Id"]).toBe("req-1");
		expect(headers.Accept).toBe("application/json");
		expect(headers.Authorization).toBeUndefined();
	});

	it("passes configured timeout to axios", async () => {
		mockedAxios.post.mockResolvedValueOnce(okResponse());
		const client = createSessionGrantClient({ ...baseCfg, timeoutMs: 1234 });
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		const opts = mockedAxios.post.mock.calls[0][2];
		expect(opts?.timeout).toBe(1234);
	});

	it("returns null expiresIn when provider omits expires_in (RFC 6749 §5.1 OPTIONAL)", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			...okResponse(),
			data: { access_token: "tok-no-exp", token_type: "Bearer" },
		});
		const client = createSessionGrantClient(baseCfg);

		const result = await client.exchange({ sessionCookieValue: "c", requestId: "r" });

		expect(result).toEqual({ accessToken: "tok-no-exp", expiresIn: null });
	});

	it("throws provider_invalid_response on 200 without access_token", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			...okResponse(),
			data: { token_type: "Bearer" },
		});
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
		});
	});

	it("throws provider_invalid_response on 200 with empty-string access_token", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			...okResponse(),
			data: { access_token: "", token_type: "Bearer" },
		});
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
		});
	});

	it("throws session_unauthorized on provider 401 with Retry-After propagation", async () => {
		const err = Object.assign(new AxiosError("Unauthorized"), {
			isAxiosError: true,
			response: {
				status: 401,
				data: { error: "invalid_grant" },
				headers: { "retry-after": "30" },
				statusText: "Unauthorized",
				config: { headers: {} },
			},
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "session_unauthorized",
			status: 401,
			retryAfter: "30",
		});
	});

	it("captures Title-case Retry-After header", async () => {
		const err = Object.assign(new AxiosError("Unauthorized"), {
			isAxiosError: true,
			response: {
				status: 401,
				data: { error: "invalid_grant" },
				headers: { "Retry-After": "60" },
				statusText: "Unauthorized",
				config: { headers: {} },
			},
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "session_unauthorized",
			status: 401,
			retryAfter: "60",
		});
	});

	it("throws provider_config_error on provider 400", async () => {
		const err = Object.assign(new AxiosError("Bad Request"), {
			isAxiosError: true,
			response: {
				status: 400,
				data: { error: "invalid_scope", error_description: "unknown scope" },
				headers: {},
				statusText: "Bad Request",
				config: { headers: {} },
			},
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_config_error",
			status: 502,
			retryAfter: null,
			message: "unknown scope",
		});
	});

	it("throws provider_config_error with generic message when provider omits error_description", async () => {
		const err = Object.assign(new AxiosError("Bad Request"), {
			isAxiosError: true,
			response: {
				status: 400,
				data: { error: "invalid_scope" },
				headers: {},
				statusText: "Bad Request",
				config: { headers: {} },
			},
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_config_error",
			status: 502,
			retryAfter: null,
			message: "provider rejected proxy configuration (client_id or scope)",
		});
	});

	it("throws provider_unavailable on provider 500", async () => {
		const err = Object.assign(new AxiosError("ISE"), {
			isAxiosError: true,
			response: {
				status: 500,
				data: {},
				headers: {},
				statusText: "ISE",
				config: { headers: {} },
			},
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_unavailable",
			status: 502,
			retryAfter: null,
			message: expect.stringContaining("provider call failed"),
		});
	});

	it("throws provider_unavailable on network error (no response)", async () => {
		const err = Object.assign(new AxiosError("ECONNREFUSED"), {
			isAxiosError: true,
			code: "ECONNREFUSED",
			response: undefined,
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({ code: "provider_unavailable", status: 502, retryAfter: null });
	});

	it("throws provider_unavailable on unexpected 4xx", async () => {
		const err = Object.assign(new AxiosError("Teapot"), {
			isAxiosError: true,
			response: {
				status: 418,
				data: {},
				headers: {},
				statusText: "Teapot",
				config: { headers: {} },
			},
		}) as AxiosError;
		mockedAxios.post.mockRejectedValueOnce(err);
		mockedAxios.isAxiosError.mockReturnValue(true);

		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({ code: "provider_unavailable", status: 502, retryAfter: null });
	});
});

describe("SessionGrantError", () => {
	it("carries code, status, message, retryAfter", () => {
		const err = new SessionGrantError(
			"session_unauthorized",
			401,
			"provider said no",
			"30",
		);
		expect(err.code).toBe("session_unauthorized");
		expect(err.status).toBe(401);
		expect(err.retryAfter).toBe("30");
		expect(err.message).toBe("provider said no");
		expect(err).toBeInstanceOf(Error);
	});
});
