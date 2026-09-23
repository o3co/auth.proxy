import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createSessionGrantClient,
	SessionGrantError,
} from "../session-grant-client.mjs";
import { MAX_TOKEN_BODY_BYTES } from "../token-endpoint.mjs";

const baseCfg = {
	providerOrigin: "http://provider.example",
	clientId: "my-spa",
	scope: "api.read api.write",
	sessionCookieName: "sid",
	timeoutMs: 5000,
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

const getFetchCallInit = (
	fetchMock: ReturnType<typeof vi.fn>,
	index = 0,
): RequestInit => fetchMock.mock.calls[index][1] as RequestInit;

const getFetchCallUrl = (
	fetchMock: ReturnType<typeof vi.fn>,
	index = 0,
): string => fetchMock.mock.calls[index][0] as string;

const getFetchCallHeaders = (
	fetchMock: ReturnType<typeof vi.fn>,
	index = 0,
): Record<string, string> =>
	getFetchCallInit(fetchMock, index).headers as Record<string, string>;

// Most fixtures below pass `sessionCookieValue: "c"`, which since #95 F30 is
// a credential that matches every string. They assert code, status or a body
// with no error_description, so nothing depends on a provider's text being
// relayed — but adding an error_description to one of them gets the proxy's
// generic wording, not the provider's.
describe("createSessionGrantClient.exchange", () => {
	let fetchMock: ReturnType<typeof vi.fn>;
	const client = () => createSessionGrantClient(baseCfg);

	beforeEach(() => {
		fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it("returns access token and expires_in on provider 200", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, {
				access_token: "tok-123",
				token_type: "Bearer",
				expires_in: 120,
			}),
		);
		const client = createSessionGrantClient(baseCfg);

		const result = await client.exchange({
			sessionCookieValue: "cookie-abc",
			requestId: "req-1",
		});

		expect(result).toEqual({ accessToken: "tok-123", expiresIn: 120 });
	});

	it("sends POST to <providerOrigin>/oauth/token", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok", token_type: "Bearer" }),
		);
		const client = createSessionGrantClient(baseCfg);
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(getFetchCallUrl(fetchMock)).toBe("http://provider.example/oauth/token");
		expect(getFetchCallInit(fetchMock).method).toBe("POST");
	});

	it("tolerates providerOrigin with a trailing slash", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok", token_type: "Bearer" }),
		);
		const client = createSessionGrantClient({
			...baseCfg,
			providerOrigin: "http://provider.example/",
		});
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		expect(getFetchCallUrl(fetchMock)).toBe("http://provider.example/oauth/token");
	});

	it("sends form-urlencoded body with grant_type=session, client_id, scope", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok", token_type: "Bearer" }),
		);
		const client = createSessionGrantClient(baseCfg);
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		const body = getFetchCallInit(fetchMock).body as string;
		const params = new URLSearchParams(body);
		expect(params.get("grant_type")).toBe("session");
		expect(params.get("client_id")).toBe("my-spa");
		expect(params.get("scope")).toBe("api.read api.write");
	});

	it("sends only isolated headers (no Authorization, no extra cookies)", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok", token_type: "Bearer" }),
		);
		const client = createSessionGrantClient(baseCfg);
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		const headers = getFetchCallHeaders(fetchMock);
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

	it("passes configured timeout as AbortSignal.timeout", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok", token_type: "Bearer" }),
		);
		const timeoutSpy = vi.spyOn(AbortSignal, "timeout");
		const client = createSessionGrantClient({ ...baseCfg, timeoutMs: 1234 });
		await client.exchange({ sessionCookieValue: "cookie-abc", requestId: "req-1" });

		expect(timeoutSpy).toHaveBeenCalledWith(1234);
		const init = getFetchCallInit(fetchMock);
		expect(init.signal).toBeInstanceOf(AbortSignal);
	});

	it("returns null expiresIn when provider omits expires_in (RFC 6749 §5.1 OPTIONAL)", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok-no-exp", token_type: "Bearer" }),
		);
		const client = createSessionGrantClient(baseCfg);

		const result = await client.exchange({ sessionCookieValue: "c", requestId: "r" });

		expect(result).toEqual({ accessToken: "tok-no-exp", expiresIn: null });
	});

	it("throws provider_invalid_response on 200 without access_token", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { token_type: "Bearer" }));
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
		});
	});

	it("throws provider_invalid_response on 200 with empty-string access_token", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "", token_type: "Bearer" }),
		);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
		});
	});

	// The array case reaches the same refusal as any other body that is not an
	// object, rather than falling through to the access_token check with a
	// message about a missing claim (#95 F34).
	it("throws provider_invalid_response on 200 with a JSON array body", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, [{ access_token: "tok" }]));
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
			message: "provider returned 200 with a body that is not a JSON object, or is over the size bound",
		});
	});

	// The bound is the point: a provider streaming an endless 200 must not be
	// able to make the proxy buffer it (#95 F35).
	it("throws provider_invalid_response on a 200 body over the bound", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(`{"access_token":"${"a".repeat(MAX_TOKEN_BODY_BYTES)}"}`, {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
		});
	});

	it("throws provider_invalid_response on 200 with non-JSON body", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response("not json at all", {
				status: 200,
				headers: { "Content-Type": "text/plain" },
			}),
		);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_invalid_response",
			status: 502,
		});
	});

	// The jwt-bearer client has always refused a redirecting token endpoint
	// rather than following it; this one let fetch follow by default, which
	// sends the session cookie wherever the Location points (#95 F8).
	it("asks fetch not to follow a redirect", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { access_token: "tok", token_type: "Bearer" }),
		);

		await createSessionGrantClient(baseCfg).exchange({
			sessionCookieValue: "c",
			requestId: "r",
		});

		expect((fetchMock.mock.calls[0][1] as RequestInit).redirect).toBe("manual");
	});

	// 300 is in the list because the range is `>= 300`, not because `fetch`
	// would follow one: it does not, any more than it follows a 304, 305 or
	// 306. They are refused as a redirect anyway, which is the bound the
	// jwt-bearer client has always used and this one now copies.
	it.each([300, 301, 302, 303, 307, 308])(
		"refuses a 3xx rather than following it (%d)",
		async (status) => {
			fetchMock.mockResolvedValueOnce(
				new Response("", { status, headers: { Location: "https://elsewhere.test/oauth/token" } }),
			);
			const client = createSessionGrantClient(baseCfg);

			await expect(
				client.exchange({ sessionCookieValue: "c", requestId: "r" }),
			).rejects.toMatchObject({
				code: "provider_config_error",
				status: 502,
				message: `provider token endpoint redirected (${status})`,
			});
		},
	);

	it("throws session_unauthorized on provider 401 with Retry-After propagation", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(401, { error: "invalid_grant" }, { "retry-after": "30" }),
		);
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
		fetchMock.mockResolvedValueOnce(
			jsonResponse(401, { error: "invalid_grant" }, { "Retry-After": "60" }),
		);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "session_unauthorized",
			status: 401,
			retryAfter: "60",
		});
	});

	it("maps a revoked session's invalid_grant to session_unauthorized", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(400, {
			error: "invalid_grant", error_description: "session_invalid",
		}, { "Retry-After": "30" }));
		const client = createSessionGrantClient(baseCfg);
		await expect(client.exchange({ sessionCookieValue: "stale-cookie", requestId: "r" }))
			.rejects.toMatchObject({ code: "session_unauthorized", status: 401, retryAfter: "30" });
	});

	it("throws provider_config_error on provider 400", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(400, {
				error: "invalid_scope",
				error_description: "unknown scope",
			}),
		);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "session-value-1", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_config_error",
			status: 502,
			retryAfter: null,
			message: "unknown scope",
		});
	});

	// The cost of #95 F30, at the level where it is paid: the description is
	// relayed to the client, so a cookie value the proxy did not choose is
	// matched anywhere in it and at any length. A one-character value is in
	// almost any sentence, and the proxy's own wording takes its place.
	it("drops a provider error_description that contains the session cookie value, however short", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(400, { error: "invalid_scope", error_description: "unknown scope" }),
		);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_config_error",
			status: 502,
			message: "provider rejected proxy configuration (client_id or scope)",
		});
	});

	it("throws provider_config_error with generic message when provider omits error_description", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(400, { error: "invalid_scope" }));
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

	// The description becomes the error message, which the router logs and
	// returns. A provider echoing the session cookie (or anything else
	// credential-shaped) there must not get it logged or reflected.
	it("drops a provider error_description that is not a safe RFC 6749 description", async () => {
		const unsafe = [
			"session cookie-abc is not valid",
			"token aaa.bbb.ccc refused",
			"multi\nline",
			'quote"d',
			"x".repeat(257),
			42,
		];
		for (const error_description of unsafe) {
			fetchMock.mockResolvedValueOnce(
				jsonResponse(400, { error: "invalid_scope", error_description }),
			);
			await expect(
				client().exchange({ sessionCookieValue: "cookie-abc", requestId: "r" }),
				String(error_description),
			).rejects.toMatchObject({
				code: "provider_config_error",
				status: 502,
				message: "provider rejected proxy configuration (client_id or scope)",
			});
		}
	});

	it("does not read an oversized 400 body", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(400, { error: "invalid_grant", pad: "a".repeat(20_000) }),
		);
		await expect(
			client().exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_config_error",
			message: "provider rejected proxy configuration (client_id or scope)",
		});
	});

	it("throws provider_unavailable on provider 500", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(500, {}));
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

	it("throws provider_unavailable on network error (fetch throws TypeError)", async () => {
		fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_unavailable",
			status: 502,
			retryAfter: null,
		});
	});

	it("throws provider_unavailable on timeout (AbortError)", async () => {
		const abortErr = new DOMException("The operation was aborted", "AbortError");
		fetchMock.mockRejectedValueOnce(abortErr);
		const client = createSessionGrantClient(baseCfg);

		await expect(
			client.exchange({ sessionCookieValue: "c", requestId: "r" }),
		).rejects.toMatchObject({
			code: "provider_unavailable",
			status: 502,
			retryAfter: null,
		});
	});

	it("throws provider_unavailable on unexpected 4xx", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(418, {}));
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
