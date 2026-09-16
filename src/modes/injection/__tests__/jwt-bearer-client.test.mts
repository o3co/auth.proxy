import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clientSecretBasic } from "../../../oauth/client-secret-basic.mjs";
import {
	createJwtBearerClient,
	JWT_BEARER_GRANT_TYPE,
	type JwtBearerClientConfig,
	JwtBearerError,
} from "../jwt-bearer-client.mjs";

const baseCfg: JwtBearerClientConfig = {
	providerOrigin: "http://provider.example",
	timeoutMs: 5000,
	clientId: "proxy-exchange",
	clientSecret: "s3cret",
	scope: null,
	audience: null,
	resource: null,
};

const ASSERTION = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpIn0.c2ln";

const jsonResponse = (
	status: number,
	body: unknown,
	headers: Record<string, string> = {},
): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});

const okResponse = (extra: Record<string, unknown> = {}): Response =>
	jsonResponse(200, { access_token: "issued-tok", token_type: "Bearer", expires_in: 300, ...extra });

describe("createJwtBearerClient.exchange", () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	const callUrl = (index = 0): string => fetchMock.mock.calls[index][0] as string;
	const callInit = (index = 0): RequestInit => fetchMock.mock.calls[index][1] as RequestInit;
	const callHeaders = (index = 0): Record<string, string> =>
		callInit(index).headers as Record<string, string>;
	const callParams = (index = 0): URLSearchParams =>
		new URLSearchParams(callInit(index).body as string);

	const exchange = (cfg: JwtBearerClientConfig = baseCfg) =>
		createJwtBearerClient(cfg).exchange({ assertion: ASSERTION, requestId: "req-1" });

	beforeEach(() => {
		fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	describe("request", () => {
		it("POSTs to <providerOrigin>/oauth/token", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await exchange();

			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(callUrl()).toBe("http://provider.example/oauth/token");
			expect(callInit().method).toBe("POST");
		});

		it("tolerates providerOrigin with a trailing slash", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await exchange({ ...baseCfg, providerOrigin: "http://provider.example/" });

			expect(callUrl()).toBe("http://provider.example/oauth/token");
		});

		it("sends grant_type=jwt-bearer and the assertion, and nothing unset", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await exchange();

			expect(JWT_BEARER_GRANT_TYPE).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
			expect([...callParams().entries()]).toEqual([
				["grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
				["assertion", ASSERTION],
			]);
		});

		it("adds the configured scope, audience and resource", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await exchange({
				...baseCfg,
				scope: "orders.read orders.write",
				audience: "https://api.example.com",
				resource: "https://api.example.com/orders",
			});

			const params = callParams();
			expect(params.get("scope")).toBe("orders.read orders.write");
			expect(params.get("audience")).toBe("https://api.example.com");
			expect(params.get("resource")).toBe("https://api.example.com/orders");
			// client_secret_basic carries the client identity; the body does not.
			expect(params.has("client_id")).toBe(false);
			expect(params.has("client_secret")).toBe(false);
		});

		it("authenticates with client_secret_basic and sends only isolated headers", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await exchange();

			const headers = callHeaders();
			expect(Object.keys(headers).sort()).toEqual([
				"Accept",
				"Authorization",
				"Content-Type",
				"X-Request-Id",
			]);
			expect(headers.Authorization).toBe(
				`Basic ${Buffer.from("proxy-exchange:s3cret").toString("base64")}`,
			);
			expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
			expect(headers.Accept).toBe("application/json");
			expect(headers["X-Request-Id"]).toBe("req-1");
		});

		it("percent-encodes reserved characters in the client credentials (RFC 6749 section 2.3.1)", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			const credentials = { clientId: "https://proxy.example/x", clientSecret: "a:b c" };
			await exchange({ ...baseCfg, ...credentials });

			expect(callHeaders().Authorization).toBe(clientSecretBasic(credentials));
			const decoded = Buffer.from(
				callHeaders().Authorization.slice("Basic ".length),
				"base64",
			).toString("utf8");
			expect(decoded).toBe("https%3A%2F%2Fproxy.example%2Fx:a%3Ab%20c");
		});

		it("passes the configured timeout as AbortSignal.timeout", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			const timeoutSpy = vi.spyOn(AbortSignal, "timeout");
			await exchange({ ...baseCfg, timeoutMs: 1234 });

			expect(timeoutSpy).toHaveBeenCalledWith(1234);
			expect(callInit().signal).toBeInstanceOf(AbortSignal);
		});

		// The body carries a bearer credential and the header the proxy's own
		// client secret: neither may be replayed to wherever a redirect points.
		it("does not follow redirects", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await exchange();

			expect(callInit().redirect).toBe("manual");
		});
	});

	describe("success", () => {
		it("returns the access token and expires_in", async () => {
			fetchMock.mockResolvedValueOnce(okResponse());
			await expect(exchange()).resolves.toEqual({ accessToken: "issued-tok", expiresIn: 300 });
		});

		it("accepts token_type case-insensitively", async () => {
			fetchMock.mockResolvedValueOnce(okResponse({ token_type: "bearer" }));
			await expect(exchange()).resolves.toMatchObject({ accessToken: "issued-tok" });
		});

		it("returns null expiresIn when expires_in is absent or not a number", async () => {
			fetchMock.mockResolvedValueOnce(
				jsonResponse(200, { access_token: "issued-tok", token_type: "Bearer" }),
			);
			await expect(exchange()).resolves.toEqual({ accessToken: "issued-tok", expiresIn: null });

			fetchMock.mockResolvedValueOnce(okResponse({ expires_in: "300" }));
			await expect(exchange()).resolves.toEqual({ accessToken: "issued-tok", expiresIn: null });
		});
	});

	describe("invalid 200 responses", () => {
		const invalid = [
			["a DPoP token_type", okResponse({ token_type: "DPoP" })],
			["a missing token_type", jsonResponse(200, { access_token: "issued-tok" })],
			["a non-string token_type", okResponse({ token_type: 1 })],
			["a missing access_token", jsonResponse(200, { token_type: "Bearer" })],
			["an empty access_token", okResponse({ access_token: "" })],
			["a non-JSON body", new Response("nope", { status: 200 })],
			["a JSON array body", jsonResponse(200, [])],
		] as const;

		for (const [label, response] of invalid) {
			it(`throws provider_invalid_response on ${label}`, async () => {
				fetchMock.mockResolvedValueOnce(response);
				await expect(exchange()).rejects.toMatchObject({
					code: "provider_invalid_response",
					status: 502,
				});
			});
		}
	});

	describe("provider refusals", () => {
		it("maps invalid_grant to credential_rejected (401), passing Retry-After through", async () => {
			fetchMock.mockResolvedValueOnce(
				jsonResponse(
					400,
					{ error: "invalid_grant", error_description: "assertion did not verify" },
					{ "Retry-After": "7" },
				),
			);
			await expect(exchange()).rejects.toMatchObject({
				code: "credential_rejected",
				status: 401,
				retryAfter: "7",
				providerError: "invalid_grant",
			});
		});

		for (const error of ["invalid_scope", "invalid_target", "unauthorized_client"]) {
			it(`maps ${error} to exchange_not_permitted (403)`, async () => {
				fetchMock.mockResolvedValueOnce(jsonResponse(400, { error }));
				await expect(exchange()).rejects.toMatchObject({
					code: "exchange_not_permitted",
					status: 403,
					retryAfter: null,
					providerError: error,
				});
			});
		}

		it("maps a provider 401 (the proxy's own client authentication) to provider_config_error", async () => {
			fetchMock.mockResolvedValueOnce(
				jsonResponse(401, { error: "invalid_client" }, { "WWW-Authenticate": "Basic" }),
			);
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_config_error",
				status: 502,
				providerError: "invalid_client",
			});
		});

		for (const body of [
			{ error: "invalid_client" },
			{ error: "invalid_request" },
			{ error: "unsupported_grant_type" },
			{},
		]) {
			it(`maps another 400 (${JSON.stringify(body)}) to provider_config_error`, async () => {
				fetchMock.mockResolvedValueOnce(jsonResponse(400, body));
				await expect(exchange()).rejects.toMatchObject({
					code: "provider_config_error",
					status: 502,
				});
			});
		}

		it("maps a 400 with a non-JSON body to provider_config_error", async () => {
			fetchMock.mockResolvedValueOnce(new Response("bad request", { status: 400 }));
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_config_error",
				status: 502,
				providerError: null,
			});
		});

		// The provider's `error` ends up in logs. A malformed or compromised
		// provider echoing a credential there must not get it logged.
		it("records only a validated error code, never an echoed credential", async () => {
			const echoes = [
				[400, ASSERTION],
				[400, "s3cret"],
				[401, "s3cret"],
				[400, "aaa.bbb.ccc"],
				[400, "invalid grant"],
				[400, "x".repeat(65)],
				[400, 42],
			] as const;
			for (const [status, error] of echoes) {
				fetchMock.mockResolvedValueOnce(jsonResponse(status, { error }));
				const err = (await exchange().catch((e: unknown) => e)) as JwtBearerError;
				expect(err, String(error)).toBeInstanceOf(JwtBearerError);
				expect(err.code, String(error)).toBe("provider_config_error");
				expect(err.providerError, String(error)).toBe("invalid_error_code");
			}
		});

		it("maps a redirect to provider_config_error", async () => {
			fetchMock.mockResolvedValueOnce(
				new Response(null, { status: 302, headers: { Location: "https://elsewhere.example" } }),
			);
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_config_error",
				status: 502,
			});
		});
	});

	describe("provider unavailable", () => {
		for (const status of [429, 500, 503]) {
			it(`maps ${status} to provider_unavailable, passing Retry-After through`, async () => {
				fetchMock.mockResolvedValueOnce(jsonResponse(status, {}, { "Retry-After": "30" }));
				await expect(exchange()).rejects.toMatchObject({
					code: "provider_unavailable",
					status: 502,
					retryAfter: "30",
				});
			});
		}

		// The mapping is unchanged; the provider's error code is now kept for
		// the log line, validated like every other one.
		for (const [status, error] of [
			[503, "temporarily_unavailable"],
			[500, "server_error"],
			[429, "slow_down"],
			[418, "teapot"],
		] as const) {
			it(`keeps the validated error code of a ${status} response`, async () => {
				fetchMock.mockResolvedValueOnce(
					jsonResponse(status, { error, error_description: "busy" }, { "Retry-After": "30" }),
				);
				await expect(exchange()).rejects.toMatchObject({
					code: "provider_unavailable",
					status: 502,
					retryAfter: "30",
					providerError: error,
				});
			});
		}

		it("records no code for a non-JSON or oversized error body, and never an echoed credential", async () => {
			fetchMock
				.mockResolvedValueOnce(new Response("<html>bad gateway</html>", { status: 502 }))
				.mockResolvedValueOnce(
					jsonResponse(503, { error: "temporarily_unavailable", pad: "a".repeat(20_000) }),
				)
				.mockResolvedValueOnce(jsonResponse(503, { error: ASSERTION }))
				.mockResolvedValueOnce(
					jsonResponse(400, { error: "invalid_grant", pad: "a".repeat(20_000) }),
				);

			for (const expected of [null, null, "invalid_error_code"]) {
				await expect(exchange()).rejects.toMatchObject({
					code: "provider_unavailable",
					status: 502,
					providerError: expected,
				});
			}
			// an oversized 400 body is not read, so it is a configuration error
			// with no code rather than a credential rejection
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_config_error",
				providerError: null,
			});
		});

		it("maps an unexpected 4xx to provider_unavailable", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse(418, {}));
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_unavailable",
				status: 502,
			});
		});

		it("maps a network error to provider_unavailable", async () => {
			fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_unavailable",
				status: 502,
				retryAfter: null,
			});
		});

		it("maps a timeout to provider_unavailable", async () => {
			fetchMock.mockRejectedValueOnce(
				new DOMException("The operation was aborted due to timeout", "TimeoutError"),
			);
			await expect(exchange()).rejects.toMatchObject({
				code: "provider_unavailable",
				status: 502,
			});
		});
	});

	it("never puts the assertion or the client secret into an error message", async () => {
		const responses = [
			jsonResponse(400, { error: "invalid_grant", error_description: "x" }),
			jsonResponse(400, { error: "invalid_scope" }),
			jsonResponse(401, { error: "invalid_client" }),
			jsonResponse(503, {}),
			okResponse({ token_type: "DPoP" }),
		];
		for (const response of responses) {
			fetchMock.mockResolvedValueOnce(response);
			const err = await exchange().catch((e: unknown) => e);
			expect(err).toBeInstanceOf(JwtBearerError);
			expect(String((err as Error).message)).not.toContain(ASSERTION);
			expect(String((err as Error).message)).not.toContain("s3cret");
		}
	});
});
