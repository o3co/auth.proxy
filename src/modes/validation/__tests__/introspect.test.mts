import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	buildAuthHeader,
	clearCache,
	IntrospectHttpError,
	introspect,
} from "../introspect.mjs";

const jsonResponse = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});

const getFetchCall = (
	fetchMock: ReturnType<typeof vi.fn>,
	index = 0,
): { url: string; init: RequestInit } => ({
	url: fetchMock.mock.calls[index][0] as string,
	init: fetchMock.mock.calls[index][1] as RequestInit,
});

describe("buildAuthHeader", () => {
	it("returns Basic auth when client credentials are provided", () => {
		const header = buildAuthHeader(
			{ clientId: "my-proxy", clientSecret: "s3cret" },
			"some-token",
		);
		expect(header).toBe(`Basic ${Buffer.from("my-proxy:s3cret").toString("base64")}`);
	});

	it("returns Bearer with the request token when no client credentials", () => {
		const header = buildAuthHeader(null, "my-bearer-token");
		expect(header).toBe("Bearer my-bearer-token");
	});
});

describe("introspect", () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		clearCache();
		fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it("sends form-urlencoded body with correct Content-Type", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));

		await introspect("test-token", "http://auth/introspect", 30, "req-1", "Bearer test-token");

		const { url, init } = getFetchCall(fetchMock);
		expect(url).toBe("http://auth/introspect");
		expect(init.method).toBe("POST");
		expect(init.body).toBe("token=test-token");
		const headers = init.headers as Record<string, string>;
		expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
		expect(headers.Authorization).toBe("Bearer test-token");
		expect(headers["x-request-id"]).toBe("req-1");
	});

	it("passes custom timeoutMs as AbortSignal.timeout", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));
		const timeoutSpy = vi.spyOn(AbortSignal, "timeout");

		await introspect(
			"test-token",
			"http://auth/introspect",
			30,
			"req-t",
			"Bearer test-token",
			10000,
			1234,
		);

		expect(timeoutSpy).toHaveBeenCalledWith(1234);
		const { init } = getFetchCall(fetchMock);
		expect(init.signal).toBeInstanceOf(AbortSignal);
	});

	it("encodes special characters in token using URLSearchParams", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));

		await introspect(
			"token+with=special&chars",
			"http://auth/introspect",
			30,
			"req-2",
			"Bearer x",
		);

		const { init } = getFetchCall(fetchMock);
		expect(init.body).toBe("token=token%2Bwith%3Dspecial%26chars");
	});

	it("uses Basic auth header when client credentials are configured", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));

		const authHeader = buildAuthHeader(
			{ clientId: "client-id", clientSecret: "client-secret" },
			"some-token",
		);
		await introspect("some-token", "http://auth/introspect", 30, "req-3", authHeader);

		const { init } = getFetchCall(fetchMock);
		const headers = init.headers as Record<string, string>;
		expect(headers.Authorization).toBe(
			`Basic ${Buffer.from("client-id:client-secret").toString("base64")}`,
		);
	});

	it("returns cached result on second call within TTL", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true, sub: "user-1" }));

		const result1 = await introspect(
			"cached-token",
			"http://auth/introspect",
			30,
			"req-4",
			"Bearer cached-token",
		);
		const result2 = await introspect(
			"cached-token",
			"http://auth/introspect",
			30,
			"req-5",
			"Bearer cached-token",
		);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(result1).toEqual(result2);
	});

	it.each([
		["string active value (truthy, would bypass)", { active: "false" }],
		["numeric active value", { active: 1 }],
		["null active value", { active: null }],
		["missing active key", { token_type: "Bearer" }],
	])(
		"throws IntrospectHttpError(502) when active is not a boolean — %s",
		async (_label, body) => {
			fetchMock.mockResolvedValueOnce(
				new Response(JSON.stringify(body), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				}),
			);

			await expect(
				introspect("t", "http://auth/introspect", 30, "r", "Bearer t"),
			).rejects.toMatchObject({
				name: "IntrospectHttpError",
				status: 502,
			});
		},
	);

	it.each([
		["JSON string body", JSON.stringify("not-an-object")],
		["JSON number body", "42"],
		["JSON array body", "[1,2,3]"],
		["JSON null body", "null"],
	])(
		"throws IntrospectHttpError(502) when 200 body is valid JSON but not a plain object — %s",
		async (_label, rawBody) => {
			fetchMock.mockResolvedValueOnce(
				new Response(rawBody, {
					status: 200,
					headers: { "Content-Type": "application/json" },
				}),
			);

			await expect(
				introspect("t", "http://auth/introspect", 30, "r", "Bearer t"),
			).rejects.toMatchObject({
				name: "IntrospectHttpError",
				status: 502,
			});
		},
	);

	it("throws IntrospectHttpError(502) on 200 with non-JSON body", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response("not json at all", {
				status: 200,
				headers: { "Content-Type": "text/plain" },
			}),
		);

		await expect(
			introspect("t", "http://auth/introspect", 30, "r", "Bearer t"),
		).rejects.toMatchObject({
			name: "IntrospectHttpError",
			status: 502,
		});
	});

	it("throws IntrospectHttpError with matching status on non-2xx response", async () => {
		fetchMock.mockResolvedValueOnce(new Response("", { status: 503 }));

		const p = introspect("t", "http://auth/introspect", 30, "r", "Bearer t");
		await expect(p).rejects.toBeInstanceOf(IntrospectHttpError);
		await expect(p).rejects.toMatchObject({ status: 503 });
	});

	it("propagates fetch rejection (network error / AbortError)", async () => {
		const abortErr = new DOMException("The operation was aborted", "AbortError");
		fetchMock.mockRejectedValueOnce(abortErr);

		await expect(
			introspect("t", "http://auth/introspect", 30, "r", "Bearer t"),
		).rejects.toBe(abortErr);
	});

	it("evicts oldest entry when cache exceeds maxCacheEntries", async () => {
		fetchMock
			.mockResolvedValueOnce(jsonResponse(200, { active: true, sub: "user-a" }))
			.mockResolvedValueOnce(jsonResponse(200, { active: true, sub: "user-b" }))
			.mockResolvedValueOnce(jsonResponse(200, { active: true, sub: "user-c" }))
			.mockResolvedValueOnce(jsonResponse(200, { active: true, sub: "user-a-re" }));

		await introspect("token-a", "http://auth/introspect", 30, "r1", "Bearer x", 2);
		await introspect("token-b", "http://auth/introspect", 30, "r2", "Bearer x", 2);
		await introspect("token-c", "http://auth/introspect", 30, "r3", "Bearer x", 2);

		await introspect("token-a", "http://auth/introspect", 30, "r4", "Bearer x", 2);
		expect(fetchMock).toHaveBeenCalledTimes(4);
	});
});
