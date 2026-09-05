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

	// RFC 6749 section 2.3.1: both halves are form-urlencoded BEFORE they are
	// joined with ":" and base64'd. Without that, a ":" in the client_id
	// re-splits the credential at the wrong place and the provider reads a
	// different client_id / secret pair than the operator configured.
	it("percent-encodes a ':' in either half so the credential cannot re-split", () => {
		const header = buildAuthHeader(
			{ clientId: "https://api.example.com/orders", clientSecret: "a:b" },
			"unused",
		);
		const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");

		expect(decoded).toBe("https%3A%2F%2Fapi.example.com%2Forders:a%3Ab");
		// Exactly one ":" survives — the userid/password separator itself.
		expect(decoded.split(":")).toHaveLength(2);
	});

	// The provider decodes with `decodeURIComponent(s.replace(/\+/g, " "))`, the
	// matching form-urlencoded decoder, so every encoded byte round-trips. A
	// space becomes %20 rather than "+" (encodeURIComponent), which that decoder
	// reads back as a space just the same.
	it("round-trips reserved characters through the provider's form-urlencoded decoder", () => {
		const clientId = "cl ient+id%20&x=1";
		const clientSecret = "s3:cret/with?reserved#chars";
		const header = buildAuthHeader({ clientId, clientSecret }, "unused");
		const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
		const [encodedId, encodedSecret] = decoded.split(":");
		const formUrlDecode = (v: string): string => decodeURIComponent(v.replace(/\+/g, " "));

		expect(formUrlDecode(encodedId)).toBe(clientId);
		expect(formUrlDecode(encodedSecret)).toBe(clientSecret);
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

	it("stops accepting a warm cache entry at the token's exp", async () => {
		const start = 1_700_000_000_000;
		const clock = vi.spyOn(Date, "now").mockReturnValue(start);
		fetchMock.mockImplementation(async () => jsonResponse(200, {
			active: true, exp: start / 1000 + 1,
		}));
		expect((await introspect("t", "http://auth/introspect", 30, "r", "Bearer t")).active).toBe(true);
		clock.mockReturnValue(start + 1000);
		expect((await introspect("t", "http://auth/introspect", 30, "r", "Bearer t")).active).toBe(false);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it("refuses a positive response that expires during the provider call", async () => {
		const start = 1_700_000_000_000;
		const clock = vi.spyOn(Date, "now").mockReturnValue(start);
		fetchMock.mockImplementation(async () => {
			clock.mockReturnValue(start + 2000);
			return jsonResponse(200, { active: true, exp: start / 1000 + 1 });
		});
		expect((await introspect("t", "http://auth/introspect", 30, "r", "Bearer t")).active).toBe(false);
	});

	it("does not reuse a cached result when caching is disabled", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }))
			.mockResolvedValueOnce(jsonResponse(200, { active: false }));
		await introspect("t", "http://auth/introspect", 30, "r", "Bearer t");
		expect((await introspect("t", "http://auth/introspect", 0, "r", "Bearer t")).active).toBe(false);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it.each(["soon", null, {}, []].map((exp) => ({ exp })))("refuses malformed exp $exp", async ({ exp }) => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true, exp }));
		await expect(introspect("t", "http://auth/introspect", 30, "r", "Bearer t"))
			.rejects.toMatchObject({ status: 502 });
	});

	it("accepts a case-insensitive Bearer token type", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true, token_type: "bearer" }));
		expect((await introspect("t", "http://auth/introspect", 30, "r", "Bearer t")).active).toBe(true);
	});

	it.each([
		{ cnf: { jkt: "proof-key" }, token_type: "DPoP" },
		{ cnf: { jkt: "proof-key" }, token_type: "Bearer" },
		{ cnf: { "x5t#S256": "certificate" }, token_type: "Bearer" },
		{ cnf: {} },
		{ cnf: null },
		{ token_type: "DPoP" },
	])("refuses unsupported possession evidence on the Bearer path: %j", async (claims) => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true, ...claims }));
		expect((await introspect("t", "http://auth/introspect", 30, "r", "Bearer t")).active).toBe(false);
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
