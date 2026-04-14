import axios from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { buildAuthHeader, clearCache, introspect } from "../introspect.mjs";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("buildAuthHeader", () => {
	it("returns Basic auth when client credentials are provided", () => {
		const header = buildAuthHeader({ clientId: "my-proxy", clientSecret: "s3cret" }, "some-token");
		expect(header).toBe(
			`Basic ${Buffer.from("my-proxy:s3cret").toString("base64")}`,
		);
	});

	it("returns Bearer with the request token when no client credentials", () => {
		const header = buildAuthHeader(null, "my-bearer-token");
		expect(header).toBe("Bearer my-bearer-token");
	});
});

describe("introspect", () => {
	beforeEach(() => {
		clearCache();
		vi.clearAllMocks();
	});

	it("sends form-urlencoded body with correct Content-Type", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			data: { active: true },
		});

		await introspect("test-token", "http://auth/introspect", 30, "req-1", "Bearer test-token");

		expect(mockedAxios.post).toHaveBeenCalledWith(
			"http://auth/introspect",
			"token=test-token",
			{
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: "Bearer test-token",
					"x-request-id": "req-1",
				},
				timeout: 5000,
			},
		);
	});

	it("passes custom timeoutMs to axios", async () => {
		mockedAxios.post.mockResolvedValueOnce({ data: { active: true } });

		await introspect("test-token", "http://auth/introspect", 30, "req-t", "Bearer test-token", 10000, 1234);

		const opts = mockedAxios.post.mock.calls[0][2];
		expect(opts?.timeout).toBe(1234);
	});

	it("encodes special characters in token using URLSearchParams", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			data: { active: true },
		});

		await introspect("token+with=special&chars", "http://auth/introspect", 30, "req-2", "Bearer x");

		const body = mockedAxios.post.mock.calls[0][1] as string;
		expect(body).toBe("token=token%2Bwith%3Dspecial%26chars");
	});

	it("uses Basic auth header when client credentials are configured", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			data: { active: true },
		});

		const authHeader = buildAuthHeader({ clientId: "client-id", clientSecret: "client-secret" }, "some-token");
		await introspect("some-token", "http://auth/introspect", 30, "req-3", authHeader);

		const headers = mockedAxios.post.mock.calls[0][2]?.headers;
		expect(headers?.Authorization).toBe(
			`Basic ${Buffer.from("client-id:client-secret").toString("base64")}`,
		);
	});

	it("returns cached result on second call within TTL", async () => {
		mockedAxios.post.mockResolvedValueOnce({
			data: { active: true, sub: "user-1" },
		});

		const result1 = await introspect("cached-token", "http://auth/introspect", 30, "req-4", "Bearer cached-token");
		const result2 = await introspect("cached-token", "http://auth/introspect", 30, "req-5", "Bearer cached-token");

		expect(mockedAxios.post).toHaveBeenCalledTimes(1);
		expect(result1).toEqual(result2);
	});

	it("evicts oldest entry when cache exceeds maxCacheEntries", async () => {
		// Fill cache to the limit (maxCacheEntries = 2)
		mockedAxios.post
			.mockResolvedValueOnce({ data: { active: true, sub: "user-a" } })
			.mockResolvedValueOnce({ data: { active: true, sub: "user-b" } })
			.mockResolvedValueOnce({ data: { active: true, sub: "user-c" } })
			.mockResolvedValueOnce({ data: { active: true, sub: "user-a-re" } });

		await introspect("token-a", "http://auth/introspect", 30, "r1", "Bearer x", 2);
		await introspect("token-b", "http://auth/introspect", 30, "r2", "Bearer x", 2);
		// Adding token-c should evict token-a (oldest)
		await introspect("token-c", "http://auth/introspect", 30, "r3", "Bearer x", 2);

		// token-a should no longer be cached — expect a fresh network call
		await introspect("token-a", "http://auth/introspect", 30, "r4", "Bearer x", 2);
		expect(mockedAxios.post).toHaveBeenCalledTimes(4);
	});
});
