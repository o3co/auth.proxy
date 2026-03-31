import axios from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { buildAuthHeader, clearCache, introspect } from "../router/Proxy.mjs";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("buildAuthHeader", () => {
	it("returns Basic auth when client credentials are provided", () => {
		const header = buildAuthHeader("my-proxy", "s3cret", "some-token");
		expect(header).toBe(
			`Basic ${Buffer.from("my-proxy:s3cret").toString("base64")}`,
		);
	});

	it("returns Bearer with the request token when no client credentials", () => {
		const header = buildAuthHeader(null, null, "my-bearer-token");
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
			},
		);
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

		const authHeader = buildAuthHeader("client-id", "client-secret", "some-token");
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
});
