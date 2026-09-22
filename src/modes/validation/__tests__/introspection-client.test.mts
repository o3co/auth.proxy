// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The introspection client on its own (#95 F5): one `POST` per call and the
 * reading of the response as an RFC 7662 response — the status, the JSON, and
 * `active` being a boolean. What the proxy then does with a valid response,
 * and what is cached, is `introspect.test.mts`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	buildAuthHeader,
	createIntrospectionClient,
	IntrospectHttpError,
} from "../introspection-client.mjs";

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

const clientFor = (overrides: Partial<Parameters<typeof createIntrospectionClient>[0]> = {}) =>
	createIntrospectionClient({
		url: "http://auth/introspect",
		timeoutMs: 5000,
		credentials: null,
		...overrides,
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
	// different client.
	it("percent-encodes a ':' in either half so the credential cannot re-split", () => {
		const header = buildAuthHeader({ clientId: "a:b", clientSecret: "c:d" }, "t");
		const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString();
		expect(decoded).toBe("a%3Ab:c%3Ad");
		expect(decoded.split(":")).toHaveLength(2);
	});

	it("round-trips reserved characters through the provider's form-urlencoded decoder", () => {
		const header = buildAuthHeader({ clientId: "a b+c", clientSecret: "d/e=f" }, "t");
		const [id, secret] = Buffer.from(header.slice("Basic ".length), "base64")
			.toString()
			.split(":");
		expect(decodeURIComponent(id)).toBe("a b+c");
		expect(decodeURIComponent(secret)).toBe("d/e=f");
	});
});

describe("createIntrospectionClient", () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it("sends form-urlencoded body with correct Content-Type", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));

		await clientFor().introspect("test-token", "req-1");

		const { url, init } = getFetchCall(fetchMock);
		expect(url).toBe("http://auth/introspect");
		expect(init.method).toBe("POST");
		expect(init.body).toBe("token=test-token");
		const headers = init.headers as Record<string, string>;
		expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
		expect(headers.Authorization).toBe("Bearer test-token");
		expect(headers["x-request-id"]).toBe("req-1");
	});

	it("passes the configured timeoutMs as AbortSignal.timeout", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));
		const timeoutSpy = vi.spyOn(AbortSignal, "timeout");

		await clientFor({ timeoutMs: 1234 }).introspect("test-token", "req-t");

		expect(timeoutSpy).toHaveBeenCalledWith(1234);
		const { init } = getFetchCall(fetchMock);
		expect(init.signal).toBeInstanceOf(AbortSignal);
	});

	it("encodes special characters in token using URLSearchParams", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));

		await clientFor().introspect("token+with=special&chars", "req-2");

		const { init } = getFetchCall(fetchMock);
		expect(init.body).toBe("token=token%2Bwith%3Dspecial%26chars");
	});

	it("uses Basic auth when client credentials are configured, the same header for every token", async () => {
		fetchMock
			.mockResolvedValueOnce(jsonResponse(200, { active: true }))
			.mockResolvedValueOnce(jsonResponse(200, { active: true }));
		const client = clientFor({
			credentials: { clientId: "client-id", clientSecret: "client-secret" },
		});

		await client.introspect("some-token", "req-3");
		await client.introspect("another-token", "req-4");

		const expected = `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`;
		for (const index of [0, 1]) {
			const headers = getFetchCall(fetchMock, index).init.headers as Record<string, string>;
			expect(headers.Authorization).toBe(expected);
		}
	});

	it("presents the token itself when no client credentials are configured", async () => {
		fetchMock
			.mockResolvedValueOnce(jsonResponse(200, { active: true }))
			.mockResolvedValueOnce(jsonResponse(200, { active: true }));
		const client = clientFor();

		await client.introspect("token-one", "req-5");
		await client.introspect("token-two", "req-6");

		expect((getFetchCall(fetchMock, 0).init.headers as Record<string, string>).Authorization).toBe(
			"Bearer token-one",
		);
		expect((getFetchCall(fetchMock, 1).init.headers as Record<string, string>).Authorization).toBe(
			"Bearer token-two",
		);
	});

	it("returns the response as it stands when it is a valid RFC 7662 body", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true, sub: "user-1", exp: 42 }));

		await expect(clientFor().introspect("t", "r")).resolves.toEqual({
			active: true,
			sub: "user-1",
			exp: 42,
		});
	});

	it.each([
		["string active value (truthy, would bypass)", { active: "false" }],
		["numeric active value", { active: 1 }],
		["null active value", { active: null }],
		["missing active key", { token_type: "Bearer" }],
	])(
		"throws IntrospectHttpError(502) when active is not a boolean — %s",
		async (_label, body) => {
			fetchMock.mockResolvedValueOnce(jsonResponse(200, body));

			await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
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

			await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
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

		await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
			name: "IntrospectHttpError",
			status: 502,
		});
	});

	it("throws IntrospectHttpError with matching status on non-2xx response", async () => {
		fetchMock.mockResolvedValueOnce(new Response("", { status: 503 }));

		const p = clientFor().introspect("t", "r");
		await expect(p).rejects.toBeInstanceOf(IntrospectHttpError);
		await expect(p).rejects.toMatchObject({ status: 503 });
	});

	it("propagates fetch rejection (network error / AbortError)", async () => {
		const abortErr = new DOMException("The operation was aborted", "AbortError");
		fetchMock.mockRejectedValueOnce(abortErr);

		await expect(clientFor().introspect("t", "r")).rejects.toBe(abortErr);
	});
});
