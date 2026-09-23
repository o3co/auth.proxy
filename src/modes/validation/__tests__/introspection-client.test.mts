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
	MAX_INTROSPECTION_BODY_BYTES,
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

	// #95 F39: the injection clients have read their 200 at a bound since F35;
	// this one buffered whatever the provider sent, per in-flight request.
	describe("the bound on a 200 body", () => {
		const bodyOfExactly = (bytes: number): string => {
			const wrapper = '{"active":true,"pad":""}';
			return `{"active":true,"pad":"${"a".repeat(bytes - wrapper.length)}"}`;
		};

		it("reads a body of exactly MAX_INTROSPECTION_BODY_BYTES", async () => {
			const body = bodyOfExactly(MAX_INTROSPECTION_BODY_BYTES);
			expect(Buffer.byteLength(body)).toBe(MAX_INTROSPECTION_BODY_BYTES);
			fetchMock.mockResolvedValueOnce(new Response(body, { status: 200 }));

			await expect(clientFor().introspect("t", "r")).resolves.toMatchObject({ active: true });
		});

		it("refuses one byte past it as a provider error, rather than buffering what follows", async () => {
			const body = bodyOfExactly(MAX_INTROSPECTION_BODY_BYTES + 1);
			fetchMock.mockResolvedValueOnce(new Response(body, { status: 200 }));

			await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
				name: "IntrospectHttpError",
				status: 502,
			});
		});

		// The bound is only worth having if it stops the read.
		it("cancels the stream at the bound instead of reading what follows", async () => {
			const chunkBytes = 8 * 1024;
			const chunk = new TextEncoder().encode("a".repeat(chunkBytes));
			let pulled = 0;
			let cancelled = false;
			fetchMock.mockResolvedValueOnce(
				new Response(
					new ReadableStream<Uint8Array>({
						pull(controller) {
							if (pulled === 64) {
								controller.close();
								return;
							}
							pulled += 1;
							controller.enqueue(chunk);
						},
						cancel() {
							cancelled = true;
						},
					}),
					{ status: 200 },
				),
			);

			await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({ status: 502 });

			expect(cancelled).toBe(true);
			// One read past the bound detects it. The stream may also have
			// pulled one chunk ahead to fill its own queue while the client was
			// awaiting fetch — that slot is the stream's read-ahead, not the
			// reader's — and nothing beyond it: 512 KiB was on offer.
			expect(pulled).toBeLessThanOrEqual(MAX_INTROSPECTION_BODY_BYTES / chunkBytes + 2);
		});

		// What the bound is for, in absolute terms: a response carrying a
		// generous claim set has to fit.
		it("admits a response with 32 KiB of claims", async () => {
			const claims = { active: true, sub: "user-1", ext: "c".repeat(32 * 1024) };
			fetchMock.mockResolvedValueOnce(jsonResponse(200, claims));

			await expect(clientFor().introspect("t", "r")).resolves.toEqual(claims);
		});

		// The ceiling as well as the floor: the boundary tests above derive
		// their sizes from the constant, so without this it could be raised
		// arbitrarily with a green suite.
		it("is 64 KiB, the same allowance as a token response", () => {
			expect(MAX_INTROSPECTION_BODY_BYTES).toBe(64 * 1024);
		});

		// resp.json(), which this used before F39, decodes as UTF-8 and drops a
		// leading BOM. The bounded reader decodes the same way (F35), and a
		// provider emitting one must keep working.
		it("reads a body behind a UTF-8 BOM", async () => {
			fetchMock.mockResolvedValueOnce(new Response('\uFEFF{"active":true}', { status: 200 }));

			await expect(clientFor().introspect("t", "r")).resolves.toEqual({ active: true });
		});
	});

	it("throws IntrospectHttpError with matching status on non-2xx response", async () => {
		fetchMock.mockResolvedValueOnce(new Response("", { status: 503 }));

		const p = clientFor().introspect("t", "r");
		await expect(p).rejects.toBeInstanceOf(IntrospectHttpError);
		await expect(p).rejects.toMatchObject({ status: 503 });
	});

	// Nothing here reads an error body (#95 F28). Past undici's 64 KiB
	// read-ahead an unread one would hold its socket until the response is
	// collected; within it undici has already pooled the socket, so this is
	// defensive. The non-2xx path is the only one that throws before the body
	// is dealt with: every other refusal runs after readBoundedJsonObject has
	// read it to the end or cancelled it at the bound (#95 F39).
	it.each([401, 503])(
		"cancels the body of a %d response instead of leaving it unread",
		async (status) => {
			let cancelled = false;
			const resp = new Response(
				new ReadableStream<Uint8Array>({
					start(controller) {
						controller.enqueue(new TextEncoder().encode('{"error":"x"}'));
					},
					cancel() {
						cancelled = true;
					},
				}),
				{ status },
			);
			fetchMock.mockResolvedValueOnce(resp);

			await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
				name: "IntrospectHttpError",
				status,
			});

			expect(cancelled).toBe(true);
			expect(resp.bodyUsed).toBe(true);
		},
	);

	// The cancellation is a release, not an answer. A stream that is already
	// errored — the connection reset before anything read it — rejects its own
	// cancel, and without the swallow that rejection would replace the status
	// this call exists to report: a provider 401 would reach the decision as an
	// unknown failure and be answered 500 rather than 401 Invalid Token.
	it("keeps the provider's status when cancelling the body fails", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				new ReadableStream<Uint8Array>({
					start(controller) {
						controller.enqueue(new TextEncoder().encode('{"error":"x"}'));
					},
					cancel() {
						throw new Error("socket hang up");
					},
				}),
				{ status: 401 },
			),
		);

		await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
			name: "IntrospectHttpError",
			status: 401,
		});
	});

	// RFC 7662 section 2.3: the introspection request is authenticated. Which
	// credential it carried decides what the provider's 401 is about, and only
	// this module knows which one it sent (#95 F7).
	it("marks a 401 as the proxy's own client credentials when they are configured", async () => {
		fetchMock.mockResolvedValueOnce(new Response("", { status: 401 }));

		await expect(
			clientFor({ credentials: { clientId: "my-proxy", clientSecret: "s3cret" } }).introspect(
				"t",
				"r",
			),
		).rejects.toMatchObject({ status: 401, refusedCredential: "client" });
	});

	it("marks a 401 as the inbound token when there are no client credentials", async () => {
		fetchMock.mockResolvedValueOnce(new Response("", { status: 401 }));

		await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
			status: 401,
			refusedCredential: "token",
		});
	});

	it.each([403, 500, 503])("marks nothing on a %d, which is not about a credential", async (status) => {
		fetchMock.mockResolvedValueOnce(new Response("", { status }));

		await expect(
			clientFor({ credentials: { clientId: "my-proxy", clientSecret: "s3cret" } }).introspect(
				"t",
				"r",
			),
		).rejects.toMatchObject({ status, refusedCredential: null });
	});

	// #95 F43, the validation counterpart of F8. The introspection endpoint is
	// configuration; a followed redirect re-sends the credential this request
	// carries (the inbound token, or the proxy's Basic header) to a path
	// nothing configured on a same-origin 307/308, and loses it cross-origin.
	it("asks fetch not to follow a redirect", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { active: true }));

		await clientFor().introspect("t", "r");

		expect(getFetchCall(fetchMock).init.redirect).toBe("manual");
	});

	it.each([301, 302, 303, 307, 308])(
		"carries a %d as the provider's status, and releases its body",
		async (status) => {
			let cancelled = false;
			fetchMock.mockResolvedValueOnce(
				new Response(
					new ReadableStream<Uint8Array>({
						start(controller) {
							controller.enqueue(new TextEncoder().encode("moved"));
						},
						cancel() {
							cancelled = true;
						},
					}),
					{ status, headers: { Location: "https://elsewhere.test/introspect" } },
				),
			);

			await expect(clientFor().introspect("t", "r")).rejects.toMatchObject({
				name: "IntrospectHttpError",
				status,
				refusedCredential: null,
			});
			expect(cancelled).toBe(true);
		},
	);

	it("propagates fetch rejection (network error / AbortError)", async () => {
		const abortErr = new DOMException("The operation was aborted", "AbortError");
		fetchMock.mockRejectedValueOnce(abortErr);

		await expect(clientFor().introspect("t", "r")).rejects.toBe(abortErr);
	});
});
