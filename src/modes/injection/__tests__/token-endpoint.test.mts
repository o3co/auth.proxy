// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The two things every token-endpoint call in this directory needs (#95 F19):
 * where the endpoint is, and how a body is read when it may not be JSON at
 * all. Both were exercised only through the clients until now.
 */
import { describe, expect, it } from "vitest";

import { MAX_ERROR_BODY_BYTES } from "../provider-error.mjs";
import { buildTokenUrl, MAX_TOKEN_BODY_BYTES, parseJsonBody } from "../token-endpoint.mjs";

describe("buildTokenUrl", () => {
	it.each([
		["http://provider.example", "http://provider.example/oauth/token"],
		["https://provider.example", "https://provider.example/oauth/token"],
		["http://127.0.0.1:8080", "http://127.0.0.1:8080/oauth/token"],
	])("puts /oauth/token on %s", (origin, expected) => {
		expect(buildTokenUrl(origin)).toBe(expected);
	});

	it.each(["http://provider.example/base", "http://provider.example/base/"])(
		"replaces the path of %s rather than appending to it, which is why the schema validates origin-only",
		(origin) => {
			// The leading slash makes the path absolute against the origin. The
			// trailing-slash case is the one that tells that apart: a relative
			// specifier would resolve to /base/oauth/token there and to
			// /oauth/token without the slash. A provider mounted under a prefix
			// would need a different builder, and the config schema is what keeps
			// that case from arriving here.
			expect(buildTokenUrl(origin)).toBe("http://provider.example/oauth/token");
		},
	);
});

describe("parseJsonBody", () => {
	const responseOf = (body: string): Response => new Response(body, { status: 400 });

	it("returns the object a JSON body carries", async () => {
		await expect(parseJsonBody(responseOf('{"error":"invalid_grant"}'))).resolves.toEqual({
			error: "invalid_grant",
		});
	});

	it.each([
		["an empty body", ""],
		["a body that is not JSON", "<html>gateway error</html>"],
		["a JSON string", '"invalid_grant"'],
		["a JSON number", "42"],
		["JSON null", "null"],
	])("answers null for %s", async (_label, body) => {
		await expect(parseJsonBody(responseOf(body))).resolves.toBeNull();
	});

	it.each([
		["an array of objects", '[{"error":"invalid_grant"}]'],
		["an array of scalars", "[1,2,3]"],
		["an empty array", "[]"],
	])("answers null for %s, which the declared return type excludes (#95 F34)", async (_label, body) => {
		// A JSON array is `typeof === "object"`, so it used to come back as it
		// stood, typed as a Record the caller could read `.error` off. No
		// provider sends one; what made it worth removing is that the type said
		// it could not happen and the two callers disagreed about whether it
		// could.
		await expect(parseJsonBody(responseOf(body))).resolves.toBeNull();
	});

	it("never throws on a body the provider cut short", async () => {
		await expect(parseJsonBody(responseOf('{"error":"invalid_'))).resolves.toBeNull();
	});

	// The success path used to buffer whatever arrived, while the error path
	// next door stopped at 16 KiB (#95 F35).
	describe("the bound", () => {
		// Padded to an exact byte count, so these land on the boundary itself
		// rather than near it. ASCII throughout, so one character is one byte.
		const bodyOfExactly = (bytes: number): string => {
			const wrapper = '{"access_token":""}';
			return `{"access_token":"${"a".repeat(bytes - wrapper.length)}"}`;
		};

		it("reads a body of exactly MAX_TOKEN_BODY_BYTES", async () => {
			const body = bodyOfExactly(MAX_TOKEN_BODY_BYTES);

			expect(Buffer.byteLength(body)).toBe(MAX_TOKEN_BODY_BYTES);
			await expect(parseJsonBody(responseOf(body))).resolves.toMatchObject({
				access_token: expect.any(String),
			});
		});

		it("answers null one byte past it, rather than buffering what follows", async () => {
			const body = bodyOfExactly(MAX_TOKEN_BODY_BYTES + 1);

			expect(Buffer.byteLength(body)).toBe(MAX_TOKEN_BODY_BYTES + 1);
			await expect(parseJsonBody(responseOf(body))).resolves.toBeNull();
		});

		// The bound is only worth having if it stops the read: answering null
		// after draining the whole body would leave the memory it was meant to
		// bound already spent.
		it("cancels the stream at the bound instead of reading what follows", async () => {
			const chunkBytes = 8 * 1024;
			const chunk = new TextEncoder().encode("a".repeat(chunkBytes));
			const availableChunks = 64;
			let pulled = 0;
			let cancelled = false;
			const body = new ReadableStream<Uint8Array>({
				pull(controller) {
					if (pulled === availableChunks) {
						controller.close();
						return;
					}
					pulled += 1;
					controller.enqueue(chunk);
				},
				cancel() {
					cancelled = true;
				},
			});

			await expect(parseJsonBody(new Response(body, { status: 200 }))).resolves.toBeNull();

			expect(cancelled).toBe(true);
			// One read past the bound is what detects it; the remaining
			// 512 KiB - 64 KiB the source would have handed over is not read.
			expect(pulled).toBe(MAX_TOKEN_BODY_BYTES / chunkBytes + 1);
		});

		// What the bound is FOR, in absolute terms rather than relative to
		// itself: a token response carrying a large id_token beside the access
		// and refresh tokens has to fit, and an error body's allowance does not
		// have to. Without this the constant could be moved to anything —
		// including back to the error bound — with a green suite.
		it("admits a token response with a 32 KiB id_token, which the error bound would refuse", async () => {
			const idToken = `header.${"c".repeat(32 * 1024)}.signature`;
			const body = JSON.stringify({
				access_token: "at",
				refresh_token: "rt",
				id_token: idToken,
				token_type: "Bearer",
				expires_in: 300,
			});

			expect(Buffer.byteLength(body)).toBeGreaterThan(MAX_ERROR_BODY_BYTES);
			expect(MAX_TOKEN_BODY_BYTES).toBeGreaterThan(MAX_ERROR_BODY_BYTES);
			await expect(parseJsonBody(responseOf(body))).resolves.toMatchObject({
				id_token: idToken,
			});
		});
	});

	// resp.text(), which this used before F35, decodes as UTF-8 and drops a
	// leading BOM; Buffer.toString("utf8") keeps it and JSON.parse then refuses
	// the body. A provider emitting one must keep working.
	it("reads a body behind a UTF-8 BOM, as a UTF-8 decode does", async () => {
		await expect(parseJsonBody(responseOf('\uFEFF{"access_token":"tok"}'))).resolves.toEqual({
			access_token: "tok",
		});
	});
});
