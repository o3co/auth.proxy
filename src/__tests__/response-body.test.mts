// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * What to do with a provider response body, for every path that has one
 * (#95 F28, F35, F37, F39): read at most a bound of it as a JSON object, or
 * release it unread. Moved here from `modes/injection/provider-error.mts`
 * when validation became the third caller of the reader.
 */
import { describe, expect, it } from "vitest";
import { discardBody, readBoundedJsonObject } from "../response-body.mjs";

/** An arbitrary bound for the cases that are not about the bound. */
const BOUND = 16 * 1024;

describe("readBoundedJsonObject", () => {
	const body = (text: string, status = 503) => new Response(text, { status });

	it("returns a JSON object body", async () => {
		await expect(readBoundedJsonObject(body('{"error":"temporarily_unavailable"}'), BOUND)).resolves.toEqual({
			error: "temporarily_unavailable",
		});
	});

	// The bytes are decoded as UTF-8, which drops a leading BOM — the same
	// reading Response.text() and Response.json() give, which every caller
	// replaced when it started reading through here (#95 F35, F39).
	it("decodes as UTF-8, so a leading BOM does not cost the diagnostic", async () => {
		await expect(readBoundedJsonObject(body('\uFEFF{"error":"invalid_grant"}'), BOUND)).resolves.toEqual({
			error: "invalid_grant",
		});
	});

	it("tolerates a body that is not a JSON object", async () => {
		for (const text of ["", "<html>busy</html>", "[1,2]", "null", '"text"', "{"]) {
			await expect(readBoundedJsonObject(body(text), BOUND), text).resolves.toBeNull();
		}
		await expect(readBoundedJsonObject(new Response(null, { status: 503 }), BOUND)).resolves.toBeNull();
	});

	it("gives up on a body larger than the limit", async () => {
		const json = JSON.stringify({ error: "x", pad: "a".repeat(100) });
		await expect(readBoundedJsonObject(body(json), json.length)).resolves.toEqual({
			error: "x",
			pad: "a".repeat(100),
		});
		await expect(readBoundedJsonObject(body(json), json.length - 1)).resolves.toBeNull();
	});

	it("tolerates a body stream that fails mid-read", async () => {
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode('{"error":'));
				controller.error(new Error("connection reset"));
			},
		});
		await expect(readBoundedJsonObject(new Response(stream, { status: 503 }), BOUND)).resolves.toBeNull();
	});
});

describe("discardBody", () => {
	it("cancels a body nothing has read", async () => {
		let cancelled = false;
		const resp = new Response(
			new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new TextEncoder().encode("x"));
				},
				cancel() {
					cancelled = true;
				},
			}),
		);

		await discardBody(resp);

		expect(cancelled).toBe(true);
		expect(resp.bodyUsed).toBe(true);
	});

	it("resolves when the cancel itself fails, so it cannot replace the caller's answer", async () => {
		const resp = new Response(
			new ReadableStream<Uint8Array>({
				cancel() {
					throw new Error("socket hang up");
				},
			}),
		);

		await expect(discardBody(resp)).resolves.toBeUndefined();
	});

	it("does nothing for a response without a body", async () => {
		await expect(discardBody(new Response(null, { status: 304 }))).resolves.toBeUndefined();
	});
});
