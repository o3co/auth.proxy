// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The two things every token-endpoint call in this directory needs (#95 F19):
 * where the endpoint is, and how a body is read when it may not be JSON at
 * all. Both were exercised only through the clients until now.
 */
import { describe, expect, it } from "vitest";

import { buildTokenUrl, parseJsonBody } from "../token-endpoint.mjs";

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
});
