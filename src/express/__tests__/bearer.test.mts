// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Authorization header parsing, moved in from `@o3co/auth.utils/express`.
 *
 * The proxy decides from this whether a request carries a credential at all,
 * so the grammar it accepts is part of the proxy's own contract and belongs
 * where its tests can pin it.
 */
import { describe, expect, it } from "vitest";
import { extractBearerToken, namesBearerScheme } from "../bearer.mjs";

describe("extractBearerToken", () => {
	it("extracts the token from a well-formed header", () => {
		expect(extractBearerToken("Bearer abc123")).toBe("abc123");
	});

	it("returns null when the header is absent", () => {
		expect(extractBearerToken(undefined)).toBeNull();
	});

	it("returns null for an empty header", () => {
		expect(extractBearerToken("")).toBeNull();
	});

	it("is case-sensitive on the scheme (RFC 6750 spells it `Bearer`)", () => {
		expect(extractBearerToken("bearer abc123")).toBeNull();
		expect(extractBearerToken("BEARER abc123")).toBeNull();
	});

	it("rejects a different scheme", () => {
		expect(extractBearerToken("Basic abc123")).toBeNull();
	});

	it("rejects a scheme with no token", () => {
		expect(extractBearerToken("Bearer")).toBeNull();
		expect(extractBearerToken("Bearer ")).toBeNull();
	});

	it("rejects a double space, which leaves an empty token", () => {
		expect(extractBearerToken("Bearer  abc123")).toBeNull();
	});

	it("keeps only the first token when the header carries trailing content", () => {
		expect(extractBearerToken("Bearer abc123 extra")).toBe("abc123");
	});
});

// #95 F45: which of extractBearerToken's refusals named Bearer.
describe("namesBearerScheme", () => {
	it.each(["Bearer", "Bearer ", "Bearer  t"])("is true for the malformed Bearer %j", (header) => {
		expect(namesBearerScheme(header)).toBe(true);
	});

	it.each(["Basic dXNlcjpwYXNz", "bearer t", "BEARER t", "Bearerx t"])(
		"is false for %j, which is another method to this parser",
		(header) => {
			expect(namesBearerScheme(header)).toBe(false);
		},
	);
});
