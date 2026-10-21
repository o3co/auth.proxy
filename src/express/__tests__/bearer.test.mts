// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Authorization header parsing (`bearer.mts`).
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

	it("admits every b64token character, and trailing `=` padding (RFC 6750 §2.1)", () => {
		const b64 = "ABCXYZabcxyz0189-._~+/";
		expect(extractBearerToken(`Bearer ${b64}`)).toBe(b64);
		expect(extractBearerToken("Bearer abc==")).toBe("abc==");
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

	it("rejects anything but exactly one SP between scheme and token", () => {
		expect(extractBearerToken("Bearer  abc123")).toBeNull();
		expect(extractBearerToken("Bearer\tabc123")).toBeNull();
	});

	// What is introspected must be the whole of what is forwarded: an upstream
	// that reads a header differently must find nothing else in it to read.
	it.each([
		["a second word", "Bearer abc123 extra"],
		["a second token", "Bearer good eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."],
		["trailing whitespace", "Bearer abc123 "],
		["a comma", "Bearer abc,def"],
		["`=` before the end", "Bearer a=b"],
		["padding alone", "Bearer =="],
		["a quote", 'Bearer "abc"'],
		["a line break", "Bearer abc\nx"],
		["a non-ASCII character", "Bearer abcé"],
	])("rejects a token with %s", (_label, header) => {
		expect(extractBearerToken(header)).toBeNull();
	});
});

// Which of extractBearerToken's refusals named Bearer.
describe("namesBearerScheme", () => {
	it.each([
		"Bearer",
		"Bearer ",
		"Bearer  t",
		"Bearer\tt",
		"Bearer t extra",
		"Bearer t ",
		"Bearer a,b",
		"Bearer=abc",
		"Beareré",
	])("is true for the malformed Bearer %j", (header) => {
		expect(namesBearerScheme(header)).toBe(true);
	});

	it.each(["Basic dXNlcjpwYXNz", "bearer t", "BEARER t", "Bearerx t", "Bearer-x t", " Bearer t", ""])(
		"is false for %j, which is another method to this parser",
		(header) => {
			expect(namesBearerScheme(header)).toBe(false);
		},
	);
});
