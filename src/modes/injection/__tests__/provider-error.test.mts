import { describe, expect, it } from "vitest";
import { INVALID_ERROR_CODE, sanitizeErrorCode } from "../provider-error.mjs";

const SECRET = "s3cret-value";
const ASSERTION = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpIn0.c2lnbmF0dXJl";

describe("sanitizeErrorCode", () => {
	const sanitize = (value: unknown) => sanitizeErrorCode(value, [ASSERTION, SECRET]);

	it("keeps an RFC 6749 section 5.2 error code", () => {
		for (const code of [
			"invalid_grant",
			"invalid_client",
			"temporarily_unavailable",
			"urn:example:custom-error",
			"!#$%&'()*+,-/:;<=>?@[]^_`{|}~",
		]) {
			expect(sanitize(code), code).toBe(code);
		}
	});

	it("returns null when the provider sent no error", () => {
		expect(sanitize(undefined)).toBeNull();
	});

	it("replaces a value that is not a string with the placeholder", () => {
		for (const value of [null, 42, true, ["invalid_grant"], { error: "x" }]) {
			expect(sanitize(value), JSON.stringify(value)).toBe(INVALID_ERROR_CODE);
		}
	});

	it("replaces a value outside the error charset with the placeholder", () => {
		// %x20 (space) is in the RFC charset but never in a code; whitespace of
		// any kind, DQUOTE, backslash, control characters and non-ASCII are out.
		for (const value of [
			"",
			"invalid grant",
			"invalid_grant\n",
			"\tinvalid_grant",
			'invalid"grant',
			"invalid\\grant",
			"invalid\u0000grant",
			"invalid_grànt",
		]) {
			expect(sanitize(value), JSON.stringify(value)).toBe(INVALID_ERROR_CODE);
		}
	});

	it("bounds the length at 64", () => {
		expect(sanitize("a".repeat(64))).toBe("a".repeat(64));
		expect(sanitize("a".repeat(65))).toBe(INVALID_ERROR_CODE);
	});

	it("replaces anything shaped like a JWT", () => {
		for (const value of ["aaa.bbb.ccc", "eyJhbGciOi.eyJzdWIi.sig", "x.y.", "prefix:aa.bb.cc"]) {
			expect(sanitize(value), value).toBe(INVALID_ERROR_CODE);
		}
	});

	it("replaces a value that echoes a credential it was given", () => {
		expect(sanitize(SECRET)).toBe(INVALID_ERROR_CODE);
		expect(sanitize(`bad_${SECRET}`)).toBe(INVALID_ERROR_CODE);
		expect(sanitize(ASSERTION)).toBe(INVALID_ERROR_CODE);
	});

	it("ignores empty credentials rather than refusing every code", () => {
		expect(sanitizeErrorCode("invalid_grant", ["", SECRET])).toBe("invalid_grant");
	});
});
