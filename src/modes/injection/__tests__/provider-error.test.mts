import { describe, expect, it } from "vitest";
import {
	INVALID_ERROR_CODE,
	MAX_ERROR_BODY_BYTES,
	sanitizeErrorCode,
	sanitizeErrorDescription,
} from "../provider-error.mjs";

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

describe("sanitizeErrorDescription", () => {
	const sanitize = (value: unknown) => sanitizeErrorDescription(value, [ASSERTION, SECRET]);

	it("keeps an RFC 6749 section 5.2 error_description, spaces included", () => {
		for (const text of ["unknown scope", "client is not authorized for grant_type session"]) {
			expect(sanitize(text), text).toBe(text);
		}
	});

	it("returns null for an absent, non-string or empty value", () => {
		for (const value of [undefined, null, 42, ""]) {
			expect(sanitize(value), String(value)).toBeNull();
		}
	});

	it("returns null for a value outside the charset", () => {
		for (const value of ["line\nbreak", "tab\there", 'quote"d', "back\\slash", "ünïcode"]) {
			expect(sanitize(value), JSON.stringify(value)).toBeNull();
		}
	});

	it("bounds the length at 256", () => {
		expect(sanitize("a".repeat(256))).toBe("a".repeat(256));
		expect(sanitize("a".repeat(257))).toBeNull();
	});

	it("returns null for a value carrying a JWT or a credential", () => {
		expect(sanitize("token aaa.bbb.ccc was refused")).toBeNull();
		expect(sanitize(`session ${SECRET} is invalid`)).toBeNull();
		expect(sanitize(ASSERTION)).toBeNull();
	});
});

describe("credential matching", () => {
	it("refuses text containing a credential of 8 characters or more", () => {
		expect(sanitizeErrorCode("x_12345678_x", ["12345678"])).toBe(INVALID_ERROR_CODE);
		expect(sanitizeErrorDescription("bad 12345678 here", ["12345678"])).toBe(null);
	});

	// Until #95 F30 a credential shorter than 8 characters was matched exactly
	// and not as a substring, so `bad abc` reached a log line and a relayed
	// error_description with the cookie value `abc` inside it. Length is not
	// something the proxy can bound for a value the caller chose, and losing a
	// provider's diagnostic costs less than putting a credential in a log.
	it.each([1, 2, 3, 7])(
		"refuses text containing a credential of %d characters, not only an exact echo",
		(length) => {
			const credential = "c".repeat(length);

			expect(sanitizeErrorCode(`x_${credential}_x`, [credential])).toBe(INVALID_ERROR_CODE);
			expect(sanitizeErrorDescription(`bad ${credential} here`, [credential])).toBe(null);
		},
	);

	it("still refuses an exact echo, at any length", () => {
		expect(sanitizeErrorCode("abc", ["abc"])).toBe(INVALID_ERROR_CODE);
		expect(sanitizeErrorDescription("c", ["c"])).toBe(null);
	});

	// The cost of the change, stated rather than discovered: a one-character
	// credential refuses almost any text. The caller substitutes its own
	// wording for a refusal, so what is lost is the provider's diagnostic and
	// never the answer — `sanitizeErrorCode` classifies the raw value before
	// this runs.
	it("refuses ordinary text that happens to contain a very short credential", () => {
		expect(sanitizeErrorCode("invalid_scope", ["c"])).toBe(INVALID_ERROR_CODE);
		expect(sanitizeErrorDescription("unknown scope", ["c"])).toBe(null);
	});

	// An empty credential is in no text and in every text; it must not be read
	// as being in every text.
	it("ignores an empty credential rather than refusing everything", () => {
		expect(sanitizeErrorCode("invalid_scope", [""])).toBe("invalid_scope");
		expect(sanitizeErrorDescription("unknown scope", [""])).toBe("unknown scope");
	});
});

// The error path's bound, now that the reader it is passed to lives in
// src/response-body.mts and has no default of its own (#95 F39).
describe("MAX_ERROR_BODY_BYTES", () => {
	it("is 16 KiB", () => {
		expect(MAX_ERROR_BODY_BYTES).toBe(16 * 1024);
	});
});
