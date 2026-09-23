import { describe, expect, it } from "vitest";
import {
	INVALID_ERROR_CODE,
	readBoundedJsonObject,
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

describe("readBoundedJsonObject", () => {
	const body = (text: string, status = 503) => new Response(text, { status });

	it("returns a JSON object body", async () => {
		await expect(readBoundedJsonObject(body('{"error":"temporarily_unavailable"}'))).resolves.toEqual({
			error: "temporarily_unavailable",
		});
	});

	// The bytes are decoded as UTF-8, which drops a leading BOM — the same
	// reading Response.text() gives, and what the success path needs since it
	// reads through this too (#95 F35).
	it("decodes as UTF-8, so a leading BOM does not cost the diagnostic", async () => {
		await expect(readBoundedJsonObject(body('\uFEFF{"error":"invalid_grant"}'))).resolves.toEqual({
			error: "invalid_grant",
		});
	});

	it("tolerates a body that is not a JSON object", async () => {
		for (const text of ["", "<html>busy</html>", "[1,2]", "null", '"text"', "{"]) {
			await expect(readBoundedJsonObject(body(text)), text).resolves.toBeNull();
		}
		await expect(readBoundedJsonObject(new Response(null, { status: 503 }))).resolves.toBeNull();
	});

	it("gives up on a body larger than the limit", async () => {
		const json = JSON.stringify({ error: "x", pad: "a".repeat(100) });
		await expect(readBoundedJsonObject(body(json), json.length)).resolves.toEqual({
			error: "x",
			pad: "a".repeat(100),
		});
		await expect(readBoundedJsonObject(body(json), json.length - 1)).resolves.toBeNull();
	});

	it("bounds the default read at 16 KiB", async () => {
		const json = JSON.stringify({ error: "x", pad: "a".repeat(16 * 1024) });
		await expect(readBoundedJsonObject(body(json))).resolves.toBeNull();
	});

	it("tolerates a body stream that fails mid-read", async () => {
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode('{"error":'));
				controller.error(new Error("connection reset"));
			},
		});
		await expect(readBoundedJsonObject(new Response(stream, { status: 503 }))).resolves.toBeNull();
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
	// A substring test on a very short value would refuse ordinary text for
	// no gain; below 8 characters only an exact echo is refused.
	it("refuses an exact echo of a short credential but not text that merely contains it", () => {
		expect(sanitizeErrorCode("abc", ["abc"])).toBe(INVALID_ERROR_CODE);
		expect(sanitizeErrorCode("invalid_scope", ["c"])).toBe("invalid_scope");
		expect(sanitizeErrorDescription("c", ["c"])).toBeNull();
		expect(sanitizeErrorDescription("unknown scope", ["c"])).toBe("unknown scope");
	});

	it("refuses text containing a credential of 8 characters or more", () => {
		expect(sanitizeErrorCode("x_12345678_x", ["12345678"])).toBe(INVALID_ERROR_CODE);
		expect(sanitizeErrorDescription("bad 12345678 here", ["12345678"])).toBeNull();
	});
});
