import { describe, expect, it } from "vitest";
import { extractCookie } from "../cookie-extractor.mjs";

describe("extractCookie", () => {
	it("returns null when header is undefined", () => {
		expect(extractCookie(undefined, "sid")).toBeNull();
	});

	it("returns null when header is empty string", () => {
		expect(extractCookie("", "sid")).toBeNull();
	});

	it("extracts a single cookie value", () => {
		expect(extractCookie("sid=abc123", "sid")).toBe("abc123");
	});

	it("extracts the target cookie from a multi-cookie header", () => {
		expect(extractCookie("analytics=xyz; sid=abc123; other=foo", "sid")).toBe("abc123");
	});

	it("returns null when the target cookie is absent", () => {
		expect(extractCookie("analytics=xyz; other=foo", "sid")).toBeNull();
	});

	it("returns null when the target cookie value is empty", () => {
		expect(extractCookie("sid=; other=foo", "sid")).toBeNull();
	});

	it("preserves values containing '=' (JWT-like)", () => {
		expect(extractCookie("sid=header.payload.sig==", "sid")).toBe("header.payload.sig==");
	});

	it("is case-sensitive on cookie name (RFC 6265)", () => {
		expect(extractCookie("SID=abc123", "sid")).toBeNull();
	});

	it("tolerates extra whitespace between cookies", () => {
		expect(extractCookie("a=1;  sid=abc123 ; b=2", "sid")).toBe("abc123");
	});

	it("does not match a name that is a suffix of another cookie name", () => {
		expect(extractCookie("xsid=abc; other=foo", "sid")).toBeNull();
	});

	it("returns the first matching cookie when a name appears twice", () => {
		expect(extractCookie("sid=first; sid=second", "sid")).toBe("first");
	});
});
