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

	// RFC 6265 section 4.1.1 cookie-octet grammar (#23). The extracted value is
	// interpolated verbatim into the outbound `Cookie` header of the session
	// grant call, so anything outside the grammar must be treated as missing.
	describe("cookie-octet grammar (#23)", () => {
		describe("rejects values outside the grammar", () => {
			it("never lets ';' into the value — it is the cookie-pair delimiter", () => {
				const value = extractCookie("sid=abc;def", "sid");
				expect(value).toBe("abc");
				expect(value).not.toContain(";");
			});

			it("rejects a comma inside the value", () => {
				expect(extractCookie("sid=abc,def", "sid")).toBeNull();
			});

			it("rejects whitespace inside the value", () => {
				expect(extractCookie("sid=abc def", "sid")).toBeNull();
				expect(extractCookie("sid=abc\tdef", "sid")).toBeNull();
			});

			it("rejects a DQUOTE inside the value or an unbalanced DQUOTE", () => {
				expect(extractCookie('sid=ab"c', "sid")).toBeNull();
				expect(extractCookie('sid="abc', "sid")).toBeNull();
				expect(extractCookie('sid=abc"', "sid")).toBeNull();
			});

			it("rejects a backslash inside the value", () => {
				expect(extractCookie("sid=abc\\def", "sid")).toBeNull();
			});

			it("rejects every control character (0x00-0x1F, 0x7F) inside the value", () => {
				const controls = [...Array.from({ length: 0x20 }, (_, i) => i), 0x7f];
				for (const code of controls) {
					const header = `sid=abc${String.fromCharCode(code)}def`;
					expect(extractCookie(header, "sid"), `U+${code.toString(16).padStart(4, "0")}`).toBeNull();
				}
			});

			it("rejects non-ASCII characters inside the value", () => {
				expect(extractCookie("sid=abcédef", "sid")).toBeNull();
				expect(extractCookie("sid=abcĀdef", "sid")).toBeNull();
				expect(extractCookie("sid=abc\u{1f512}def", "sid")).toBeNull();
			});
		});

		describe("accepts values inside the grammar", () => {
			it("accepts a base64url value", () => {
				expect(extractCookie("sid=Ab9-_xYz0123", "sid")).toBe("Ab9-_xYz0123");
			});

			it("accepts a hex value", () => {
				expect(extractCookie("sid=deadbeef0123456789", "sid")).toBe("deadbeef0123456789");
			});

			it("accepts a JWT-like dotted value", () => {
				const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
				expect(extractCookie(`sid=${jwt}`, "sid")).toBe(jwt);
			});

			it("accepts an express-session style percent-encoded signed value", () => {
				const signed = "s%3AabcXYZ.Kq%2Fw9%2BZ";
				expect(extractCookie(`sid=${signed}`, "sid")).toBe(signed);
			});

			it("accepts every cookie-octet (%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E)", () => {
				const ranges: [number, number][] = [
					[0x21, 0x21],
					[0x23, 0x2b],
					[0x2d, 0x3a],
					[0x3c, 0x5b],
					[0x5d, 0x7e],
				];
				const all = ranges
					.flatMap(([lo, hi]) => Array.from({ length: hi - lo + 1 }, (_, i) => lo + i))
					.map((code) => String.fromCharCode(code))
					.join("");
				expect(extractCookie(`sid=${all}`, "sid")).toBe(all);
			});
		});

		describe("optional surrounding DQUOTE pair", () => {
			it("accepts a DQUOTE-wrapped value and preserves the quotes", () => {
				expect(extractCookie('sid="abc123"', "sid")).toBe('"abc123"');
			});

			it("treats an empty DQUOTE-wrapped value as missing", () => {
				expect(extractCookie('sid=""', "sid")).toBeNull();
			});

			it("rejects a DQUOTE-wrapped value whose interior is outside the grammar", () => {
				expect(extractCookie('sid="a,b"', "sid")).toBeNull();
				expect(extractCookie('sid="a b"', "sid")).toBeNull();
			});
		});
	});
});
