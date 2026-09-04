import { describe, expect, it } from "vitest";
import { type CookieRejectReason, extractCookie } from "../cookie-extractor.mjs";

const absent = { kind: "absent" } as const;
const found = (value: string, skipped: CookieRejectReason | null = null) => ({
	kind: "found",
	value,
	skipped,
});
const rejected = (reason: CookieRejectReason) => ({ kind: "rejected", reason });

describe("extractCookie", () => {
	describe("absent — no pair with the requested name (#73)", () => {
		it("reports absent when the header is undefined", () => {
			expect(extractCookie(undefined, "sid")).toEqual(absent);
		});

		it("reports absent when the header is an empty string", () => {
			expect(extractCookie("", "sid")).toEqual(absent);
		});

		it("reports absent when the target cookie is not in the header", () => {
			expect(extractCookie("analytics=xyz; other=foo", "sid")).toEqual(absent);
		});

		it("is case-sensitive on cookie name (RFC 6265)", () => {
			expect(extractCookie("SID=abc123", "sid")).toEqual(absent);
		});

		it("does not match a name that is a suffix of another cookie name", () => {
			expect(extractCookie("xsid=abc; other=foo", "sid")).toEqual(absent);
		});
	});

	describe("found — a well-formed pair", () => {
		it("extracts a single cookie value", () => {
			expect(extractCookie("sid=abc123", "sid")).toEqual(found("abc123"));
		});

		it("extracts the target cookie from a multi-cookie header", () => {
			expect(extractCookie("analytics=xyz; sid=abc123; other=foo", "sid")).toEqual(
				found("abc123"),
			);
		});

		it("preserves values containing '=' (JWT-like)", () => {
			expect(extractCookie("sid=header.payload.sig==", "sid")).toEqual(
				found("header.payload.sig=="),
			);
		});

		it("tolerates extra whitespace between cookies", () => {
			expect(extractCookie("a=1;  sid=abc123 ; b=2", "sid")).toEqual(found("abc123"));
		});

		it("returns the first matching cookie when a name appears twice", () => {
			expect(extractCookie("sid=first; sid=second", "sid")).toEqual(found("first"));
		});
	});

	// A malformed pair must not abort the scan: user agents may legitimately send
	// two same-name pairs (RFC 6265 section 5.4 orders them by path length and
	// creation time), and a stale or broken duplicate should not blind the proxy
	// to the well-formed one.
	describe("same-name pairs — the first well-formed pair wins (#74)", () => {
		it("skips a malformed first pair and uses the next well-formed one, reporting the skip", () => {
			expect(extractCookie("sid=bad,val; sid=good", "sid")).toEqual(found("good", "grammar"));
		});

		it("skips an empty first pair and uses the next well-formed one", () => {
			expect(extractCookie("sid=; sid=good", "sid")).toEqual(found("good", "empty"));
		});

		it("skips a badly quoted first pair and uses the next well-formed one", () => {
			expect(extractCookie('sid="bad; sid=good', "sid")).toEqual(found("good", "quoting"));
		});

		it("reports the reason of the first skipped pair when several were skipped", () => {
			expect(extractCookie('sid=; sid="bad; sid=good', "sid")).toEqual(found("good", "empty"));
		});

		it("keeps a well-formed first pair even when a later same-name pair is malformed", () => {
			expect(extractCookie("sid=good; sid=bad,val", "sid")).toEqual(found("good"));
		});

		it("rejects with the first pair's reason when every same-name pair is malformed", () => {
			expect(extractCookie('sid=bad,val; sid="x', "sid")).toEqual(rejected("grammar"));
			expect(extractCookie('sid="x; sid=bad,val', "sid")).toEqual(rejected("quoting"));
		});

		it("ignores other cookies between the same-name pairs", () => {
			expect(extractCookie("sid=bad,val; other=foo; sid=good; b=2", "sid")).toEqual(
				found("good", "grammar"),
			);
		});

		it("keeps the OWS-only trimming and verbatim value semantics while scanning (#23)", () => {
			expect(extractCookie("sid= bad;  sid=good ; b=2", "sid")).toEqual(found("good", "grammar"));
			expect(extractCookie("sid=bad,val; sid= good", "sid")).toEqual(rejected("grammar"));
			expect(extractCookie("sid=bad,val; sid=good\u00a0", "sid")).toEqual(rejected("grammar"));
		});
	});

	// A pair with the requested name exists but cannot be forwarded. The result
	// carries only a bounded reason class — never the value bytes — so the router
	// can log it without leaking the cookie (#73).
	describe("rejected — a same-name pair that cannot be forwarded (#73)", () => {
		it("reports reason 'empty' for an empty bare value", () => {
			expect(extractCookie("sid=; other=foo", "sid")).toEqual(rejected("empty"));
		});

		it("reports reason 'empty' for an empty DQUOTE-wrapped value", () => {
			expect(extractCookie('sid=""', "sid")).toEqual(rejected("empty"));
		});

		it("reports reason 'quoting' for a DQUOTE anywhere other than one surrounding pair", () => {
			expect(extractCookie('sid=ab"c', "sid")).toEqual(rejected("quoting"));
			expect(extractCookie('sid="abc', "sid")).toEqual(rejected("quoting"));
			expect(extractCookie('sid=abc"', "sid")).toEqual(rejected("quoting"));
			expect(extractCookie('sid="', "sid")).toEqual(rejected("quoting"));
			expect(extractCookie('sid="a"b"', "sid")).toEqual(rejected("quoting"));
		});

		it("reports reason 'grammar' for a cookie-octet violation, bare or DQUOTE-wrapped", () => {
			expect(extractCookie("sid=abc,def", "sid")).toEqual(rejected("grammar"));
			expect(extractCookie('sid="a,b"', "sid")).toEqual(rejected("grammar"));
			expect(extractCookie('sid="a b"', "sid")).toEqual(rejected("grammar"));
		});

		it("never carries the value bytes in the result", () => {
			const result = extractCookie("sid=secret,bytes", "sid");
			expect(result.kind).toBe("rejected");
			expect(JSON.stringify(result)).not.toContain("secret");
		});
	});

	// RFC 6265 section 4.1.1 cookie-octet grammar (#23). The extracted value is
	// interpolated verbatim into the outbound `Cookie` header of the session
	// grant call, so anything outside the grammar must not be forwarded.
	describe("cookie-octet grammar (#23)", () => {
		describe("rejects values outside the grammar", () => {
			it("never lets ';' into the value — it is the cookie-pair delimiter", () => {
				const result = extractCookie("sid=abc;def", "sid");
				expect(result).toEqual(found("abc"));
				expect(JSON.stringify(result)).not.toContain(";");
			});

			it("rejects a comma inside the value", () => {
				expect(extractCookie("sid=abc,def", "sid")).toEqual(rejected("grammar"));
			});

			it("rejects whitespace inside the value", () => {
				expect(extractCookie("sid=abc def", "sid")).toEqual(rejected("grammar"));
				expect(extractCookie("sid=abc\tdef", "sid")).toEqual(rejected("grammar"));
			});

			it("rejects whitespace immediately after '=' instead of normalising it away", () => {
				expect(extractCookie("sid= abc", "sid")).toEqual(rejected("grammar"));
				expect(extractCookie("sid=\tabc", "sid")).toEqual(rejected("grammar"));
				expect(extractCookie("sid= abc; other=foo", "sid")).toEqual(rejected("grammar"));
			});

			it("treats only SP / HTAB next to the ';' separator or the header ends as slack", () => {
				expect(extractCookie("sid=abc ; other=foo", "sid")).toEqual(found("abc"));
				expect(extractCookie("sid=abc\t", "sid")).toEqual(found("abc"));
				expect(extractCookie("other=foo;\tsid=abc", "sid")).toEqual(found("abc"));
				// A latin-1 NBSP is not OWS: it stays in the value and is refused.
				expect(extractCookie("sid=abc\u00a0; other=foo", "sid")).toEqual(rejected("grammar"));
			});

			it("rejects a DQUOTE inside the value or an unbalanced DQUOTE", () => {
				expect(extractCookie('sid=ab"c', "sid")).toEqual(rejected("quoting"));
				expect(extractCookie('sid="abc', "sid")).toEqual(rejected("quoting"));
				expect(extractCookie('sid=abc"', "sid")).toEqual(rejected("quoting"));
			});

			it("rejects a backslash inside the value", () => {
				expect(extractCookie("sid=abc\\def", "sid")).toEqual(rejected("grammar"));
			});

			it("rejects every control character (0x00-0x1F, 0x7F) inside the value", () => {
				const controls = [...Array.from({ length: 0x20 }, (_, i) => i), 0x7f];
				for (const code of controls) {
					const header = `sid=abc${String.fromCharCode(code)}def`;
					expect(
						extractCookie(header, "sid"),
						`U+${code.toString(16).padStart(4, "0")}`,
					).toEqual(rejected("grammar"));
				}
			});

			it("rejects non-ASCII characters inside the value", () => {
				expect(extractCookie("sid=abcédef", "sid")).toEqual(rejected("grammar"));
				expect(extractCookie("sid=abcĀdef", "sid")).toEqual(rejected("grammar"));
				expect(extractCookie("sid=abc\u{1f512}def", "sid")).toEqual(rejected("grammar"));
			});
		});

		describe("accepts values inside the grammar", () => {
			it("accepts a base64url value", () => {
				expect(extractCookie("sid=Ab9-_xYz0123", "sid")).toEqual(found("Ab9-_xYz0123"));
			});

			it("accepts a hex value", () => {
				expect(extractCookie("sid=deadbeef0123456789", "sid")).toEqual(
					found("deadbeef0123456789"),
				);
			});

			it("accepts a JWT-like dotted value", () => {
				const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
				expect(extractCookie(`sid=${jwt}`, "sid")).toEqual(found(jwt));
			});

			it("accepts an express-session style percent-encoded signed value", () => {
				const signed = "s%3AabcXYZ.Kq%2Fw9%2BZ";
				expect(extractCookie(`sid=${signed}`, "sid")).toEqual(found(signed));
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
				expect(extractCookie(`sid=${all}`, "sid")).toEqual(found(all));
			});
		});

		describe("optional surrounding DQUOTE pair", () => {
			it("accepts a DQUOTE-wrapped value and preserves the quotes", () => {
				expect(extractCookie('sid="abc123"', "sid")).toEqual(found('"abc123"'));
			});

			it("treats an empty DQUOTE-wrapped value as rejected (empty)", () => {
				expect(extractCookie('sid=""', "sid")).toEqual(rejected("empty"));
			});

			it("rejects a DQUOTE-wrapped value whose interior is outside the grammar", () => {
				expect(extractCookie('sid="a,b"', "sid")).toEqual(rejected("grammar"));
				expect(extractCookie('sid="a b"', "sid")).toEqual(rejected("grammar"));
			});
		});
	});
});
