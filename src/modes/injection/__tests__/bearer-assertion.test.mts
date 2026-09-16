import { describe, expect, it } from "vitest";
import { parseBearerAssertion } from "../bearer-assertion.mjs";

const b64url = (value: unknown): string =>
	Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

const jwt = (
	payload: unknown,
	header: unknown = { alg: "RS256", typ: "JWT" },
	signature = "c2lnbmF0dXJl",
): string => `${b64url(header)}.${b64url(payload)}.${signature}`;

describe("parseBearerAssertion", () => {
	it("extracts the assertion with its unverified iss and exp", () => {
		const assertion = jwt({ iss: "https://idp.example", sub: "u1", exp: 1_900_000_000 });

		expect(parseBearerAssertion(`Bearer ${assertion}`)).toEqual({
			kind: "assertion",
			assertion,
			issuer: "https://idp.example",
			expiresAt: 1_900_000_000,
		});
	});

	// RFC 9110 section 11.1: the auth-scheme is case-insensitive. Loosening it
	// here widens nothing that reaches upstream — the header is replaced by
	// the issued token or the request is refused.
	it("matches the Bearer scheme case-insensitively", () => {
		const assertion = jwt({ iss: "i", exp: 1 });
		expect(parseBearerAssertion(`bearer ${assertion}`)).toMatchObject({ kind: "assertion" });
		expect(parseBearerAssertion(`BEARER ${assertion}`)).toMatchObject({ kind: "assertion" });
	});

	it("reports issuer and expiresAt as null when the claims are absent or of the wrong type", () => {
		expect(parseBearerAssertion(`Bearer ${jwt({ sub: "u1" })}`)).toMatchObject({
			kind: "assertion",
			issuer: null,
			expiresAt: null,
		});
		expect(
			parseBearerAssertion(`Bearer ${jwt({ iss: 42, exp: "1900000000" })}`),
		).toMatchObject({ kind: "assertion", issuer: null, expiresAt: null });
		expect(parseBearerAssertion(`Bearer ${jwt({ iss: "", exp: 1 })}`)).toMatchObject({
			issuer: null,
			expiresAt: 1,
		});
	});

	it("refuses a scheme other than Bearer", () => {
		for (const header of ["", "Basic dXNlcjpwYXNz", "DPoP abc.def.ghi", "Bearerx a.b.c"]) {
			expect(parseBearerAssertion(header), header).toEqual({
				kind: "unsupported",
				reason: "scheme",
			});
		}
	});

	it("refuses a Bearer credential that is not a JWS compact JWT", () => {
		const good = jwt({ iss: "i", exp: 1 });
		const [h, p] = good.split(".");
		const cases = [
			"Bearer",
			"Bearer ",
			"Bearer opaque-token-123",
			`Bearer ${h}.${p}`,
			`Bearer ${good}.extra`,
			`Bearer ${h}.${p}.`,
			`Bearer .${p}.sig`,
			`Bearer ${h}..sig`,
			`Bearer ${good} trailing`,
			`Bearer\t${good}`,
			`Bearer ${h}=.${p}.sig`,
			`Bearer ${h}.${p}.si+g`,
			// a JWE (five segments) is not an assertion this path submits
			`Bearer ${h}.${p}.a.b.c`,
		];
		for (const header of cases) {
			expect(parseBearerAssertion(header), header).toEqual({
				kind: "unsupported",
				reason: "format",
			});
		}
	});

	it("refuses a JWT whose header or payload is not a JSON object", () => {
		const cases = [
			`Bearer ${b64url("not json")}.${b64url({ iss: "i" })}.sig`,
			`Bearer ${b64url({ alg: "RS256" })}.${b64url("not json")}.sig`,
			`Bearer ${b64url({ alg: "RS256" })}.${b64url([1, 2])}.sig`,
			`Bearer ${b64url({ alg: "RS256" })}.${b64url("null")}.sig`,
			`Bearer ${b64url([])}.${b64url({ iss: "i" })}.sig`,
		];
		for (const header of cases) {
			expect(parseBearerAssertion(header), header).toEqual({
				kind: "unsupported",
				reason: "format",
			});
		}
	});

	it("accepts multiple spaces between the scheme and the token (RFC 6750 1*SP)", () => {
		const assertion = jwt({ iss: "i", exp: 1 });
		expect(parseBearerAssertion(`Bearer   ${assertion}`)).toMatchObject({
			kind: "assertion",
			assertion,
		});
	});
});
