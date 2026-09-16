import { describe, expect, it } from "vitest";
import { clientSecretBasic } from "../client-secret-basic.mjs";

const decode = (header: string): string =>
	Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");

describe("clientSecretBasic", () => {
	it("builds a Basic header from client_id and client_secret", () => {
		expect(clientSecretBasic({ clientId: "my-proxy", clientSecret: "s3cret" })).toBe(
			`Basic ${Buffer.from("my-proxy:s3cret").toString("base64")}`,
		);
	});

	// RFC 6749 section 2.3.1: each half is form-urlencoded before the two are
	// joined with ":", so a ":" inside either half cannot re-split the pair.
	it("percent-encodes both halves before joining them", () => {
		const decoded = decode(
			clientSecretBasic({ clientId: "https://proxy.example/x", clientSecret: "a:b" }),
		);

		expect(decoded).toBe("https%3A%2F%2Fproxy.example%2Fx:a%3Ab");
		expect(decoded.split(":")).toHaveLength(2);
	});

	it("round-trips reserved characters through a form-urlencoded decoder", () => {
		const clientId = "cl ient+id%20&x=1";
		const clientSecret = "s3:cret/with?reserved#chars";
		const [encodedId, encodedSecret] = decode(clientSecretBasic({ clientId, clientSecret })).split(
			":",
		);
		const formUrlDecode = (v: string): string => decodeURIComponent(v.replace(/\+/g, " "));

		expect(formUrlDecode(encodedId)).toBe(clientId);
		expect(formUrlDecode(encodedSecret)).toBe(clientSecret);
	});
});
