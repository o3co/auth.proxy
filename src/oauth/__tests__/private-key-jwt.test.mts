import { createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import {
	CLIENT_ASSERTION_LIFETIME_SECONDS,
	CLIENT_ASSERTION_TYPE,
	ClientKeyError,
	parseClientKey,
	signClientAssertion,
} from "../private-key-jwt.mjs";

type PrivateJwk = Record<string, unknown> & { d?: string };

const ed25519 = (): { jwk: PrivateJwk; publicKey: KeyObject } => {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return { jwk: privateKey.export({ format: "jwk" }) as PrivateJwk, publicKey };
};

const ec = (namedCurve: string): { jwk: PrivateJwk; publicKey: KeyObject } => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve });
	return { jwk: privateKey.export({ format: "jwk" }) as PrivateJwk, publicKey };
};

const rsa = (): { jwk: PrivateJwk; publicKey: KeyObject } => {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	return { jwk: privateKey.export({ format: "jwk" }) as PrivateJwk, publicKey };
};

const CLIENT_ID = "proxy-client";
const ISSUER = "https://auth.example.test";

describe("CLIENT_ASSERTION_TYPE", () => {
	it("is RFC 7523 section 2.2's client assertion type", () => {
		expect(CLIENT_ASSERTION_TYPE).toBe("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
	});
});

describe("parseClientKey", () => {
	it.each([
		["an Ed25519 key", () => ed25519(), "EdDSA"],
		["an EC P-256 key", () => ec("P-256"), "ES256"],
		["an EC P-384 key", () => ec("P-384"), "ES384"],
		["an EC P-521 key", () => ec("P-521"), "ES512"],
		["an RSA key", () => rsa(), "RS256"],
	])("reads %s and signs with %s", (_label, make, alg) => {
		expect(parseClientKey(make().jwk).alg).toBe(alg);
	});

	it("takes the algorithm the JWK names when it fits the key", () => {
		expect(parseClientKey({ ...rsa().jwk, alg: "PS256" }).alg).toBe("PS256");
	});

	it("carries the JWK's kid, and null when it has none", () => {
		expect(parseClientKey({ ...ed25519().jwk, kid: "proxy-2026-09" }).kid).toBe("proxy-2026-09");
		expect(parseClientKey(ed25519().jwk).kid).toBeNull();
	});

	it("reads the JWK from a JSON string, as the environment supplies it", () => {
		const { jwk } = ed25519();
		expect(parseClientKey(JSON.stringify({ ...jwk, kid: "k1" }))).toMatchObject({
			alg: "EdDSA",
			kid: "k1",
		});
	});

	it.each([
		["a string that is not JSON", () => "not json"],
		["JSON that is not an object", () => "[1,2]"],
		["a public key, with no private member", () => {
			const { d: _d, ...publicJwk } = ed25519().jwk;
			return publicJwk;
		}],
		["a symmetric key", () => ({ kty: "oct", k: "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0" })],
		["an X25519 key, which cannot sign", () =>
			generateKeyPairSync("x25519").privateKey.export({ format: "jwk" })],
		["an EC key on a curve the provider does not verify", () => ({ ...ec("P-256").jwk, crv: "secp256k1" })],
		["an algorithm that does not fit the key", () => ({ ...ec("P-256").jwk, alg: "EdDSA" })],
		["a symmetric algorithm", () => ({ ...rsa().jwk, alg: "HS256" })],
		["an empty kid", () => ({ ...ed25519().jwk, kid: "" })],
		["key material that does not form a key", () => ({ ...ed25519().jwk, x: "AAAA" })],
	])("refuses %s", (_label, make) => {
		expect(() => parseClientKey(make())).toThrow(ClientKeyError);
	});

	it("never quotes the key it refuses", () => {
		const { jwk } = ed25519();
		const refused = JSON.stringify({ ...jwk, alg: "HS256" });
		let message = "";
		try {
			parseClientKey(refused);
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).not.toBe("");
		expect(message).not.toContain(jwk.d as string);
		expect(message).not.toContain(refused);
	});
});

describe("signClientAssertion", () => {
	it("signs an assertion the provider's checks accept: iss and sub the client, aud the issuer", async () => {
		const { jwk, publicKey } = ed25519();
		const assertion = await signClientAssertion({
			clientId: CLIENT_ID,
			audience: ISSUER,
			key: parseClientKey({ ...jwk, kid: "proxy-2026-09" }),
		});

		const { payload, protectedHeader } = await jwtVerify(assertion, publicKey, {
			issuer: CLIENT_ID,
			subject: CLIENT_ID,
			audience: ISSUER,
			algorithms: ["EdDSA"],
		});
		expect(protectedHeader).toMatchObject({ alg: "EdDSA", kid: "proxy-2026-09" });
		expect(payload.aud).toBe(ISSUER);
		expect(typeof payload.jti).toBe("string");
		expect((payload.jti as string).length).toBeGreaterThan(0);
	});

	it("puts no kid in the header when the key has none", async () => {
		const assertion = await signClientAssertion({
			clientId: CLIENT_ID,
			audience: ISSUER,
			key: parseClientKey(ed25519().jwk),
		});
		expect(decodeProtectedHeader(assertion).kid).toBeUndefined();
	});

	it("lives CLIENT_ASSERTION_LIFETIME_SECONDS from the time it is signed", async () => {
		const { jwk, publicKey } = ec("P-256");
		const now = Date.UTC(2026, 8, 30, 12, 0, 0);
		const assertion = await signClientAssertion(
			{ clientId: CLIENT_ID, audience: ISSUER, key: parseClientKey(jwk) },
			now,
		);
		const { payload } = await jwtVerify(assertion, publicKey, {
			currentDate: new Date(now),
			algorithms: ["ES256"],
		});
		expect(CLIENT_ASSERTION_LIFETIME_SECONDS).toBe(60);
		expect(payload.iat).toBe(now / 1000);
		expect(payload.exp).toBe(now / 1000 + CLIENT_ASSERTION_LIFETIME_SECONDS);
	});

	it("gives every assertion its own jti", async () => {
		const key = parseClientKey(ed25519().jwk);
		const sign = () => signClientAssertion({ clientId: CLIENT_ID, audience: ISSUER, key });
		const jtis = await Promise.all(
			Array.from({ length: 5 }, async () => {
				const { payload } = await jwtVerify(await sign(), createPublicKey(key.key));
				return payload.jti;
			}),
		);
		expect(new Set(jtis).size).toBe(5);
	});

	it.each([
		["RSA with RS256", () => rsa(), undefined, "RS256"],
		["RSA with PS256", () => rsa(), "PS256", "PS256"],
		["EC P-521", () => ec("P-521"), undefined, "ES512"],
	])("signs with %s so the public key verifies it", async (_label, make, alg, expected) => {
		const { jwk, publicKey } = make();
		const assertion = await signClientAssertion({
			clientId: CLIENT_ID,
			audience: ISSUER,
			key: parseClientKey(alg === undefined ? jwk : { ...jwk, alg }),
		});
		const { protectedHeader } = await jwtVerify(assertion, publicKey, { algorithms: [expected] });
		expect(protectedHeader.alg).toBe(expected);
	});
});
