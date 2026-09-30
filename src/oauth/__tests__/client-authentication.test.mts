import { generateKeyPairSync } from "node:crypto";
import { jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { authenticateClient } from "../client-authentication.mjs";
import { clientSecretBasic } from "../client-secret-basic.mjs";
import { CLIENT_ASSERTION_TYPE, parseClientKey } from "../private-key-jwt.mjs";

const ISSUER = "https://auth.example.test";

describe("authenticateClient", () => {
	it("authenticates a client secret with the Basic header and nothing in the body", async () => {
		const call = await authenticateClient({ clientId: "proxy", clientSecret: "s3cret" });

		expect(call).toEqual({
			authorization: clientSecretBasic({ clientId: "proxy", clientSecret: "s3cret" }),
			params: {},
			credential: "s3cret",
		});
	});

	it("authenticates a client key with an assertion in the body and no Authorization header", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const clientKey = parseClientKey(privateKey.export({ format: "jwk" }));

		const call = await authenticateClient({ clientId: "proxy", clientKey, audience: ISSUER });

		expect(call.authorization).toBeNull();
		expect(Object.keys(call.params).sort()).toEqual([
			"client_assertion",
			"client_assertion_type",
			"client_id",
		]);
		expect(call.params.client_id).toBe("proxy");
		expect(call.params.client_assertion_type).toBe(CLIENT_ASSERTION_TYPE);
		expect(call.credential).toBe(call.params.client_assertion);
		await expect(
			jwtVerify(call.params.client_assertion, publicKey, {
				issuer: "proxy",
				subject: "proxy",
				audience: ISSUER,
			}),
		).resolves.toBeDefined();
	});

	it("authenticates with the secret when a secret-credentials object also carries clientKey: null", async () => {
		const secret = { clientId: "proxy", clientSecret: "s3cret", clientKey: null };

		const call = await authenticateClient(secret as unknown as Parameters<typeof authenticateClient>[0]);

		expect(call.authorization).toBe(clientSecretBasic({ clientId: "proxy", clientSecret: "s3cret" }));
		expect(call.params).toEqual({});
	});

	it("signs a new assertion for every call", async () => {
		const clientKey = parseClientKey(
			generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }),
		);
		const auth = { clientId: "proxy", clientKey, audience: ISSUER };

		const [first, second] = await Promise.all([authenticateClient(auth), authenticateClient(auth)]);

		expect(first.params.client_assertion).not.toBe(second.params.client_assertion);
	});
});
