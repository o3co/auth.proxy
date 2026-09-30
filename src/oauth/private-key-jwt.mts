/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Client authentication at the provider by `private_key_jwt` (RFC 7523
 * section 2.2): the configured key, read from a private JWK, and the client
 * assertion signed with it for one call.
 */

import { createPrivateKey, type JsonWebKeyInput, type KeyObject, randomUUID } from "node:crypto";
import { type JWTHeaderParameters, SignJWT } from "jose";

/** RFC 7523 section 2.2. */
export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * How long an assertion lives. The provider records each `jti` until the
 * assertion expires, and one is signed per call, so a short life keeps that
 * record small; a minute leaves room for a proxy clock that runs behind.
 */
export const CLIENT_ASSERTION_LIFETIME_SECONDS = 60;

export type ClientAssertionAlgorithm =
	| "EdDSA"
	| "ES256"
	| "ES384"
	| "ES512"
	| "RS256"
	| "RS384"
	| "RS512"
	| "PS256"
	| "PS384"
	| "PS512";

const RSA_ALGORITHMS: readonly ClientAssertionAlgorithm[] = [
	"RS256",
	"RS384",
	"RS512",
	"PS256",
	"PS384",
	"PS512",
];

/**
 * The algorithms a key of each type and curve may sign with, the first being
 * the one used when the JWK names none. Every one is asymmetric and among
 * those the provider verifies a client assertion with; a curve with none
 * here (X25519, secp256k1) is refused.
 */
const algorithmsFor = (kty: unknown, crv: unknown): readonly ClientAssertionAlgorithm[] => {
	if (kty === "OKP" && crv === "Ed25519") return ["EdDSA"];
	if (kty === "EC" && crv === "P-256") return ["ES256"];
	if (kty === "EC" && crv === "P-384") return ["ES384"];
	if (kty === "EC" && crv === "P-521") return ["ES512"];
	if (kty === "RSA") return RSA_ALGORITHMS;
	return [];
};

/** Below this, `jose` refuses to sign with an RSA key. */
const MIN_RSA_MODULUS_BITS = 2048;

/** The key the proxy signs its client assertions with. */
export interface ClientKey {
	readonly key: KeyObject;
	readonly alg: ClientAssertionAlgorithm;
	/** The JWK's `kid`, sent in the assertion's header so the provider picks the key. */
	readonly kid: string | null;
}

/** A configured client key that cannot sign. Its message never quotes the key. */
export class ClientKeyError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ClientKeyError";
	}
}

/**
 * Reads a client key from a private JWK, given as an object or as its JSON
 * text (the form an environment variable carries). The key must be one the
 * provider can verify an assertion from: an Ed25519, EC P-256/P-384/P-521 or
 * RSA (2048 bits or more) private key. The JWK's `alg`, when present, must fit
 * the key; its `kid`, when present, goes in every assertion's header.
 *
 * @throws {ClientKeyError} naming what is wrong, never quoting the key.
 */
export const parseClientKey = (value: unknown): ClientKey => {
	let jwk: unknown = value;
	if (typeof value === "string") {
		try {
			jwk = JSON.parse(value);
		} catch {
			throw new ClientKeyError("the client key is not JSON; expected a private JWK");
		}
	}
	if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
		throw new ClientKeyError("the client key is not a JWK object");
	}
	const { kty, crv, alg, kid, d } = jwk as Record<string, unknown>;

	const algorithms = algorithmsFor(kty, crv);
	if (algorithms.length === 0) {
		throw new ClientKeyError(
			"the client key is not an Ed25519, EC P-256/P-384/P-521 or RSA key, so it cannot sign an assertion the provider verifies",
		);
	}
	if (typeof d !== "string" || d.length === 0) {
		throw new ClientKeyError(
			"the client key has no private part (d): the proxy signs with the private key; the provider holds the public one",
		);
	}
	if (alg !== undefined && !algorithms.includes(alg as ClientAssertionAlgorithm)) {
		throw new ClientKeyError(
			`the client key's alg does not fit the key; for this key use one of ${algorithms.join(", ")}`,
		);
	}
	if (kid !== undefined && (typeof kid !== "string" || kid.length === 0)) {
		throw new ClientKeyError("the client key's kid must be a non-empty string");
	}

	let key: KeyObject;
	try {
		key = createPrivateKey({ key: jwk, format: "jwk" } as JsonWebKeyInput);
	} catch {
		throw new ClientKeyError("the client key's material does not form a private key");
	}
	const modulusLength = key.asymmetricKeyDetails?.modulusLength;
	if (kty === "RSA" && (modulusLength === undefined || modulusLength < MIN_RSA_MODULUS_BITS)) {
		throw new ClientKeyError(`the client key is an RSA key shorter than ${MIN_RSA_MODULUS_BITS} bits`);
	}

	return {
		key,
		alg: (alg as ClientAssertionAlgorithm | undefined) ?? algorithms[0],
		kid: (kid as string | undefined) ?? null,
	};
};

export interface ClientAssertionParams {
	clientId: string;
	/** The provider's issuer identifier: the assertion's only audience. */
	audience: string;
	key: ClientKey;
}

/**
 * Signs one client assertion: `iss` and `sub` the client, `aud` the issuer, a
 * random `jti`, and `exp` {@link CLIENT_ASSERTION_LIFETIME_SECONDS} after
 * `iat`. The provider accepts each `jti` once, so a call signs its own and
 * never reuses one.
 */
export const signClientAssertion = async (
	{ clientId, audience, key }: ClientAssertionParams,
	now: number = Date.now(),
): Promise<string> => {
	const iat = Math.floor(now / 1000);
	const header: JWTHeaderParameters = { alg: key.alg };
	if (key.kid !== null) header.kid = key.kid;
	return new SignJWT({})
		.setProtectedHeader(header)
		.setIssuer(clientId)
		.setSubject(clientId)
		.setAudience(audience)
		.setJti(randomUUID())
		.setIssuedAt(iat)
		.setExpirationTime(iat + CLIENT_ASSERTION_LIFETIME_SECONDS)
		.sign(key.key);
};
