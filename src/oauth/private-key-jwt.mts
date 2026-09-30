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

import {
	constants,
	createHash,
	createPrivateKey,
	createPublicKey,
	type JsonWebKeyInput,
	type KeyObject,
	randomUUID,
	sign,
} from "node:crypto";

/** RFC 7523 section 2.2. */
export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * The assertion's explicit type (RFC 8725 section 3.11), so it cannot be taken
 * for another kind of JWT signed with the same key. The provider's client
 * assertion check reads no `typ`, so any value is accepted there.
 */
export const CLIENT_ASSERTION_JWT_TYPE = "client-authentication+jwt";

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
 * here (X25519, Ed448, secp256k1) is refused.
 */
const algorithmsFor = (kty: unknown, crv: unknown): readonly ClientAssertionAlgorithm[] => {
	if (kty === "OKP" && crv === "Ed25519") return ["EdDSA"];
	if (kty === "EC" && crv === "P-256") return ["ES256"];
	if (kty === "EC" && crv === "P-384") return ["ES384"];
	if (kty === "EC" && crv === "P-521") return ["ES512"];
	if (kty === "RSA") return RSA_ALGORITHMS;
	return [];
};

/**
 * RFC 9864's fully specified name for an Ed25519 signature: the same
 * signature as `EdDSA` on an Ed25519 key, which is the name the provider
 * verifies.
 */
const ED25519_ALIAS = "Ed25519";

/** Below this, an RSA signature is not one a JOSE verifier accepts. */
const MIN_RSA_MODULUS_BITS = 2048;

/** The key the proxy signs its client assertions with. */
export interface ClientKey {
	readonly key: KeyObject;
	readonly alg: ClientAssertionAlgorithm;
	/** The JWK's `kid`, sent in the assertion's header so the provider picks the key. */
	readonly kid: string | null;
	/** The RFC 7638 thumbprint of the public key: names the key without revealing it. */
	readonly thumbprint: string;
}

/** A configured client key that cannot sign. Its message never quotes the key. */
export class ClientKeyError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ClientKeyError";
	}
}

/** RFC 7638: the required members of the public key, sorted, hashed. */
const thumbprintOf = (key: KeyObject): string => {
	const jwk = createPublicKey(key).export({ format: "jwk" }) as Record<string, string>;
	const members: Record<string, readonly string[]> = {
		OKP: ["crv", "kty", "x"],
		EC: ["crv", "kty", "x", "y"],
		RSA: ["e", "kty", "n"],
	};
	const required = members[jwk.kty] ?? [];
	const canonical = `{${required.map((name) => `${JSON.stringify(name)}:${JSON.stringify(jwk[name])}`).join(",")}}`;
	return createHash("sha256").update(canonical).digest("base64url");
};

/**
 * Reads a client key from a private JWK, given as an object or as its JSON
 * text (the form an environment variable carries). The key must be one the
 * provider can verify an assertion from: an Ed25519, EC P-256/P-384/P-521 or
 * RSA (2048 bits or more) private key, not marked for another use than
 * signing (`use`, `key_ops`). The JWK's `alg`, when present, must fit the
 * key; its `kid`, when present, goes in every assertion's header.
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
	const { kty, crv, alg, kid, d, use } = jwk as Record<string, unknown>;
	const keyOps = (jwk as Record<string, unknown>).key_ops;

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
	if (use !== undefined && use !== "sig") {
		throw new ClientKeyError('the client key is marked for another use than signing (use must be "sig")');
	}
	if (keyOps !== undefined && !(Array.isArray(keyOps) && keyOps.includes("sign"))) {
		throw new ClientKeyError('the client key\'s key_ops do not include "sign"');
	}
	const named = alg === ED25519_ALIAS && algorithms.includes("EdDSA") ? "EdDSA" : alg;
	if (named !== undefined && !algorithms.includes(named as ClientAssertionAlgorithm)) {
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
		alg: (named as ClientAssertionAlgorithm | undefined) ?? algorithms[0],
		kid: (kid as string | undefined) ?? null,
		thumbprint: thumbprintOf(key),
	};
};

/**
 * The JWS signature (RFC 7518 section 3) over `input`. Synchronous, on the
 * calling thread: a call's deadline starts after signing, and signing never
 * waits for the threadpool. ECDSA signatures are the fixed-width `R || S`
 * JWS uses, not DER.
 */
const signJws = (alg: ClientAssertionAlgorithm, input: Buffer, key: KeyObject): Buffer => {
	switch (alg) {
		case "EdDSA":
			return sign(null, input, key);
		case "ES256":
		case "ES384":
		case "ES512":
			return sign(`sha${alg.slice(2)}`, input, { key, dsaEncoding: "ieee-p1363" });
		case "RS256":
		case "RS384":
		case "RS512":
			return sign(`sha${alg.slice(2)}`, input, key);
		case "PS256":
		case "PS384":
		case "PS512":
			return sign(`sha${alg.slice(2)}`, input, {
				key,
				padding: constants.RSA_PKCS1_PSS_PADDING,
				saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
			});
	}
};

const base64urlJson = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

export interface ClientAssertionParams {
	clientId: string;
	/** The provider's issuer identifier: the assertion's only audience. */
	audience: string;
	key: ClientKey;
}

/**
 * Signs one client assertion, a JWS compact JWT: `iss` and `sub` the client,
 * `aud` the issuer, a random `jti`, and `exp`
 * {@link CLIENT_ASSERTION_LIFETIME_SECONDS} after `iat`. The provider accepts
 * each `jti` once, so a call signs its own and never reuses one.
 */
export const signClientAssertion = (
	{ clientId, audience, key }: ClientAssertionParams,
	now: number = Date.now(),
): string => {
	const iat = Math.floor(now / 1000);
	const header: Record<string, string> = { alg: key.alg, typ: CLIENT_ASSERTION_JWT_TYPE };
	if (key.kid !== null) header.kid = key.kid;
	const payload = {
		iss: clientId,
		sub: clientId,
		aud: audience,
		jti: randomUUID(),
		iat,
		exp: iat + CLIENT_ASSERTION_LIFETIME_SECONDS,
	};
	const input = `${base64urlJson(header)}.${base64urlJson(payload)}`;
	return `${input}.${signJws(key.alg, Buffer.from(input), key.key).toString("base64url")}`;
};
