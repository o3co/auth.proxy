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
	verify,
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

/**
 * The members that make a JWK's public key (RFC 7638 section 3.2), in the
 * lexicographic order its thumbprint hashes them in.
 */
const PUBLIC_MEMBERS: Record<string, readonly string[]> = {
	OKP: ["crv", "kty", "x"],
	EC: ["crv", "kty", "x", "y"],
	RSA: ["e", "kty", "n"],
};

/** RFC 7638: the public members, in order, hashed. */
const thumbprintOf = (publicJwk: Record<string, unknown>): string => {
	const canonical = `{${Object.entries(publicJwk)
		.map(([name, value]) => `${JSON.stringify(name)}:${JSON.stringify(value)}`)
		.join(",")}}`;
	return createHash("sha256").update(canonical).digest("base64url");
};

/**
 * Reads a client key from a private JWK, given as an object or as its JSON
 * text (the form an environment variable carries). The key must be one the
 * provider can verify an assertion from: an Ed25519, EC P-256/P-384/P-521 or
 * RSA (2048 bits or more) private key, not marked for another use than
 * signing (`use`, `key_ops`), whose public members are its private key's. The
 * JWK's `alg`, when present, must fit the key by its JWS name (`EdDSA`, not
 * RFC 9864's `Ed25519`); its `kid`, when present, goes in every assertion's
 * header.
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
	// The provider matches a registered key's alg to the header's exactly, so
	// RFC 9864's Ed25519 would be refused where EdDSA is verified.
	if (alg === "Ed25519") {
		throw new ClientKeyError(
			"the client key's alg is RFC 9864's Ed25519, which is not what the provider verifies: set alg to EdDSA or remove it, and register the public key the same way",
		);
	}
	if (alg !== undefined && !algorithms.includes(alg as ClientAssertionAlgorithm)) {
		throw new ClientKeyError(
			`the client key's alg does not fit the key; for this key use one of ${algorithms.join(", ")}, or no alg`,
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

	// The operator registers the public part this JWK carries, and the provider
	// verifies with it: a signature by the private part must verify under it.
	// Not every Node checks the two agree when the key is read.
	const chosen = (alg as ClientAssertionAlgorithm | undefined) ?? algorithms[0];
	const members = jwk as Record<string, unknown>;
	const publicJwk = Object.fromEntries(
		(PUBLIC_MEMBERS[kty as string] ?? []).map((name) => [name, members[name]]),
	);
	let matches = false;
	try {
		const publicKey = createPublicKey({ key: publicJwk, format: "jwk" } as JsonWebKeyInput);
		const probe = Buffer.from("client key self-check");
		matches = verifyJws(chosen, probe, publicKey, signJws(chosen, probe, key));
	} catch {
		matches = false;
	}
	if (!matches) {
		throw new ClientKeyError("the client key's public part does not match its private part");
	}

	return {
		key,
		alg: chosen,
		kid: (kid as string | undefined) ?? null,
		thumbprint: thumbprintOf(publicJwk),
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

/** Verifies a signature {@link signJws} made. */
const verifyJws = (
	alg: ClientAssertionAlgorithm,
	input: Buffer,
	key: KeyObject,
	signature: Buffer,
): boolean => {
	switch (alg) {
		case "EdDSA":
			return verify(null, input, key, signature);
		case "ES256":
		case "ES384":
		case "ES512":
			return verify(`sha${alg.slice(2)}`, input, { key, dsaEncoding: "ieee-p1363" }, signature);
		case "RS256":
		case "RS384":
		case "RS512":
			return verify(`sha${alg.slice(2)}`, input, key, signature);
		case "PS256":
		case "PS384":
		case "PS512":
			return verify(
				`sha${alg.slice(2)}`,
				input,
				{ key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
				signature,
			);
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
