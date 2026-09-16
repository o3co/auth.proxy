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
 * Why a credential was not accepted for exchange — a bounded class, so it can
 * be logged without the header bytes:
 *
 *   - `scheme`  the `Authorization` scheme is not `Bearer`
 *   - `format`  a `Bearer` credential that is not a JWS compact JWT whose
 *               header and payload are JSON objects (an opaque token, a JWE,
 *               a malformed segment)
 */
export type AssertionRejectReason = "scheme" | "format";

export type BearerAssertion =
	| {
			kind: "assertion";
			/** The JWT exactly as received, to be submitted as `assertion`. */
			assertion: string;
			/** Unverified `iss`; `null` when absent, empty or not a string. */
			issuer: string | null;
			/** Unverified `exp` in seconds; `null` when absent or not a number. */
			expiresAt: number | null;
	  }
	| { kind: "unsupported"; reason: AssertionRejectReason };

/** Three non-empty base64url segments: header, payload, signature (RFC 7515 section 7.1). */
const JWS_COMPACT_RE = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+$/;

const decodeJsonObject = (segment: string): Record<string, unknown> | null => {
	try {
		const parsed: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
};

/**
 * Reads an inbound `Authorization` header as an RFC 7523 JWT assertion
 * WITHOUT verifying it.
 *
 * Nothing here establishes identity or trust. The signature, issuer, audience,
 * expiry and every profile rule (ID-JAG's `typ`, `client_id` binding and
 * one-time `jti`) are the provider's to check when the assertion is submitted.
 * The unverified claims are read for exactly two purposes: `exp` can only
 * SHORTEN how long the exchanged token is cached, and `iss` feeds the optional
 * `allowedIssuers` prefilter, which can only refuse. Neither selects an
 * endpoint, a key or a client.
 *
 * Grammar: RFC 6750 section 2.1 `"Bearer" 1*SP b64token`, with the scheme
 * compared case-insensitively (RFC 9110 section 11.1). Only a JWS compact
 * serialization is accepted as the token, so an opaque access token or a JWE
 * is refused here rather than costing a provider call.
 */
export const parseBearerAssertion = (header: string): BearerAssertion => {
	const schemeEnd = header.search(/[ \t]/);
	const scheme = schemeEnd === -1 ? header : header.slice(0, schemeEnd);
	if (scheme.toLowerCase() !== "bearer") {
		return { kind: "unsupported", reason: "scheme" };
	}

	const token = /^ +(\S+)$/.exec(header.slice(scheme.length))?.[1];
	const segments = token === undefined ? null : JWS_COMPACT_RE.exec(token);
	if (token === undefined || segments === null) {
		return { kind: "unsupported", reason: "format" };
	}

	const jose = decodeJsonObject(segments[1]);
	const claims = decodeJsonObject(segments[2]);
	if (jose === null || claims === null) {
		return { kind: "unsupported", reason: "format" };
	}

	return {
		kind: "assertion",
		assertion: token,
		issuer: typeof claims.iss === "string" && claims.iss.length > 0 ? claims.iss : null,
		expiresAt:
			typeof claims.exp === "number" && Number.isFinite(claims.exp) ? claims.exp : null,
	};
};
